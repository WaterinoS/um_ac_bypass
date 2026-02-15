#!/usr/bin/env python3
"""
VOWAC Binary Analyzer - Extracts HMAC secret and protocol details from vowac.exe
Supports plaintext (v1), BSWAP+XOR (v2), and BSWAP+ROR+dual-XOR (v3+) obfuscation
"""

import struct
import sys
import os
import hashlib
import string


def parse_pe_sections(data):
    """Parse PE64 section headers."""
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    sig = struct.unpack_from('<I', data, e_lfanew)[0]
    if sig != 0x4550:
        return None

    coff_off = e_lfanew + 4
    machine = struct.unpack_from('<H', data, coff_off)[0]
    num_sections = struct.unpack_from('<H', data, coff_off + 2)[0]

    opt_off = coff_off + 20
    magic = struct.unpack_from('<H', data, opt_off)[0]
    image_base = struct.unpack_from('<Q', data, opt_off + 24)[0]

    sections = []
    section_off = opt_off + 240  # PE32+ optional header
    for i in range(num_sections):
        s = section_off + i * 40
        name = data[s:s+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize = struct.unpack_from('<I', data, s + 8)[0]
        va = struct.unpack_from('<I', data, s + 12)[0]
        rawsize = struct.unpack_from('<I', data, s + 16)[0]
        rawoff = struct.unpack_from('<I', data, s + 20)[0]
        sections.append({
            'name': name, 'va': va, 'vsize': vsize,
            'rawoff': rawoff, 'rawsize': rawsize
        })

    return {
        'image_base': image_base,
        'machine': machine,
        'sections': sections
    }


def find_section(sections, name):
    """Find a section by name."""
    for s in sections:
        if s['name'] == name:
            return s
    return None


def rva_to_file(sections, rva):
    """Convert RVA to file offset."""
    for s in sections:
        if s['va'] <= rva < s['va'] + s['rawsize']:
            return rva - s['va'] + s['rawoff']
    return None


def file_to_rva(sections, foff):
    """Convert file offset to RVA."""
    for s in sections:
        if s['rawoff'] <= foff < s['rawoff'] + s['rawsize']:
            return foff - s['rawoff'] + s['va']
    return None


def try_plaintext_secret(data):
    """Try to find the secret as a plaintext string (v1 method)."""
    # Known old secrets to check
    known = [
        b'0XJuw8J8WdMVsbAAYeDaCfigrZfSLifWASLPn1FfICW3c2HI',
        b'7bVxJq3mT9eQpN1aLkH0rY2uZsC4dF6gW8nP5iE1oR3tU7yX',
    ]
    for s in known:
        pos = data.find(s)
        if pos >= 0:
            return s.decode(), pos, "plaintext (known)"

    # Also try to find any 48-byte string near SK1|
    sk1_pos = data.find(b'SK1|')
    if sk1_pos < 0:
        return None, -1, ""

    # Search in a window around SK1|
    search_start = max(0, sk1_pos - 0x400)
    search_end = min(len(data), sk1_pos + 0x400)
    window = data[search_start:search_end]

    import re
    # Look for 48-char base64-like strings
    for m in re.finditer(rb'[A-Za-z0-9+/]{48}', window):
        candidate = m.group().decode()
        abs_pos = search_start + m.start()
        # Verify it's not a common string
        if not any(x in candidate.lower() for x in ['users', 'target', 'release', 'build', 'windows']):
            return candidate, abs_pos, "plaintext (heuristic)"

    return None, -1, ""


def try_obfuscated_secret(data, pe_info):
    """Try to find the obfuscated secret (v2+ method, k0_obf.rs)."""
    sections = pe_info['sections']
    image_base = pe_info['image_base']

    # Step 1: Find k0_obf.rs anchor
    k0_pos = data.find(b'k0_obf.rs')
    if k0_pos < 0:
        return None, -1, "", -1

    # Step 2: Locate the 48 obfuscated bytes using structural layout:
    # k0_obf.rs string → padding to 8-byte align → Location struct (24 bytes) → 48 bytes data
    # Location struct = { ptr: u64, len: u64, col: u32, line: u32 }
    k0_end = k0_pos + len(b'k0_obf.rs')
    # Align to next 8-byte boundary
    aligned = (k0_end + 7) & ~7
    # Skip the Location struct (24 bytes: 8+8+4+4)
    obf_pos = aligned + 24

    obf_data = data[obf_pos:obf_pos + 48]
    non_ascii = sum(1 for b in obf_data if b > 0x7F)

    # If structural method didn't find obfuscated-looking data, fall back to scanning
    # v2 data has ~38+ high bytes, v3 has ~25+, so use a low threshold
    if non_ascii < 10:
        ac_pos = data.find(b'ac_crypto.rs', k0_pos)
        if ac_pos < 0:
            ac_pos = data.find(b'ac_crypto.rs')
        search_end = ac_pos if (ac_pos and ac_pos > k0_pos) else k0_pos + 0x200
        obf_data = None
        obf_pos = -1
        for offset in range(k0_pos, search_end - 48):
            chunk = data[offset:offset + 48]
            hi = sum(1 for b in chunk if b > 0x7F)
            if hi >= 38:
                obf_data = chunk
                obf_pos = offset
                break
        if obf_data is None:
            return None, -1, "", -1

    # Step 3: Try v3 deobfuscation first (BSWAP+ROR+dual-XOR), then v2 (BSWAP+XOR)
    text_sec = find_section(sections, '.text')
    if text_sec is None:
        return None, -1, "", -1

    def is_printable_secret(b):
        return b and all(chr(c) in string.printable and chr(c) not in '\t\n\r\x0b\x0c' for c in b)

    # Try v3: extract key table and counter from the deobfuscation function
    v3_result = try_v3_deobfuscation(data, pe_info, obf_pos, obf_data)
    if v3_result:
        return v3_result.decode(), obf_pos, "obfuscated (v3: BSWAP+ROR+dual-XOR)", -1

    # Try v2: find XOR key
    xor_key = find_xor_key(data, pe_info, obf_pos)
    if xor_key < 0:
        for candidate_key in [0xA7, 0x5A, 0x3C, 0xFF, 0x42]:
            result = deobfuscate(obf_data, candidate_key)
            if is_printable_secret(result):
                return result.decode(), obf_pos, f"obfuscated (BSWAP+XOR 0x{candidate_key:02X}, guessed)", candidate_key
        return None, obf_pos, "", -1

    result = deobfuscate(obf_data, xor_key)
    if is_printable_secret(result):
        return result.decode(), obf_pos, f"obfuscated (BSWAP+XOR 0x{xor_key:02X})", xor_key

    return None, obf_pos, "", xor_key


def find_xor_key(data, pe_info, obf_file_offset):
    """Find the XOR key from the deobfuscation function in .text."""
    sections = pe_info['sections']
    image_base = pe_info['image_base']
    text_sec = find_section(sections, '.text')

    if text_sec is None:
        return -1

    # Calculate the RVA of the obfuscated data
    obf_rva = file_to_rva(sections, obf_file_offset)
    if obf_rva is None:
        return -1
    obf_va = image_base + obf_rva

    # Search for MOVUPS/LEA instructions referencing the obfuscated data (RIP-relative)
    text_start = text_sec['rawoff']
    text_end = text_start + text_sec['rawsize']

    ref_locations = []
    for i in range(text_start, text_end - 8):
        # MOVUPS xmm, [rip+disp32] = 0F 10 05 xx xx xx xx (7 bytes)
        if data[i] == 0x0F and data[i+1] == 0x10 and (data[i+2] & 0xC7) == 0x05:
            disp32 = struct.unpack_from('<i', data, i + 3)[0]
            next_ip_va = image_base + file_to_rva(sections, i + 7)
            target = next_ip_va + disp32
            if target == obf_va:
                ref_locations.append(i)

    if not ref_locations:
        return -1

    # For each reference, search nearby for XOR dl/al, IMM8
    for ref_loc in ref_locations:
        # Search in a window around the reference (the deobfuscation loop is nearby)
        for i in range(ref_loc, min(ref_loc + 0x100, text_end - 3)):
            # XOR dl, imm8 = 80 F2 xx
            if data[i] == 0x80 and data[i+1] == 0xF2:
                return data[i+2]
            # XOR al, imm8 = 34 xx
            if data[i] == 0x34:
                # Needs more context to confirm, skip for now
                pass
            # XOR cl, imm8 = 80 F1 xx
            if data[i] == 0x80 and data[i+1] == 0xF1:
                return data[i+2]

    return -1


def deobfuscate(obf_data, xor_key):
    """Deobfuscate v2: BSWAP each 8-byte chunk, then XOR each byte."""
    if len(obf_data) != 48:
        return None
    result = bytearray()
    for i in range(6):
        chunk = obf_data[i*8:(i+1)*8]
        reversed_chunk = chunk[::-1]
        for b in reversed_chunk:
            result.append(b ^ xor_key)
    return bytes(result)


def ror8(val, count):
    """Rotate right an 8-bit value."""
    count = count % 8
    return ((val >> count) | (val << (8 - count))) & 0xFF


def deobfuscate_v3(obf_data, key_table, init_counter=0xDE):
    """Deobfuscate v3: BSWAP + position-dependent ROR + dual XOR (key table + running counter).

    Algorithm (from disassembly at VA 0x1403EDCBF in v3 binary):
      bpl starts at 1 (increments per chunk), r15b starts at init_counter.
      For each 8-byte chunk (chunk_idx 0..5):
        bswap the chunk, then for each byte position r8 (0..7):
          r14 = chunk_idx + r8 (inner counter)
          rotation = uint8(bpl - uint8((r14//7)*7)) + r8
          decoded = key_table[r8] ^ r15b ^ ror8(bswapped[r8], rotation)
          r15b += bpl
        After chunk: bpl++, r15b = saved_r15b + 0xA7
    """
    if len(obf_data) != 48 or len(key_table) != 8:
        return None
    result = bytearray()
    bpl = 1
    r15b = init_counter
    for chunk_idx in range(6):
        chunk = obf_data[chunk_idx*8:(chunk_idx+1)*8]
        bswapped = chunk[::-1]  # BSWAP reverses byte order
        saved_r15b = r15b
        r14 = chunk_idx
        for r8 in range(8):
            div_result = r14 // 7
            mul_result = div_result * 7
            cl = (bpl - (mul_result & 0xFF)) & 0xFF
            cl = (cl + r8) & 0xFF
            rotated = ror8(bswapped[r8], cl)
            dl = key_table[r8] ^ r15b ^ rotated
            result.append(dl)
            r14 += 1
            r15b = (r15b + bpl) & 0xFF
        bpl = (bpl + 1) & 0xFF
        r15b = (saved_r15b + 0xA7) & 0xFF
    return bytes(result)


def try_v3_deobfuscation(data, pe_info, obf_file_offset, obf_data):
    """Try v3 deobfuscation by extracting key table and init counter from the deobfuscation function.

    Looks for the function that references the obfuscated data via LEA (not MOVUPS).
    The function contains two MOVABS instructions loading the key table constant and
    an 'mov r15b, IMM8' for the initial counter, plus 'mov esi, 7' as a signature.
    """
    sections = pe_info['sections']
    image_base = pe_info['image_base']
    text_sec = find_section(sections, '.text')
    if text_sec is None:
        return None

    obf_rva = file_to_rva(sections, obf_file_offset)
    if obf_rva is None:
        return None
    obf_va = image_base + obf_rva

    text_start = text_sec['rawoff']
    text_end = text_start + text_sec['rawsize']

    # Find LEA reg, [rip+disp32] referencing the obfuscated data
    ref_locations = []
    for i in range(text_start, text_end - 7):
        # LEA r8, [rip+disp32] = 4C 8D 05 xx xx xx xx
        # LEA rax, [rip+disp32] = 48 8D 05 xx xx xx xx
        # LEA rcx, [rip+disp32] = 48 8D 0D xx xx xx xx
        if data[i] in (0x48, 0x4C) and data[i+1] == 0x8D and (data[i+2] & 0xC7) == 0x05:
            disp32 = struct.unpack_from('<i', data, i + 3)[0]
            rva = file_to_rva(sections, i + 7)
            if rva is None:
                continue
            next_ip_va = image_base + rva
            target = next_ip_va + disp32
            if target == obf_va:
                ref_locations.append(i)

    for ref_loc in ref_locations:
        # Search backwards (up to 128 bytes) for the function prologue area
        # Look for MOVABS rax, IMM64 (48 B8 xx*8) which loads the key table constant
        # and 'mov r15b, IMM8' (41 B7 xx) for init counter
        search_start = max(text_start, ref_loc - 128)
        key_table_val = None
        init_counter = None

        for j in range(search_start, ref_loc):
            # movabs rax, imm64 = 48 B8 xx xx xx xx xx xx xx xx
            if data[j] == 0x48 and data[j+1] == 0xB8 and j + 10 <= len(data):
                val = struct.unpack_from('<Q', data, j + 2)[0]
                # Check if this is followed by a store to [rsp+0x40] which is the key table
                # Look for 'mov [rsp+0x40], rax' = 48 89 44 24 40
                for k in range(j + 10, min(j + 20, len(data) - 5)):
                    if (data[k] == 0x48 and data[k+1] == 0x89 and
                        data[k+2] == 0x44 and data[k+3] == 0x24 and data[k+4] == 0x40):
                        key_table_val = val
                        break

            # mov r15b, imm8 = 41 B7 xx
            if data[j] == 0x41 and data[j+1] == 0xB7:
                init_counter = data[j+2]

        if key_table_val is not None and init_counter is not None:
            key_table = struct.pack('<Q', key_table_val)
            result = deobfuscate_v3(obf_data, key_table, init_counter)
            if result and all(chr(b) in string.printable and chr(b) not in '\t\n\r\x0b\x0c' for b in result):
                return result

    return None


def find_format_pieces(data, pe_info):
    """Analyze the canonical string format from format_args pieces."""
    sections = pe_info['sections']
    image_base = pe_info['image_base']

    # Find v1| string
    v1_pos = data.find(b'v1|')
    if v1_pos < 0:
        return None

    v1_rva = file_to_rva(sections, v1_pos)
    if v1_rva is None:
        return None
    v1_va = image_base + v1_rva

    # Find the pipe separator |
    # Look for a single | byte referenced from .rdata pointers near v1|
    # The format pieces array should be right after v1|\0
    pieces_start = v1_pos + 3  # after "v1|"

    # Skip null bytes / padding
    while pieces_start < v1_pos + 0x10 and data[pieces_start] == 0:
        pieces_start += 1

    # Try to parse the pieces array (ptr + len pairs, 16 bytes each)
    # First entry should point to v1| with length 3
    pieces = []
    pos = pieces_start
    for i in range(10):  # max 10 pieces
        if pos + 16 > len(data):
            break
        ptr = struct.unpack_from('<Q', data, pos)[0]
        length = struct.unpack_from('<Q', data, pos + 8)[0]

        # Sanity check: ptr should be in the image range, length should be small
        if ptr < image_base or ptr > image_base + len(data) or length > 100:
            break

        # Read the string
        ptr_rva = ptr - image_base
        ptr_foff = rva_to_file(sections, ptr_rva)
        if ptr_foff is None or ptr_foff + length > len(data):
            break

        piece_str = data[ptr_foff:ptr_foff + length].decode('ascii', errors='replace')
        pieces.append(piece_str)
        pos += 16

        # Stop if we hit something that's not a | separator (after the first entry)
        if i > 0 and piece_str != '|':
            break

    return pieces


def find_key_derivation_format(data):
    """Check if SK1| key derivation pattern exists."""
    sk1_pos = data.find(b'SK1|')
    if sk1_pos >= 0:
        return True, sk1_pos
    return False, -1


def check_field_names(data):
    """Check for known protocol field names."""
    fields = {
        'playerId': False,
        'sessionToken': False,
        'challenge': False,
        'machineId': False,
        'newChallenge': False,
        'tsUnixSeconds': False,
        'tick': False,
        'violatingModulesCount': False,
        'SignedReport': False,
    }
    for field in fields:
        if data.find(field.encode()) >= 0:
            fields[field] = True
    return fields


def main():
    if len(sys.argv) < 2:
        exe_path = r'C:\requests\vowac.exe'
    else:
        exe_path = sys.argv[1]

    if not os.path.exists(exe_path):
        print(f"[!] File not found: {exe_path}")
        sys.exit(1)

    data = open(exe_path, 'rb').read()
    file_hash = hashlib.sha256(data).hexdigest()
    file_size = len(data)

    print("=" * 65)
    print("  VOWAC Binary Analyzer")
    print("=" * 65)
    print(f"  File:   {exe_path}")
    print(f"  Size:   {file_size:,} bytes ({file_size/1024/1024:.2f} MB)")
    print(f"  SHA256: {file_hash}")
    print()

    # Parse PE
    pe_info = parse_pe_sections(data)
    if pe_info is None:
        print("[!] Not a valid PE file")
        sys.exit(1)

    print(f"  Image base: 0x{pe_info['image_base']:X}")
    print(f"  Machine:    0x{pe_info['machine']:X} ({'AMD64' if pe_info['machine'] == 0x8664 else 'unknown'})")
    print(f"  Sections:   {len(pe_info['sections'])}")
    print()

    # === SECRET EXTRACTION ===
    print("-" * 65)
    print("  SECRET EXTRACTION")
    print("-" * 65)

    secret = None

    # Try known plaintext secrets first (exact match)
    known_secrets = [
        b'0XJuw8J8WdMVsbAAYeDaCfigrZfSLifWASLPn1FfICW3c2HI',
        b'7bVxJq3mT9eQpN1aLkH0rY2uZsC4dF6gW8nP5iE1oR3tU7yX',
        b'rklbgifMCYwUdiqbIoHwEPpddSwiXW3YovpUKDpQQqPmVg3E',
    ]
    for ks in known_secrets:
        pos = data.find(ks)
        if pos >= 0:
            secret = ks.decode()
            print(f"  [+] SECRET found (known plaintext)")
            print(f"      Value:  {secret}")
            print(f"      Length: {len(secret)} bytes")
            print(f"      Offset: 0x{pos:X}")
            break

    # Try obfuscated method (v2+)
    if secret is None:
        ob_secret, ob_pos, ob_method, xor_key = try_obfuscated_secret(data, pe_info)
        if ob_secret:
            secret = ob_secret
            print(f"  [+] SECRET found ({ob_method})")
            print(f"      Value:  {secret}")
            print(f"      Length: {len(secret)} bytes")
            print(f"      Data at: 0x{ob_pos:X}")
        elif ob_pos >= 0:
            print(f"  [~] Found obfuscated data at 0x{ob_pos:X} but could not decode")
            print(f"      Raw hex: {data[ob_pos:ob_pos+48].hex()}")
            if xor_key >= 0:
                print(f"      XOR key found: 0x{xor_key:02X}")
                result = deobfuscate(data[ob_pos:ob_pos+48], xor_key)
                print(f"      Decoded (raw): {result}")
            print()
            print("  [!] MANUAL ANALYSIS REQUIRED")
            print("      The obfuscation method may have changed.")
            print("      Check the deobfuscation function near k0_obf.rs references.")
        else:
            print("  [!] SECRET NOT FOUND")
            print("      Neither plaintext nor obfuscated secret detected.")
            print()
            print("  [!] MANUAL ANALYSIS REQUIRED")
            print("      Possible reasons:")
            print("      - Secret storage method changed entirely")
            print("      - Binary structure differs from known patterns")
            print("      - Look for k0_obf.rs, ac_crypto.rs, SK1| strings as anchors")

    print()

    # === PROTOCOL ANALYSIS ===
    print("-" * 65)
    print("  PROTOCOL ANALYSIS")
    print("-" * 65)

    # Key derivation
    has_sk1, sk1_pos = find_key_derivation_format(data)
    if has_sk1:
        print(f"  [+] SK1| prefix found at 0x{sk1_pos:X}")
        print(f"      Key derivation: SK1|{{challenge}}|{{field1}}|{{field2}}")
    else:
        print("  [!] SK1| prefix NOT FOUND - key derivation may have changed")

    # Format pieces
    pieces = find_format_pieces(data, pe_info)
    if pieces:
        n_args = len(pieces)  # pieces == args when no trailing literal
        format_str = ""
        for i, p in enumerate(pieces):
            format_str += p
            if i < n_args:
                format_str += f"{{arg{i}}}"
        # Clean up the last arg placeholder if pieces == args
        print(f"  [+] Canonical string format ({len(pieces)} pieces, likely {len(pieces)} args):")
        # Reconstruct the known format
        if len(pieces) == 6 and pieces[0] == 'v1|' and all(p == '|' for p in pieces[1:]):
            print(f"      v1|{{method}}|{{path}}|{{sessionToken}}|{{ts}}|{{nonce}}|{{bodyHash}}")
            print(f"      (matches known pattern: v1|POST|/report|...)")
        else:
            print(f"      Pieces: {pieces}")
            print(f"      [~] Format may have changed - manual analysis recommended")
    else:
        print("  [~] Could not parse format pieces - manual analysis recommended")

    print()

    # Field names
    print("-" * 65)
    print("  FIELD NAMES")
    print("-" * 65)
    fields = check_field_names(data)
    for field, found in fields.items():
        status = "[+]" if found else "[-]"
        print(f"  {status} {field}")

    # Envelope
    ts_pos = data.find(b'tsnonce')
    if ts_pos >= 0:
        print()
        print(f"  [+] Envelope fields at 0x{ts_pos:X}: ts, nonce (+ body, sig from SignedReport)")

    print()
    print("=" * 65)
    if secret:
        print(f"  RESULT: SECRET = {secret}")
    else:
        print("  RESULT: Could not extract secret - manual analysis needed")
    print("=" * 65)


if __name__ == '__main__':
    main()
