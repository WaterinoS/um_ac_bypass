; CallStackSpoofer.asm - x86 assembly helper functions
.386
.model flat, c

PUBLIC _GetReturnAddressX86
PUBLIC _SetReturnAddressX86
PUBLIC _GetStackPointerX86

.code

; void* _GetReturnAddressX86()
_GetReturnAddressX86 PROC
    mov eax, [esp] 
    ret
_GetReturnAddressX86 ENDP

; void _SetReturnAddressX86(void* newAddress)
_SetReturnAddressX86 PROC
    mov eax, [esp + 4]
    mov [esp + 4], eax 
    ret
_SetReturnAddressX86 ENDP

; void** _GetStackPointerX86()
_GetStackPointerX86 PROC
    lea eax, [esp + 4]
    ret
_GetStackPointerX86 ENDP

END