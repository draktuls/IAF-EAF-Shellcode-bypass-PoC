IFDEF RAX

.code

read_primitive_long_long PROC
	jmp read_primitive	; Jump to the real gadget - overloading
read_primitive_long_long ENDP

read_primitive_int PROC
	jmp read_primitive	; Jump to the real gadget - overloading
read_primitive_int ENDP

read_primitive_char PROC
	jmp read_primitive	; Jump to the real gadget - overloading
read_primitive_char ENDP

read_primitive PROC
	push rdi			; Save rdi
	mov rdi, rcx		; Load gadget ptr to rdi which we will call later
	mov rax, rdx		; Load target pointer into rax - which is the gadget
	test r9b, r9b		; Test for negative number - this is either 0 or 1 and sets the ZF flag accordingly
	jz positive			; If ZF flag is zero we are dealing with [rax + x] gadget otherwise [rax - x] so we add or sub accordingly

	negative:
	add rax, r8
	jmp calling

	positive:
	sub rax, r8			; Decrease rax by the offset

	calling:
	call rdi			; Call gadget
	pop rdi				; Restore rdi
	ret
read_primitive ENDP

write_primitive PROC
	push rdi			; Save rdi
	mov rdi, rcx		; Load gadget ptr to rdi which we will call later
	mov rcx, rdx		; Load target pointer into rcx which will be accessed
	mov rax, r8			; Load new pointer into rax which will is referenced in the gadget
	call rdi			; Call gadget
	pop rdi				; Restore rdi
	ret
write_primitive ENDP

ELSE
.model flat ; 32
.code

; There are _ prefixes beacause otherwise the linking breaks - idk why

_read_primitive_int PROC
	jmp read_primitive				; Jump to the real gadget - overloading
_read_primitive_int ENDP

_read_primitive_char PROC
	jmp read_primitive				; Jump to the real gadget - overloading
_read_primitive_char ENDP

read_primitive PROC
	push ebp						; Push last ebp
	mov ebp, esp					; Get current esp
	push ecx						; We use this register so save it

	mov eax, dword ptr [ebp+12]		; Load target pointer
	mov ecx, dword ptr [ebp+20]		; Load offset
	test ecx,ecx					; Test offset like above
	jz positive
	negative:
	add eax, dword ptr [ebp+16]
	jmp calling

	positive:
	sub eax, dword ptr [ebp+16]

	calling:
	call dword ptr [ebp+8]			; To bypass EAF+ we need our ebp to be inside the threads stack memory

	pop ecx							; Now return to normal
	pop ebp
	ret
read_primitive ENDP

_write_primitive PROC
	push ecx
	mov eax, dword ptr [esp+16]
	mov ecx, dword ptr [esp+12]
	call dword ptr [esp+8]
	pop ecx
	ret
_write_primitive ENDP

ENDIF

end