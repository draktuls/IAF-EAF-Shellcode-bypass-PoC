IFDEF RAX

.code

EXTRN	main:PROC

AlignRSP PROC
    push rsi ; Preserve RSI since we're stomping on it
    mov rsi, rsp ; Save the value of RSP so it can be restored
    and rsp, 0FFFFFFFFFFFFFFF0h ; Align RSP to 16 bytes
    sub rsp, 020h ; Allocate homing space for ExecutePayload
    call main ; Call the entry point of the payload
    mov rsp, rsi ; Restore the original value of RSP
    pop rsi ; Restore RSI
    ret ; Return to caller
AlignRSP ENDP

ELSE
.model flat
.code

; There is _ as prefix because some weird things are happening while linking

EXTRN	_main_x86:PROC

_main PROC
    sub esp,4               ; Make a space
    call _get_current_eip   ; Call get address 
    sub eax, 8              ; Subtract 8 from the result to get the first instruction
    mov [esp], eax          ; Set result into empty space on stack
    call _main_x86          ; Call the entry point of the payload
    add esp,4               ; Remove the result or we will be in an infinite loop
    ret                     ; Return to caller
_main ENDP

_get_current_eip PROC
	mov eax, [esp]
	ret
_get_current_eip ENDP

ENDIF

end 