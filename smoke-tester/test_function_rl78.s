    ; The stepping test's program for RL78, as test_function_arm.s is for ARM: AX counts, E
    ; flags the end, and FFH (the illegal instruction, which enters the debug monitor) stands
    ; in for BKPT.
    .text
    .global test_func
test_func:
    clrw    ax              ; 0x00
    movw    bc, #128        ; 0x01
    mov     e, #0           ; 0x04
    .byte   0xff            ; 0x06
loop:
    incw    ax              ; 0x07
    cmpw    ax, bc          ; 0x08
    bnh     $loop           ; 0x09
    mov     e, #1           ; 0x0c
    .byte   0xff            ; 0x0e
finish:
    br      $finish         ; 0x0f
