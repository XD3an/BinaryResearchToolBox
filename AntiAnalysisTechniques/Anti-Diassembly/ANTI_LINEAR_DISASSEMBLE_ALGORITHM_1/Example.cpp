#include <Windows.h>

#define ANTI_LINEAR_DISASSEMBLE_ALGORITHM_1 asm("jmp next\n.byte 0xe8;\nnext:\n")

int start(void) {
    ANTI_LINEAR_DISASSEMBLE_ALGORITHM_1;
    return 0;
}

