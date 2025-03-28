// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2024 Jaroslav Rohel, jaroslav.rohel@gmail.com

#ifndef _TYPES_H_
#define _TYPES_H_

#include <stdint.h>

// structs are paked
#pragma pack(push, 1)

// The `i86_interrupt_regs_pack` is used to access the register values stored on the stack.
// It assumes that the registers were stored by instructions in this order:
// 1. INT n  -  stores flags, cs, ip
// 2. PUSHA  -  `Temp = SP; PUSH AX; PUSH CX; PUSH DX; PUSH BX; PUSH Temp; PUSH BP; PUSH SI; PUSH DI;`
// 3. PUSH ds
// 4. PUSH es
union i86_interrupt_regs_pack {
    struct {
        uint16_t es;
        uint16_t ds;
        uint16_t di;
        uint16_t si;
        uint16_t bp;
        uint16_t sp;
        uint16_t bx;
        uint16_t dx;
        uint16_t cx;
        uint16_t ax;
        uint16_t ip;
        uint16_t cs;
        uint16_t flags;
    } w;
    struct {
        unsigned /*es*/ : 16, /*ds*/ : 16,
            /*di*/ : 16, /*si*/ : 16,
            /*bp*/ : 16, /*sp*/ : 16;
        uint8_t bl, bh;
        uint8_t dl, dh;
        uint8_t cl, ch;
        uint8_t al, ah;
    } b;
};


// bits defined for flags field
enum {
    I86_FLAG_CF = 0x0001,  // carry
    I86_FLAG_PF = 0x0004,  // parity
    I86_FLAG_AF = 0x0010,  // auxiliary carry
    I86_FLAG_ZF = 0x0040,  // zero
    I86_FLAG_SF = 0x0080,  // sign
    I86_FLAG_TF = 0x0100,  // trace
    I86_FLAG_IF = 0x0200,  // interrupt
    I86_FLAG_DF = 0x0400,  // direction
    I86_FLAG_OF = 0x0800   // overflow
};

#pragma pack(pop)

#endif
