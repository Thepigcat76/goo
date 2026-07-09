#pragma once

#include "lilc/numbers.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// clang-format off
/* Instruction Layout:
 * +-------------+------------+---+----------+---+--------+---+--------------+---+-----------+
 * | Prefix  | + | Opcode     | + | ModR/M   | + | SIB    | + | Displacement | + | Immediate |
 * | 4 Bytes |   | 1-3 Bytes  |   | 1 Byte   |   | 1 Byte |   | 1-4 Bytes    |   | 1-4 Bytes | <= 15 Bytes
 * | (Opt)   |   | (Required) |   | (Common) |   | (Opt)  |   | (Opt)        |   | (Opt)     |
 * +-------------+------------+---+----------+---+--------+---+--------------+---+-----------+
 */
// clang-format on

typedef struct {
  struct {
    uint8_t byte;
    bool present;
  } entry[4];
} Prefix;

typedef struct {
  uint8_t bytes[3];
  size_t len;
} Opcode;

// Special case (32-bit mode):
// If mod=00 and r/m=101, that means the address is a 32-bit absolute address
// (displacement only), not a register.
#define MOD_MEM_NO_DISP 0b00
#define MOD_MEM_8BIT_DISP 0b01
#define MOD_MEM_32BIT_DISP 0b10
#define MOD_REG_DIRECT 0b11

typedef int8_t Register;

#define REG_EAX 0b000
#define REG_ECX 0b001
#define REG_EDX 0b010
#define REG_EBX 0b011
#define REG_ESP 0b100
#define REG_EBP 0b101
#define REG_ESI 0b110
#define REG_EDI 0b111

typedef struct {
  // 7-6
  uint8_t mod;
  // 5-3
  uint8_t reg;
  // 2-0
  uint8_t rm;
} ModRM;

uint8_t mod_rm_gen(ModRM mod_rm);

#define SIB_SCALE_1 0b00
#define SIB_SCALE_2 0b01
#define SIB_SCALE_4 0b10
#define SIB_SCALE_8 0b11

typedef struct {
  // 7-6
  uint8_t scale;
  // 5-3 (register for index)
  uint8_t index;
  // 2-0 (register for base)
  uint8_t base;
} SIB;

uint8_t sib_gen(SIB sib);

typedef struct {
  bool has_prefix;
  bool has_mod_rm;
  bool has_sib;
  bool has_disp;
  bool has_imm;
  bool imm8;
  bool switch_imm_disp;
  bool explicit_disp8;
} InsFlags;

typedef struct {
  Prefix prefix;
  Opcode opcode;
  ModRM mod_rm;
  SIB sib;
  uint8_t disp[4];
  uint8_t imm[8];
  u8 imm_size;
  InsFlags flags;
} Instruction;

#define PREFIX_EMPTY ((Prefix){})

#define OPCODE1(b0) ((Opcode){.bytes = {[0] = b0}, .len = 1})
#define OPCODE2(b0, b1) ((Opcode){.bytes = {[0] = b0, [1] = b1}, .len = 2})
#define OPCODE3(b0, b1, b2)                                                    \
  ((Opcode){.bytes = {[0] = b0, [1] = b1, [2] = b2}, .len = 3})

#define MOD_RM_EMPTY ((ModRM){})

#define MOD_RM(_mod, _reg, _rm)                                                \
  (ModRM) { .mod = _mod, .reg = _reg, .rm = _rm }

#define SIB_EMPTY ((SIB){})

#define SIB_SCALE(_scale)                                                      \
  (_scale == 1                                                                 \
       ? 0b00                                                                  \
       : (_scale == 2                                                          \
              ? 0b01                                                           \
              : (_scale == 4 ? 0b10                                            \
                             : (_scale == 8 ? 0b11                             \
                                            : (uint8_t)(long)panic(            \
                                                  "INVALID SIB SCALE: %d",     \
                                                  (int)_scale)))))

#define DISP_EMPTY                                                             \
  {                                                                            \
  }

#define IMM_EMPTY                                                              \
  {                                                                            \
  }

#define IMM32_PACK(imm)                                                        \
  {                                                                            \
      [0] = (imm) & 0xFF,                                                      \
      [1] = ((imm) >> 8) & 0xFF,                                               \
      [2] = ((imm) >> 16) & 0xFF,                                              \
      [3] = ((imm) >> 24) & 0xFF,                                              \
  }

#define IMM64_PACK(imm)                                                        \
  {                                                                            \
      [0] = (imm) & 0xFF,         [1] = ((imm) >> 8) & 0xFF,                   \
      [2] = ((imm) >> 16) & 0xFF, [3] = ((imm) >> 24) & 0xFF,                  \
      [4] = ((imm) >> 32) & 0xFF, [5] = ((imm) >> 40) & 0xFF,                  \
      [6] = ((imm) >> 48) & 0xFF, [7] = ((imm) >> 56) & 0xFF,                  \
  }

#ifdef INS_IMPL
#define INS(name, args, ...)                                                   \
  Instruction ins_##name args { return (Instruction)__VA_ARGS__; }
#else
#define INS(name, args, ...) Instruction ins_##name args;
#endif

#define INS_MAKE(...) (Instruction) __VA_ARGS__

static const Instruction INS_RET = INS_MAKE({.opcode = OPCODE1(0xc3)});
static const Instruction INS_NOP = INS_MAKE({.opcode = OPCODE1(0x90)});
static const Instruction INS_CALL = INS_MAKE({
    .opcode = OPCODE1(0xe8),
    .imm = IMM32_PACK(0),
    .flags = {.has_imm = true},
});

INS(jmp_disp8, (i8 disp), {
  .opcode = OPCODE1(0xeb),
  .disp = {(u8)disp, 0, 0, 0},
  .flags = {
    .has_disp = true,
  },
})

INS(jne_disp32, (u32 disp), {
  .opcode = OPCODE2(0x0f, 0x85),
  .disp = IMM32_PACK(disp),
  .flags = {
    .has_disp = true,
  },
})

INS(je_disp8, (i8 disp), {
  .opcode = OPCODE1(0x74),
  .disp = {(u8)disp, 0, 0, 0},
  .flags = {
    .has_disp = true,
    .explicit_disp8 = true,
  },
})

INS(jmp_disp32, (u32 disp), {
  .opcode = OPCODE1(0xe9),
  .disp = IMM32_PACK(disp),
  .flags = {
    .has_disp = true,
  },
})

INS(jle_disp32, (u32 disp), {
  .opcode = OPCODE2(0x0f, 0x8e),
  .disp = IMM32_PACK(disp),
  .flags = {
    .has_disp = true,
  },
})

INS(jl_disp32, (u32 disp), {
  .opcode = OPCODE2(0x0f, 0x8c),
  .disp = IMM32_PACK(disp),
  .flags = {
    .has_disp = true,
  },
})

INS(push_r32, (Register reg), {
  .opcode = OPCODE1(0x50 + reg),
})

INS(pop_r32, (Register reg), {
  .opcode = OPCODE1(0x58 + reg),
})

INS(mov_i32_r32, (Register reg, u32 imm), {
  .opcode = OPCODE1(0xb8 + reg),
  .imm = IMM32_PACK(imm),
  .flags = {
    .has_imm = true,
  },
})

INS(mov_i32_r64, (Register reg, u32 imm), {
  .opcode = OPCODE2(0x48, 0xc7),
  .mod_rm = {.mod = MOD_REG_DIRECT, .rm = reg},
  .imm = IMM32_PACK(imm),
  .flags = {
    .has_imm = true,
    .has_mod_rm = true,
  },
})

INS(mov_i8_r32_disp8, (Register reg, i8 disp, u8 imm), {
  .prefix = PREFIX_EMPTY,
  .opcode = OPCODE1(0xc6),
  .mod_rm = {.mod = MOD_MEM_8BIT_DISP, .reg = 0b00, .rm = reg},
  .sib = SIB_EMPTY,
  .disp = {(u8)disp, 0, 0, 0},
  .imm = {[0] = imm},
  .imm_size = 1,
  .flags = {
    .has_imm = true,
    .has_disp = true,
    .has_mod_rm = true,
  },
})

INS(mov_i16_r32_disp8, (Register reg, i8 disp, u16 imm), {
  .prefix = PREFIX_EMPTY,
  .opcode = OPCODE2(0x66, 0xc7),
  .mod_rm = {.mod = MOD_MEM_8BIT_DISP, .reg = 0b00, .rm = reg},
  .sib = SIB_EMPTY,
  .disp = {(u8)disp, 0, 0, 0},
  .imm = {[0] = (u8)(imm & 0xff), [1] = (u8)((imm >> 8) & 0xff)},
  .imm_size = 2,
  .flags = {
    .has_imm = true,
    .has_disp = true,
    .has_mod_rm = true,
  },
})

INS(mov_i32_r32_disp8, (Register reg, i8 disp, u32 imm), {
  .prefix = PREFIX_EMPTY,
  .opcode = OPCODE1(0xc7),
  .mod_rm = {.mod = MOD_MEM_8BIT_DISP, .reg = 0b00, .rm = reg},
  .sib = SIB_EMPTY,
  .disp = {(u8)disp, 0, 0, 0},
  .imm = IMM32_PACK(imm),
  .flags = {
    .has_imm = true,
    .has_disp = true,
    .has_mod_rm = true,
  },
})

INS(mov_i64_r64, (Register reg, u64 imm), {
  .prefix = PREFIX_EMPTY,
  .opcode = OPCODE2(0x48, 0xb8 + reg),
  .sib = SIB_EMPTY,
  .imm = IMM64_PACK(imm),
  .imm_size = 8,
  .flags = {
    .has_imm = true,
  },
})

INS(cmp_i32_r64, (Register reg, u32 imm), {
  .opcode = OPCODE2(0x48, 0x81),
  .mod_rm = {.mod = MOD_REG_DIRECT, .reg = 0b111, .rm = reg},
  .imm = IMM32_PACK(imm),
  .flags = {
    .has_imm = true,
    .has_mod_rm = true,
  },
})

INS(cmp_i32_r64_disp32, (u32 imm, Register reg, u32 disp), {
  .opcode = OPCODE2(0x48, 0x81),
  .mod_rm = {.mod = MOD_MEM_32BIT_DISP, .reg = 0b111, .rm = reg},
  .imm = IMM32_PACK(imm),
  .disp = IMM32_PACK(disp),
  .flags = {
    .has_imm = true,
    .has_mod_rm = true,
    .has_disp = true,
  },
})

INS(cmp_i8_r64, (Register reg, u8 imm), {
  .opcode = OPCODE1(0x83),
  .mod_rm = {.mod = MOD_REG_DIRECT, .reg = 0b111, .rm = reg},
  .imm = {[0] = imm},
  .imm_size = 1,
  .flags = {
    .has_imm = true,
    .has_mod_rm = true,
    .imm8 = true,
  },
})

INS(xor_r32_r32, (Register r_src, Register r_dest), {
  .prefix = PREFIX_EMPTY,
  .opcode = OPCODE1(0x31),
  .mod_rm = {.mod = MOD_REG_DIRECT, .reg = r_src, .rm = r_dest},
  .sib = SIB_EMPTY,
  .flags = {
    .has_mod_rm = true,
  },
})

INS(lea_r32_r32_disp32, (Register r_src, Register r_dest, u32 disp), {
  .opcode = OPCODE1(0x8D),
  .mod_rm = {.mod = MOD_MEM_32BIT_DISP, .reg = r_dest, .rm = r_src},
  .disp = IMM32_PACK(disp),
  .imm = IMM32_PACK(0),
  .flags = {
    .has_mod_rm = true,
    .has_disp = true,
  },
})

INS(lea_abs_addr32_r32, (u32 disp, Register r_dest), {
  .opcode = OPCODE1(0x8D),
  .mod_rm = {.mod = MOD_MEM_NO_DISP, .reg = r_dest, .rm = 101},
  .disp = IMM32_PACK(disp),
  .imm = IMM32_PACK(0),
  .flags = {
    .has_mod_rm = true,
    .has_disp = true,
  },
})

INS(lea_abs_addr32_r64, (u32 disp, Register r_dest), {
  .opcode = OPCODE2(0x48, 0x8D),
  .mod_rm = {.mod = MOD_MEM_NO_DISP, .reg = r_dest, .rm = 101},
  .disp = IMM32_PACK(disp),
  .imm = IMM32_PACK(0),
  .flags = {
    .has_mod_rm = true,
    .has_disp = true,
  },
})

INS(lea_r32_r32_disp8, (Register r_src, Register r_dest, i8 disp), {
  .opcode = OPCODE1(0x8d),
  .mod_rm = {.mod = MOD_MEM_8BIT_DISP, .reg = r_dest, .rm = r_src},
  .disp = {(u8)disp, 0, 0, 0},
  .flags = {
    .has_mod_rm = true,
    .has_disp = true,
  },
})

INS(mov_r32_disp8_r32_hacky, (Register r_src, i8 disp, Register r_dest), {
  .opcode = OPCODE1(0x8b),
  .mod_rm = {.mod = MOD_MEM_8BIT_DISP, .reg = r_dest, .rm = r_src},
  .disp = {(u8)disp, 0, 0, 0},
  .flags = {
    .has_mod_rm = true,
    .has_disp = true,
  },
})

INS(mov_byte_r64_disp8_r64, (Register r_src, i8 disp, Register r_dest), {
  .opcode = OPCODE2(0x0f, 0xb6),
  .mod_rm = {.mod = MOD_MEM_8BIT_DISP, .reg = r_dest, .rm = r_src},
  .disp = {(u8)disp, 0, 0, 0},
  .flags = {
    .has_mod_rm = true,
    .has_disp = true,
  },
})

INS(mov_word_r64_disp8_r64, (Register r_src, i8 disp, Register r_dest), {
  .opcode = OPCODE2(0x0f, 0xb7),
  .mod_rm = {.mod = MOD_MEM_8BIT_DISP, .reg = r_dest, .rm = r_src},
  .disp = {(u8)disp, 0, 0, 0},
  .flags = {
    .has_mod_rm = true,
    .has_disp = true,
  },
})

INS(mov_r64_disp8_r64_hacky, (Register r_src, i8 disp, Register r_dest), {
  .opcode = OPCODE2(0x48, 0x8b),
  .mod_rm = {.mod = MOD_MEM_8BIT_DISP, .reg = r_dest, .rm = r_src},
  .disp = {(u8)disp, 0, 0, 0},
  .flags = {
    .has_mod_rm = true,
    .has_disp = true,
  },
})

INS(mov_indexed_r64_disp32,
    (Register r_src, u32 disp, Register r_index, u8 scale, Register r_dest),
    {
        .opcode = OPCODE1(0x8b),
        .mod_rm = {.mod = MOD_MEM_32BIT_DISP, .reg = r_dest, .rm = 100},
        .sib = {.scale = scale, .index = r_index, .base = r_src},
        .disp = IMM32_PACK(disp),
        .flags =
            {
                .has_mod_rm = true,
                .has_disp = true,
                .has_sib = true,
            },
    })

INS(mov_r32_disp8_r32, (Register r_src, i8 disp, Register r_dest),
    {
        .opcode = OPCODE1(0x8b),
        .mod_rm = {.mod = MOD_MEM_8BIT_DISP, .reg = r_dest, .rm = r_src},
        .disp = {(u8)disp, 0, 0, 0},
        .flags =
            {
                .has_mod_rm = true,
                .has_disp = true,
            },
    })

INS(mov_r32_disp32_r32, (Register r_src, u32 disp, Register r_dest),
    {
        .opcode = OPCODE1(0x8b),
        .mod_rm = {.mod = MOD_MEM_32BIT_DISP, .reg = r_dest, .rm = r_src},
        .disp = IMM32_PACK(disp),
        .flags =
            {
                .has_mod_rm = true,
                .has_disp = true,
            },
    })

INS(mov_r64_disp32_r64, (Register r_src, u32 disp, Register r_dest),
    {
        .opcode = OPCODE2(0x48, 0x8b),
        .mod_rm = {.mod = MOD_MEM_32BIT_DISP, .reg = r_dest, .rm = r_src},
        .disp = IMM32_PACK(disp),
        .flags =
            {
                .has_mod_rm = true,
                .has_disp = true,
            },
    })

INS(mov_abs_addr32_r32, (u32 disp, Register r_dest),
    {
        .opcode = OPCODE1(0x8b),
        .mod_rm = {.mod = MOD_MEM_NO_DISP, .reg = r_dest, .rm = 101},
        .disp = IMM32_PACK(disp),
        .flags =
            {
                .has_mod_rm = true,
                .has_disp = true,
            },
    })

INS(mov_abs_addr32_r64, (u32 disp, Register r_dest),
    {
        .opcode = OPCODE2(0x48, 0x8b),
        .mod_rm = {.mod = MOD_MEM_NO_DISP, .reg = r_dest, .rm = 101},
        .disp = IMM32_PACK(disp),
        .flags =
            {
                .has_mod_rm = true,
                .has_disp = true,
            },
    })

INS(mov_r32_r32_disp8, (Register r_src, Register r_dest, i8 disp),
    {
        .opcode = OPCODE1(0x89),
        .mod_rm = {.mod = MOD_MEM_8BIT_DISP, .reg = r_src, .rm = r_dest},
        .disp = {(u8)disp, 0, 0, 0},
        .flags =
            {
                .has_mod_rm = true,
                .has_disp = true,
            },
    })

INS(mov_r32_r32_disp32, (Register r_src, Register r_dest, u32 disp),
    {
        .opcode = OPCODE1(0x89),
        .mod_rm = {.mod = MOD_MEM_32BIT_DISP, .reg = r_src, .rm = r_dest},
        .disp = IMM32_PACK(disp),
        .flags =
            {
                .has_mod_rm = true,
                .has_disp = true,
            },
    })

INS(mov_r64_r64_disp8, (Register r_src, Register r_dest, i8 disp),
    {
        .opcode = OPCODE2(0x48, 0x89),
        .mod_rm = {.mod = MOD_MEM_8BIT_DISP, .reg = r_src, .rm = r_dest},
        .disp = {(u8)disp, 0, 0, 0},
        .flags =
            {
                .has_mod_rm = true,
                .has_disp = true,
            },
    })

INS(mov_r64_r64_disp32, (Register r_src, Register r_dest, u32 disp),
    {
        .opcode = OPCODE2(0x48, 0x89),
        .mod_rm = {.mod = MOD_MEM_32BIT_DISP, .reg = r_src, .rm = r_dest},
        .disp = IMM32_PACK(disp),
        .flags =
            {
                .has_mod_rm = true,
                .has_disp = true,
            },
    })

INS(lea_r32_r32, (Register r_src, Register r_dest),
    {
        .opcode = OPCODE1(0x8D),
        .mod_rm = {.mod = MOD_MEM_NO_DISP, .reg = r_dest, .rm = r_src},
        .flags =
            {
                .has_mod_rm = true,
            },
    })

INS(lea_r64_r64, (Register r_src, Register r_dest),
    {
        .opcode = OPCODE2(0x48, 0x8D),
        .mod_rm = {.mod = MOD_MEM_NO_DISP, .reg = r_dest, .rm = r_src},
        .flags =
            {
                .has_mod_rm = true,
            },
    })

INS(lea_r64_disp_r64, (Register r_src, u32 disp, Register r_dest),
    {
        .opcode = OPCODE2(0x48, 0x8D),
        .mod_rm = {.mod = MOD_MEM_32BIT_DISP, .reg = r_dest, .rm = r_src},
        .disp = IMM32_PACK(disp),
        .flags =
            {
                .has_mod_rm = true,
                .has_disp = true,
            },
    })

INS(mov_r64_r64_mem, (Register r_src, Register r_dest),
    {
        .opcode = OPCODE2(0x48, 0x89),
        .mod_rm = {.mod = MOD_MEM_NO_DISP, .reg = r_src, .rm = r_dest},
        .flags =
            {
                .has_mod_rm = true,
            },
    })

INS(mov_r64_mem_r64, (Register r_src, Register r_dest),
    {
        .opcode = OPCODE2(0x48, 0x8B),
        .mod_rm = {.mod = MOD_MEM_NO_DISP, .reg = r_dest, .rm = r_src},
        .flags =
            {
                .has_mod_rm = true,
            },
    })

INS(mov_r64_r64, (Register r_src, Register r_dest),
    {
        .opcode = OPCODE2(0x48, 0x89),
        .mod_rm = {.mod = MOD_REG_DIRECT, .reg = r_src, .rm = r_dest},
        .flags =
            {
                .has_mod_rm = true,
            },
    })

INS(mov_r32_r32, (Register r_src, Register r_dest),
    {
        .opcode = OPCODE1(0x89),
        .mod_rm = {.mod = MOD_REG_DIRECT, .reg = r_src, .rm = r_dest},
        .flags =
            {
                .has_mod_rm = true,
            },
    })

INS(mov_r8_r32, (Register r_src, Register r_dest),
    {
        .opcode = OPCODE2(0x0f, 0xb6),
        .mod_rm = {.mod = MOD_REG_DIRECT, .reg = r_src, .rm = r_dest},
        .flags =
            {
                .has_mod_rm = true,
            },
    })

INS(add_i32_r32, (Register r_dest, u32 imm),
    {
        .opcode = OPCODE1(0x81),
        .mod_rm = {.mod = MOD_REG_DIRECT, .rm = r_dest},
        .imm = IMM32_PACK(imm),
        .flags =
            {
                .has_mod_rm = true,
                .has_imm = true,
            },
    })

INS(add_i32_r64, (u32 imm, Register r_dest),
    {
        .opcode = OPCODE2(0x48, 0x81),
        .mod_rm = {.mod = MOD_REG_DIRECT, .rm = r_dest},
        .imm = IMM32_PACK(imm),
        .flags =
            {
                .has_mod_rm = true,
                .has_imm = true,
            },
    })

INS(add_i32_r64_disp32, (u32 imm, Register r_dest, u32 disp),
    {
        .opcode = OPCODE2(0x48, 0x81),
        .mod_rm = {.mod = MOD_MEM_32BIT_DISP, .rm = r_dest},
        .imm = IMM32_PACK(imm),
        .disp = IMM32_PACK(disp),
        .flags =
            {
                .has_mod_rm = true,
                .has_imm = true,
                .has_disp = true,
            },
    })

INS(add_r64_r64, (Register r_src, Register r_dest),
    {
        .opcode = OPCODE2(0x48, 0x01),
        .mod_rm = {.mod = MOD_REG_DIRECT, .rm = r_dest, .reg = r_src},
        .flags =
            {
                .has_mod_rm = true,
            },
    })

INS(sub_i32_r64, (u32 imm, Register r_dest),
    {
        .opcode = OPCODE2(0x48, 0x81),
        .mod_rm = {.mod = MOD_REG_DIRECT, .rm = r_dest, .reg = 0b101},
        .imm = IMM32_PACK(imm),
        .flags =
            {
                .has_mod_rm = true,
                .has_imm = true,
            },
    })

INS(sub_r64_r64, (Register r_src, Register r_dest),
    {
        .opcode = OPCODE2(0x48, 0x29),
        .mod_rm = {.mod = MOD_REG_DIRECT, .rm = r_dest, .reg = r_src},
        .flags =
            {
                .has_mod_rm = true,
            },
    })

INS(sub_abs_addr_r64, (Register r_dest),
    {
        .opcode = OPCODE2(0x48, 0x2b),
        .mod_rm = {.mod = MOD_MEM_NO_DISP, .reg = r_dest, .rm = 0b101},
        .disp = {0, 0, 0, 0},
        .flags =
            {
                .has_mod_rm = true,
                .has_disp = true,
            },
    })

INS(mul_i32_r64, (u32 imm, Register r_src, Register r_dest),
    {
        .opcode = OPCODE2(0x48, 0x69),
        .mod_rm = {.mod = MOD_REG_DIRECT, .reg = r_dest, .rm = r_src},
        .imm = IMM32_PACK(imm),
        .flags =
            {
                .has_mod_rm = true,
                .has_imm = true,
            },
    })

INS(mul_i32_abs_addr_r64, (u32 imm, Register r_dest),
    {
        .opcode = OPCODE2(0x48, 0x69),
        .mod_rm = {.mod = MOD_MEM_NO_DISP, .reg = r_dest, .rm = 0b101},
        .disp = {0, 0, 0, 0},
        .imm = IMM32_PACK(imm),
        .flags =
            {
                .has_mod_rm = true,
                .has_disp = true,
                .has_imm = true,
                .switch_imm_disp = false,
            },
    })

INS(sub_i8_r64, (u8 imm, Register r_dest),
    {
        .opcode = OPCODE2(0x48, 0x83),
        .mod_rm = {.mod = 0b11, .reg = 0b101, .rm = r_dest},
        .imm = {[0] = imm},
        .imm_size = 1,
        .flags =
            {
                .has_mod_rm = true,
                .has_imm = true,
                .imm8 = true,
            },
    })

INS(add_i8_r64, (u8 imm, Register r_dest),
    {
        .opcode = OPCODE2(0x48, 0x83),
        .mod_rm = {.mod = 0b11, .rm = r_dest},
        .imm = {[0] = imm},
        .imm_size = 1,
        .flags =
            {
                .has_mod_rm = true,
                .has_imm = true,
                .imm8 = true,
            },
    })

// return length
size_t ins_gen(const Instruction *ins, uint8_t *ins_bytes);

// int _main(void) {
//   uint8_t ins_bytes[32] = {0};
//   size_t offset = 0;
//   // offset += ins_gen(&INS_RET, ins_bytes + offset);
//   // offset += ins_gen(&INS_CALL, ins_bytes + offset);
//   // offset += ins_gen(&INS_NOP, ins_bytes + offset);
//   // offset += ins_gen(&INS_POP_R32(REG_EBP), ins_bytes + offset);
//   offset += ins_gen(&INS_JMP_DISP32(IMM32_PACK(512000)), ins_bytes + offset);
//   offset += ins_gen(&INS_MOV_I32_R32(REG_EBX, IMM32_PACK(512000)),
//                     ins_bytes + offset);
//   printf("Bytes:\n");
//   for (size_t i = 0; i < 32; i++) {
//     printf("%02x ", ins_bytes[i]);
//   }
//   printf("\n");
// }
