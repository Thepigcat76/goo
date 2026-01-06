#pragma once

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

typedef uint8_t Register;

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
} InsFlags;

typedef struct {
  Prefix prefix;
  Opcode opcode;
  ModRM mod_rm;
  SIB sib;
  uint8_t disp[4];
  uint8_t imm[4];
  InsFlags flags;
} Instruction;

#define PREFIX_EMPTY ((Prefix){})

#define OPCODE1(b0) ((Opcode){.bytes = {[0] = b0}, .len = 1})
#define OPCODE2(b0, b1) ((Opcode){.bytes = {[0] = b0, [1] = b1}, .len = 2})
#define OPCODE3(b0, b1, b2)                                                    \
  ((Opcode){.bytes = {[0] = b0, [1] = b1, [2] = b2}, .len = 3})

#define MOD_RM_EMPTY ((ModRM){})

#define SIB_EMPTY ((SIB){})

#define DISP_EMPTY                                                             \
  {                                                                            \
  }

#define IMM_EMPTY                                                              \
  {                                                                            \
  }

#define IMM32_PACK(imm)                                                        \
  {[0] = (imm) & 0xFF,                                                         \
   [1] = ((imm) >> 8) & 0xFF,                                                  \
   [2] = ((imm) >> 16) & 0xFF,                                                 \
   [3] = ((imm) >> 24) & 0xFF}

#define MAKE_INS(_prefix, _opcode, _mod_rm, _sib, _disp, _imm, ...)            \
  (Instruction) {                                                              \
    .prefix = _prefix, .opcode = _opcode, .mod_rm = _mod_rm, .sib = _sib,      \
    .disp = _disp, .imm = _imm, .flags = (InsFlags)__VA_ARGS__                 \
  }

#define MAKE_INS_OPCODE_ONLY(...)                                              \
  MAKE_INS(PREFIX_EMPTY, __VA_ARGS__, MOD_RM_EMPTY, SIB_EMPTY, DISP_EMPTY,     \
           IMM_EMPTY,                                                          \
           {.has_prefix = false,                                               \
            .has_mod_rm = false,                                               \
            .has_sib = false,                                                  \
            .has_disp = false,                                                 \
            .has_imm = false})

#define MAKE_INS_OPCODE_DISP(_opcode, ...)                                     \
  (Instruction) {                                                              \
    .prefix = PREFIX_EMPTY, .opcode = _opcode, .mod_rm = MOD_RM_EMPTY,         \
    .sib = SIB_EMPTY, .disp = DISP_EMPTY, .imm = __VA_ARGS__, .flags = {       \
      .has_imm = true                                                          \
    }                                                                          \
  }

#define MAKE_INS_OPCODE_IMM(_opcode, ...)                                      \
  (Instruction) {                                                              \
    .prefix = PREFIX_EMPTY, .opcode = _opcode, .mod_rm = MOD_RM_EMPTY,         \
    .sib = SIB_EMPTY, .disp = DISP_EMPTY, .imm = __VA_ARGS__, .flags = {       \
      .has_imm = true                                                          \
    }                                                                          \
  }

static const Instruction INS_RET = MAKE_INS_OPCODE_ONLY(OPCODE1(0xc3));
static const Instruction INS_NOP = MAKE_INS_OPCODE_ONLY(OPCODE1(0x90));
static const Instruction INS_CALL = (Instruction){
    .opcode = OPCODE1(0xe8), .imm = IMM32_PACK(0), .flags = {.has_imm = true}};

#define INS_JMP_DISP8(...) MAKE_INS_OPCODE_DISP(OPCODE1(0xeb), __VA_ARGS__)

#define INS_JMP_DISP32(...) MAKE_INS_OPCODE_DISP(OPCODE1(0xe9), __VA_ARGS__)

#define INS_PUSH_R32(reg) MAKE_INS_OPCODE_ONLY(OPCODE1(0x50 + reg))

#define INS_POP_R32(reg) MAKE_INS_OPCODE_ONLY(OPCODE1(0x58 + reg))

// Src -> Dest

#define INS_MOV_I32_R32(reg, ...)                                              \
  MAKE_INS_OPCODE_IMM(OPCODE1(0xb8 + reg), __VA_ARGS__)

#define INS_MOV_I32_R32_DISP8(_reg, _disp, ...)                                \
  (Instruction) {                                                              \
    .prefix = PREFIX_EMPTY, .opcode = OPCODE1(0xc7),                           \
    .mod_rm = {.mod = MOD_MEM_8BIT_DISP, .reg = 0b00, .rm = _reg},             \
    .sib = SIB_EMPTY, .disp = {256 - _disp, 0, 0, 0}, .imm = __VA_ARGS__,      \
    .flags = {                                                                 \
      .has_imm = true,                                                         \
      .has_disp = true,                                                        \
      .has_mod_rm = true,                                                      \
    }                                                                          \
  }

#define INS_XOR_R32_R32(r_src, r_dest)                                         \
  (Instruction) {                                                              \
    .prefix = PREFIX_EMPTY, .opcode = OPCODE1(0x31),                           \
    .mod_rm = {.mod = MOD_REG_DIRECT, .reg = r_src, .rm = r_dest},             \
    .sib = SIB_EMPTY, .flags = {                                               \
      .has_mod_rm = true,                                                      \
    }                                                                          \
  }

#define INS_LEA_R32_R32_DISP32(r_src, r_dest, _disp)                           \
  (Instruction) {                                                              \
    .opcode = OPCODE1(0x8D),                                                   \
    .mod_rm = {.mod = MOD_MEM_32BIT_DISP, .reg = r_dest, .rm = r_src},         \
    .disp = _disp, .imm = IMM32_PACK(0), .flags = {                            \
      .has_mod_rm = true,                                                      \
      .has_disp = true                                                         \
    }                                                                          \
  }

#define INS_LEA_ABS_ADDR32_R32(_disp, r_dest)                                  \
  (Instruction) {                                                              \
    .opcode = OPCODE1(0x8D),                                                   \
    .mod_rm = {.mod = MOD_MEM_NO_DISP, .reg = r_dest, .rm = 101},              \
    .disp = _disp, .imm = IMM32_PACK(0), .flags = {                            \
      .has_mod_rm = true,                                                      \
      .has_disp = true                                                         \
    }                                                                          \
  }

#define INS_LEA_ABS_ADDR32_R64(_disp, r_dest)                                  \
  (Instruction) {                                                              \
    .opcode = OPCODE2(0x48, 0x8D),                                                   \
    .mod_rm = {.mod = MOD_MEM_NO_DISP, .reg = r_dest, .rm = 101},              \
    .disp = _disp, .imm = IMM32_PACK(0), .flags = {                            \
      .has_mod_rm = true,                                                      \
      .has_disp = true                                                         \
    }                                                                          \
  }

#define INS_LEA_R32_R32_DISP8(r_src, r_dest, _disp)                            \
  (Instruction) {                                                              \
    .opcode = OPCODE1(0x8d),                                                   \
    .mod_rm = {.mod = MOD_MEM_8BIT_DISP, .reg = r_dest, .rm = r_src},          \
    .disp = _disp, .flags = {                                                  \
      .has_mod_rm = true,                                                      \
      .has_disp = true                                                         \
    }                                                                          \
  }

#define INS_MOV_R32_DISP8_R32(r_src, _disp, r_dest)                            \
  (Instruction) {                                                              \
    .opcode = OPCODE2(0x48, 0x8b),                                             \
    .mod_rm = {.mod = MOD_MEM_8BIT_DISP, .reg = r_dest, .rm = r_src},          \
    .disp = _disp, .flags = {                                                  \
      .has_mod_rm = true,                                                      \
      .has_disp = true                                                         \
    }                                                                          \
  }

#define INS_MOV_R32_DISP32_R32(r_src, _disp, r_dest)                           \
  (Instruction) {                                                              \
    .opcode = OPCODE1(0x8b),                                                   \
    .mod_rm = {.mod = MOD_MEM_32BIT_DISP, .reg = r_dest, .rm = r_src},         \
    .disp = _disp, .flags = {                                                  \
      .has_mod_rm = true,                                                      \
      .has_disp = true                                                         \
    }                                                                          \
  }

#define INS_MOV_ABS_ADDR32_R32(_disp, r_dest)                                  \
  (Instruction) {                                                              \
    .opcode = OPCODE1(0x8b),                                                   \
    .mod_rm = {.mod = MOD_MEM_NO_DISP, .reg = r_dest, .rm = 101},              \
    .disp = _disp, .flags = {                                                  \
      .has_mod_rm = true,                                                      \
      .has_disp = true                                                         \
    }                                                                          \
  }

#define INS_MOV_R32_R32_DISP8(r_src, r_dest, _disp)                            \
  (Instruction) {                                                              \
    .opcode = OPCODE1(0x89),                                                   \
    .mod_rm = {.mod = MOD_MEM_8BIT_DISP, .reg = r_src, .rm = r_dest},          \
    .disp = _disp, .flags = {                                                  \
      .has_mod_rm = true,                                                      \
      .has_disp = true                                                         \
    }                                                                          \
  }

#define INS_MOV_R32_R32_DISP32(r_src, r_dest, _disp)                           \
  (Instruction) {                                                              \
    .opcode = OPCODE1(0x8),                                                    \
    .mod_rm = {.mod = MOD_MEM_32BIT_DISP, .reg = r_src, .rm = r_dest},         \
    .disp = _disp, .flags = {                                                  \
      .has_mod_rm = true,                                                      \
      .has_disp = true                                                         \
    }                                                                          \
  }

#define INS_MOV_R32_R32(r_src, r_dest)                                         \
  (Instruction) {                                                              \
    .opcode = OPCODE2(0x48, 0x89),                                                   \
    .mod_rm = {.mod = MOD_REG_DIRECT, .reg = r_src, .rm = r_dest}, .flags = {  \
      .has_mod_rm = true,                                                      \
    }                                                                          \
  }

#define INS_LEA_R32_R32(r_src, r_dest)                                         \
  (Instruction) {                                                              \
    .opcode = OPCODE1(0x8D),                                                   \
    .mod_rm = {.mod = MOD_MEM_NO_DISP, .reg = r_dest, .rm = r_src}, .flags = { \
      .has_mod_rm = true,                                                      \
    }                                                                          \
  }

#define INS_ADD_I32_R32(r_dest, _imm)                                          \
  (Instruction) {                                                              \
    .opcode = OPCODE1(0x81), .mod_rm = {.mod = MOD_REG_DIRECT, .rm = r_dest},  \
    .imm = _imm, .flags = {                                                    \
      .has_mod_rm = true,                                                      \
      .has_imm = true,                                                         \
    }                                                                          \
  }

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
