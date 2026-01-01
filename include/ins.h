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
} Ins;

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
   [1] = (imm >> 8) & 0xFF,                                                    \
   [2] = (imm >> 16) & 0xFF,                                                   \
   [3] = (imm >> 24) & 0xFF}

#define MAKE_INS(_prefix, _opcode, _mod_rm, _sib, _disp, _imm, ...)            \
  (Ins) {                                                                      \
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

#define MAKE_INS_OPCODE_DISP(_opcode, ...)                                      \
  (Ins) {                                                                      \
    .prefix = PREFIX_EMPTY, .opcode = _opcode, .mod_rm = MOD_RM_EMPTY,         \
    .sib = SIB_EMPTY, .disp = DISP_EMPTY, .imm = __VA_ARGS__, .flags = {       \
      .has_imm = true                                                          \
    }                                                                          \
  }

#define MAKE_INS_OPCODE_IMM(_opcode, ...)                                      \
  (Ins) {                                                                      \
    .prefix = PREFIX_EMPTY, .opcode = _opcode, .mod_rm = MOD_RM_EMPTY,         \
    .sib = SIB_EMPTY, .disp = DISP_EMPTY, .imm = __VA_ARGS__, .flags = {       \
      .has_imm = true                                                          \
    }                                                                          \
  }

static const Ins INS_RET = MAKE_INS_OPCODE_ONLY(OPCODE1(0xc3));
static const Ins INS_NOP = MAKE_INS_OPCODE_ONLY(OPCODE1(0x90));
static const Ins INS_CALL = MAKE_INS_OPCODE_ONLY(OPCODE1(0xe8));

#define INS_JMP_DISP8(...) MAKE_INS_OPCODE_DISP(OPCODE1(0xeb), __VA_ARGS__)

#define INS_JMP_DISP32(...) MAKE_INS_OPCODE_DISP(OPCODE1(0xe9), __VA_ARGS__)

#define INS_PUSH_R32(reg) MAKE_INS_OPCODE_ONLY(OPCODE1(0x50 + reg))

#define INS_POP_R32(reg) MAKE_INS_OPCODE_ONLY(OPCODE1(0x58 + reg))

#define INS_MOV_R32_I32(reg, ...)                                              \
  MAKE_INS_OPCODE_IMM(OPCODE1(0xb8 + reg), __VA_ARGS__)

#define INS_MOV_R32_I32(reg, ...)                                              \
  MAKE_INS_OPCODE_IMM(OPCODE1(0xb8 + reg), __VA_ARGS__)

// return length
size_t ins_gen(const Ins *ins, uint8_t *ins_bytes);

int main(void) {
  uint8_t ins_bytes[32] = {0};
  size_t offset = 0;
  // offset += ins_gen(&INS_RET, ins_bytes + offset);
  // offset += ins_gen(&INS_CALL, ins_bytes + offset);
  // offset += ins_gen(&INS_NOP, ins_bytes + offset);
  // offset += ins_gen(&INS_POP_R32(REG_EBP), ins_bytes + offset);
  offset += ins_gen(&INS_JMP_DISP32(IMM32_PACK(512000)),
                    ins_bytes + offset);
  offset += ins_gen(&INS_MOV_R32_I32(REG_EBX, IMM32_PACK(512000)),
                    ins_bytes + offset);
  printf("Bytes:\n");
  for (size_t i = 0; i < 32; i++) {
    printf("%02x ", ins_bytes[i]);
  }
  printf("\n");
}
