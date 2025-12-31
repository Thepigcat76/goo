#pragma once

#include "parser.h"
#include <stdio.h>

// If an instruction doesn't have a flag, you need to manually add it to the
// switch statement in the insn_generate function

// clang-format off
/* Arg Flags */
#define IF_ARG_SPECIAL         0x00
#define IF_ARG_NONE            0x00
#define IF_ARG_IMM8            0x01
#define IF_ARG_IMM16           0x02
#define IF_ARG_IMM32           0x03
#define IF_ARG_IMM64           0x04
#define IF_ARG_IMM8_DISP8      0x05
#define IF_ARG_IMM16_DISP8     0x06
#define IF_ARG_IMM32_DISP8     0x07
#define IF_ARG_IMM64_DISP8     0x08
#define IF_ARG_DISP8           0x09
#define IF_ARG_DISP32          0x0a
#define IF_ARG_REG_DISP8       0x0b
#define IF_ARG_REG_DISP32      0x0c
#define IF_ARG_REG_IMM8        0x0d
#define IF_ARG_REG_IMM16       0x0e
#define IF_ARG_REG_IMM32       0x0f
#define IF_ARG_REG_IMM64       0x10
#define IF_ARG_REG             0x11
#define IF_ARG_REG_REG         0x12
#define IF_ARG_REG_IMM_DISP8   0x13
#define IF_ARG_IMM8_DISP32     0x14
#define IF_ARG_IMM16_DISP32    0x15
#define IF_ARG_IMM32_DISP32    0x16
#define IF_ARG_IMM64_DISP32    0x17

/* Ins Flags */
#define IF_INS_XOR     0x00
#define IF_INS_MOV     0x01
#define IF_INS_JMP     0x02
#define IF_INS_CALL    0x03
#define IF_INS_LEA     0x04
#define IF_INS_ADD     0x05
#define IF_INS_SUB     0x06
#define IF_INS_MUL     0x07
#define IF_INS_DIV     0x08
#define IF_INS_PUSH    0x09
#define IF_INS_POP     0x0a
#define IF_INS_GENERIC 0x0b            /* An instruction without args that does not need manual adjustments */

#define OPCODE1(flag_arg, flag_ins, b0)                                         \
  (((uint64_t)(flag_arg) << 0) |                                                \
  ((uint64_t)(flag_ins) << 8) |                                                 \
  ((uint64_t)(0x01) << 16) |                                                    \
  ((uint64_t)(b0) << 24))

#define OPCODE2(flag_arg, flag_ins, b0, b1)                                     \
  (((uint64_t)(flag_arg) << 0) |                                                \
  ((uint64_t)(flag_ins) << 8) |                                                 \
  ((uint64_t)(0x02) << 16) |                                                    \
  ((uint64_t)(b0) << 24) |                                                      \
  ((uint64_t)(b1) << 32))

#define OPCODE3(flag_arg, flag_ins, b0, b1, b2)                                 \
  (((uint64_t)(flag_arg) << 0) |                                                \
  ((uint64_t)(flag_ins) << 8) |                                                 \
  ((uint64_t)(0x03) << 16) |                                                    \
  ((uint64_t)(b0) << 24) |                                                      \
  ((uint64_t)(b1) << 32) |                                                      \
  ((uint64_t)(b2) << 40))

typedef uint64_t Opcode;

// src -> dest
  /* INS_JMP_<imm> */
#define INS_JMP_IMM8                OPCODE1(IF_ARG_IMM8, IF_INS_JMP, 0xeb)
#define INS_JMP_IMM32               OPCODE1(IF_ARG_IMM32, IF_INS_JMP, 0xe9)
  /* END INS_JMP_<imm> */
  /* INS_XOR_<reg>_<reg> (Reg-Base: C0) */
// FIXME: This xors <rax> <reg64>
#define INS_XOR_REG64               OPCODE2(IF_ARG_REG, IF_INS_XOR, 0x48, 0x31)
#define INS_XOR_REG32               OPCODE1(IF_ARG_REG, IF_INS_XOR, 0x31)
#define INS_XOR_REG16               OPCODE2(IF_ARG_REG, IF_INS_XOR, 0x66, 0x31)
#define INS_XOR_REG8                OPCODE1(IF_ARG_REG, IF_INS_XOR, 0x30)
  /* END - INS_XOR_<reg>_<reg> */
  /* INS_MOV_<imm>_<reg> (Reg-Base: 05) */
#define INS_MOV_IMM64_REG           OPCODE2(IF_ARG_REG_IMM64, IF_INS_MOV, 0x48, 0xb8)            /* [SPECIAL]: r8-r15 need REX.B prefix (0x49), [SPECIAL]: rcx needs 0xb9 as sec byte */
#define INS_MOV_IMM32_REG           OPCODE1(IF_ARG_REG_IMM32, IF_INS_MOV, 0xb8)                  /* [SPECIAL]: R8d-R15d need REX.B prefix (0x49), [SPECIAL]: ecx needs 0xb9 as first byte */
#define INS_MOV_IMM16_REG           OPCODE2(IF_ARG_REG_IMM16, IF_INS_MOV, 0x66, 0xb8)
#define INS_MOV_IMM8_REG            OPCODE1(IF_ARG_REG_IMM8, IF_INS_MOV, 0xb0)
  /* END - INS_MOV_<imm>_<reg> */
  /* INS_MOV_<imm>_<reg>_<disp> (Reg-Base: 01) */
#define INS_MOV_IMM8_REG_DISP8      OPCODE2(IF_ARG_REG_IMM_DISP8, IF_INS_MOV, 0xc6, 0x40)
#define INS_MOV_IMM8_REG_DISP32     OPCODE2(IF_ARG_REG_IMM_DISP32, IF_INS_MOV, 0xc6, 0x80)
#define INS_MOV_IMM16_REG_DISP8     OPCODE3(IF_ARG_REG_IMM_DISP8, IF_INS_MOV, 0x66, 0xc7, 0x40)
#define INS_MOV_IMM16_REG_DISP32    OPCODE3(IF_ARG_REG_IMM_DISP32, IF_INS_MOV, 0x66, 0xc7, 0x80)
#define INS_MOV_IMM32_REG_DISP8     OPCODE2(IF_ARG_REG_IMM_DISP8, IF_INS_MOV, 0xc7, 0x40)
#define INS_MOV_IMM32_REG_DISP32    OPCODE2(IF_ARG_REG_IMM_DISP32, IF_INS_MOV, 0xc7, 0x80)
#define INS_MOV_IMM64_REG_DISP8     OPCODE3(IF_ARG_REG_IMM_DISP8, IF_INS_MOV, 0x48, 0xc7, 0x40)
#define INS_MOV_IMM64_REG_DISP32    OPCODE3(IF_ARG_REG_IMM_DISP32, IF_INS_MOV, 0x48, 0xc7, 0x80)
  /* END - INS_MOV_<imm>_<reg>_<disp> */
  /* INS_MOV_<reg0>_<reg1> */
#define INS_MOV_REG32_REG32         OPCODE1(IF_ARG_REG_REG, IF_INS_MOV, 0x89)
#define INS_MOV_REG32_DISP8_REG32   OPCODE3(IF_ARG_REG_REG)
#define INS_MOV_REG32_DISP32_REG32  OPCODE3()
#define INS_MOV_REG32_REG32_DISP8   OPCODE3()
#define INS_MOV_REG32_REG32_DISP32  OPCODE3()
  /* END - INS_MOV_<reg0>_<reg1> */
#define INS_MOV_RPB_DISP8_REG   OPCODE2(IF_ARG_REG_DISP8, IF_INS_MOV, 0x48, 0x8b)
#define INS_MOV_REG_RBP_DISP8   OPCODE2(IF_ARG_REG_DISP8, IF_INS_MOV, 0x48, 0x89)
#define INS_ADD_IMM8_RSP        OPCODE3(IF_ARG_IMM8, IF_INS_ADD, 0x48, 0x83, 0xc4)
#define INS_SUB_IMM8_RSP        OPCODE3(IF_ARG_IMM8, IF_INS_ADD, 0x48, 0x83, 0xec)
/* Arithmetic operations */
#define INS_ADD_IMM32_REG       OPCODE1(IF_ARG_REG_IMM32, IF_INS_ADD, 0x48)
#define INS_SUB_IMM32_REG       OPCODE1(IF_ARG_REG_IMM32, IF_INS_SUB, 0x48)
#define INS_MUL_IMM32_REG       OPCODE1(IF_ARG_REG_IMM32, IF_INS_MUL, 0x48)
#define INS_ADD_IMM32_RAX       OPCODE2(IF_ARG_IMM32, IF_INS_ADD, 0x48, 0x05)
#define INS_SUB_IMM32_RAX       OPCODE2(IF_ARG_IMM32, IF_INS_SUB, 0x48, 0x2d)
#define INS_MUL_IMM32_RAX       OPCODE3(IF_ARG_IMM32, IF_INS_MUL, 0x48, 0x69, 0xc0)
#define INS_ADD_RDX_RAX         OPCODE3(IF_ARG_NONE, IF_INS_ADD, 0x48, 0x01, 0xd0)
#define INS_SUB_RDX_RAX         OPCODE3(IF_ARG_NONE, IF_INS_SUB, 0x48, 0x29, 0xd0)
#define INS_IMUL_RDX_RAX        OPCODE3(IF_ARG_SPECIAL, IF_INS_MUL, 0x48, 0x0f, 0xaf)
/* End of arithmetic operations */
#define INS_MOV_RIP_REG_DISP32  OPCODE2(IF_ARG_REG_DISP32, IF_INS_MOV, 0x48, 0x8b)
/* Load effective address */
#define INS_LEA_RIP_RDI         OPCODE3(IF_ARG_IMM32, IF_INS_LEA, 0x48, 0x8d, 0x3d)
#define INS_LEA_RIP_REG         OPCODE2(IF_ARG_REG_DISP32, IF_INS_LEA, 0x48, 0x8d)
#define INS_LEA_RIP_RAX         OPCODE3(IF_ARG_IMM32, IF_INS_LEA, 0x48, 0x8d, 0x05)
#define INS_LEA_RBP_DISP8_RAX   OPCODE3(IF_ARG_DISP8, IF_INS_LEA, 0x48, 0x8d, 0x45)
#define INS_MOV_I32_REG         OPCODE2(IF_ARG_REG_IMM32, IF_INS_MOV, 0x48, 0x8b)
#define INS_MOV_I32_RAX         OPCODE3(IF_ARG_IMM32, IF_INS_MOV, 0x48, 0x8b, 0x05)
#define INS_MOV_I32_RDX         OPCODE3(IF_ARG_IMM32, IF_INS_MOV, 0x48, 0x8b, 0x15)
#define INS_MOV_I32_EAX         OPCODE1(IF_ARG_IMM32, IF_INS_MOV, 0xb8)
#define INS_MOV_REG_RAX         OPCODE2(IF_ARG_REG, IF_INS_MOV, 0x48, 0x8b)
#define INS_MOV_REG_RDX         OPCODE2(IF_ARG_REG, IF_INS_MOV, 0x48, 0x89)
/* MISC */
#define INS_RESET_SP            OPCODE3(IF_ARG_NONE, IF_INS_MOV, 0x48, 0x89, 0xe5)
#define INS_PUSH_SP             OPCODE1(IF_ARG_NONE, IF_INS_PUSH, 0x55)
#define INS_POP_SP              OPCODE1(IF_ARG_NONE, IF_INS_POP, 0x5d)
#define INS_RET                 OPCODE1(IF_ARG_NONE, IF_INS_GENERIC, 0xc3)
#define INS_SYSCALL             OPCODE2(IF_ARG_NONE, IF_INS_GENERIC, 0x0f, 0x05)
#define INS_CALL                OPCODE1(IF_ARG_SPECIAL, IF_INS_CALL, 0xe8)
// clang-format on

typedef enum {
  SECTION_DATA,
  SECTION_RODATA,
  SECTION_TEXT,
} SectionType;

typedef enum {
  REG_RAX,
  REG_RCX,
  REG_RDX,
  REG_RBX,
  REG_RSP,
  REG_RBP,
  REG_RSI,
  REG_RDI,
  REG_R8,
  REG_R9,
  REG_R10,
  REG_R11,
  REG_R12,
  REG_R13,
  REG_R14,
  REG_R15,
} Register;

#define REG_ALIGN_09(reg) reg * 0x09
#define REG_BASE_C0(reg) 0xc0 + reg
// used to be Lea
#define REG_BASE_05(reg) 0x05 + reg
// used to be Move
#define REG_BASE_45(reg) 0x45 + reg
#define REG_BASE_C2(reg) 0xc2 + reg

// clang-format off
typedef struct {
  Opcode opcode;
  struct {
    // In case an instruction uses a foreign value, the 'imm' field is
    // used as the offset/index and the sec field needs to be filled
    // with the section the foreign value is stored in
    union {
      Register reg;
      uint64_t imm;
    } op0, op1;
    size_t op0_size;
    size_t op1_size;
    uint32_t disp;
    /* if near_disp is true, the disp is 8 bits, otherwise it is 32 bits */
    bool near_disp;
    struct {
      bool foreign;
      SectionType sec;
      uint8_t r_offset;
    } reloc_info;
    struct {
      char *function_name;
    } special;
  } args;
} Instruction;
// clang-format on

typedef struct {
  unsigned char *bytes;
  size_t bytes_len;
} DataValue;

typedef struct {
  DataValue *values;
  // Name -> indice
  Hashmap(Ident *, size_t) section_lookup;
} DataSection;

typedef enum {
  COMPILE_STEP_COMPILE_SRC,
  COMPILE_STEP_GENERATE_MACHINE,
  COMPILE_STEP_OUTPUT_OBJECT,
} CompilerStep;

typedef struct {
  Hashmap(Ident *, size_t) symbol_table;
  size_t sp_offset;
} Frame;

typedef enum {
  RELOCATION_RODATA,
  RELOCATION_DATA,
  RELOCATION_FUNCTION,
} RelocationType;

typedef struct {
  RelocationType rel_type;
  char *symbol;
  size_t data_offset;
  size_t program_offset;
  size_t r_offset;
} Relocation;

typedef enum {
  DATA_IMMEDIATE,
  DATA_POINTER,
} DataType;

typedef struct {
  enum {
    GLOB_DATA_LOC_RODATA,
    GLOB_DATA_LOC_DATA,
  } type;
  DataType data_type;
  size_t data_index;
} GlobalDataLocation;

typedef struct {
  const Statement *stmts;
  size_t stmt_index;
  Instruction *insns;
  Relocation *relocations;
  CompilerStep step;
  Hashmap(Ident *, GlobalDataLocation) globals;
  Hashmap(Ident *, size_t) labels;
  Hashmap(Ident *, size_t) extern_functions;
  Frame cur_frame;
  /* Data */
  DataSection data_section;
  DataSection rodata_section;
  /* Program */
  uint8_t *program_data;
  size_t program_data_size;
} Compiler;

Compiler compiler_new(const Statement *stmts);

void compiler_compile(Compiler *compiler);

void compiler_generate(Compiler *compiler);

void compiler_write(Compiler *compiler, FILE *file);
