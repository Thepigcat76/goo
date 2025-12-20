#pragma once

#include "parser.h"
#include <stdio.h>

// If an instruction doesn't have a flag, you need to manually add it to the
// switch statement in the insn_generate function
#define IF_NONE 0x0
#define IF_NO_ARG 0x0
#define IF_ARG_IMM32 0x1
#define IF_ARG_IMM64 0x2
#define IF_ARG_IMM32_DISP8 0x3
#define IF_ARG_IMM64_DISP8 0x4
#define IF_ARG_DISP8 0x5

#define OPCODE1(flag, b0) (flag << 0) | (0x01 << 6) | (b0 << 8)

#define OPCODE2(flag, b0, b1) (flag << 0) | (0x02 << 6) | (b0 << 8) | (b1 << 16)

#define OPCODE3(flag, b0, b1, b2)                                              \
  (flag << 0) | (0x03 << 6) | (b0 << 8) | (b1 << 16) | (b2 << 24)

// src -> dest
typedef enum {
  INS_XOR_RDI_RDI = OPCODE2(IF_NO_ARG, 0x31, 0xff),
  INS_MOV_I64_RBP = OPCODE2(IF_ARG_IMM64, 0x48, 0xbd),
  INS_MOV_I32_RBP_DISP8 = OPCODE2(IF_ARG_IMM32_DISP8, 0xc7, 0x45),
  INS_MOV_I64_RBP_DISP8 = OPCODE3(IF_ARG_IMM64_DISP8, 0x48, 0xc7, 0x45),
  INS_MOV_I64_RAX = OPCODE2(IF_ARG_IMM64, 0x48, 0xb8),
  INS_MOV_RAX_RDI = OPCODE3(IF_NO_ARG, 0x48, 0x89, 0xc7),
  INS_MOV_RPB_DISP8_RDI = OPCODE3(IF_ARG_DISP8, 0x48, 0x8b, 0x7d),
  INS_RET = OPCODE1(IF_NO_ARG, 0xc3),
  INS_CALL = OPCODE1(IF_NONE, 0xe8),
  INS_SYSCALL = OPCODE2(IF_NO_ARG, 0x0f, 0x05),
  INS_MOV_RDI_RBP_DISP8 = OPCODE3(IF_ARG_DISP8, 0x48, 0x89, 0x7d),
  /* Load effective address */
  INS_LEA_RIP_RDI = OPCODE3(IF_ARG_IMM32, 0x48, 0x8d, 0x3d),
  INS_LEA_RBP_DISP8_RAX = OPCODE3(IF_ARG_DISP8, 0x48, 0x8d, 0x45),
  /* Arg related Operations */
  INS_MOV_I32EDI = OPCODE1(IF_ARG_IMM32, 0xbf),
  INS_MOV_I32ESI = OPCODE1(IF_ARG_IMM32, 0xbe),
  INS_MOV_I32EDX = OPCODE1(IF_ARG_IMM32, 0xba),
  INS_MOV_I32ECX = OPCODE1(IF_ARG_IMM32, 0xb9),
  INS_MOV_I64RDI = OPCODE2(IF_ARG_IMM64, 0x48, 0xbf),
  INS_MOV_I64RSI = OPCODE2(IF_ARG_IMM64, 0x48, 0xbe),
  INS_MOV_I64RDX = OPCODE2(IF_ARG_IMM64, 0x48, 0xba),
  /* Stack Pointer Operations */
  INS_PUSH_SP = OPCODE1(IF_NO_ARG, 0x55),
  INS_POP_SP = OPCODE1(IF_NO_ARG, 0x5d),
  INS_RESET_SP = OPCODE3(IF_NO_ARG, 0x48, 0x89, 0xe5),
} Opcode;

#undef OPCODE1
#undef OPCODE2
#undef OPCODE3

typedef enum {
  SECTION_DATA,
  SECTION_RODATA,
  SECTION_TEXT,
} SectionType;

// clang-format off
typedef struct {
  Opcode opcode;
  union {
    struct { uint32_t imm; bool foreign; SectionType sec; } imm32; /* In case these are foreign, the 'imm' field is used as the offset/index */
    struct { uint64_t imm; bool foreign; SectionType sec; } imm64;
    struct { uint32_t imm; uint8_t disp; bool foreign; SectionType sec; } imm32_disp8;
    struct { uint64_t imm; uint8_t disp; bool foreign; SectionType sec; } imm64_disp8;
    struct { uint8_t disp; } disp8;
    struct { char *function_name; bool foreign; } call_ins;
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
} Relocation;

typedef struct {
  enum {
    GLOB_DATA_LOC_RODATA,
    GLOB_DATA_LOC_DATA,
  } type;
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
