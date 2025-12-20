#pragma once

#include "parser.h"
#include <stdio.h>

// If an instruction doesn't have a flag, you need to manually add it to the
// switch statement in the insn_generate function
#define IF_SPECIAL 0x0
#define IF_NO_ARG 0x0
#define IF_ARG_IMM8 0x1
#define IF_ARG_IMM32 0x2
#define IF_ARG_IMM64 0x3
#define IF_ARG_IMM32_DISP8 0x4
#define IF_ARG_IMM64_DISP8 0x5
#define IF_ARG_DISP8 0x6
#define IF_ARG_DISP32 0x7
#define IF_ARG_REG_DISP8 0x8
#define IF_ARG_REG_DISP32 0x9

#define OPCODE1(flag, b0) (flag << 0) | (0x01 << 6) | (b0 << 8)

#define OPCODE2(flag, b0, b1) (flag << 0) | (0x02 << 6) | (b0 << 8) | (b1 << 16)

#define OPCODE3(flag, b0, b1, b2)                                              \
  (flag << 0) | (0x03 << 6) | (b0 << 8) | (b1 << 16) | (b2 << 24)

// src -> dest
typedef enum {
  INS_XOR_RDI_RDI = OPCODE2(IF_NO_ARG, 0x31, 0xff),
  INS_XOR_RAX_RAX = OPCODE2(IF_NO_ARG, 0x31, 0xc0),
  INS_MOV_I64_RBP = OPCODE2(IF_ARG_IMM64, 0x48, 0xbd),
  INS_MOV_I32_RBP_DISP8 = OPCODE2(IF_ARG_IMM32_DISP8, 0xc7, 0x45),
  INS_MOV_I64_RBP_DISP8 = OPCODE3(IF_ARG_IMM64_DISP8, 0x48, 0xc7, 0x45),
  INS_MOV_I64_RAX = OPCODE2(IF_ARG_IMM64, 0x48, 0xb8),
  INS_MOV_RAX_RDI = OPCODE3(IF_NO_ARG, 0x48, 0x89, 0xc7),
  INS_MOV_RPB_DISP8_REG = OPCODE2(IF_ARG_REG_DISP8, 0x48, 0x8b),
  INS_RET = OPCODE1(IF_NO_ARG, 0xc3),
  INS_LEAVE = OPCODE1(IF_NO_ARG, 0xc9),
  INS_CALL = OPCODE1(IF_SPECIAL, 0xe8),
  INS_SYSCALL = OPCODE2(IF_NO_ARG, 0x0f, 0x05),
  INS_MOV_REG_RBP_DISP8 = OPCODE2(IF_ARG_REG_DISP8, 0x48, 0x89),
  INS_ADD_IMM8_RSP = OPCODE3(IF_ARG_IMM8, 0x48, 0x83, 0xc4),
  INS_SUB_IMM8_RSP = OPCODE3(IF_ARG_IMM8, 0x48, 0x83, 0xec),
  INS_ADD_IMM32_RAX = OPCODE2(IF_ARG_IMM32, 0x48, 0x05),
  INS_ADD_RDX_RAX = OPCODE3(IF_NO_ARG, 0x48, 0x01, 0xd0),
  INS_MOV_RIP_REG_DISP32 = OPCODE2(IF_ARG_REG_DISP32, 0x48, 0x8b),
  /* Load effective address */
  INS_LEA_RIP_RDI = OPCODE3(IF_ARG_IMM32, 0x48, 0x8d, 0x3d),
  INS_LEA_RIP_REG = OPCODE2(IF_ARG_REG_DISP32, 0x48, 0x8d),
  INS_LEA_RIP_RAX = OPCODE3(IF_ARG_IMM32, 0x48, 0x8d, 0x05),
  INS_LEA_RBP_DISP8_RAX = OPCODE3(IF_ARG_DISP8, 0x48, 0x8d, 0x45),
  INS_MOV_I32_RAX = OPCODE3(IF_ARG_IMM32, 0x48, 0x8b, 0x05),
  INS_MOV_I32_RDX = OPCODE3(IF_ARG_IMM32, 0x48, 0x8b, 0x15),
  INS_MOV_I32_EAX = OPCODE1(IF_ARG_IMM32, 0xb8),
  /* Arg related Operations */
  /* Args: 32-bit */
  INS_MOV_I32_EDI = OPCODE1(IF_ARG_IMM32, 0xbf),
  INS_MOV_I32_ESI = OPCODE1(IF_ARG_IMM32, 0xbe),
  INS_MOV_I32_EDX = OPCODE1(IF_ARG_IMM32, 0xba),
  INS_MOV_I32_ECX = OPCODE1(IF_ARG_IMM32, 0xb9),
  /* Arg: 64-bit */
  INS_MOV_I64_RDI = OPCODE2(IF_ARG_IMM64, 0x48, 0xbf),
  INS_MOV_I64_RSI = OPCODE2(IF_ARG_IMM64, 0x48, 0xbe),
  INS_MOV_I64_RDX = OPCODE2(IF_ARG_IMM64, 0x48, 0xba),
  /* End of arg related operations*/
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

typedef uint8_t Register;

#define REG_RAX 0x00
#define REG_RCX 0x08
#define REG_RDX 0x10
#define REG_RBX 0x18
#define REG_RSP 0x20
#define REG_RBP 0x28
#define REG_RSI 0x30
#define REG_RDI 0x38
#define REG_R8 0x40
#define REG_R9 0x48

#define LEA_REG(reg) 0x05 + reg
#define MOV_REG(reg) 0x45 + reg

// clang-format off
typedef struct {
  Opcode opcode;
  union {
    // In case these are foreign, the 'imm' field is used as the offset/index
    // and the sec field needs to be filled with the section the foreign
    // value is stored in, otherwise it can stay empty
    struct { uint32_t imm; bool foreign; SectionType sec; uint8_t r_offset; } imm8; 
    struct { uint32_t imm; bool foreign; SectionType sec; uint8_t r_offset; } imm32; 
    struct { uint64_t imm; bool foreign; SectionType sec; uint8_t r_offset; } imm64;
    struct { uint32_t imm; uint8_t disp; bool foreign; SectionType sec; uint8_t r_offset; } imm32_disp8;
    struct { uint64_t imm; uint8_t disp; bool foreign; SectionType sec; uint8_t r_offset; } imm64_disp8;
    struct { uint8_t disp; } disp8;
    struct { uint32_t disp; bool foreign; SectionType sec; uint8_t r_offset; } disp32;
    struct { Register reg; uint8_t disp; } reg_disp8;
    struct { Register reg; uint32_t disp; bool foreign; SectionType sec; uint8_t r_offset; } reg_disp32;
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
