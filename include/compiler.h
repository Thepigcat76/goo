#pragma once

#include "parser.h"
#include <stdio.h>

typedef enum {
  INS_MOV_R2R,
  INS_MOV_M2R,
  INS_MOV_I2R,
  INS_MOV_I2RAX,
  INS_MOV_I2RBP,
  INS_XOR_RDI_RDI,
  /* Stack Pointer Operations */
  INS_PUSH_SP,
  INS_POP_SP,
  INS_RESET_SP,
  INS_RET,
  INS_SYSCALL,
  INS_LEA_RBX,
  INS_CALL,
  INS_FOREIGN_CALL,
} InstructionType;

typedef uint8_t Opcode[3];

typedef uint64_t Register;
typedef uint64_t Memory;

// clang-format off
typedef struct {
  InstructionType type;
  union {
    struct { int32_t immediate; } mov_i2rax;
    struct { int32_t immediate; size_t disp; } mov_i2rbp;
    struct { Register dest; Register val; } mov_r2r_ins;
    struct { Register dest; Memory val; } mov_m2r_ins;
    struct { Register dest; int32_t val; } mov_i2r_ins;
    struct { int32_t immediate; } lea_rbx_ins;
    struct { char *function_name; } foreign_call_ins;
    struct { char *function_name; } call_ins;
  } var;
} Instruction;
// clang-format on

typedef struct {
  unsigned char *bytes;
  size_t bytes_len;
} DataValue;

typedef Hashmap(Ident *, DataValue) DataSection;

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
  size_t program_offset;
} Relocation;

typedef struct {
  const Statement *stmts;
  size_t stmt_index;
  Instruction *insns;
  Relocation *relocations;
  CompilerStep step;
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
