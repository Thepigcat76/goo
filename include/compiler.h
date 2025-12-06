#pragma once

#include "parser.h"
#include <stdio.h>

typedef enum {
  INS_MOV,
  INS_RET,
  INS_SYSCALL,
  INS_CALL,
} InstructionType;

typedef int Register;

// clang-format off
typedef struct {
  InstructionType type;
  union {
    struct { Register dest; Register val; } mov_ins;
    struct { int function; } call_ins;
  } var;
} Instruction;
// clang-format on

typedef enum {
  COMPILE_STEP_COMPILE_SRC,
  COMPILE_STEP_GENERATE_MACHINE,
  COMPILE_STEP_OUTPUT_OBJECT,
} CompilerStep;

typedef struct {
  const Statement *stmts;
  size_t stmt_index;
  Instruction *insns;
  CompilerStep step;
} Compiler;

Compiler compiler_new(const Statement *stmts);

void compiler_compile(Compiler *compiler);

void compiler_generate(Compiler *compiler);

void compiler_write(Compiler *compiler, FILE *file);
