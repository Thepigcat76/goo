#pragma once

#include "ast.h"
#include "ins.h"
#include "lilc/alloc.h"
#include "module.h"
#include "shared.h"
#include <lilc/hashmap0.h>
#include <stdio.h>

typedef struct {
  uint8_t *bytes;
  size_t bytes_len;
} DataValue;

typedef struct {
  uint8_t *data_bytes;
  size_t data_capacity;
  size_t data_len;
  // Name -> offset
  Hashmap section_lookup; // Ident -> size_t
} DataSection;

typedef enum {
  COMPILE_STEP_COMPILE_SRC,
  COMPILE_STEP_GENERATE_MACHINE,
  COMPILE_STEP_OUTPUT_OBJECT,
} CompilerStep;

typedef struct {
  size_t offset;
  size_t size;
  bool inline_val;
} StackObject;

typedef struct {
  Hashmap symbol_table; // Ident -> StackObject
  size_t sp_offset;

  size_t sub_stack_size_ins_idx;
} Frame;

typedef enum {
  RELOCATION_RODATA,
  RELOCATION_DATA,
  RELOCATION_FUNCTION,
} RelocationType;

typedef enum {
  SECTION_TYPE_RODATA,
  SECTION_TYPE_DATA,
  SECTION_TYPE_TEXT,
} SectionType;

typedef struct {
  SectionType sec;
  uint8_t r_offset;
  uint8_t data_offset;
  char *symbol;
  // The offset in the .text section
  size_t program_offset;
} Relocation;

// typedef struct {
//   RelocationType rel_type;
//   char *symbol;
//   size_t data_offset;
//   size_t program_offset;
//   size_t r_offset;
// } Relocation;

typedef enum {
  DATA_IMMEDIATE,
  DATA_POINTER,
} DataType;

typedef struct {
  enum {
    GLOB_DATA_LOC_RODATA,
    GLOB_DATA_LOC_DATA,
  } kind;
  DataType data_type;
  size_t data_offset;
} GlobalDataLocation;

typedef struct {
  RelocationType rel_type;
  size_t data_offset;
  size_t r_offset;
  size_t program_offset;
  char *symbol;
} Elf64_Relocation;

typedef enum {
  COMPILE_LEVEL_GLOBAL,
  COMPILE_LEVEL_LOCAL,
} CompileLevel;

typedef struct {
  CompileLevel level;
  const char *function_name;
} CompileContext;

typedef struct {
  const Type *variable_type;
} ExprCompileContext;

typedef struct {
  const Statement *stmts;
  TypeTable *type_tables;
  CompilerStep step;

  /* Type size cache*/

  size_t stmt_index;
  Instruction *insns;
  Relocation *relocations;
  Hashmap globals;           // Ident -> GlobalDataLocation
  Hashmap function_symbols;  // Ident -> size_t
  Hashmap mangled_functions; // ModulePath -> Ident

  Frame cur_frame;
  size_t program_size;
  /* Data */
  DataSection data_section;
  DataSection rodata_section;
  /* Relocations */
  Elf64_Relocation *elf64_relocations;
  /* Program */
  uint8_t *program_data;
  size_t program_data_size;
  size_t program_data_capacity;

  /* Module info */
  ModulePath mod_path;

  /* Context */
  CompileContext context;

  Bump compiler_arena;
  Allocator compiler_arena_allocator;
} Compiler;

void compiler_init(Compiler *compiler);

void compiler_deinit(Compiler *compiler);

void compiler_compile(Compiler *compiler);

void compiler_generate(Compiler *compiler);

void compiler_write(Compiler *compiler, FILE *file);

void module_compile(Module *module, Compiler *compiler, const Statement *stmts,
                    TypeTable *type_tables,
                    Hashmap mangled_functions /* ModulePath -> Ident */,
                    FILE *out_file);
