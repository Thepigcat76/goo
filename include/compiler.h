#pragma once

#include "ast.h"
#include "ins.h"
#include "shared.h"
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
  Hashmap(Ident *, size_t) section_lookup;
} DataSection;

typedef enum {
  COMPILE_STEP_COMPILE_SRC,
  COMPILE_STEP_GENERATE_MACHINE,
  COMPILE_STEP_OUTPUT_OBJECT,
} CompilerStep;

typedef struct {
  size_t offset;
  size_t size;
} StackObject;

typedef struct {
  Hashmap(Ident *, StackObject) symbol_table;
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
  } type;
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

typedef struct {
  const Statement *stmts;
  TypeTable *type_tables;

  size_t stmt_index;
  Instruction *insns;
  Relocation *relocations;
  CompilerStep step;
  Hashmap(Ident *, GlobalDataLocation) globals;
  Hashmap(Ident *, size_t) symbols;
  Hashmap(ModulePath, Ident) mangled_functions;
  // Hashmap(Ident *, size_t) extern_functions;
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
} Compiler;

Compiler compiler_new(const Statement *stmts, TypeTable *type_tables,
                      Hashmap(ModulePath, Ident) mangled_functions,
                      ModulePath mod_path);

void compiler_compile(Compiler *compiler);

void compiler_generate(Compiler *compiler);

void compiler_write(Compiler *compiler, FILE *file);
