#include "../../include/compiler.h"
#include "lilc/array.h"
#include "lilc/eq.h"
#include "lilc/hash.h"
#include <complex.h>
#include <elf.h>
#include <endian.h>
#include <lilc/alloc.h>
#include "lilc/hashmap0.h"
#include <lilc/log.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

static inline void data_section_init(DataSection *section) {
  section->data_bytes = malloc(256);
  section->data_capacity = 256,
  hashmap_init(&section->section_lookup, &HEAP_ALLOCATOR, Ident *, size_t,
               str_ptrv_hash, str_ptrv_eq, NULL);
}

static inline void data_section_deinit(DataSection *section) {
  free(section->data_bytes);
  hashmap_deinit(&section->section_lookup);
}

void compiler_init(Compiler *compiler, const Statement *statements,
                   TypeTable *type_tables, Hashmap mangled_functions,
                   ModulePath mod_path) {
  compiler->stmts = statements;
  compiler->type_tables = type_tables;
  compiler->relocations = array_new(Relocation, &HEAP_ALLOCATOR);
  compiler->insns = array_new_capacity(Instruction, 512, &HEAP_ALLOCATOR);
  hashmap_init(&compiler->function_symbols, &HEAP_ALLOCATOR, Ident *, size_t,
               str_ptrv_hash, str_ptrv_eq, NULL);
  hashmap_init(&compiler->globals, &HEAP_ALLOCATOR, Ident *, GlobalDataLocation,
               str_ptrv_hash, str_ptrv_eq, NULL);
  compiler->mangled_functions = mangled_functions;
  data_section_init(&compiler->data_section);
  data_section_init(&compiler->rodata_section);
  compiler->elf64_relocations =
      array_new_capacity(Elf64_Relocation, 64, &HEAP_ALLOCATOR);
  compiler->mod_path = mod_path;
  bump_init(&compiler->compiler_arena, 80000);
  bump_allocator_init(&compiler->compiler_arena_allocator,
                      &compiler->compiler_arena);
}

void compiler_deinit(Compiler *compiler) {
  array_free(compiler->relocations);
  array_free(compiler->insns);
  hashmap_deinit(&compiler->function_symbols);
  hashmap_deinit(&compiler->globals);
  data_section_deinit(&compiler->data_section);
  data_section_deinit(&compiler->rodata_section);
  array_free(compiler->elf64_relocations);
}
