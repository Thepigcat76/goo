#include "../../include/compiler.h"
#include "lilc/array.h"
#include "lilc/eq.h"
#include "lilc/hash.h"
#include <complex.h>
#include <elf.h>
#include <endian.h>
#include <lilc/alloc.h>
#include <lilc/hashmap.h>
#include <lilc/log.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

static inline DataSection data_section_new(void) {
  return (DataSection){.data_bytes = malloc(256),
                       .data_capacity = 256,
                       .section_lookup =
                           hashmap_new(Ident *, size_t, &HEAP_ALLOCATOR,
                                       str_ptrv_hash, str_ptrv_eq, NULL)};
}

Compiler compiler_new(const Statement *statements, TypeTable *type_tables,
                      Hashmap(ModulePath, Ident) mangled_functions,
                      ModulePath mod_path) {
  return (Compiler){
      .stmts = statements,
      .type_tables = type_tables,
      .relocations = array_new(Relocation, &HEAP_ALLOCATOR),
      .insns = array_new_capacity(Instruction, 512, &HEAP_ALLOCATOR),
      .symbols = hashmap_new(Ident *, size_t, &HEAP_ALLOCATOR, str_ptrv_hash,
                             str_ptrv_eq, NULL),
      .globals = hashmap_new(Ident *, GlobalDataLocation, &HEAP_ALLOCATOR,
                             str_ptrv_hash, str_ptrv_eq, NULL),
      .mangled_functions = mangled_functions,
      .data_section = data_section_new(),
      .rodata_section = data_section_new(),
      .elf64_relocations =
          array_new_capacity(Elf64_Relocation, 64, &HEAP_ALLOCATOR),
      .mod_path = mod_path};
}
