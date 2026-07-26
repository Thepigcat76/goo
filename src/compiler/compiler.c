#include "../../include/compiler.h"
#include "lilc/array.h"
#include "lilc/deque.h"
#include "lilc/eq.h"
#include "lilc/hash.h"
#include "lilc/hashmap0.h"
#include <complex.h>
#include <elf.h>
#include <endian.h>
#include <lilc/alloc.h>
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

void module_compile_init(ModuleCompile *mod_compile) {
  hashmap_init(&mod_compile->function_symbols, &HEAP_ALLOCATOR, Ident *, size_t,
               str_ptrv_hash, str_ptrv_eq, NULL);
  hashmap_init(&mod_compile->globals, &HEAP_ALLOCATOR, Ident *,
               GlobalDataLocation, str_ptrv_hash, str_ptrv_eq, NULL);
}

static void module_compile_info_init(ModuleCompileInfo *info) {
  data_section_init(&info->data_section);
  data_section_init(&info->rodata_section);
  info->elf64_relocations =
      array_new_capacity(Elf64_Relocation, 64, &HEAP_ALLOCATOR);
  deque_init(info->frames, &HEAP_ALLOCATOR);
}

static void module_compile_info_deinit(ModuleCompileInfo *info) {
  data_section_deinit(&info->data_section);
  data_section_deinit(&info->rodata_section);
  array_free(info->elf64_relocations);
  deque_deinit(info->frames);
}

void compiler_init(Compiler *compiler) {
  bump_init(&compiler->compiler_arena, 80000);
  bump_allocator_init(&compiler->compiler_arena_allocator,
                      &compiler->compiler_arena);
}

void compiler_deinit(Compiler *compiler) {
  bump_free(&compiler->compiler_arena);
}

void module_compile(Module *module, Compiler *compiler,
                    ModuleCompile mod_compile, FILE *out_file) {
  if (compiler->cur_step != COMPILE_STEP_COMPILE_SRC) {
    module_compile_info_deinit(&compiler->cur_mod_compile_info);
    bump_reset(&compiler->compiler_arena);
  }

  module_compile_info_init(&compiler->cur_mod_compile_info);

  compiler->cur_module = module;
  compiler->cur_mod_compile = mod_compile;

  compiler_compile(compiler);

  compiler_generate(compiler);

  compiler_write(compiler, out_file);
}
