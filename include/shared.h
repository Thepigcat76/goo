#pragma once

#include "lilc/alloc.h"
#include "lilc/dynstr.h"
#include <stdbool.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__)
#define constexpr const
#elif __STDC_VERSION__ < 202311L
#define constexpr const
#endif

typedef char *Ident;

typedef Ident *IdentArray;

struct debug_flags {
  bool print_tokens;
  bool print_ast;
  bool print_preprocessed_ast;
  bool print_parse_info;
  bool print_preprocessor_info;
  bool print_checker_info;
  // Compiler
  bool print_compile_info;
  bool print_codegen_info;
  bool print_obj_write_info;
  bool extra_parse_err_info;
};

extern char *corelib_path;

extern struct debug_flags debug_flags;

void *_internal_heap_clone(void *ptr, size_t size);

#define heap_clone(ptr) _internal_heap_clone(ptr, sizeof(typeof(*(ptr))))

void *_internal_bump_clone(Bump *bump, void *ptr, size_t size);

#define bump_clone(bump, ptr) _internal_bump_clone(bump, ptr, sizeof(typeof(*(ptr))))

#define MODULE_PATH_ROOT                                                       \
  (ModulePath) { .path = NULL }

#define CORE_LIB_PATH "CORE_LIB_PATH"
#define DEFAULT_CORE_LIB_PATH "./goo-libs/core"

#define POINTER_SIZE 8

#define DATA_SECTION_SIZE 8
