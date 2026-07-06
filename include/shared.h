#pragma once

#include "lilc/str.h"
#include <stdbool.h>
#include <stdint.h>

#if !defined(__STDC_VERSION__)
#define constexpr const
#elif __STDC_VERSION__ < 202311L
#define constexpr const
#endif

typedef char *Ident;

typedef struct {
  Ident *path;
} ModulePath;

struct debug_flags {
  bool print_tokens;
  bool print_ast;
  bool print_parse_info;
  bool print_preprocessor_info;
  bool print_checker_info;
  // Compiler
  bool print_compile_info;
  bool print_codegen_info;
  bool print_obj_write_info;
  bool extra_parse_err_info;
};

extern struct debug_flags debug_flags;

#define MODULE_PATH_ROOT                                                       \
  (ModulePath) { .path = NULL }

#define CORE_LIB_PATH "CORE_LIB_PATH"
#define DEFAULT_CORE_LIB_PATH "./goo-libs/core"

#define POINTER_SIZE 8

#define DATA_SECTION_SIZE 8

#define scoped_dyn_string(_dyn_string, str, ...)                               \
  do {                                                                         \
    dyn_string_t evaled_dyn_str = _dyn_string;                                 \
    str = evaled_dyn_str.string;                                               \
    __VA_ARGS__                                                                \
    dyn_string_free(&evaled_dyn_str);                                          \
  } while (0)

int32_t module_path_ptrv_hash(const void *array);

bool module_path_ptrv_eq(const void *array0, const void *array1);

ModulePath module_path_copy(const ModulePath *path, Allocator *allocator);

ModulePath module_path_root(const char *str, Allocator *allocator);

Ident mangle_function_name(const ModulePath *module_path);

ModulePath parse_module_path_from_string(const char *str);

dyn_string_t module_path_fmt(const ModulePath *path);
