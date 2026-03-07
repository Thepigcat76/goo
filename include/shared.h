#pragma once

#include <stdint.h>
#include "lilc/str.h"

typedef char *Ident;

typedef struct {
  Ident *path;
} ModulePath;

#define MODULE_PATH_ROOT (ModulePath){.path = NULL}

#define CORE_LIB_PATH "CORE_LIB_PATH"
#define DEFAULT_CORE_LIB_PATH "./goo-libs/core"

int32_t module_path_ptrv_hash(const void *array);

bool module_path_ptrv_eq(const void *array0, const void *array1);

ModulePath module_path_copy(const ModulePath *path);

ModulePath module_path_root(const char *str);

Ident mangle_function_name(const ModulePath *module_path);

ModulePath parse_module_path_from_string(const char *str);

dyn_string_t module_path_fmt(const ModulePath *path);
