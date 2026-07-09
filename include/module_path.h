#pragma once

#include "shared.h"

typedef struct {
  Ident *path;
} ModulePath;

int32_t module_path_ptrv_hash(const void *array);

bool module_path_ptrv_eq(const void *array0, const void *array1);

ModulePath module_path_copy(const ModulePath *path, Allocator *allocator);

ModulePath module_path_root(const char *str, Allocator *allocator);

ModulePath parse_module_path_from_string(const char *str);

dyn_string_t module_path_fmt(const ModulePath *path);

// TODO: Maybe move to parser or smth like that
Ident mangle_function_name(const ModulePath *module_path);
