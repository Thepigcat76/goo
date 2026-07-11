#pragma once

#include "shared.h"
#include <lilc/alloc.h>

typedef struct {
  Ident *path;
} ModulePath;

int32_t mod_path_ptrv_hash(const void *array);

bool mod_path_ptrv_eq(const void *array0, const void *array1);

ModulePath mod_path_copy(const ModulePath *path, Allocator *allocator);

ModulePath mod_path_root(const char *str, Allocator *allocator);

ModulePath mod_path_parse_str(const char *str, Allocator *alloc);

dyn_string_t mod_path_fmt(const ModulePath *path);

void mod_path_deinit(ModulePath *mod_path);

// TODO: Maybe move to parser or smth like that
Ident mangle_function_name(const ModulePath *module_path, Allocator *alloc);
