#include "../include/shared.h"
#include "lilc/array.h"
#include "lilc/hash.h"
#include "lilc/eq.h"
#include "stddef.h"
#include <lilc/alloc.h>
#include <lilc/str.h>
#include <stdbool.h>

int32_t module_path_ptrv_hash(const void *array) {
  const ModulePath *path = array;

  int32_t hash = 1;
  if (path != NULL) {
    size_t len = array_len(path->path);
    for (size_t i = 0; i < len; i++) {
      Ident ident = path->path[i];
      hash = 31 * hash + (ident == NULL ? 0 : strv_hash(ident));
    }
  }
  return hash;
}

#define MANGLE_PREFIX "_GM"
#define MANGLE_MODULE_INDICATOR 'M'
#define MANGLE_MODULE_SEPERATOR "_M"

Ident mangle_function_name(const ModulePath *module_path) {
  Ident *path = module_path->path;
  size_t path_len = array_len(path);
  dyn_string_t mangled_ident = {0};
  dyn_string_init(&mangled_ident);

  dyn_string_copy_str(&mangled_ident, MANGLE_PREFIX);
  dyn_string_add_char(&mangled_ident, MANGLE_MODULE_INDICATOR);

  for (size_t i = 0; i < path_len; i++) {
    dyn_string_add_str(&mangled_ident, path[i]);
    if (i < path_len - 1) {
      dyn_string_add_str(&mangled_ident, MANGLE_MODULE_SEPERATOR);
    }
  }
  dyn_string_add_char(&mangled_ident, '\0');

  return mangled_ident.string;
}

ModulePath parse_module_path_from_string(const char *str) {
  ModulePath path = {.path = array_new(Ident, &HEAP_ALLOCATOR)};

  const char *c = str;
  dyn_string_t cur_ident = {0};
  dyn_string_init(&cur_ident);
  for (;;) {
    if (*c == '/' || *c == '\0') {
      dyn_string_t new_str = {0};
      dyn_string_init(&new_str);
      dyn_string_copy(&new_str, &cur_ident);
      array_add(path.path, new_str.string);
      dyn_string_clear(&cur_ident);
      if (*c == '\0') {
        break;
      }
    } else {
      dyn_string_add_char(&cur_ident, *c);
    }
    c++;
  }

  return path;
}

bool module_path_ptrv_eq(const void *array0, const void *array1) {
  const ModulePath *path0 = array0;
  const ModulePath *path1 = array1;

  if (path0 == NULL || path1 == NULL)
    return false;

  size_t len0 = array_len(path0->path);
  size_t len1 = array_len(path1->path);

  if (len0 != len1)
    return false;

  for (size_t i = 0; i < len0; i++) {
    if (!strv_eq(path0->path[i], path1->path[i])) return false;
  }

  return true;
}

ModulePath module_path_copy(const ModulePath *path) {
  if (path->path == NULL) {
    return (ModulePath){.path = array_new(Ident, &HEAP_ALLOCATOR)};
  }

  ModulePath new_path = {.path = array_new_capacity(Ident, array_len(path->path) * 2, &HEAP_ALLOCATOR)};
  for (size_t i = 0; i < array_len(path->path); i++) {
    array_add(new_path.path, path->path[i]);
  }
  return new_path;
}

ModulePath module_path_root(const char *str) {
  ModulePath path = {.path = array_new(Ident, &HEAP_ALLOCATOR)};
  array_add(path.path, str);
  return path;
}

dyn_string_t module_path_fmt(const ModulePath *path) {
  dyn_string_t str = {0};
  dyn_string_init(&str);

  for (size_t i = 0; i < array_len(path->path); i++) {
    dyn_string_add_str(&str, path->path[i]);
    if (i < array_len(path->path) - 1) {
      dyn_string_add_char(&str, '.');
    } else {
      // FIXME: This is pretty hacky and shouldnt be neccessary
      dyn_string_add_char(&str, '\0');
    }
  }
  return str;
}

