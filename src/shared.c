#include "../include/shared.h"
#include "lilc/array.h"
#include "lilc/hash.h"
#include "lilc/eq.h"
#include "stddef.h"
#include <lilc/alloc.h>
#include <stdbool.h>

int32_t module_path_ptrv_hash(const void *array) {
  ModulePath *path = array;

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
