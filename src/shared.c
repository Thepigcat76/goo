#include "../include/shared.h"
#include <stddef.h>
#include <string.h>

struct debug_flags debug_flags = {0};

void *_internal_heap_clone(void *ptr, size_t size) {
  void *new_ptr = malloc(size);
  memcpy(new_ptr, ptr, size);
  return new_ptr;
}

void *_internal_bump_clone(Bump *bump, void *ptr, size_t size) {
  void *new_ptr = bump_alloc(bump, size);
  memcpy(new_ptr, ptr, size);
  return new_ptr;
}
