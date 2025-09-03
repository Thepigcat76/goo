#pragma once

#include <stdlib.h>

typedef struct {
  void *(*alloc)(size_t bytes);
  void (*dealloc)(void *ptr);
} Allocator;

extern Allocator HEAP_ALLOCATOR;

void alloc_init();