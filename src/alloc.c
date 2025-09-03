
#include "alloc.h"
#include <stdint.h>
#include <stdlib.h>

Allocator HEAP_ALLOCATOR;
Allocator GLOBAL_BUMP_ALLOCATOR;

static void *heap_allocator_alloc(size_t bytes) { return malloc(bytes); }

static void heap_allocator_dealloc(void *ptr) { free(ptr); }

void alloc_init() {
  HEAP_ALLOCATOR = (Allocator){.alloc = heap_allocator_alloc, .dealloc = heap_allocator_dealloc};
}