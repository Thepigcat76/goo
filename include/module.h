#pragma once

/* Every file is its own module. Relevant for importing and compilation */

#include "types.h"
#include <lilc/alloc.h>
#include <lilc/hashmap.h>

typedef struct {
  const char *filename;
  const char *source;
  Hashmap(ModulePath, FuncDescriptor) functions;
  TypedIdent *decls;
} Module;


void module_init(Module *module, const char *filename, const char *source);

void module_deinit(Module *module);
