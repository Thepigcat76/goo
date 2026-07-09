#pragma once

/* Every file is its own module. Relevant for importing and compilation */

#include "types.h"
#include "lilc/hashmap0.h"

typedef struct {
  const char *filename;
  const char *source;
  Hashmap functions; // ModulePath -> FuncDescriptor
  TypedIdent *decls;
} Module;


void module_init(Module *module, const char *filename, const char *source);

void module_deinit(Module *module);
