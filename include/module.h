#pragma once

/* Every file is its own module. Relevant for importing and compilation */

#include "module_path.h"
#include "types.h"
#include "lilc/hashmap0.h"

typedef struct {
  const char *filename;
  const char *source;

  ModulePath path;

  Hashmap functions; // ModulePath -> FuncDescriptor
  TypedIdent *decls;
} Module;


void module_init(Module *module, ModulePath path, const char *filename, const char *source);

void module_parse_standalone(Module *module);

void module_deinit(Module *module);
