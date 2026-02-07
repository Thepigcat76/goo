#pragma once

/* Every file is its own module. Relevant for importing and compilation */

#include "ast.h"
#include "types.h"
#include <lilc/alloc.h>
#include <lilc/hashmap.h>

typedef struct {
  const char *filename;
  const char *source;
  Hashmap(Ident *, FuncDescriptor) functions;
  TypedIdent *decls;
} Module;
