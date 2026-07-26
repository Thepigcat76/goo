#pragma once

#include "parser.h"
#include "lilc/hashmap0.h"

typedef Type *CallerArgs;

typedef struct {
  Ident *generics;
  ExprCall **caller_exprs;
  CallerArgs *callers_args;
} GenericFunction;

typedef struct {
  Hashmap table; // Ident *, GenericFunction
} GenericFunctionsTable;

GenericFunction *gft_get(GenericFunctionsTable *table, Ident *name);

void gft_add(GenericFunctionsTable *table, Ident *name,
                    GenericFunction func);

void gft_init(GenericFunctionsTable *table);
