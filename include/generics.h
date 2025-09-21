#pragma once

#include "parser.h"
#include "../vendor/lilc/hashmap.h"

typedef Type *CallerArgs;

typedef struct {
  Ident *generics;
  ExprCall **caller_exprs;
  CallerArgs *callers_args;
} GenericFunction;

typedef struct {
  Hashmap(Ident *, GenericFunction) table;
} GenericFunctionsTable;

GenericFunction *gft_get(GenericFunctionsTable *table, Ident *name);

void gft_add(GenericFunctionsTable *table, Ident *name,
                    GenericFunction func);

GenericFunctionsTable gft_new();
