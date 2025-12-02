#pragma once

#include "evaluator.h"

extern char println_buf[1024];

typedef struct {
  Ident name;
  Expression expr;
  Object (*execute)(Object *objects);
} BuiltinFunction;

extern BuiltinFunction PRINTLN_FUNCTION;
extern BuiltinFunction PRINTFN_FUNCTION;
extern BuiltinFunction EXIT_FUNCTION;

void builtin_functions_init(TypeTable *global_table);
