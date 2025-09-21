#pragma once

#include "evaluator.h"

#define obj_cast_int(obj_ptr) (obj_ptr)->var.obj_int
#define obj_cast_string(obj_ptr) (obj_ptr)->var.obj_string

extern char println_buf[1024];

typedef struct {
  Ident name;
  Expression expr;
  Object (*execute)(Object *objects);
} BuiltinFunction;

extern BuiltinFunction PRINTLN_FUNCTION;
extern BuiltinFunction EXIT_FUNCTION;

void builtin_functions_init(TypeTable *global_table);
