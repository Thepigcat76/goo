#pragma once

#include "../ast.h"
#include "../shared.h"

typedef struct {
  ModulePath name;
  Expression expr;
} BuiltinFunction;

typedef enum {
  BUILTIN_FUNC_PRINTFN,
  BUILTIN_FUNC_FORMAT,
  BUILTIN_FUNC_EXIT,

  _amount_builtin_funcs,
} BuiltinFunctionKind;

extern BuiltinFunction BUILTIN_FUNCTIONS[_amount_builtin_funcs];

void builtin_functions_init(Allocator *alloc, TypeTable *type_table);

void builtin_functions_deinit(TypeTable *global_type_table);
