#include "../include/builtins.h"
#include "../vendor/lilc/array.h"
#include <stdio.h>

#define BUILTIN_FUNCTION_DEFINE(_ret_type, _native_function)                   \
  (Expression) {                                                               \
    .type = EXPR_FUNCTION, .var = {                                            \
      .expr_function = {.desc = {.ret_type = _ret_type,                        \
                                 .args =                                       \
                                     array_new(TypedIdent, &HEAP_ALLOCATOR)},  \
                        .block = NULL,                                         \
                        .native_function = _native_function}                   \
    }                                                                          \
  }

#define BUILTIN_FUNCTION_SET_ARG_TYPES(_expr, ...)                             \
  do {                                                                         \
    TypedIdent *args = _expr.var.expr_function.desc.args;                      \
    TypedIdent provided[] = {__VA_ARGS__ __VA_OPT__(, )(TypedIdent){0}};       \
    for (size_t i = 0; provided[i].ident != NULL; i++) {                       \
      array_add(args, provided[i]);                                            \
    }                                                                          \
  } while (0)

#define BUILTIN_FUNCTION(func, _name, _execute_func, _ret_type, ...)           \
  do {                                                                         \
    Expression expr = BUILTIN_FUNCTION_DEFINE(_ret_type, _execute_func);       \
    BUILTIN_FUNCTION_SET_ARG_TYPES(expr, __VA_ARGS__);                         \
    func = (BuiltinFunction){                                                  \
        .expr = expr, .name = _name, .execute = _execute_func};                \
  } while (0)

#define ARG(_ident, _type)                                                     \
  (TypedIdent) { .ident = _ident, .type = _type }

#define obj_cast_int(obj_ptr) (obj_ptr)->var.obj_int
#define obj_cast_string(obj_ptr) (obj_ptr)->var.obj_string

BuiltinFunction PRINTLN_FUNCTION;
BuiltinFunction EXIT_FUNCTION;

static Object execute_println(Object *objects) {
  char *value = obj_cast_string(&objects[0]);
  puts(value);
  return UNIT_OBJ;
}

static Object execute_exit(Object *objects) {
  int code = obj_cast_int(&objects[0]);
  exit(code);
  return UNIT_OBJ;
}

void builtin_functions_init(TypeTable *type_table) {
  BUILTIN_FUNCTION(PRINTLN_FUNCTION, "println", execute_println,
                   UNIT_BUILTIN_TYPE, ARG("value", STRING_BUILTIN_TYPE));
  BUILTIN_FUNCTION(EXIT_FUNCTION, "exit", execute_exit, UNIT_BUILTIN_TYPE,
                   ARG("code", INT_BUILTIN_TYPE));

  type_table_add(type_table, &PRINTLN_FUNCTION.name,
                 EXPR_VAR_EXPR(PRINTLN_FUNCTION.expr), OPT_TYPE_EMPTY);
  type_table_add(type_table, &EXIT_FUNCTION.name,
                 EXPR_VAR_EXPR(PRINTLN_FUNCTION.expr), OPT_TYPE_EMPTY);
}
