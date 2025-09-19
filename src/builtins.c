#include "../include/builtins.h"
#include "lilc/array.h"

#define BUILTIN_FUNCTION_DEFINE(_ret_type)                                     \
  (Expression) {                                                               \
    .type = EXPR_FUNCTION, .var = {                                            \
      .expr_function = {.desc = {.ret_type = _ret_type,                        \
                                 .args =                                       \
                                     array_new(TypedIdent, &HEAP_ALLOCATOR)}}  \
    }                                                                          \
  }

#define BUILTIN_FUNCTION_SET_ARG_TYPES(func, ...)                              \
  do {                                                                         \
    TypedIdent *args = func.var.expr_function.desc.args;                       \
    TypedIdent provided[] = {__VA_ARGS__ __VA_OPT__(, )(TypedIdent){0}};       \
    for (size_t i = 0; provided[i].ident != NULL; i++) {                       \
      array_add(args, provided[i]);                                            \
    }                                                                          \
  } while (0)

#define BUILTIN_FUNCTION(func, _ret_type, ...)                                 \
  do {                                                                         \
    func = BUILTIN_FUNCTION_DEFINE(_ret_type);                                 \
    BUILTIN_FUNCTION_SET_ARG_TYPES(func, __VA_ARGS__);                         \
  } while (0)

#define ARG(_ident, _type)                                                     \
  (TypedIdent) { .ident = _ident, .type = _type }

Expression PRINTLN_FUNCTION_EXPR;
Expression EXIT_FUNCTION_EXPR;

static char *PRINTLN_FUNC = "println";
static char *EXIT_FUNC = "exit";

void builtin_functions_init(TypeTable *type_table) {
  BUILTIN_FUNCTION(PRINTLN_FUNCTION_EXPR, UNIT_BUILTIN_TYPE,
                   ARG("value", STRING_BUILTIN_TYPE));
  BUILTIN_FUNCTION(EXIT_FUNCTION_EXPR, UNIT_BUILTIN_TYPE,
                   ARG("code", INT_BUILTIN_TYPE));

  type_table_add(type_table, &PRINTLN_FUNC, EXPR_VAR_EXPR(PRINTLN_FUNCTION_EXPR), OPT_TYPE_EMPTY);
  type_table_add(type_table, &EXIT_FUNC, EXPR_VAR_EXPR(PRINTLN_FUNCTION_EXPR), OPT_TYPE_EMPTY);
}
