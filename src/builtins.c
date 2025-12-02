#include "../include/builtins.h"
#include "../vendor/lilc/array.h"
#include <stdio.h>

#define BUILTIN_FUNCTION_DEFINE(_ret_type, _native_function)                   \
  (Expression) {                                                               \
    .type = EXPR_FUNCTION, .var =                                              \
    {.expr_function = {.desc = {.ret_type = _ret_type,                         \
                                .args = array_new(Argument, &HEAP_ALLOCATOR)}, \
                       .block = NULL,                                          \
                       .native_function = _native_function} }                  \
  }

#define BUILTIN_FUNCTION_SET_ARG_TYPES(_expr, ...)                             \
  do {                                                                         \
    Argument *args = _expr.var.expr_function.desc.args;                        \
    Argument provided[] = {__VA_ARGS__ __VA_OPT__(, )(Argument){0}};           \
    size_t i;                                                                  \
    for (i = 0; provided[i].type != ARG_VARARG &&                              \
                provided[i].var.typed_arg.ident != NULL;                       \
         i++) {                                                                \
      array_add(args, provided[i]);                                            \
    }                                                                          \
    if (provided[i].type == ARG_VARARG) {                                      \
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
  (Argument) {                                                                 \
    .type = ARG_TYPED_ARG, .var = {                                            \
      .typed_arg = {.ident = _ident, .type = _type}                            \
    }                                                                          \
  }

#define VARARG(_ident)                                                         \
  (Argument) {                                                                 \
    .type = ARG_VARARG, .var = {.vararg = _ident }                             \
  }

BuiltinFunction PRINTLN_FUNCTION;
BuiltinFunction PRINTFN_FUNCTION;
BuiltinFunction FORMAT_FUNCTION;
BuiltinFunction EXIT_FUNCTION;

char println_buf[1024] = {'\0'};

static Object execute_println(Object *objects) {
  char *string = obj_cast_string(&objects[0]);
  strcat(println_buf, string);
  strcat(println_buf, "\n");
  puts(string);
  return UNIT_OBJ;
}

static Object execute_exit(Object *objects) {
  int code = obj_cast_int(&objects[0]);
  exit(code);
  return UNIT_OBJ;
}

static Object execute_printfn(Object *objects) {
  char *fmt_string = obj_cast_string(&objects[0]);

  size_t arg_index = 0;
  char *c = &fmt_string[0];
  while (*c != '\0') {
    if (*c == '%') {
      Object cast_obj = obj_cast(&STRING_BUILTIN_TYPE, &objects[arg_index + 1]);

      printf("%s", obj_cast_string(&cast_obj));
      arg_index++;
    } else {
      printf("%c", *c);
    }
    c++;
  }

  puts("");

  return UNIT_OBJ;
}

static Object execute_format(Object *objects) {
  size_t new_string_capacity = 256;
  char *new_string = malloc(new_string_capacity);
  size_t new_string_len = 0;

  char *fmt_string = obj_cast_string(&objects[0]);

  size_t arg_index = 0;
  char *c = &fmt_string[0];
  while (*c != '\0') {
    if (*c == '%') {
      Object cast_obj = obj_cast(&STRING_BUILTIN_TYPE, &objects[arg_index + 1]);
      char *cast_obj_str = obj_cast_string(&cast_obj);
      size_t cast_obj_str_len = strlen(cast_obj_str);
      if (new_string_len + cast_obj_str_len >= new_string_capacity) {
        new_string_capacity *= 2;
        new_string = realloc(new_string, new_string_capacity);
      }
      for (size_t i = 0; i < cast_obj_str_len; i++) {
        new_string[new_string_len++] = cast_obj_str[i];
      }
      arg_index++;
    } else if (*c == '\\') {
      char next_c = *(c + 1);
      if (next_c == '%') {
        new_string[new_string_len++] = '%';
        c++;
        next_c = *(c + 1);
      }
    } else {
      new_string[new_string_len++] = *c;
      if (new_string_len >= new_string_capacity) {
        new_string_capacity *= 2;
        new_string = realloc(new_string, new_string_capacity);
      }
    }
    c++;
  }

  new_string[new_string_len] = '\0';
  return OBJ_STR(new_string);
}

void builtin_functions_init(TypeTable *type_table) {
  BUILTIN_FUNCTION(PRINTLN_FUNCTION, "println", execute_println,
                   UNIT_BUILTIN_TYPE, ARG("value", STRING_BUILTIN_TYPE));
  BUILTIN_FUNCTION(PRINTFN_FUNCTION, "printfn", execute_printfn,
                   UNIT_BUILTIN_TYPE, ARG("format", STRING_BUILTIN_TYPE),
                   VARARG("args"));
  BUILTIN_FUNCTION(FORMAT_FUNCTION, "format", execute_format,
                   STRING_BUILTIN_TYPE, ARG("format", STRING_BUILTIN_TYPE),
                   VARARG("args"));
  BUILTIN_FUNCTION(EXIT_FUNCTION, "exit", execute_exit, UNIT_BUILTIN_TYPE,
                   ARG("code", INT_BUILTIN_TYPE));

  type_table_add(type_table, &PRINTLN_FUNCTION.name,
                 EXPR_VAR_EXPR(PRINTLN_FUNCTION.expr), OPT_TYPE_EMPTY);
  type_table_add(type_table, &PRINTFN_FUNCTION.name,
                 EXPR_VAR_EXPR(PRINTFN_FUNCTION.expr), OPT_TYPE_EMPTY);
  type_table_add(type_table, &EXIT_FUNCTION.name,
                 EXPR_VAR_EXPR(EXIT_FUNCTION.expr), OPT_TYPE_EMPTY);
  type_table_add(type_table, &FORMAT_FUNCTION.name,
                 EXPR_VAR_EXPR(FORMAT_FUNCTION.expr), OPT_TYPE_EMPTY);
}
