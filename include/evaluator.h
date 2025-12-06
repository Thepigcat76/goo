#pragma once

#include "../vendor/lilc/hashmap.h"
#include "parser.h"
#include "types.h"
#include <stdarg.h>
#include <stdio.h>

#define obj_cast_int(obj_ptr) (obj_ptr)->var.obj_int
#define obj_cast_string(obj_ptr) (obj_ptr)->var.obj_string

#define OBJ_STR(_str)                                                          \
  (Object) {                                                                   \
    .type = OBJECT_STRING, .var = {.obj_string = _str }                        \
  }

#define OBJ_INT(_int)                                                          \
  (Object) {                                                                   \
    .type = OBJECT_INT, .var = {.obj_int = _int }                              \
  }

#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 2, 3)))
#endif
static int exit_with_msg(int exit_code, const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  vprintf(format, ap);
  va_end(ap);
  exit(exit_code);
}

#define obj_try_cast_int(obj_ptr, err_msg, ...)                                \
  ((obj_ptr)->type == OBJECT_INT)                                              \
      ? (obj_ptr)->var.obj_int                                                 \
      : exit_with_msg(1, err_msg __VA_OPT__(, ) __VA_ARGS__)

typedef struct {
  Argument *args;
  ExprBlock *block;
  struct _obj (*native_function)(struct _obj *objects);
} ObjectFunction;

typedef struct {
  Hashmap(Ident, Object) fields;
} ObjectStruct;

typedef struct {
  struct _obj *items;
} ObjectArray;

typedef struct _obj {
  enum {
    OBJECT_INT,
    OBJECT_STRING,
    OBJECT_BOOL,
    OBJECT_FUNCTION,
    OBJECT_UNIT,
    OBJECT_STRUCT,
    OBJECT_ARRAY,
    OBJECT_PTR,
  } type;
  union {
    int obj_int;
    char *obj_string;
    bool obj_bool;
    ObjectFunction obj_function;
    ObjectStruct obj_struct;
    ObjectArray obj_array;
    struct _obj *obj_ptr;
  } var;
} Object;

extern const Object UNIT_OBJ;

typedef struct {
  Hashmap(Ident, Object) env;
} Environment;

typedef struct {
  Statement *stmts;

  // Basically our version of a stack. Each environment represents a "stack
  // frame"
  Environment *environments;
  // Very first entry of the 'environments' field. Stores variables that are
  // global aka will never go out of scope
  Environment *global_env;
  // The current environment (last environment on the environments stack)
  Environment *cur_env;
} Evaluator;

typedef struct {
  Object obj;
  bool present;
} OptionalObject;

Evaluator evaluator_new(Statement *stmts);

void evaluator_eval_global(Evaluator *evaluator, TypeTable *global_table);

OptionalObject evaluator_eval_stmt(Evaluator *evaluator, Statement *stmt);

Object evaluator_eval_expr(Evaluator *evaluator, Expression *expr);

Object obj_cast(const Type *type, const Object *obj);
