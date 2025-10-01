#pragma once

#include "types.h"
#include "parser.h"
#include "../vendor/lilc/hashmap.h"
#include <stdio.h>

#define obj_cast_int(obj_ptr) (obj_ptr)->var.obj_int
#define obj_cast_string(obj_ptr) (obj_ptr)->var.obj_string

static int exit_with_msg(char *err_msg, int exit_code) {
  fputs(err_msg, stderr);
  exit(exit_code);
}

#define obj_try_cast_int(obj_ptr, err_msg) ((obj_ptr)->type == OBJECT_INT) ? (obj_ptr)->var.obj_int : exit_with_msg(err_msg, 1)

typedef struct {
  TypedIdent *args;
  ExprBlock *block;
  struct _obj (*native_function)(struct _obj *objects);
} ObjectFunction;

typedef struct _obj {
  enum {
    OBJECT_INT,
    OBJECT_STRING,
    OBJECT_FUNCTION,
    OBJECT_UNIT,
  } type;
  union {
    int obj_int;
    char *obj_string;
    ObjectFunction obj_function;
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

Evaluator evaluator_new(Statement *stmts);

void evaluator_eval_global(Evaluator *evaluator, TypeTable *global_table);

void evaluator_eval_stmt(Evaluator *evaluator, Statement *stmt);

Object evaluator_eval_expr(Evaluator *evaluator, Expression *expr);
