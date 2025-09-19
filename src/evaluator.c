#include "../include/evaluator.h"
#include "lilc/array.h"
#include <lilc/alloc.h>
#include <stdio.h>

const Object UNIT_OBJ = {.type = OBJECT_UNIT};

static void evaluator_envs_push(Evaluator *evaluator);

Evaluator evaluator_new(Statement *stmts) {
  Evaluator evaluator = {
      .stmts = stmts, .environments = array_new(Environment, &HEAP_ALLOCATOR)};
  evaluator_envs_push(&evaluator);
  evaluator.global_env = &evaluator.environments[0];
  evaluator.cur_env = evaluator.global_env;
  return evaluator;
}

static void environment_add(Environment *env, Ident *symbol, Object obj) {
  hashmap_insert(&env->env, symbol, &obj);
}

static Object *environment_get(Environment *environment, const Ident *symbol,
                               Environment *global_env) {
  Object *res = hashmap_value(&environment->env, symbol);

  if (res == NULL && global_env != NULL) {
    return hashmap_value(&global_env->env, symbol);
  }

  return res;
}

static int strv_hash(const void *a) {
  const char *str = (char *)a;
  int hash = 5381;
  int c;

  while ((c = (unsigned char)*str++)) {
    hash = ((hash << 5) + hash) + c;
  }

  if (hash < 0) {
    hash = -hash;
  }

  return hash;
}

static bool strv_eq(const void *a, const void *b) { return strcmp(a, b) == 0; }

static int str_ptrv_hash(const void *a) { return strv_hash(*(char **)a); }

static bool str_ptrv_eq(const void *a, const void *b) {
  return strv_eq(*(char **)a, *(char **)b);
}

static void evaluator_envs_push(Evaluator *evaluator) {
  Environment new_env = {.env = hashmap_new(Ident, Object, &HEAP_ALLOCATOR,
                                            str_ptrv_hash, str_ptrv_eq, NULL)};
  array_add(evaluator->environments, new_env);
  evaluator->cur_env++;
}

static void evaluator_envs_pop(Evaluator *evaluator) {
  size_t len = array_len(evaluator->environments);
  if (len == 1)
    // We don't want to pop the global env
    return;

  Environment last_env = evaluator->environments[len - 1];
  _internal_array_set_len(evaluator->environments, len - 1);
  hashmap_free(&last_env.env);
  evaluator->cur_env--;
}

static void eval_stmt_decl(Evaluator *evaluator, StmtDecl *stmt_decl) {
  OptionalType type = stmt_decl->type;
  if (stmt_decl->value.type == EXPR_VAR_REG_EXPR) {
    environment_add(
        evaluator->cur_env, &stmt_decl->name,
        evaluator_eval_expr(evaluator, &stmt_decl->value.var.expr_var_reg_expr));
  }
}

static Object eval_expr_block(Evaluator *evaluator,
                              const ExprBlock *expr_block) {
  size_t len = array_len(expr_block->statements);
  for (size_t i = 0; i < len; i++) {
    if (i == len - 1) {
      Statement *stmt = &expr_block->statements[i];
      if (stmt->type == STMT_EXPR) {
        return evaluator_eval_expr(evaluator, &stmt->var.stmt_expr.expr);
      } else {
        evaluator_eval_stmt(evaluator, &expr_block->statements[i]);
      }
    } else {
      evaluator_eval_stmt(evaluator, &expr_block->statements[i]);
    }
  }
  return UNIT_OBJ;
}

Object eval_expr_call(Evaluator *evaluator, const ExprCall *expr_call) {
  Ident function = expr_call->function;
  if (strcmp(function, "println") == 0) {
    Object arg0 = evaluator_eval_expr(evaluator, &expr_call->args[0]);
    if (arg0.type == OBJECT_STRING) {
      char *expr_string = arg0.var.obj_string;
      puts(expr_string);
      return UNIT_OBJ;
    } else {
      fprintf(stderr, "Arg to println not a string\n");
    }
  } else if (strcmp(function, "exit") == 0) {
    Expression *arg0 = &expr_call->args[0];
    if (arg0->type == EXPR_INTEGER_LIT) {
      exit(arg0->var.expr_integer_literal.integer);
      return UNIT_OBJ;
    }
  }

  printf("Function: %s\n", expr_call->function);
  Object *value = environment_get(evaluator->cur_env, &expr_call->function,
                                  evaluator->global_env);
  if (value != NULL && value->type == OBJECT_FUNCTION) {
    ObjectFunction obj_function = value->var.obj_function;
    Object return_value;
    // We create a new environment for the scope of the function
    evaluator_envs_push(evaluator);
    {
      // Push function arguments to environment in case there are any
      if (expr_call->args != NULL) {
        for (size_t i = 0; i < array_len(expr_call->args); i++) {
          environment_add(evaluator->cur_env, &obj_function.args[i].ident,
                          evaluator_eval_expr(evaluator, &expr_call->args[i]));
        }
      }
      return_value = eval_expr_block(evaluator, obj_function.block);
    }
    // We pop the scope of the function from the environment after it returns
    evaluator_envs_pop(evaluator);
    return return_value;
  } else {
    fprintf(stderr,
            "Invalid name: %s for function call (func-ptr: %p), type: %d\n",
            expr_call->function, value, value != NULL ? value->type : -1);
    // hashmap_foreach(&evaluator->global_env->env, Ident * key, Object * obj,
    //                 { printf("Key: %s\n", *key); });
    exit(1);
  }
  return UNIT_OBJ;
}

Object evaluator_eval_expr(Evaluator *evaluator, Expression *expr) {
  switch (expr->type) {
  case EXPR_IDENT: {
    Object *value = environment_get(
        evaluator->cur_env, &expr->var.expr_ident.ident, evaluator->global_env);
    if (value != NULL) {
      return *value;
    } else {
      fprintf(stderr, "Error: Unknown identifier: %s\n",
              expr->var.expr_ident.ident);
      exit(1);
    }
  }
  // TODO: Function types and expressions (maybe)
  case EXPR_FUNCTION: {
    ExprBlock *block = expr->var.expr_function.block;
    return (Object){
        .type = OBJECT_FUNCTION,
        .var = {.obj_function = {.args = expr->var.expr_function.desc.args,
                                 .block = block}}};
  }
  case EXPR_CALL: {
    ExprCall expr_call = expr->var.expr_call;
    return eval_expr_call(evaluator, &expr_call);
  }
  case EXPR_BLOCK: {
    return eval_expr_block(evaluator, &expr->var.expr_block);
  }
  case EXPR_STRING_LIT: {
    return (Object){
        .type = OBJECT_STRING,
        .var = {.obj_string = expr->var.expr_string_literal.string}};
  }
  case EXPR_INTEGER_LIT: {
    return (Object){.type = OBJECT_INT,
                    .var = {.obj_int = expr->var.expr_integer_literal.integer}};
  }
  case EXPR_CAST: {
    Expression *val = expr->var.expr_cast.expr;
    Object obj = evaluator_eval_expr(evaluator, val);
    switch (obj.type) {
    case OBJECT_INT: {
      switch (expr->var.expr_cast.type.type) {
      case TYPE_IDENT: {
        if (type_eq(&expr->var.expr_cast.type, &STRING_BUILTIN_TYPE)) {
          char *string = malloc(32);
          sprintf(string, "%d", obj.var.obj_int);
          return (Object){.type = OBJECT_STRING, .var = {.obj_string = string}};
        } else if (type_eq(&expr->var.expr_cast.type, &INT_BUILTIN_TYPE)) {
          return obj;
        } else {
          fprintf(stderr,
                  "Casting to custom types is currently not supported\n");
          exit(1);
        }
      }
      default: {
        fprintf(stderr, "Casting is only supported for int and string types\n");
        exit(1);
      }
      }
    }
    case OBJECT_STRING: {
      switch (expr->var.expr_cast.type.type) {
      case TYPE_IDENT: {
        if (type_eq(&expr->var.expr_cast.type, &INT_BUILTIN_TYPE)) {
          return (Object){.type = OBJECT_INT,
                          .var = {.obj_int = atoi(obj.var.obj_string)}};
        } else if (type_eq(&expr->var.expr_cast.type, &STRING_BUILTIN_TYPE)) {
          return obj;
        } else {
          fprintf(stderr,
                  "Casting to custom types is currently not supported\n");
          exit(1);
        }
      }
      default: {
        fprintf(stderr, "Casting is only supported for int and string types\n");
        exit(1);
      }
      }
    }
    case OBJECT_UNIT: {
      return UNIT_OBJ;
    }
    case OBJECT_FUNCTION: {
      break;
    }
    }
    fprintf(stderr, "Invalid cast\n");
    exit(1);
  }
  // TODO: Implement this
  case EXPR_GENERIC_CALL: {
    ExprCall expr_call = expr->var.expr_generic_call.expr_call;
    fprintf(stderr, "Evaluating generic call\n");
    return eval_expr_call(evaluator, &expr_call);
  }
  case EXPR_ARRAY: {
    return UNIT_OBJ;
  }
  case EXPR_UNIT: {
    return UNIT_OBJ;
  }
  }
}

void evaluator_eval_stmt(Evaluator *evaluator, Statement *stmt) {
  switch (stmt->type) {
  case STMT_DECL: {
    eval_stmt_decl(evaluator, &stmt->var.stmt_decl);
    break;
  }
  case STMT_EXPR: {
    Expression expr = stmt->var.stmt_expr.expr;
    evaluator_eval_expr(evaluator, &expr);
    break;
  }
  }
}

static void eval(Evaluator *evaluator) {
  for (size_t i = 0; i < array_len(evaluator->stmts); i++) {
    evaluator_eval_stmt(evaluator, &evaluator->stmts[i]);
  }
}

void evaluator_eval_global(Evaluator *evaluator, TypeTable *global_table) {
  hashmap_foreach(
      &global_table->type_table, Ident * key, TypeTableValue * val, {
        if (val->expr_variant.type == EXPR_VAR_REG_EXPR) {
          printf("Key: %s\n", *key);
          environment_add(
              evaluator->global_env, key,
              evaluator_eval_expr(evaluator, &val->expr_variant.var.expr_var_reg_expr));
        }
      });
}
