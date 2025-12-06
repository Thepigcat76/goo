#include "../include/evaluator.h"
#include "../vendor/lilc/alloc.h"
#include "../vendor/lilc/array.h"
#include "../vendor/lilc/panic.h"
#include <stdio.h>
#include <string.h>

static char *obj_to_string(Object *val_ptr) {
  Object obj = obj_cast(&STRING_BUILTIN_TYPE, val_ptr);
  return obj_cast_string(&obj);
}

#define OBJ_TO_STRING(val_ptr) obj_cast_string(obj_cast(&STRING_BUILTIN_TYPE, val_ptr))

const Object UNIT_OBJ = {.type = OBJECT_UNIT};

static const OptionalObject EMPTY_OBJECT = {.present = false};

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

static void evaluator_envs_push_copy(Evaluator *evaluator,
                                     Environment *env_to_copy) {
  Environment new_env = {.env = hashmap_new(Ident, Object, &HEAP_ALLOCATOR,
                                            str_ptrv_hash, str_ptrv_eq, NULL)};
  hashmap_foreach(&env_to_copy->env, Ident * key, Object * val,
                  { environment_add(&new_env, key, *val); });

  array_add(evaluator->environments, new_env);
  evaluator->cur_env++;
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
    environment_add(evaluator->cur_env, &stmt_decl->name,
                    evaluator_eval_expr(
                        evaluator, &stmt_decl->value.var.expr_var_reg_expr));
  }
}

static Object eval_expr_block(Evaluator *evaluator,
                              const ExprBlock *expr_block) {
  size_t len = array_len(expr_block->statements);
  for (size_t i = 0; i < len; i++) {
    Statement *stmt = &expr_block->statements[i];
    if (i == len - 1 && stmt->type == STMT_EXPR) {
      return evaluator_eval_expr(evaluator, &stmt->var.stmt_expr.expr);
    } else {
      OptionalObject opt_obj =
          evaluator_eval_stmt(evaluator, &expr_block->statements[i]);
      if (opt_obj.present) {
        return opt_obj.obj;
      }
    }
  }
  return UNIT_OBJ;
}

Object eval_expr_call(Evaluator *evaluator, const ExprCall *expr_call) {
  Ident function = expr_call->function;

  Object *value = environment_get(evaluator->cur_env, &expr_call->function,
                                  evaluator->global_env);
  if (value != NULL && value->type == OBJECT_FUNCTION) {
    ObjectFunction obj_function = value->var.obj_function;
    Object *call_args = array_new(Object, &HEAP_ALLOCATOR);
    if (expr_call->args != NULL) {
      for (size_t i = 0; i < array_len(expr_call->args); i++) {
        Object obj = evaluator_eval_expr(evaluator, &expr_call->args[i]);
        array_add(call_args, obj);
      }
    }
    Object return_value;
    // We create a new environment for the scope of the function
    evaluator_envs_push(evaluator);
    {
      // Push function arguments to environment in case there are any
      if (expr_call->args != NULL) {
        for (size_t i = 0; i < array_len(call_args); i++) {
          if (obj_function.args[i].type != ARG_VARARG &&
              i < array_len(obj_function.args)) {
            environment_add(evaluator->cur_env,
                            &obj_function.args[i].var.typed_arg.ident,
                            call_args[i]);
          }
        }
      }
      if (obj_function.native_function != NULL) {
        return_value = obj_function.native_function(call_args);
      } else {
        return_value = eval_expr_block(evaluator, obj_function.block);
      }
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

Object obj_cast(const Type *type, const Object *obj) {
  switch (obj->type) {
  case OBJECT_INT: {
    switch (type->type) {
    case TYPE_IDENT: {
      if (type_eq(type, &STRING_BUILTIN_TYPE)) {
        char *string = malloc(32);
        sprintf(string, "%d", obj->var.obj_int);
        return (Object){.type = OBJECT_STRING, .var = {.obj_string = string}};
      } else if (type_eq(type, &INT_BUILTIN_TYPE)) {
        return *obj;
      } else {
        fprintf(stderr, "Casting to custom types is currently not supported\n");
        exit(1);
      }
    }
    case TYPE_ARRAY: {
      if (type_eq(type, &STRING_BUILTIN_TYPE)) {
        char *string = malloc(32);
        sprintf(string, "%d", obj->var.obj_int);
        return OBJ_STR(string);
      } else {
        fprintf(stderr,
                "Casting to custom array types is currently not supported\n");
        exit(1);
      }
    }
    default: {
      fprintf(stderr, "Casting is only supported for int and string types\n");
      exit(1);
    }
    }
  }
  case OBJECT_PTR: {
    if (type_eq(type, &INT_BUILTIN_TYPE)) {
      return OBJ_INT((long)obj->var.obj_ptr);
    } else if (type_eq(type, &STRING_BUILTIN_TYPE)) {
      char *buf = malloc(128);
      sprintf(buf, "%p", obj->var.obj_ptr);
      return OBJ_STR(buf);
    }
  }
  case OBJECT_STRING: {
    switch (type->type) {
    case TYPE_IDENT: {
      if (type_eq(type, &INT_BUILTIN_TYPE)) {
        return (Object){.type = OBJECT_INT,
                        .var = {.obj_int = atoi(obj->var.obj_string)}};
      } else if (type_eq(type, &STRING_BUILTIN_TYPE)) {
        return *obj;
      } else {
        fprintf(stderr, "Casting to custom types is currently not supported\n");
        exit(1);
      }
    }
    // TODO: Make string typedef for u8 array
    case TYPE_ARRAY: {
      size_t len = strlen(obj->var.obj_string);
      Object *chars = array_new_capacity(Object, len + 1, &HEAP_ALLOCATOR);
      for (size_t i = 0; i < len; i++) {
        array_add(chars, OBJ_INT(obj->var.obj_string[i]));
      }
      return (Object){.type = OBJECT_ARRAY,
                      .var = {.obj_array = {.items = chars}}};
    }
    default: {
      fprintf(stderr, "Casting is only supported for int and string types\n");
      exit(1);
    }
    }
  }
  case OBJECT_ARRAY: {
    if (type_eq(type, &STRING_BUILTIN_TYPE)) {
      char *string = malloc(1024);
      string[0] = '\0';
      const ObjectArray *obj_array = &obj->var.obj_array;
      for (size_t i = 0; i < array_len(obj_array->items); i++) {
        Object item_obj = obj_cast(&STRING_BUILTIN_TYPE, &obj_array->items[i]);
        if (item_obj.type == OBJECT_STRING) {
          strcat(string, item_obj.var.obj_string);
        } else {
          strcat(string, "<UNCASTABLE OBJECT>");
        }

        if (i < array_len(obj_array->items) - 1) {
          strcat(string, ", ");
        }
      }
      return (Object){.type = OBJECT_STRING, .var = {.obj_string = string}};
    }
    break;
  }
  case OBJECT_UNIT: {
    return UNIT_OBJ;
  }
  case OBJECT_STRUCT:
  case OBJECT_FUNCTION: {
    break;
  }
  case OBJECT_BOOL: {
    switch (type->type) {
    case TYPE_IDENT: {
      if (type_eq(type, &BOOL_BUILTIN_TYPE)) {
        return *obj;
      } else if (type_eq(type, &INT_BUILTIN_TYPE)) {
        return OBJ_INT(obj->var.obj_bool ? 1 : 0);
      } else if (type_eq(type, &STRING_BUILTIN_TYPE)) {
        return (Object){
            .type = OBJECT_STRING,
            .var = {.obj_string = obj->var.obj_bool ? "true" : "false"}};
      }
    }
    default: {
      break;
    }
    }
  }
  }
  fprintf(stderr, "Invalid cast\n");
  char type_buf[128];
  type_print(type_buf, type);
  fprintf(stderr, "Tried to cast obj of type %d, to type %s\n", obj->type,
          type_buf);
  exit(1);
}

static bool obj_is_true(const Object *obj) {
  if (obj->type == OBJECT_INT) {
    return obj->var.obj_int;
  } else if (obj->type == OBJECT_BOOL) {
    return obj->var.obj_bool;
  }
  return false;
}

static Ident IT_NAME = "it";

Object evaluator_eval_expr(Evaluator *evaluator, Expression *expr) {
  switch (expr->type) {
  case EXPR_IDENT: {
    Object *value = environment_get(
        evaluator->cur_env, &expr->var.expr_ident.ident, evaluator->global_env);
    if (value != NULL) {
      return *value;
    } else {
      panic("Error: Unknown identifier: %s\n", expr->var.expr_ident.ident);
      // fprintf(stderr, "Error: Unknown identifier: %s\n",
      //         expr->var.expr_ident.ident);
      // exit(1);
    }
  }
  // TODO: Function types and expressions (maybe)
  case EXPR_FUNCTION: {
    ExprBlock *block = expr->var.expr_function.block;
    return (Object){
        .type = OBJECT_FUNCTION,
        .var = {.obj_function = {.args = expr->var.expr_function.desc.args,
                                 .block = block,
                                 .native_function =
                                     expr->var.expr_function.native_function}}};
  }
  case EXPR_CALL: {
    ExprCall expr_call = expr->var.expr_call;
    return eval_expr_call(evaluator, &expr_call);
  }
  case EXPR_IT: {
    return *environment_get(evaluator->cur_env, &IT_NAME,
                            evaluator->global_env);
  }
  case EXPR_FOR: {
    ExprFor *expr_for = &expr->var.expr_for;
    Object range_min = evaluator_eval_expr(evaluator, expr_for->range.min);
    int min = obj_cast_int(&range_min);
    Object range_max = evaluator_eval_expr(evaluator, expr_for->range.max);
    int max = obj_cast_int(&range_max);

    Ident *counter_var_name =
        expr_for->variable_name == NULL ? &IT_NAME : &expr_for->variable_name;

    evaluator_envs_push_copy(evaluator, evaluator->cur_env);
    {

      environment_add(evaluator->cur_env, counter_var_name, OBJ_INT(min));

      int i = min;
      while (i < max) {
        eval_expr_block(evaluator, &expr_for->block);
        *environment_get(evaluator->cur_env, counter_var_name,
                         evaluator->global_env) = OBJ_INT(++i);
      }
    }
    evaluator_envs_pop(evaluator);

    return UNIT_OBJ;
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
  case EXPR_BOOLEAN_LIT: {
    return (Object){
        .type = OBJECT_BOOL,
        .var = {.obj_bool = expr->var.expr_boolean_literal.boolean}};
  }
  case EXPR_ARRAY_ACCESS: {
    ExprArrayAccess arr_access = expr->var.expr_array_access;
    Object arr_obj = evaluator_eval_expr(evaluator, arr_access.array_expr);
    Object index_obj = evaluator_eval_expr(evaluator, arr_access.index_expr);
    if (index_obj.type != OBJECT_INT) {
      fprintf(stderr, "Index not an integer!\n");
      exit(1);
    }
    if (arr_obj.type == OBJECT_STRING) {
      return OBJ_INT(arr_obj.var.obj_string[obj_cast_int(&index_obj)]);
    }
    return arr_obj.var.obj_array.items[obj_cast_int(&index_obj)];
  }
  case EXPR_CAST: {
    Expression *val = expr->var.expr_cast.expr;
    Object obj = evaluator_eval_expr(evaluator, val);
    return obj_cast(&expr->var.expr_cast.type, &obj);
  }
  // TODO: Implement this
  case EXPR_GENERIC_CALL: {
    ExprCall expr_call = expr->var.expr_generic_call.expr_call;
    fprintf(stderr, "Evaluating generic call\n");
    return eval_expr_call(evaluator, &expr_call);
  }
  case EXPR_ADDR_OF: {
    Object obj = evaluator_eval_expr(evaluator, expr->var.expr_addr_of.expr);
    return (Object){.type = OBJECT_PTR, .var = {.obj_ptr = heap_clone(&obj)}};
  }
  case EXPR_PTR_DEREF: {
    Object obj = evaluator_eval_expr(evaluator, expr->var.expr_ptr_deref.expr);
    if (obj.type != OBJECT_PTR) {
      fprintf(stderr, "Cannot deref non-pointer\n");
      exit(1);
    }
    return *obj.var.obj_ptr;
  }
  case EXPR_ARRAY_INIT: {
    ExprArrayInit expr_array = expr->var.expr_array_init;
    ObjectArray obj_array = {.items = array_new(Object, &HEAP_ALLOCATOR)};

    for (size_t i = 0; i < array_len(expr_array.items); i++) {
      array_add(obj_array.items,
                evaluator_eval_expr(evaluator, &expr_array.items[i]));
    }

    return (Object){.type = OBJECT_ARRAY, .var = {.obj_array = obj_array}};
  }
  case EXPR_UNIT: {
    return UNIT_OBJ;
  }
  case EXPR_BIN_OP: {
    BinOperator op = expr->var.expr_bin_op.op;
    Object left_obj =
        evaluator_eval_expr(evaluator, expr->var.expr_bin_op.left);
    Object right_obj =
        evaluator_eval_expr(evaluator, expr->var.expr_bin_op.right);

    int left = obj_try_cast_int(&left_obj,
                                "Left object (%s) of bin expr is not an integer\n", obj_to_string(&left_obj));
    int right = obj_try_cast_int(&right_obj,
                                 "Right object (%s) of bin expr is not an integer\n", obj_to_string(&right_obj));

    switch (op) {
    case BIN_OP_ADD: {
      return OBJ_INT(left + right);
    }
    case BIN_OP_SUB: {
      return OBJ_INT(left - right);
    }
    case BIN_OP_MUL: {
      return OBJ_INT(left * right);
    }
    case BIN_OP_DIV: {
      return OBJ_INT(left / right);
    }
    case BIN_OP_LT: {
      return OBJ_INT(left < right);
    }
    case BIN_OP_GT: {
      return OBJ_INT(left > right);
    }
    case BIN_OP_LTE: {
      return OBJ_INT(left <= right);
    }
    case BIN_OP_GTE: {
      return OBJ_INT(left >= right);
    }
    }
  }
  case EXPR_STRUCT_INIT: {
    ExprStructInit *struct_init_expr = &expr->var.expr_struct_init;
    Object obj = {.type = OBJECT_STRUCT,
                  .var = {.obj_struct = {.fields = hashmap_new(
                                             char *, Object, &HEAP_ALLOCATOR,
                                             strv_hash, strv_eq, NULL)}}};
    for (size_t i = 0; i < array_len(struct_init_expr->field_inits); i++) {
      LabeledExpr *labeled_expr = &struct_init_expr->field_inits[i];
      Object field_obj = evaluator_eval_expr(evaluator, &labeled_expr->expr);
      hashmap_insert(&obj.var.obj_struct.fields, labeled_expr->field,
                     &field_obj);
    }

    return obj;
  }
  case EXPR_STRUCT_ACCESS: {
    ExprStructAccess *expr_struct_access = &expr->var.expr_struct_access;
    Object obj =
        evaluator_eval_expr(evaluator, expr_struct_access->struct_expr);
    size_t len = array_len(expr_struct_access->fields);
    for (size_t i = 0; i < len; i++) {
      Ident field = expr_struct_access->fields[i];
      if (obj.type == OBJECT_STRUCT) {
        ObjectStruct field_obj = obj.var.obj_struct;
        Object *next_obj = hashmap_value(&field_obj.fields, field);
        obj = *next_obj;
      }
    }
    return obj;
  }
  case EXPR_IF: {
    ExprIf expr_if = expr->var.expr_if;
    Object condition = evaluator_eval_expr(evaluator, expr_if.condition);

    if (obj_is_true(&condition)) {
      return eval_expr_block(evaluator, &expr_if.block);
    }

    return UNIT_OBJ;
  }
  }
}

OptionalObject evaluator_eval_stmt(Evaluator *evaluator, Statement *stmt) {
  switch (stmt->type) {
  case STMT_DECL: {
    eval_stmt_decl(evaluator, &stmt->var.stmt_decl);
    return EMPTY_OBJECT;
  }
  case STMT_EXPR: {
    Expression expr = stmt->var.stmt_expr.expr;
    evaluator_eval_expr(evaluator, &expr);
    return EMPTY_OBJECT;
  }
  case STMT_RETURN: {
    if (stmt->var.stmt_return.has_ret_val) {
      Object ret_val =
          evaluator_eval_expr(evaluator, &stmt->var.stmt_return.ret_val);
      return (OptionalObject){.obj = ret_val, .present = true};
    }
    return EMPTY_OBJECT;
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
          environment_add(
              evaluator->global_env, key,
              evaluator_eval_expr(evaluator,
                                  &val->expr_variant.var.expr_var_reg_expr));
        }
      });
}
