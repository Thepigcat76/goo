#include "../include/checker.h"
#include "../include/generics.h"
#include "../include/types.h"
#include "../vendor/lilc/alloc.h"
#include "../vendor/lilc/array.h"
#include "../vendor/lilc/eq.h"
#include "../vendor/lilc/hash.h"
#include <stdio.h>

static void checker_type_table_push(TypeChecker *checker);

TypeChecker checker_new(Statement *stmts) {
  TypeChecker checker = {.stmts = stmts,
                         .type_tables = array_new(TypeTable, &HEAP_ALLOCATOR),
                         .generic_functions_table = gft_new(),
                         .generated_generic_functions =
                             hashmap_new(Ident *, Type, &HEAP_ALLOCATOR,
                                         str_ptrv_hash, str_ptrv_eq, NULL)};
  checker_type_table_push(&checker);
  checker.global_type_table = &checker.type_tables[0];
  checker.cur_type_table = checker.global_type_table;
  return checker;
}

void type_table_add(TypeTable *table, Ident *ident, ExpressionVariant expr_var,
                    OptionalType opt_type) {
  TypeTableValue val = {.expr_variant = expr_var, .opt_type = opt_type};
  bool inserted = hashmap_insert(&table->type_table, ident, &val);
}

void type_table_add_generic(TypeTable *table, Ident *name) {
  TypeTableValue val = {.is_generic = true};
  bool inserted = hashmap_insert(&table->type_table, name, &val);
}

TypeTableValue *type_table_get(TypeTable *table, Ident *ident,
                               TypeTable *global_table) {
  TypeTableValue *res = hashmap_value(&table->type_table, ident);

  if (res == NULL && global_table != NULL) {
    return hashmap_value(&global_table->type_table, ident);
  }

  return res;
}

static void checker_type_table_push(TypeChecker *checker) {
  array_add(checker->type_tables,
            (TypeTable){.type_table = hashmap_new(
                            Ident *, TypeTableValue, &HEAP_ALLOCATOR,
                            str_ptrv_hash, str_ptrv_eq, NULL)});
  checker->cur_type_table++;
}

static void checker_type_table_pop(TypeChecker *checker) {
  size_t len = array_len(checker->type_tables);
  if (len == 1) {
    // We don't want to pop the global env
    return;
  } else if (len == 0) {
    fprintf(stderr, "Checker type table is empty.");
    exit(1);
  }

  TypeTable last_table = checker->type_tables[len - 1];
  _internal_array_set_len(checker->type_tables, len - 1);
  hashmap_free(&last_table.type_table);
  checker->cur_type_table--;
}

static Type check_stmt(TypeChecker *checker, Statement *stmt);

static Type check_expr(TypeChecker *checker, Expression *expr);

// Returns the name of the correct function
static Ident resolve_overloaded_function(TypeChecker *checker,
                                         ExprCall *expr_call) {
  Type *call_arg_types = array_new(Type, &HEAP_ALLOCATOR);
  for (size_t i = 0; i < array_len(expr_call->args); i++) {
    array_add(call_arg_types, check_expr(checker, &expr_call->args[i]));
  }

  TypeTableValue *type_val =
      type_table_get(checker->cur_type_table, &expr_call->function,
                     checker->global_type_table);
  if (type_val != NULL) {
    if (type_val->expr_variant.type == TYPE_EXPR_OVERLOAD_SET) {
      TypeExprOverloadSet overload_set =
          type_val->expr_variant.var.expr_var_type_expr.var
              .type_expr_overload_set;
      size_t i;
      for (i = 0; i < array_len(overload_set.functions); i++) {
        Ident ident = overload_set.functions[i];
        TypeTableValue *value = type_table_get(checker->cur_type_table, &ident,
                                               checker->global_type_table);
        if (value != NULL) {
          ExpressionVariant expr_var = value->expr_variant;
          if (expr_var.type == EXPR_VAR_REG_EXPR) {
            Expression overloaded_function = expr_var.var.expr_var_reg_expr;
            if (overloaded_function.type == EXPR_FUNCTION) {
              ExprFunction overloaded_func_expr =
                  overloaded_function.var.expr_function;
              TypedIdent *args = overloaded_func_expr.desc.args;
              for (size_t i = 0; i < array_len(args); i++) {
                if (array_len(call_arg_types) != array_len(args) ||
                    !(i < array_len(call_arg_types) &&
                      type_eq(&call_arg_types[i], &args[i].type))) {
                  goto end_of_outerloop;
                }
              }
              break;
            } else {
              fprintf(stderr, "Symbol is not a function: %s\n", ident);
              exit(1);
            }
          } else {
            fprintf(stderr, "Nested overloads are not supported atm\n");
            exit(1);
          }
        } else {
          fprintf(stderr, "Could not find symbol (overload): %s\n", ident);
          exit(1);
        }
      end_of_outerloop: {}
      }
      Ident resolved_func_ident = overload_set.functions[i];
      return resolved_func_ident;
    } else {
      fprintf(stderr, "Type val not overload set: %s\n", expr_call->function);
    }
  } else {
    fprintf(stderr, "Type value null\n");
  }
  fprintf(stderr, "Could not find function with name: %s\n",
          expr_call->function);
  exit(1);
}

static void type_table_dump(const TypeTable *type_table) {
  hashmap_foreach(&type_table->type_table, Ident * key, TypeTableValue * val, {
    if (val->opt_type.present) {
      char type_buf[1024];
      type_print(type_buf, &val->opt_type.type);
      printf("Key: %s, Val: %s\n", *key, type_buf);
    }
  });
}

static bool is_generic_function(const ExprFunction *func) {
  return func->desc.generics != NULL && array_len(func->desc.generics) != 0;
}

static Type check_call_expr(TypeChecker *checker, ExprCall *expr_call) {
  TypeTableValue *val =
      type_table_get(checker->cur_type_table, &expr_call->function,
                     checker->global_type_table);
  // type_table_dump(checker->cur_type_table);

  ExprFunction expr_function;

  if (val != NULL) {
    if (val->expr_variant.type != EXPR_VAR_REG_EXPR) {
      Ident resolved_overload_function =
          resolve_overloaded_function(checker, expr_call);
      expr_call->function = resolved_overload_function;
      expr_function =
          type_table_get(checker->cur_type_table, &resolved_overload_function,
                         checker->global_type_table)
              ->expr_variant.var.expr_var_reg_expr.var.expr_function;
    } else {
      if (val->expr_variant.var.expr_var_reg_expr.type == EXPR_FUNCTION) {
        expr_function =
            val->expr_variant.var.expr_var_reg_expr.var.expr_function;
      } else {
        fprintf(stderr, "Expr is not a function\n");
        exit(1);
      }
    }
  } else {
    fprintf(stderr, "Could not find symbol %s\n", expr_call->function);
    exit(1);
  }

  size_t args_len = array_len(expr_call->args);
  size_t func_args_len = 0;
  if (expr_function.desc.args != NULL) {
    func_args_len = array_len(expr_function.desc.args);
  }
  if (args_len != func_args_len) {
    fprintf(stderr,
            "Type error: Arg count for caller (%zu) and function (%zu) do not "
            "match, "
            "function: %s\n",
            args_len, func_args_len, expr_call->function);
    exit(1);
  }
  Type *arg_types = array_new(Type, &HEAP_ALLOCATOR);
  for (size_t i = 0; i < args_len; i++) {
    Type arg_type = check_expr(checker, &expr_call->args[i]);
    array_add(arg_types, arg_type);
    bool generic_type = false;
    if (expr_function.desc.args[i].type.type == TYPE_IDENT &&
        expr_function.desc.generics != NULL) {
      for (size_t j = 0; j < array_len(expr_function.desc.generics); j++) {
        if (strcmp(expr_function.desc.args[i].type.var.type_ident,
                   expr_function.desc.generics[j].name) == 0) {
          generic_type = true;
          break;
        }
      }
    }
    if (!type_eq(&arg_type, &expr_function.desc.args[i].type) &&
        !generic_type) {
      type_table_dump(checker->cur_type_table);
      char caller_arg_type_buf[512];
      type_print(caller_arg_type_buf, &arg_type);
      char func_arg_type_buf[512];
      type_print(func_arg_type_buf, &expr_function.desc.args[i].type);
      fprintf(
          stderr,
          "Type error: Arg type of caller (%s) and function (%s) do not match, "
          "function: %s, "
          "arg: %zu\n",
          caller_arg_type_buf, func_arg_type_buf, expr_call->function, i);
      exit(1);
    }
  }

  if (is_generic_function(&expr_function)) {
    GenericFunction *generic_func =
        gft_get(&checker->generic_functions_table, &expr_call->function);
    if (generic_func != NULL) {
      CallerArgs *callers_args = generic_func->callers_args;
      array_add(callers_args, arg_types);
      array_add(generic_func->caller_exprs, expr_call);
    } else {
      fprintf(stderr, "UNREACHABLE\n");
      exit(1);
    }
  }

  return expr_function.desc.ret_type;
}

static bool is_type_generic(const TypeChecker *checker, Type *type) {
  if (type->type == TYPE_IDENT) {
    TypeTableValue *val =
        type_table_get(checker->cur_type_table, &type->var.type_ident,
                       checker->global_type_table);
    return val != NULL && val->is_generic;
  }
  return false;
}

// TODO: Create a type table ident -> type
static Type check_expr(TypeChecker *checker, Expression *expr) {
  switch (expr->type) {
  case EXPR_ARRAY: {
    Type *expected_item_type = expr->var.expr_array.type.type;
    size_t declared_items_len = array_len(expr->var.expr_array.items);
    for (size_t i = 0; i < declared_items_len; i++) {
      Type item_type = check_expr(checker, &expr->var.expr_array.items[i]);
      if (!type_eq(&item_type, expected_item_type)) {
        fprintf(stderr, "Type error: Expected and provided array item types do "
                        "not match\n");
        exit(1);
      }
    }
    return (Type){.type = TYPE_ARRAY,
                  .var = {.type_array = expr->var.expr_array.type}};
  }
  case EXPR_FUNCTION: {
    // TODO: implement function types
    ExprFunction expr_function = expr->var.expr_function;
    checker_type_table_push(checker);
    {
      // Add func args to typetable
      for (size_t i = 0; i < array_len(expr_function.desc.args); i++) {
        Type type = expr_function.desc.args[i].type;
        type_table_add(
            checker->cur_type_table, &expr_function.desc.args[i].ident,
            (ExpressionVariant){.type = EXPR_VAR_REG_EXPR,
                                .var = {.expr_var_reg_expr = UNIT_EXPR}},
            (OptionalType){.type = type, .present = true});
      }

      // Add func generics to typetable
      if (expr_function.desc.generics != NULL) {
        for (size_t i = 0; i < array_len(expr_function.desc.generics); i++) {
          Generic *generic = &expr_function.desc.generics[i];
          type_table_add_generic(checker->cur_type_table, &generic->name);
        }
      }

      for (size_t i = 0; i < array_len(expr_function.block->statements); i++) {
        check_stmt(checker, &expr_function.block->statements[i]);
      }
    }
    checker_type_table_pop(checker);
    return UNIT_BUILTIN_TYPE;
  }
  case EXPR_BLOCK: {
    if (expr->var.expr_block.statements != NULL) {
      size_t len = array_len(expr->var.expr_block.statements);
      Type last_type = UNIT_BUILTIN_TYPE;
      for (size_t i = 0; i < len; i++) {
        Statement stmt = expr->var.expr_block.statements[i];
        last_type = check_stmt(checker, &stmt);
      }
      return last_type;
    }
    return UNIT_BUILTIN_TYPE;
  }
  case EXPR_CALL: {
    return check_call_expr(checker, &expr->var.expr_call);
  }
  case EXPR_CAST: {
    Type expr_type = check_expr(checker, expr->var.expr_cast.expr);
    Type cast_type = expr->var.expr_cast.type;
    if (type_eq(&expr_type, &cast_type))
      goto return_type;
    if ((type_eq(&expr_type, &STRING_BUILTIN_TYPE) &&
         type_eq(&cast_type, &INT_BUILTIN_TYPE)) ||
        (type_eq(&cast_type, &STRING_BUILTIN_TYPE) &&
         type_eq(&expr_type, &INT_BUILTIN_TYPE)) ||
        is_type_generic(checker, &expr_type)) {
    } else {
      fprintf(stderr, "Cannot cast expr to this type\n");
    }
  return_type:
    return expr->var.expr_cast.type;
  }
  case EXPR_STRING_LIT: {
    return STRING_BUILTIN_TYPE;
  }
  case EXPR_INTEGER_LIT: {
    return INT_BUILTIN_TYPE;
  }
  case EXPR_IDENT: {
    TypeTableValue *val =
        type_table_get(checker->cur_type_table, &expr->var.expr_ident.ident,
                       checker->global_type_table);
    if (val != NULL) {

      if (val->opt_type.present) {
        return val->opt_type.type;
      } else if (val->expr_variant.type == EXPR_VAR_REG_EXPR) {
        return check_expr(checker, &val->expr_variant.var.expr_var_reg_expr);
      } else {
        fprintf(stderr, "Could not find expression with symbol: %s",
                expr->var.expr_ident.ident);
        exit(1);
      }
    }
  }
  case EXPR_GENERIC_CALL: {
    // TODO: More advanced checking (does generic definition contain bounds for
    // method call)
    return check_call_expr(checker, &expr->var.expr_generic_call.expr_call);
  }
  case EXPR_UNIT: {
    return UNIT_BUILTIN_TYPE;
  }
  case EXPR_BIN_OP: {
    // TODO: Implement proper type checking
    return INT_BUILTIN_TYPE;
  }
  }
}

static Type check_stmt(TypeChecker *checker, Statement *stmt) {
  char print_buf[1024];
  parser_stmt_print(print_buf, stmt);
  switch (stmt->type) {
  case STMT_DECL: {
    OptionalType opt_type = stmt->var.stmt_decl.type;
    if (stmt->var.stmt_decl.value.type != EXPR_VAR_TYPE_EXPR) {
      Expression decl_val = stmt->var.stmt_decl.value.var.expr_var_reg_expr;
      Type value_type = check_expr(checker, &decl_val);
      if (decl_val.type == EXPR_FUNCTION) {
        Generic *generics = decl_val.var.expr_function.desc.generics;
        if (is_generic_function(&decl_val.var.expr_function)) {
          GenericFunction func = {
              .generics = array_new(Ident, &HEAP_ALLOCATOR),
              .callers_args = array_new(CallerArgs, &HEAP_ALLOCATOR),
              .caller_exprs = array_new(ExprCall *, &HEAP_ALLOCATOR)};

          for (size_t i = 0; i < array_len(func.generics); i++) {
            array_add(func.generics, generics[i].name);
          }

          gft_add(&checker->generic_functions_table, &stmt->var.stmt_decl.name,
                  func);
        }
      }

      if (opt_type.present) {
        if (!type_eq(&value_type, &opt_type.type)) {
          fprintf(
              stderr,
              "Type error: Type of declaration and value do not match, decl "
              "name: %s\n",
              stmt->var.stmt_decl.name);
          exit(1);
        }
      } else {
        opt_type.type = value_type;
        opt_type.present = true;
      }
    }

    if (stmt->var.stmt_decl.value.type == EXPR_VAR_REG_EXPR) {
      type_table_add(
          checker->cur_type_table, &stmt->var.stmt_decl.name,
          EXPR_VAR_EXPR(stmt->var.stmt_decl.value.var.expr_var_reg_expr),
          opt_type);
      char *ident = ((char *)checker->cur_type_table->type_table.keys) +
                    49 * sizeof(char *);
    } else {
      type_table_add(
          checker->cur_type_table, &stmt->var.stmt_decl.name,
          EXPR_VAR_TYPE(stmt->var.stmt_decl.value.var.expr_var_type_expr),
          opt_type);
    }

    return UNIT_BUILTIN_TYPE;
  }
  case STMT_EXPR: {
    return check_expr(checker, &stmt->var.stmt_expr.expr);
  }
  }
}

void checker_check(TypeChecker *checker) {
  for (size_t i = 0; i < array_len(checker->stmts); i++) {
    check_stmt(checker, &checker->stmts[i]);
  }
}