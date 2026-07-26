#include "../../include/checker.h"
#include "../../include/builtins/types.h"
#include "../../include/parser.h"
#include "../../include/types.h"
#include "lilc/alloc.h"
#include "lilc/array.h"
#include "lilc/eq.h"
#include <lilc/dynstr.h>
#include <lilc/hashmap0.h>
#include <lilc/log.h>
#include <lilc/panic.h>
#include <lilc/str.h>
#include <lilc/todo.h>
#include <stdio.h>

#define CHECK_RESULT_SUCCESS                                                   \
  (CheckResult) { .success = true }

static const CheckerContext EMPTY_CONTEXT = {0};

static bool type_is_integer(const Type *type) {
  bool is_signed_int = type_eq(type, &BUILTIN_TYPES[BUILTIN_TYPE_I8]) ||
                       type_eq(type, &BUILTIN_TYPES[BUILTIN_TYPE_I16]) ||
                       type_eq(type, &BUILTIN_TYPES[BUILTIN_TYPE_I32]) ||
                       type_eq(type, &BUILTIN_TYPES[BUILTIN_TYPE_I64]);
  bool is_unsigned_int = type_eq(type, &BUILTIN_TYPES[BUILTIN_TYPE_U8]) ||
                         type_eq(type, &BUILTIN_TYPES[BUILTIN_TYPE_U16]) ||
                         type_eq(type, &BUILTIN_TYPES[BUILTIN_TYPE_U32]) ||
                         type_eq(type, &BUILTIN_TYPES[BUILTIN_TYPE_U64]);

  return is_signed_int || is_unsigned_int;
}

inline void type_table_init(TypeTable *table, Allocator *alloc) {
  hashmap_init(&table->type_table, alloc, ModulePath, TypeTableValue,
               mod_path_ptrv_hash, mod_path_ptrv_eq, NULL);
}

void checker_init(TypeChecker *checker) {
  error_sink_init(&checker->sink);

  bump_init(&checker->checker_arena, 8000);
  bump_allocator_init(&checker->checker_arena_allocator,
                      &checker->checker_arena);
}

void checker_deinit(TypeChecker *checker) {
  // array_free(checker->type_tables);

  error_sink_deinit(&checker->sink);

  bump_free(&checker->checker_arena);
}

void type_table_add(TypeTable *table, ModulePath *path,
                    ExpressionVariant expr_var, OptionalType opt_type) {
  TypeTableValue val = {.expr_variant = expr_var, .opt_type = opt_type};
  hashmap_insert(&table->type_table, path, &val);
}

void type_table_add_generic(TypeTable *table, Ident *name) {
  TypeTableValue val = {.is_generic = true};
  hashmap_insert(&table->type_table, name, &val);
}

TypeTableValue *_type_table_get(TypeTable *table, ModulePath *path,
                                TypeTable *global_table) {
  // if (ident == NULL || *ident == NULL)
  //   return NULL;

  TypeTableValue *res = hashmap_value(&table->type_table, path);

  if (res == NULL && global_table != NULL) {
    return hashmap_value(&global_table->type_table, path);
  }

  return res;
}

TypeTableValue *type_table_get(TypeTables table, ModulePath *path,
                               TypeTable *global_table) {
  // if (ident == NULL || *ident == NULL)
  //   return NULL;

  TypeTableValue *res = hashmap_value(&table->type_table, path);

  if (res == NULL && global_table != NULL) {
    return hashmap_value(&global_table->type_table, path);
  }

  return res;
}

void checker_type_add(TypeChecker *checker, Ident func_name, size_t scope_idx,
                      ModulePath *key, ExpressionVariant value,
                      OptionalType type) {
  TypeTables *tables = NULL;
  if (func_name != NULL) {
    tables =
        hashmap_value(&checker->cur_mod_check.function_type_tables, &func_name);
  }

  TypeTable *table;
  if (tables == NULL) {
    table = &checker->cur_mod_check.global_type_table;
  } else {
    table = &(*tables)[scope_idx];
  }

  type_table_add(table, key, value, type);
}

TypeTableValue *
tables_type_get(Hashmap func_type_tables /* Ident -> TypeTables */,
                TypeTable global_type_table, Ident func_name, size_t scope_idx,
                ModulePath *name) {
  TypeTables *tables = NULL;
  if (func_name != NULL) {
    tables =
        hashmap_value(&func_type_tables, &func_name);
  }

  TypeTable *table;
  if (tables == NULL) {
    table = &global_type_table;
  } else {
    table = &(*tables)[scope_idx];
  }

  TypeTableValue *val = hashmap_value(&table->type_table, name);
  if (val == NULL) {
    return hashmap_value(&global_type_table.type_table, name);
  }
  return val;
}

static TypeTableValue *checker_type_get(TypeChecker *checker, Ident func_name,
                                 size_t scope_idx, ModulePath *name) {
  return tables_type_get(checker->cur_mod_check.function_type_tables,
                         checker->cur_mod_check.global_type_table, func_name,
                         scope_idx, name);
}

// TODO: Might be redundant
static ModulePath module_path_resolve(TypeChecker *checker,
                                      const ModulePath *path) {
  size_t modules_len = array_len(checker->cur_mod_check.imported_modules);
  for (size_t i = 0; i < modules_len; i++) {
    ModulePath imported_path = checker->cur_mod_check.imported_modules[i];
    size_t path_len = array_len(imported_path.path);
    Ident last_path_segment = imported_path.path[path_len - 1];
    if (strv_eq(path->path[0], last_path_segment)) {
      ModulePath new_path =
          mod_path_copy(&imported_path, &checker->checker_arena_allocator);
      for (size_t i = 1; i < array_len(path->path); i++) {
        array_add(new_path.path, path->path[i]);
      }
      return new_path;
    }
  }
  return *path;
}

static CheckResult check_stmt(TypeChecker *checker, Statement *stmt, Type *type,
                              CheckerContext context);

static Type check_expr(TypeChecker *checker, Expression *expr,
                       CheckerContext context);

/*
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
              Argument *args = overloaded_func_expr.desc.args;
              for (size_t i = 0; i < array_len(args); i++) {
                if (array_len(call_arg_types) != array_len(args) ||
                    !(i < array_len(call_arg_types) &&
                      type_eq(&call_arg_types[i],
                              &args[i].var.typed_arg.type))) {
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
*/

dyn_string_t func_desc_format(const FuncDescriptor *func_desc);

static char *arguments_str(size_t amount) {
  if (amount == 1) {
    return "argument";
  } else {
    return "arguments";
  }
}

static Type check_call_expr(TypeChecker *checker, ExprCall *expr_call,
                            CheckerContext context, i32 line, i32 lines_amount,
                            i32 begin_pos, i32 end_pos) {
  ModulePath call_function_path =
      module_path_resolve(checker, &expr_call->function);
  TypeTableValue *val =
      checker_type_get(checker, context.func_name, 0, &call_function_path);

  // type_table_dump(checker->cur_type_table);

  dyn_string_t mod_path_call = mod_path_fmt(&expr_call->function);

  ExprFunction expr_function = {0};

  if (val != NULL) {
    /*if (val->expr_variant.type != EXPR_VAR_REG_EXPR) {
      Ident resolved_overload_function =
          resolve_overloaded_function(checker, expr_call);
      expr_call->function.path[0] = resolved_overload_function;
      expr_function =
          type_table_get(checker->cur_type_table, &resolved_overload_function,
                         checker->global_type_table)
              ->expr_variant.var.expr_var_reg_expr.var.expr_function;
    } else*/
    Expression *expr = &val->expr_variant.var.expr_var_reg_expr;
    if (expr->kind == EXPR_FUNCTION) {
      expr_function = expr->var.expr_function;
    } else {
      fprintf(stderr, "Expr is not a function\n");
      exit(1);
    }
  } else {
    log_error("Could not find symbol %s", mod_path_call.string);
    exit(1);
  }

  size_t args_len = array_len(expr_call->args);
  size_t func_args_len = 0;
  if (expr_function.desc.args != NULL) {
    func_args_len = array_len(expr_function.desc.args);
  }

  bool has_varargs =
      func_args_len > 0
          ? expr_function.desc.args[func_args_len - 1].kind == ARG_VARARG
          : false;

  if (!has_varargs && args_len > func_args_len) {
    Expression first_call_arg = expr_call->args[func_args_len];
    Expression last_call_arg = expr_call->args[args_len - 1];
    size_t too_many = args_len - func_args_len;
    ErrorMessage err_msg = {
        .err_msg =
            dyn_string_makef(&checker->checker_arena_allocator,
                             "Too many arguments for function '%s', expected "
                             "%zu %s, received %zu %s",
                             mod_path_call.string, func_args_len,
                             arguments_str(func_args_len), args_len,
                             arguments_str(func_args_len))
                .string,
        .issue_line = last_call_arg.line,
        .issue_pos = first_call_arg.pos,
        .issue_len = last_call_arg.end_pos - first_call_arg.pos,
        .ctx_lines_amount = lines_amount,
        .ctx_first_line = line,
        .issue_ctx_msg =
            dyn_string_makef(&checker->checker_arena_allocator,
                             too_many == 1 ? "Remove the last argument"
                                           : "Remove the last %zu arguments",
                             too_many)
                .string,
    };

    sink_add_err(&checker->sink, err_msg);
  }

  if (args_len < func_args_len) {
    dyn_string_t func_desc_str = func_desc_format(&expr_function.desc);

    Expression last_call_arg = expr_call->args[args_len - 1];
    ErrorMessage err_msg = {
        .err_msg =
            dyn_string_makef(&checker->checker_arena_allocator,
                             "Too few arguments for function '%s', expected "
                             "%zu %s, received %zu %s",
                             mod_path_call.string, func_args_len,
                             arguments_str(func_args_len), args_len,
                             arguments_str(args_len))
                .string,
        .issue_line = last_call_arg.line,
        .issue_pos = last_call_arg.end_pos,
        .issue_len = 1,
        .ctx_lines_amount = lines_amount,
        .ctx_first_line = line,
        .issue_ctx_msg =
            dyn_string_makef(
                &checker->checker_arena_allocator,
                "Add %zu more %s for function '%s%s'", func_args_len - args_len,
                arguments_str(func_args_len - args_len),
                mod_path_fmt(&expr_call->function).string, func_desc_str.string)
                .string,
    };

    func_desc_str.allocator = &HEAP_ALLOCATOR;

    dyn_string_free(&func_desc_str);

    sink_add_err(&checker->sink, err_msg);
  }

  Type *arg_types = array_new(Type, &checker->checker_arena_allocator);
  for (size_t i = 0; i < args_len; i++) {
    i32 expr_line = expr_call->args[i].line;
    i32 expr_begin_pos = expr_call->args[i].pos;
    i32 expr_end_pos = expr_call->args[i].end_pos;

    if (expr_function.desc.args[i].kind == ARG_REGULAR_ARG) {
      checker->hint.hint = &expr_function.desc.args[i].arg_type;
    }

    Type arg_type = check_expr(checker, &expr_call->args[i], context);

    checker->hint.hint = NULL;

    array_add(arg_types, arg_type);

    if (i < func_args_len || has_varargs) {
      if (expr_function.desc.args[i].kind != ARG_VARARG &&
          !type_eq(&arg_type, &expr_function.desc.args[i].arg_type)) {
        dyn_string_t caller_arg_type =
            type_format(&TYPE_FORMATTER_DEFAULT, &arg_type);
        dyn_string_t func_arg_type = type_format(
            &TYPE_FORMATTER_DEFAULT, &expr_function.desc.args[i].arg_type);

        ErrorMessage err_msg = {
            .err_msg = dyn_string_makef(
                           &checker->checker_arena_allocator,
                           "Argument %zu of function '%s' expects type '%s' "
                           "received argument of type '%s'",
                           i, mod_path_call.string, func_arg_type.string,
                           caller_arg_type.string)
                           .string,
            .issue_line = expr_line,
            .issue_pos = expr_begin_pos,
            .issue_len = expr_end_pos - expr_begin_pos,
            .ctx_lines_amount = lines_amount,
            .ctx_first_line = line,
            .issue_ctx_msg = dyn_string_makef(&checker->checker_arena_allocator,
                                              "This needs to be of type '%s'",
                                              func_arg_type.string)
                                 .string,
        };

        sink_add_err(&checker->sink, err_msg);

        dyn_string_free(&caller_arg_type);
        dyn_string_free(&func_arg_type);
      }
    }
  }

  dyn_string_free(&mod_path_call);

  // TODO: Reimplement generic functions
  /*
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
  */

  if (expr_function.desc.has_ret_type) {
    return expr_function.desc.ret_type;
  }
  return BUILTIN_TYPES[BUILTIN_TYPE_UNIT];
}

static Type check_block_expr(TypeChecker *checker,
                             const ExprBlock *expr_block) {
  if (expr_block->statements != NULL) {
    size_t len = array_len(expr_block->statements);
    Type last_type = BUILTIN_TYPES[BUILTIN_TYPE_UNIT];
    for (size_t i = 0; i < len; i++) {
      Statement stmt = expr_block->statements[i];
      CheckResult res = check_stmt(checker, &stmt, &last_type, EMPTY_CONTEXT);
      // TODO: Handle result
    }
    return last_type;
  }
  return BUILTIN_TYPES[BUILTIN_TYPE_UNIT];
}

// TODO: Create a type table ident -> type
static Type check_expr(TypeChecker *checker, Expression *expr,
                       CheckerContext context) {
  switch (expr->kind) {
  case EXPR_ARRAY_INIT: {
    Type *expected_item_type = expr->var.expr_array_init.type.type;
    checker->hint.hint = expected_item_type;
    size_t declared_items_len = array_len(expr->var.expr_array_init.items);
    for (size_t i = 0; i < declared_items_len; i++) {
      Expression *init_value = &expr->var.expr_array_init.items[i];
      Type item_type = check_expr(checker, init_value, context);
      if (!type_eq(&item_type, expected_item_type)) {
        sink_add_err(
            &checker->sink,
            ERR_MSG({
                .err_msg =
                    dyn_string_makef(
                        &checker->checker_arena_allocator,
                        "Array of type '%s' cannot be initialized with "
                        "value of type '%s'",
                        type_format(&TYPE_FORMATTER_DEFAULT, expected_item_type)
                            .string,
                        type_format(&TYPE_FORMATTER_DEFAULT, &item_type).string)
                        .string,
                .issue_line = init_value->line,
                .issue_pos = init_value->pos,
                .issue_len = init_value->end_pos - init_value->pos,
                .ctx_lines_amount = 1,
                .ctx_first_line = init_value->line,
                .issue_ctx_msg =
                    dyn_string_makef(
                        &checker->checker_arena_allocator,
                        "Value needs to be of type '%s'",
                        type_format(&TYPE_FORMATTER_DEFAULT, expected_item_type)
                            .string)
                        .string,
            }));
      }
    }
    checker->hint.hint = NULL;
    return (Type){.kind = TYPE_ARRAY,
                  .var = {.type_array = expr->var.expr_array_init.type}};
  } break;
  case EXPR_ARRAY_ACCESS: {
    ExprArrayAccess *arr_access_expr = &expr->var.expr_array_access;
    Type array_ty = check_expr(checker, arr_access_expr->array_expr, context);

    bool valid_arr_expr = true;
    if (array_ty.kind != TYPE_ARRAY) {
      ErrorMessage err_msg = {
          .err_msg = "Tried indexing value that is not an array",
          .ctx_first_line = arr_access_expr->array_expr->line,
          .issue_line = arr_access_expr->bracket_line,
          .issue_pos = arr_access_expr->bracket_begin_pos,
          .ctx_lines_amount = arr_access_expr->index_expr->line -
                              arr_access_expr->array_expr->line + 1,
          .issue_len = 1,
      };
      if (checker->hint.hint != NULL &&
          type_eq(checker->hint.hint, &array_ty)) {
        err_msg.issue_ctx_msg = "Try removing the indexing operation, it will "
                                "result in the expected type";
      }
      sink_add_err(&checker->sink, err_msg);
      valid_arr_expr = false;
    }

    Type index_ty = check_expr(checker, arr_access_expr->index_expr, context);
    if (!type_is_integer(&index_ty)) {
      sink_add_err(
          &checker->sink,
          ERR_MSG({
              .err_msg =
                  dyn_string_makef(
                      &checker->checker_arena_allocator,
                      "Arrays can only be indexed with integers, tried "
                      "indexing with type '%s'",
                      type_format(&TYPE_FORMATTER_DEFAULT, &index_ty).string)
                      .string,
              .issue_line = arr_access_expr->index_expr->line,
              .issue_pos = arr_access_expr->index_expr->pos,
              .ctx_lines_amount = arr_access_expr->index_expr->lines_amount,
              .ctx_first_line = arr_access_expr->index_expr->line,
              .issue_len = 1,
              .issue_ctx_msg = "Replace the index with an integer value",
          }));
    }

    if (!valid_arr_expr) {
      return array_ty;
    }
    return *array_ty.var.type_array.type;
  } break;
  case EXPR_IF: {
    ExprIf expr_if = expr->var.expr_if;
    Type cond_ty = check_expr(checker, expr_if.condition, context);
    if (!type_eq(&cond_ty, &BUILTIN_TYPES[BUILTIN_TYPE_I32]) &&
        !type_eq(&cond_ty, &BUILTIN_TYPES[BUILTIN_TYPE_BOOL])) {
      fprintf(
          stderr,
          "Type error: Expected integer/boolean as condition, received: %s\n",
          type_format(&TYPE_FORMATTER_DEFAULT, &cond_ty).string);
      exit(1);
    }
    return check_block_expr(checker, &expr_if.block);
  } break;
  case EXPR_FUNCTION: {
    // TODO: implement function types
    ExprFunction expr_function = expr->var.expr_function;

    if (context.func_name == NULL) {
      panic("Inline functions not yet supported");
    }

    TypeTables tables = array_new(TypeTable, &checker->checker_arena_allocator);

    TypeTable function_table = {0};
    type_table_init(&function_table, &checker->checker_arena_allocator);

    // Add func args to typetable
    for (size_t i = 0; i < array_len(expr_function.desc.args); i++) {
      Type type = expr_function.desc.args[i].arg_type;
      ModulePath arg_path = {.path = array_new(Ident, &HEAP_ALLOCATOR)};
      array_add(arg_path.path, expr_function.desc.args[i].arg_name);
      log_debug("Argument module path: %s", mod_path_fmt(&arg_path).string);
      type_table_add(
          &function_table, &arg_path,
          (ExpressionVariant){.kind = EXPR_VAR_REG_EXPR,
                              .var = {.expr_var_reg_expr = UNIT_EXPR}},
          (OptionalType){.type = type, .present = true});
    }

    array_add(tables, function_table);

    hashmap_insert(&checker->cur_mod_check.function_type_tables,
                   &context.func_name, &tables);

    CheckerContext new_context = {.cur_func_desc =
                                      &expr->var.expr_function.desc};

    for (size_t i = 0; i < array_len(expr_function.block->statements); i++) {
      Type t;
      CheckResult res = check_stmt(checker, &expr_function.block->statements[i],
                                   &t, new_context);
      // TODO: Handle
    }
    return BUILTIN_TYPES[BUILTIN_TYPE_UNIT];
  } break;
  case EXPR_BLOCK: {
    return check_block_expr(checker, &expr->var.expr_block);
  } break;
  case EXPR_CALL: {
    return check_call_expr(checker, &expr->var.expr_call, context, expr->line,
                           expr->lines_amount, expr->pos, expr->end_pos);
  } break;
  case EXPR_CAST: {
    Type expr_type = check_expr(checker, expr->var.expr_cast.expr, context);
    Type cast_type = expr->var.expr_cast.type;

    bool str_to_int =
        type_eq(&expr_type, &BUILTIN_TYPES[BUILTIN_TYPE_STRING]) &&
        type_eq(&cast_type, &BUILTIN_TYPES[BUILTIN_TYPE_I32]);

    bool int_to_str = type_eq(&expr_type, &BUILTIN_TYPES[BUILTIN_TYPE_I32]) &&
                      type_eq(&cast_type, &BUILTIN_TYPES[BUILTIN_TYPE_STRING]);

    bool str_to_arr =
        type_eq(&expr_type, &BUILTIN_TYPES[BUILTIN_TYPE_STRING]) &&
        cast_type.kind == TYPE_ARRAY &&
        type_eq(cast_type.var.type_array.type,
                &BUILTIN_TYPES[BUILTIN_TYPE_I32]);

    bool arr_to_str = expr_type.kind == TYPE_ARRAY &&
                      type_eq(&cast_type, &BUILTIN_TYPES[BUILTIN_TYPE_I32]);

    if (type_eq(&expr_type, &cast_type)) {
      return expr->var.expr_cast.type;
    } else if (str_to_int || int_to_str || str_to_arr || arr_to_str) {
      return expr->var.expr_cast.type;
    } else {
      fprintf(stderr, "Cannot cast expr to this type\n");
    }
  } break;
  case EXPR_STRING_LIT: {
    return BUILTIN_TYPES[BUILTIN_TYPE_STRING];
  } break;
  case EXPR_INTEGER_LIT: {
    if (checker->hint.hint != NULL) {
      if (type_is_integer(checker->hint.hint)) {
        return *checker->hint.hint;
      }
    }
    return BUILTIN_TYPES[BUILTIN_TYPE_I32];
  } break;
  case EXPR_BOOLEAN_LIT: {
    return BUILTIN_TYPES[BUILTIN_TYPE_BOOL];
  } break;
  case EXPR_IDENT: {
    TypeTableValue *val = checker_type_get(checker, context.func_name, 0,
                                           &expr->var.expr_ident.ident);
    if (val != NULL) {
      if (val->opt_type.present) {
        return val->opt_type.type;
      } else if (val->expr_variant.kind == EXPR_VAR_REG_EXPR) {
        return check_expr(checker, &val->expr_variant.var.expr_var_reg_expr,
                          context);
      } else {
        fprintf(stderr, "Could not find expression with symbol: %s",
                mod_path_fmt(&expr->var.expr_ident.ident).string);
        exit(1);
      }
    }

    log_error("Failed to get type for ident '%s'",
              dyn_string_temp_copy_and_free(
                  mod_path_fmt(&expr->var.expr_ident.ident)));
    exit(1);
  } break;
  case EXPR_ADDR_OF: {
    Type origin_type =
        check_expr(checker, expr->var.expr_addr_of.expr, context);
    return (Type){.kind = TYPE_POINTER,
                  .var = {.type_pointer = {.type = heap_clone(&origin_type)}}};
  }
  case EXPR_PTR_DEREF: {
    return *check_expr(checker, expr->var.expr_ptr_deref.expr, context)
                .var.type_pointer.type;
  }
  case EXPR_GENERIC_CALL: {
    // TODO: More advanced checking (does generic definition contain bounds for
    // method call)
    return check_call_expr(checker, &expr->var.expr_generic_call.expr_call,
                           context, expr->line, expr->lines_amount, expr->pos,
                           expr->end_pos);
  }
  case EXPR_UNIT: {
    return BUILTIN_TYPES[BUILTIN_TYPE_UNIT];
  }
  case EXPR_BIN_OP: {
    // TODO: Implement proper type checking
    return BUILTIN_TYPES[BUILTIN_TYPE_I32];
  }
  case EXPR_STRUCT_INIT: {
    ExprStructInit *expr_struct_init = &expr->var.expr_struct_init;
    ModulePath struct_name_mod_path = mod_path_root(
        expr_struct_init->struct_name, &checker->checker_arena_allocator);
    TypeTableValue *value =
        checker_type_get(checker, context.func_name, 0, &struct_name_mod_path);
    if (value != NULL) {
      if (value->expr_variant.kind == EXPR_VAR_TYPE_EXPR) {
        TypeExprStruct ty_expr_struct =
            value->expr_variant.var.expr_var_type_expr.var.type_expr_struct;
        for (size_t i = 0; i < array_len(expr_struct_init->field_inits); i++) {
          LabeledExpr *labeled_expr = &expr_struct_init->field_inits[i];
          Type labeled_expr_type =
              check_expr(checker, &labeled_expr->expr, context);
          for (size_t j = 0; j < array_len(ty_expr_struct.fields); j++) {
            TypedIdentOptValue *field = &ty_expr_struct.fields[j];
            log_debug("Label field: %s, struct field: %s", labeled_expr->field,
                      field->ident);
            if (strv_eq(labeled_expr->field, field->ident)) {
              if (!type_eq(&labeled_expr_type, &field->type)) {
                char *expected_type_buf =
                    type_format(&TYPE_FORMATTER_DEFAULT, &field->type).string;
                char *received_type_buf =
                    type_format(&TYPE_FORMATTER_DEFAULT, &labeled_expr_type)
                        .string;
                fprintf(stderr,
                        "Type Error: Types of struct initializer and struct "
                        "declaration "
                        "don't match. Affected field: %s. Expected type: %s, "
                        "Received type: %s\n",
                        field->ident, expected_type_buf, received_type_buf);
                exit(1);
              }
              break;
            }
          }
        }
        TypedIdent *fields =
            array_new(TypedIdent, &checker->checker_arena_allocator);
        TypedIdentOptValue *field_opt_val;
        array_foreach(ty_expr_struct.fields, field_opt_val) {
          array_add(fields, (TypedIdent){
                                .ident = field_opt_val->ident,
                                .type = field_opt_val->type,
                            });
        }
        return (Type){.kind = TYPE_STRUCT,
                      .var = {.type_struct = {.fields = fields}}};
      }
    }
    fprintf(stderr, "Cannot find key (type): %s\n",
            expr_struct_init->struct_name);
    exit(1);
  }
  case EXPR_FOR: {
    return BUILTIN_TYPES[BUILTIN_TYPE_UNIT];
  } break;
  case EXPR_STRUCT_ACCESS:
  case EXPR_IT: {
    TODO();
  } break;
  }
}

static TypeStruct
create_struct_from_expr(const TypeExprStruct *ty_expr_struct) {
  TypeStruct type_struct =
      (TypeStruct){.fields = array_new(TypedIdent, &HEAP_ALLOCATOR)};
  for (size_t i = 0; i < array_len(ty_expr_struct->fields); i++) {
    array_add(type_struct.fields, ty_expr_struct->fields[i]);
  }
  return type_struct;
}

static CheckResult check_stmt(TypeChecker *checker, Statement *stmt, Type *type,
                              CheckerContext context) {
  // char print_buf[1024];
  //  parser_stmt_print(print_buf, stmt);
  switch (stmt->kind) {
  case STMT_RETURN: {
    StmtReturn stmt_return = stmt->var.stmt_return;

    if (context.cur_func_desc == NULL) {
      sink_add_err(&checker->sink,
                   ERR_MSG({
                       .err_msg = "Return stmt cannot be outside of a function",
                       .issue_line = stmt->line,
                       .issue_pos = stmt->pos,
                       .issue_len = stmt->len,
                       .ctx_lines_amount = 1,
                       .ctx_first_line = stmt->line,
                       .issue_ctx_msg = "Remove this 'return' statement",
                   }));
      return (CheckResult){0};
    }

    if (stmt_return.has_ret_val) {
      if (!context.cur_func_desc->has_ret_type) {
        sink_add_err(
            &checker->sink,
            ERR_MSG({
                .err_msg =
                    "Return stmt cannot have return value, if the function "
                    "doesn't have return value",
                .issue_line = stmt_return.ret_val.line,
                .issue_pos = stmt_return.ret_val.pos,
                .issue_len =
                    stmt_return.ret_val.end_pos - stmt_return.ret_val.pos,
                .ctx_lines_amount = stmt_return.ret_val.lines_amount,
                .ctx_first_line = stmt->line,
                .issue_ctx_msg = "Remove this expression",
            }));
        return (CheckResult){0};
      } else {
        Type ret_type = check_expr(checker, &stmt_return.ret_val, context);
        if (!type_eq(&context.cur_func_desc->ret_type, &ret_type)) {
          dyn_string_t err_msg = {0};
          dyn_string_t func_ret_type_str = type_format(
              &TYPE_FORMATTER_DEFAULT, &context.cur_func_desc->ret_type);
          dyn_string_init(&err_msg, &HEAP_ALLOCATOR);
          dyn_string_printf(&err_msg,
                            "Return Statement returns expression of type '%s', "
                            "but return type "
                            "of function expects '%s'",
                            dyn_string_temp_copy_and_free(type_format(
                                &TYPE_FORMATTER_DEFAULT, &ret_type)),
                            func_ret_type_str.string);

          dyn_string_t issue_ctx_msg = {0};
          dyn_string_init(&issue_ctx_msg, &HEAP_ALLOCATOR);
          dyn_string_printf(&issue_ctx_msg,
                            "This expression needs to be of type '%s'",
                            func_ret_type_str.string);
          sink_add_err(&checker->sink,
                       ERR_MSG({
                           .err_msg = err_msg.string,
                           .issue_line = stmt_return.ret_val.line,
                           .issue_pos = stmt_return.ret_val.pos,
                           .issue_len = stmt_return.ret_val.end_pos -
                                        stmt_return.ret_val.pos,
                           .ctx_lines_amount = stmt_return.ret_val.lines_amount,
                           .ctx_first_line = stmt->line,
                           .issue_ctx_msg = issue_ctx_msg.string,
                       }));
        }
      }
    } else {
      if (context.cur_func_desc->has_ret_type) {
        fprintf(stderr, "Return stmt needs to have return value, because the "
                        "function has return type\n");
        exit(1);
      }
    }

    return CHECK_RESULT_SUCCESS;
  }
  case STMT_ASSIGN: {
    StmtAssign stmt_assign = stmt->var.stmt_assign;
    Type left_type = check_expr(checker, &stmt_assign.left_expr, context);
    // if (val == NULL || !val->opt_type.present) {
    //   log_error("Cannot assign to non-existing variable %s",
    //             dyn_string_temp_copy_and_free(
    //                 module_path_fmt(&stmt_assign.left_expr.ident)));
    //   exit(1);
    // }

    Type right_type = check_expr(checker, &stmt_assign.right_expr, context);

    if (!type_eq(&left_type, &right_type)) {
      log_error("Cannot assign expr of type %s to expr of type %s",
                type_format(&TYPE_FORMATTER_DEFAULT, &right_type).string,
                type_format(&TYPE_FORMATTER_DEFAULT, &left_type).string);
    }

    return CHECK_RESULT_SUCCESS;
  } break;
  case STMT_DECL: {
    log_debug("Checking decl stmt: %s", stmt->var.stmt_decl.name);
    OptionalType opt_type = stmt->var.stmt_decl.type;

    if (stmt->var.stmt_decl.has_value) {
      if (opt_type.present) {
        checker->hint.hint = &opt_type.type;
      }
      Expression decl_val = stmt->var.stmt_decl.value;
      if (decl_val.kind == EXPR_FUNCTION) {
        context.func_name = stmt->var.stmt_decl.name;
      }
      Type value_type = check_expr(checker, &decl_val, context);
      context.func_name = NULL;

      checker->hint.hint = NULL;

      if (!opt_type.present) {
        opt_type.type = value_type;
        opt_type.present = true;
      }

      ModulePath decl_path = mod_path_root(stmt->var.stmt_decl.name,
                                           &checker->checker_arena_allocator);

      checker_type_add(checker, context.func_name, 0, &decl_path,
                       EXPR_VAR_EXPR(stmt->var.stmt_decl.value), opt_type);

      if (!type_eq(&value_type, &opt_type.type)) {
        char *value_type_buf =
            type_format(&TYPE_FORMATTER_DEFAULT, &value_type).string;
        char *decl_type_buf =
            type_format(&TYPE_FORMATTER_DEFAULT, &opt_type.type).string;

        dyn_string_t err_msg = dyn_string_makef(
            &checker->checker_arena_allocator,
            "Cannot declare variable of type '%s' with value of type '%s'",
            decl_type_buf, value_type_buf);
        dyn_string_t ctx_err_msg = dyn_string_makef(
            &checker->checker_arena_allocator,
            "Expression needs to be of type '%s'", decl_type_buf);

        sink_add_err(&checker->sink,
                     ERR_MSG({
                         .err_msg = err_msg.string,
                         .issue_line = stmt->line,
                         .issue_pos = decl_val.pos,
                         .issue_len = decl_val.end_pos - decl_val.pos,
                         .ctx_first_line = stmt->line,
                         .ctx_lines_amount = 1,
                         .issue_ctx_msg = ctx_err_msg.string,
                     }));
        return (CheckResult){0};
      }
    }

    return CHECK_RESULT_SUCCESS;
  } break;
  case STMT_TYPE_DECL: {
    ModulePath name_mod_path = mod_path_root(stmt->var.stmt_type_decl.name,
                                             &checker->checker_arena_allocator);

    OptionalType opt_type = stmt->var.stmt_type_decl.type;
    TypeExpr type_expr = stmt->var.stmt_type_decl.value;
    if (type_expr.kind == TYPE_EXPR_STRUCT) {
      TypeExprStruct *ty_expr_struct = &type_expr.var.type_expr_struct;
      for (size_t i = 0; i < array_len(ty_expr_struct->fields); i++) {
        TypedIdentOptValue *field = &ty_expr_struct->fields[i];
        if (field->type.kind == TYPE_IDENT &&
            !type_eq(&field->type, &BUILTIN_TYPES[BUILTIN_TYPE_I32]) &&
            !type_eq(&field->type, &BUILTIN_TYPES[BUILTIN_TYPE_STRING])) {
          ModulePath *ty_ident = &field->type.var.type_ident;
          TypeTableValue *actual_type =
              checker_type_get(checker, context.func_name, 0, ty_ident);
          if (actual_type != NULL &&
              actual_type->expr_variant.kind == EXPR_VAR_TYPE_EXPR) {
            TypeExpr resolved_ty_expr =
                actual_type->expr_variant.var.expr_var_type_expr;
            if (resolved_ty_expr.kind == TYPE_EXPR_STRUCT) {
              field->type = (Type){
                  .kind = TYPE_STRUCT,
                  .var.type_struct = create_struct_from_expr(
                      &resolved_ty_expr.var.type_expr_struct),
              };
            }
          }
        }

        if (field->has_value) {
          Type opt_val_type = check_expr(checker, field->value, context);
          if (!type_eq(&opt_val_type, &field->type)) {
            sink_add_err(&checker->sink,
                         ERR_MSG({
                             .err_msg = "Type of struct field and default "
                                        "value do not match",
                         }));
          }
        }
      }
    }

    log_debug("Checking type expr struct, func name: %s, struct name: %s", context.func_name, mod_path_fmt(&name_mod_path).string);

    checker_type_add(checker, context.func_name, 0, &name_mod_path,
                     EXPR_VAR_TYPE(type_expr), opt_type);
    return CHECK_RESULT_SUCCESS;
  } break;
  case STMT_FOREIGN: {
    StmtForeign stmt_foreign = stmt->var.stmt_foreign;
    ExprFunction expr_function = {
        .desc = stmt_foreign.desc,
        .block = NULL,
    };
    Expression expr = {.kind = EXPR_FUNCTION,
                       .var = {.expr_function = expr_function}};
    checker_type_add(checker, context.func_name, 0, &stmt_foreign.name,
                     EXPR_VAR_EXPR(expr), OPT_TYPE_EMPTY);
    return CHECK_RESULT_SUCCESS;
  } break;
  case STMT_EXPR: {
    check_expr(checker, &stmt->var.stmt_expr.expr, context);
    return CHECK_RESULT_SUCCESS;
  } break;
  }
}

static bool checker_check(TypeChecker *checker) {
  if (debug_flags.print_checker_info) {
    log_info("[TYPECHECKER] Start type checking");
  }

  Statement *stmt;
  array_foreach(checker->cur_mod_check.stmts, stmt) {
    Type t;
    check_stmt(checker, stmt, &t, EMPTY_CONTEXT);
  }

  bool errors = array_len(checker->sink.msgs) > 0;

  sink_print_errors(checker->cur_mod_check.lines, checker->cur_module->filename,
                    &checker->sink);

  return !errors;
}

bool module_check(Module *module, TypeChecker *checker, ModuleCheck mod_check) {
  error_sink_reset(&checker->sink);

  bump_reset(&checker->checker_arena);

  checker->cur_module = module;
  checker->cur_mod_check = mod_check;

  bool success = checker_check(checker);

  return success;
}