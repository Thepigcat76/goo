#include "../include/checker.h"
#include "../include/generics.h"
#include "../include/types.h"
#include "lilc/alloc.h"
#include "lilc/array.h"
#include "lilc/eq.h"
#include "lilc/hash.h"
#include <lilc/hashmap.h>
#include <lilc/log.h>
#include <lilc/str.h>
#include <stdio.h>

static const CheckerContext EMPTY_CONTEXT = {0};

static void checker_type_table_push(TypeChecker *checker);

TypeChecker checker_new(Parser *parser) {
  TypeChecker checker = {.stmts = parser->statements,
                         .type_tables = array_new(TypeTable, &HEAP_ALLOCATOR),
                         .generic_functions_table = gft_new(),
                         .imported_modules = parser->imported_modules,
                         .generated_generic_functions =
                             hashmap_new(Ident *, Type, &HEAP_ALLOCATOR,
                                         str_ptrv_hash, str_ptrv_eq, NULL)};
  checker_type_table_push(&checker);
  checker.global_type_table = &checker.type_tables[0];
  checker.cur_type_table = checker.global_type_table;

  return checker;
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

TypeTableValue *type_table_get(TypeTable *table, ModulePath *path,
                               TypeTable *global_table) {
  // if (ident == NULL || *ident == NULL)
  //   return NULL;

  TypeTableValue *res = hashmap_value(&table->type_table, path);

  if (res == NULL && global_table != NULL) {
    return hashmap_value(&global_table->type_table, path);
  }

  return res;
}

static void checker_type_table_push(TypeChecker *checker) {
  array_add(checker->type_tables,
            (TypeTable){.type_table = hashmap_new(
                            ModulePath, TypeTableValue, &HEAP_ALLOCATOR,
                            module_path_ptrv_hash, module_path_ptrv_eq, NULL)});
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

// TODO: Might be redundant
static ModulePath module_path_resolve(TypeChecker *checker,
                                      const ModulePath *path) {
  size_t modules_len = array_len(checker->imported_modules);
  for (size_t i = 0; i < modules_len; i++) {
    ModulePath imported_path = checker->imported_modules[i];
    size_t path_len = array_len(imported_path.path);
    Ident last_path_segment = imported_path.path[path_len - 1];
    if (strv_eq(path->path[0], last_path_segment)) {
      ModulePath new_path = module_path_copy(&imported_path);
      for (size_t i = 1; i < array_len(path->path); i++) {
        array_add(new_path.path, path->path[i]);
      }
      return new_path;
    }
  }
  return *path;
}

static Type check_stmt(TypeChecker *checker, Statement *stmt,
                       CheckerContext context);

static Type check_expr(TypeChecker *checker, Expression *expr);

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

static void type_table_dump(const TypeTable *type_table) {
  hashmap_foreach(
      &type_table->type_table, ModulePath * key, TypeTableValue * val, {
        if (val->opt_type.present) {
          dyn_string_t type_buf =
              type_format(&(TypeFormatter){.debug = true}, &val->opt_type.type);
          printf("Key: %s, Val: %s\n", module_path_fmt(key).string,
                 type_buf.string);
        }
      });
}

static bool is_generic_function(const ExprFunction *func) {
  return func->desc.generics != NULL && array_len(func->desc.generics) != 0;
}

static Type check_call_expr(TypeChecker *checker, ExprCall *expr_call) {
  ModulePath call_function_path =
      module_path_resolve(checker, &expr_call->function);
  TypeTableValue *val = type_table_get(
      checker->cur_type_table, &call_function_path, checker->global_type_table);

  // type_table_dump(checker->cur_type_table);

  dyn_string_t mod_path_call = module_path_fmt(&expr_call->function);

  ExprFunction expr_function;

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
    {
      Expression *expr = &val->expr_variant.var.expr_var_reg_expr;
      if (expr->type == EXPR_FUNCTION) {
        expr_function = expr->var.expr_function;
      } else {
        fprintf(stderr, "Expr is not a function\n");
        exit(1);
      }
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
          ? expr_function.desc.args[func_args_len - 1].type == ARG_VARARG
          : false;

  if (!has_varargs && args_len != func_args_len) {
    log_error("Type error: Expected %zu arguments for function %s, received "
              "%zu arguments",
              func_args_len, mod_path_call.string, args_len);
    exit(1);
  }
  Type *arg_types = array_new(Type, &HEAP_ALLOCATOR);
  for (size_t i = 0; i < args_len; i++) {
    Type arg_type = check_expr(checker, &expr_call->args[i]);
    array_add(arg_types, arg_type);
    bool generic_type = false;
    if (expr_function.desc.args[i].var.typed_arg.type.type == TYPE_IDENT &&
        expr_function.desc.generics != NULL) {
      for (size_t j = 0; j < array_len(expr_function.desc.generics); j++) {
        if (strcmp(expr_function.desc.args[i]
                       .var.typed_arg.type.var.type_ident.path[0],
                   expr_function.desc.generics[j].name) == 0) {
          generic_type = true;
          break;
        }
      }
    }
    if (!(i >= func_args_len && has_varargs)) {
      if (expr_function.desc.args[i].type != ARG_VARARG &&
          !type_eq(&arg_type, &expr_function.desc.args[i].var.typed_arg.type) &&
          !generic_type) {
        type_table_dump(checker->cur_type_table);
        dyn_string_t caller_arg_type =
            type_format(&checker->type_fmt, &arg_type);
        dyn_string_t func_arg_type = type_format(
            &checker->type_fmt, &expr_function.desc.args[i].var.typed_arg.type);
        log_error(
            "Type error: Expected type %s for argument %zu of function %s, "
            "received argument of type %s",
            func_arg_type.string, i, mod_path_call.string,
            caller_arg_type.string);
        dyn_string_free(&caller_arg_type);
        dyn_string_free(&func_arg_type);
        exit(1);
      }
    }
  }

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

static bool type_is_numeric(const Type *type) {
  return type_eq(type, &I32_BUILTIN_TYPE);
}

static Type check_block_expr(TypeChecker *checker,
                             const ExprBlock *expr_block) {
  if (expr_block->statements != NULL) {
    size_t len = array_len(expr_block->statements);
    Type last_type = UNIT_BUILTIN_TYPE;
    for (size_t i = 0; i < len; i++) {
      Statement stmt = expr_block->statements[i];
      last_type = check_stmt(checker, &stmt, EMPTY_CONTEXT);
    }
    return last_type;
  }
  return UNIT_BUILTIN_TYPE;
}

// TODO: Create a type table ident -> type
static Type check_expr(TypeChecker *checker, Expression *expr) {
  switch (expr->type) {
  case EXPR_ARRAY_INIT: {
    Type *expected_item_type = expr->var.expr_array_init.type.type;
    size_t declared_items_len = array_len(expr->var.expr_array_init.items);
    for (size_t i = 0; i < declared_items_len; i++) {
      Type item_type = check_expr(checker, &expr->var.expr_array_init.items[i]);
      if (!type_eq(&item_type, expected_item_type)) {
        log_error(
            "Type error: Expected (%s) and provided (%s) array item types do "
            "not match\n",
            type_format(&TYPE_FORMATTER_DEFAULT, expected_item_type).string,
            type_format(&TYPE_FORMATTER_DEFAULT, &item_type).string);
        exit(1);
      }
    }
    return (Type){.type = TYPE_ARRAY,
                  .var = {.type_array = expr->var.expr_array_init.type}};
  }
  case EXPR_ARRAY_ACCESS: {
    ExprArrayAccess *arr_access_expr = &expr->var.expr_array_access;
    Type array_ty = check_expr(checker, arr_access_expr->array_expr);
    if (array_ty.type != TYPE_ARRAY) {
      fprintf(stderr, "Type error: Only arrays can be indexed, received: %s\n",
              type_format(&TYPE_FORMATTER_DEFAULT, &array_ty).string);
      exit(1);
    }
    Type index_ty = check_expr(checker, arr_access_expr->index_expr);
    if (!type_is_numeric(&index_ty)) {
      fprintf(stderr,
              "Type error: Invalid type for indexing into array. Expected "
              "numeric type, received: %s\n",
              type_format(&TYPE_FORMATTER_DEFAULT, &index_ty).string);
      exit(1);
    }

    return *array_ty.var.type_array.type;
  }
  case EXPR_IF: {
    ExprIf expr_if = expr->var.expr_if;
    Type cond_ty = check_expr(checker, expr_if.condition);
    if (!type_eq(&cond_ty, &I32_BUILTIN_TYPE) &&
        !type_eq(&cond_ty, &BOOL_BUILTIN_TYPE)) {
      fprintf(
          stderr,
          "Type error: Expected integer/boolean as condition, received: %s\n",
          type_format(&TYPE_FORMATTER_DEFAULT, &cond_ty).string);
      exit(1);
    }
    return check_block_expr(checker, &expr_if.block);
  }
  case EXPR_FUNCTION: {
    // TODO: implement function types
    ExprFunction expr_function = expr->var.expr_function;
    checker_type_table_push(checker);
    {
      // Add func args to typetable
      for (size_t i = 0; i < array_len(expr_function.desc.args); i++) {
        Type type = expr_function.desc.args[i].var.typed_arg.type;
        ModulePath arg_path = {.path = array_new(Ident, &HEAP_ALLOCATOR)};
        array_add(arg_path.path,
                  expr_function.desc.args[i].var.typed_arg.ident);
        log_debug("Argument module path: %s",
                  module_path_fmt(&arg_path).string);
        type_table_add(
            checker->cur_type_table, &arg_path,
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

      CheckerContext context = {.cur_func_desc = &expr->var.expr_function.desc};

      for (size_t i = 0; i < array_len(expr_function.block->statements); i++) {
        check_stmt(checker, &expr_function.block->statements[i], context);
      }
    }
    checker_type_table_pop(checker);
    return UNIT_BUILTIN_TYPE;
  }
  case EXPR_BLOCK: {
    return check_block_expr(checker, &expr->var.expr_block);
  }
  case EXPR_CALL: {
    return check_call_expr(checker, &expr->var.expr_call);
  }
  case EXPR_CAST: {
    Type expr_type = check_expr(checker, expr->var.expr_cast.expr);
    Type cast_type = expr->var.expr_cast.type;

    bool str_to_int = type_eq(&expr_type, &STRING_BUILTIN_TYPE) &&
                      type_eq(&cast_type, &I32_BUILTIN_TYPE);

    bool int_to_str = type_eq(&expr_type, &I32_BUILTIN_TYPE) &&
                      type_eq(&cast_type, &STRING_BUILTIN_TYPE);

    bool str_to_arr = type_eq(&expr_type, &STRING_BUILTIN_TYPE) &&
                      cast_type.type == TYPE_ARRAY &&
                      type_eq(cast_type.var.type_array.type, &I32_BUILTIN_TYPE);

    bool arr_to_str = expr_type.type == TYPE_ARRAY &&
                      type_eq(&cast_type, &STRING_BUILTIN_TYPE);

    bool generic_type = is_type_generic(checker, &expr_type);

    if (type_eq(&expr_type, &cast_type)) {
      goto return_type;
    } else if (str_to_int || int_to_str || str_to_arr || arr_to_str ||
               generic_type) {
      goto return_type;
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
    return I32_BUILTIN_TYPE;
  }
  case EXPR_BOOLEAN_LIT: {
    return BOOL_BUILTIN_TYPE;
  }
  case EXPR_IDENT: {
    TypeTableValue *val =
        type_table_get(checker->cur_type_table, &expr->var.expr_ident.ident,
                       checker->global_type_table);
    log_debug("Looking up val by name: %s",
              module_path_fmt(&expr->var.expr_ident.ident).string);
    if (val != NULL) {
      if (val->opt_type.present) {
        return val->opt_type.type;
      } else if (val->expr_variant.type == EXPR_VAR_REG_EXPR) {
        return check_expr(checker, &val->expr_variant.var.expr_var_reg_expr);
      } else {
        fprintf(stderr, "Could not find expression with symbol: %s",
                module_path_fmt(&expr->var.expr_ident.ident).string);
        exit(1);
      }
    }
  }
  case EXPR_ADDR_OF: {
    Type origin_type = check_expr(checker, expr->var.expr_addr_of.expr);
    return (Type){.type = TYPE_POINTER,
                  .var = {.type_pointer = {.type = heap_clone(&origin_type)}}};
  }
  case EXPR_PTR_DEREF: {
    return *check_expr(checker, expr->var.expr_ptr_deref.expr)
                .var.type_pointer.type;
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
    return I32_BUILTIN_TYPE;
  }
  case EXPR_STRUCT_INIT: {
    ExprStructInit *expr_struct_init = &expr->var.expr_struct_init;
    TypeTableValue *value =
        type_table_get(checker->cur_type_table, NULL,//&expr_struct_init->struct_name,
                       checker->global_type_table);
    if (value != NULL) {
      if (value->expr_variant.type == EXPR_VAR_TYPE_EXPR) {
        TypeExprStruct ty_expr_struct =
            value->expr_variant.var.expr_var_type_expr.var.type_expr_struct;
        for (size_t i = 0; i < array_len(expr_struct_init->field_inits); i++) {
          LabeledExpr *labeled_expr = &expr_struct_init->field_inits[i];
          Type labeled_expr_type = check_expr(checker, &labeled_expr->expr);
          for (size_t j = 0; j < array_len(ty_expr_struct.fields); j++) {
            TypedIdent *field = &ty_expr_struct.fields[j];
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
        return (Type){
            .type = TYPE_STRUCT,
            .var = {.type_struct = {.fields = ty_expr_struct.fields}}};
      }
    }
    fprintf(stderr, "Cannot find key (type): %s\n",
            expr_struct_init->struct_name);
    exit(1);
  }
  case EXPR_STRUCT_ACCESS:
    return UNIT_BUILTIN_TYPE;
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

static Type check_stmt(TypeChecker *checker, Statement *stmt,
                       CheckerContext context) {
  // char print_buf[1024];
  //  parser_stmt_print(print_buf, stmt);
  switch (stmt->type) {
  case STMT_RETURN: {
    StmtReturn stmt_return = stmt->var.stmt_return;

    if (context.cur_func_desc == NULL) {
      fprintf(stderr, "Cannot use return outside of function\n");
      exit(1);
    }

    if (stmt_return.has_ret_val) {
      if (!context.cur_func_desc->has_ret_type) {
        fprintf(stderr, "Return stmt cannot have return value, if the function "
                        "doesn't have return value\n");
        exit(1);
      }
    } else {
      if (context.cur_func_desc->has_ret_type) {
        fprintf(stderr, "Return stmt needs to have return value, because the "
                        "function has return type\n");
        exit(1);
      }
    }

    return UNIT_BUILTIN_TYPE;
  }
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
          char *value_type_buf =
              type_format(&TYPE_FORMATTER_DEFAULT, &value_type).string;
          char *decl_type_buf =
              type_format(&TYPE_FORMATTER_DEFAULT, &opt_type.type).string;
          fprintf(stderr,
                  "Type error: Type of declaration (%s) and value (%s) do not "
                  "match, decl "
                  "name: %s\n",
                  decl_type_buf, value_type_buf, stmt->var.stmt_decl.name);
          exit(1);
        }
      } else {
        opt_type.type = value_type;
        opt_type.present = true;
      }
    }

    if (stmt->var.stmt_decl.value.type == EXPR_VAR_REG_EXPR) {
      ModulePath decl_path = module_path_root(stmt->var.stmt_decl.name);
      type_table_add(
          checker->cur_type_table, &decl_path,
          EXPR_VAR_EXPR(stmt->var.stmt_decl.value.var.expr_var_reg_expr),
          opt_type);
    } else {
      TypeExpr type_expr = stmt->var.stmt_decl.value.var.expr_var_type_expr;
      if (type_expr.type == TYPE_EXPR_STRUCT) {
        TypeExprStruct *ty_expr_struct = &type_expr.var.type_expr_struct;
        for (size_t i = 0; i < array_len(ty_expr_struct->fields); i++) {
          TypedIdent *field = &ty_expr_struct->fields[i];
          if (field->type.type == TYPE_IDENT &&
              !type_eq(&field->type, &I32_BUILTIN_TYPE) &&
              !type_eq(&field->type, &STRING_BUILTIN_TYPE)) {
            ModulePath *ty_ident = &field->type.var.type_ident;
            TypeTableValue *actual_type = type_table_get(
                checker->cur_type_table, ty_ident, checker->global_type_table);
            if (actual_type != NULL) {
              if (actual_type->expr_variant.type == EXPR_VAR_TYPE_EXPR) {
                TypeExpr resolved_ty_expr =
                    actual_type->expr_variant.var.expr_var_type_expr;
                if (resolved_ty_expr.type == TYPE_EXPR_STRUCT) {
                  field->type = (Type){
                      .type = TYPE_STRUCT,
                      .var = {.type_struct = create_struct_from_expr(
                                  &resolved_ty_expr.var.type_expr_struct)}};
                }
              }
            }
          }
        }
      }
      type_table_add(checker->cur_type_table, NULL,//&stmt->var.stmt_decl.name,
                     EXPR_VAR_TYPE(type_expr), opt_type);
    }

    return UNIT_BUILTIN_TYPE;
  }
  case STMT_FOREIGN: {
    StmtForeign stmt_foreign = stmt->var.stmt_foreign;
    ExprFunction expr_function = {
        .desc = stmt_foreign.desc, .native_function = NULL, .block = NULL};
    Expression expr = {.type = EXPR_FUNCTION,
                       .var = {.expr_function = expr_function}};
    type_table_add(checker->global_type_table, &stmt_foreign.name,
                   EXPR_VAR_EXPR(expr), OPT_TYPE_EMPTY);
  }
  case STMT_EXPR: {
    return check_expr(checker, &stmt->var.stmt_expr.expr);
  }
  }
}

void checker_check(TypeChecker *checker) {
  if (debug_flags.print_checker_info) {
    log_info("[TYPECHECKER] Start type checking");
  }

  for (size_t i = 0; i < array_len(checker->stmts); i++) {
    check_stmt(checker, &checker->stmts[i], EMPTY_CONTEXT);
  }
}