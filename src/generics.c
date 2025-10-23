#include "../include/checker.h"
#include "../include/types.h"
#include "../vendor/lilc/array.h"
#include "../vendor/lilc/hash.h"
#include "../vendor/lilc/eq.h"
#include <stdio.h>
#include "../vendor/lilc/hashmap.h"

GenericFunction *gft_get(GenericFunctionsTable *table, Ident *name) {
  return hashmap_value(&table->table, name);
}

void gft_add(GenericFunctionsTable *table, Ident *name,
                    GenericFunction func) {
  hashmap_insert(&table->table, name, &func);
}

GenericFunctionsTable gft_new() {
  return (GenericFunctionsTable){
      .table = hashmap_new(Ident *, GenericFunction, &HEAP_ALLOCATOR,
                           str_ptrv_hash, str_ptrv_eq, NULL)};
}

static Type try_transform_generic_type(const Type *type,
                                       Hashmap(Ident *, Type) generics_lookup) {

  //hashmap_foreach(&generics_lookup, Ident * key, Type * val, {
  //  char print_buf[512];
  //  type_print(print_buf, val);
  //  printf("Key: %s, Val: %s\n", *key, print_buf);
  //});
  if (type->type == TYPE_IDENT) {
    Type *resolved_type =
        hashmap_value(&generics_lookup, &type->var.type_ident);
    if (resolved_type != NULL) {
      return *resolved_type;
    }
  }
  return *type;
}

static ExprBlock *transform_generic_block(TypeChecker *checker,
                                          ExprBlock *block,
                                          Hashmap(Ident *, Type)
                                              generics_lookup);

static ExprFunction transform_generic_function(TypeChecker *checker,
                                               ExprFunction *expr_func,
                                               Hashmap(Ident *, Type)
                                                   generics_lookup);

static void transform_generic_expr(TypeChecker *checker, Expression *expr,
                                   Hashmap(Ident *, Type) generics_lookup) {
  switch (expr->type) {
  case EXPR_CAST: {
    ExprCast *expr_cast = &expr->var.expr_cast;
    expr_cast->type =
        try_transform_generic_type(&expr_cast->type, generics_lookup);
    break;
  }
  case EXPR_ARRAY_INIT: {
    ExprArrayInit *expr_array = &expr->var.expr_array;
    *expr_array->type.type =
        try_transform_generic_type(expr_array->type.type, generics_lookup);
    break;
  }
  case EXPR_FUNCTION: {
    ExprFunction *expr_func = &expr->var.expr_function;
    transform_generic_function(checker, expr_func, generics_lookup);
    break;
  }
  case EXPR_BLOCK: {
    ExprBlock *expr_block = &expr->var.expr_block;
    *expr_block =
        *transform_generic_block(checker, expr_block, generics_lookup);
    break;
  }
  case EXPR_STRUCT_ACCESS:
  case EXPR_STRUCT_INIT:
  case EXPR_GENERIC_CALL:
  case EXPR_BIN_OP:
  case EXPR_CALL:
  case EXPR_STRING_LIT:
  case EXPR_INTEGER_LIT:
  case EXPR_IDENT:
  case EXPR_UNIT:
    break;
  }
}

static ExprBlock *transform_generic_block(TypeChecker *checker,
                                          ExprBlock *block,
                                          Hashmap(Ident *, Type)
                                              generics_lookup) {
  array_foreach(block->statements, Statement, stmt, {
    switch (stmt.type) {
    case STMT_DECL: {
      StmtDecl *stmt_decl = &stmt.var.stmt_decl;
      if (stmt_decl->type.present) {
        stmt_decl->type.type =
            try_transform_generic_type(&stmt_decl->type.type, generics_lookup);
      }
      transform_generic_expr(checker, &stmt_decl->value.var.expr_var_reg_expr,
                             generics_lookup);
      break;
    }
    case STMT_EXPR: {
      transform_generic_expr(checker, &stmt.var.stmt_expr.expr,
                             generics_lookup);
      break;
    }
    }
  });
  return block;
}

static ExprFunction transform_generic_function(TypeChecker *checker,
                                               ExprFunction *expr_func,
                                               Hashmap(Ident *, Type)
                                                   generics_lookup) {
  TypedIdent *args = array_new_capacity(
      TypedIdent, array_len(expr_func->desc.args), &HEAP_ALLOCATOR);
  for (size_t i = 0; i < array_len(expr_func->desc.args); i++) {
    array_add(args,
              (TypedIdent){.type = try_transform_generic_type(
                               &expr_func->desc.args[i].type, generics_lookup),
                           .ident = expr_func->desc.args[i].ident});
  }
  ExprFunction func = {
      .desc = {.generics = NULL,
               .args = args,
               .ret_type = try_transform_generic_type(&expr_func->desc.ret_type,
                                                      generics_lookup)},
      .block = expr_func->block};
  return func;
}

// Returns null if type is not a generic
// Otherwise the generic will be returned
static Ident type_generic(const FuncDescriptor *desc, size_t arg_index) {
  Type func_arg_type = desc->args[arg_index].type;
  if (func_arg_type.type == TYPE_IDENT && desc->generics != NULL) {
    for (size_t i = 0; i < array_len(desc->generics); i++) {
      Generic *generic = &desc->generics[i];
      if (strv_eq(func_arg_type.var.type_ident, generic->name)) {
        return generic->name;
      }
    }
  }

  return NULL;
}

void checker_gen_functions(TypeChecker *checker) {
  // Iterate through all functions (with generics)
  hashmap_foreach(
      &checker->generic_functions_table.table, Ident * key,
      GenericFunction * generic_func, {
        TypeTableValue *val =
            type_table_get(checker->global_type_table, key, NULL);
        if (val != NULL) {
          ExprFunction expr_function =
              val->expr_variant.var.expr_var_reg_expr.var.expr_function;
          // Iterate through all callers
          if (generic_func->callers_args != NULL) {
            array_foreach(generic_func->callers_args, CallerArgs, args, {
              Hashmap(Ident *, Type) generics_lookup =
                  hashmap_new(Ident *, Type, &HEAP_ALLOCATOR, str_ptrv_hash,
                              str_ptrv_eq, NULL);

              char *generic_func_name = malloc(512);
              sprintf(generic_func_name, "%s$", *key);
              // iterate through the caller args
              if (args != NULL) {
                for (size_t k = 0; k < array_len(args); k++) {
                  Type arg = args[k];
                  char type_buf[256];
                  type_print(type_buf, &arg);
                  strcat(generic_func_name, type_buf);
                  if (k < array_len(args) - 1) {
                    strcat(generic_func_name, ",");
                  }

                  Ident generic_ident = type_generic(&expr_function.desc, k);
                  if (generic_ident != NULL) {
                    hashmap_insert(&generics_lookup, &generic_ident, &args[k]);
                  } else {
                    fprintf(stderr,
                            "!!Could not find generic ident at index: %zu, "
                            "generics amount: %zu!!\n",
                            k, array_len(expr_function.desc.generics));
                    char print_buf[512];
                    func_desc_print(print_buf, &expr_function.desc);
                    fprintf(stderr, "Func desc: %s\n", print_buf);
                    exit(1);
                  }
                }
              }

              char *generic_func_name_cpy = strdup(generic_func_name);
              if (!hashmap_contains(&checker->generated_generic_functions,
                                    &generic_func_name)) {
                Expression _expr = {
                    .type = EXPR_FUNCTION,
                    .var = {.expr_function = transform_generic_function(
                                checker, &expr_function, generics_lookup)}};
                hashmap_insert(&checker->generated_generic_functions,
                               &generic_func_name_cpy, &_expr);
                type_table_add(checker->global_type_table,
                               &generic_func_name_cpy, EXPR_VAR_EXPR(_expr),
                               (OptionalType){.present = false});
              }

              generic_func->caller_exprs[_arr_foreach_index]->function =
                  generic_func_name_cpy;

              hashmap_free(&generics_lookup);
            });
          }
        } else {
          fprintf(stderr, "UNREACHABLE\n");
          exit(1);
        }
      });
}