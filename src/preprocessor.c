#include "../include/preprocess.h"
#include "lilc/log.h"
#include <assert.h>
#include <lilc/alloc.h>
#include <lilc/array.h>
#include <lilc/dynstr.h>
#include <lilc/eq.h>
#include <lilc/hash.h>
#include <lilc/hashmap0.h>
#include <lilc/panic.h>
#include <lilc/todo.h>
#include <stdio.h>

typedef enum {
  PROCESS_RES_SUCCESS_REMOVE,
  PROCESS_RES_ERROR,
  PROCESS_RES_SUCCESS,
} ProcessResult;

typedef struct {
  bool comptime;
} ProcessContext;

static ProcessResult stmt_process(PreProcessor *preprocessor, Statement *stmt,
                                  Statement *new_stmt);

typedef struct {
  Ident decl_name;
} ExprProcessContext;

#define EXPR_PROC_CTX(...) (ExprProcessContext) __VA_ARGS__

static void expr_process(PreProcessor *preprocessor, Expression *expr,
                         ExprProcessContext ctx);

static Expression println_execute(Expression *args) {
  if (array_len(args) != 1) {
    log_error("Expected only a single arg for println, received: %zu",
              array_len(args));
    exit(1);
  }

  if (args[0].kind != EXPR_STRING_LIT) {
    log_error("Expected a string as the arg for println, received expression "
              "of kind %d",
              args[0].kind);
    exit(1);
  }

  puts(args[0].var.expr_string_literal.string);
  return (Expression){.kind = EXPR_UNIT};
}

void preprocessor_init(PreProcessor *pp) {
  pp->pp_dir_cond_line = -1;
  hashmap_init(&pp->comptime_functions, &HEAP_ALLOCATOR, Ident *,
               ComptimeBuiltinFunction, str_ptrv_hash, str_ptrv_eq, NULL);
  hashmap_init(&pp->valid_lines, &HEAP_ALLOCATOR, size_t, size_t, size_tv_hash,
               size_tv_eq, NULL);
  hashmap_init(&pp->comptime_constants, &HEAP_ALLOCATOR, Ident *, Expression,
               str_ptrv_hash, str_ptrv_eq, NULL);
  char *println_name = "println";
  hashmap_insert(
      &pp->comptime_functions, &println_name,
      &(ComptimeBuiltinFunction){.execute = println_execute, .builtin = true});
}

void preprocessor_deinit(PreProcessor *pp) {
  hashmap_deinit(&pp->comptime_functions);
  hashmap_deinit(&pp->valid_lines);
  hashmap_deinit(&pp->comptime_constants);
}

static uint32_t apply_lit_bin_op(uint32_t a, uint32_t b, BinOperator op) {
  switch (op) {
  case BIN_OP_ADD:
    return a + b;
  case BIN_OP_SUB:
    return a - b;
  case BIN_OP_MUL:
    return a * b;
  case BIN_OP_DIV:
    return a / b;
  case BIN_OP_EQ:
    return a == b;
  case BIN_OP_LT:
    return a < b;
  case BIN_OP_GT:
    return a > b;
  case BIN_OP_LTE:
    return a <= b;
  case BIN_OP_GTE:
    return a >= b;
  }
}

static Expression expr_eval_comptime(PreProcessor *preprocessor,
                                     const Expression *expr,
                                     ExprProcessContext context);

static void expr_block_eval_comptime(PreProcessor *preprocessor,
                                     const ExprBlock *expr) {
  for (size_t i = 0; i < array_len(expr->statements); i++) {
    if (expr->statements[i].kind == STMT_EXPR) {
      expr_eval_comptime(preprocessor, &expr->statements[i].var.stmt_expr.expr,
                         EXPR_PROC_CTX({0}));
    }
  }
}

static Expression expr_eval_comptime(PreProcessor *preprocessor,
                                     const Expression *expr,
                                     ExprProcessContext context) {
  switch (expr->kind) {
  case EXPR_BIN_OP: {
    ExprBinOp expr_bin_op = expr->var.expr_bin_op;
    u32 a =
        expr_eval_comptime(preprocessor, expr_bin_op.left, EXPR_PROC_CTX({0}))
            .var.expr_integer_literal.integer;
    u32 b =
        expr_eval_comptime(preprocessor, expr_bin_op.right, EXPR_PROC_CTX({0}))
            .var.expr_integer_literal.integer;

    return (Expression){
        .kind = EXPR_INTEGER_LIT,
        .var = {.expr_integer_literal = {
                    .integer = apply_lit_bin_op(a, b, expr_bin_op.op)}}};
  }
  case EXPR_BOOLEAN_LIT:
  case EXPR_INTEGER_LIT:
  case EXPR_STRING_LIT: {
    return *expr;
  }
  case EXPR_CAST: {
    break;
  }
  case EXPR_ARRAY_INIT: {
    break;
  }
  case EXPR_ARRAY_ACCESS: {
    break;
  }
  case EXPR_FUNCTION: {
    ExprFunction expr_function = expr->var.expr_function;
    Statement *block_stmt;
    array_foreach(expr->var.expr_function.block->statements, block_stmt) {
      ProcessResult res = stmt_process(preprocessor, block_stmt, block_stmt);
    }
    log_debug("Comptime function: %s", context.decl_name);
    hashmap_insert(&preprocessor->comptime_functions, &context.decl_name,
                   &(ComptimeBuiltinFunction){.builtin = false,
                                              .expr_function = expr_function});
    return *expr;
  } break;
  case EXPR_BLOCK: {
    break;
  }
  case EXPR_CALL: {
    ExprCall expr_call = expr->var.expr_call;
    ComptimeBuiltinFunction *func = hashmap_value(
        &preprocessor->comptime_functions, &expr_call.function.path[0]);
    if (func != NULL) {
      if (func->builtin) {
        func->execute(expr_call.args);
      } else {
        expr_block_eval_comptime(preprocessor, func->expr_function.block);
      }
    }
    return *expr;
  }
  case EXPR_GENERIC_CALL: {
    break;
  }
  case EXPR_IDENT: {
    break;
  }
  case EXPR_UNIT: {
    break;
  }
  case EXPR_STRUCT_INIT: {
    break;
  }
  case EXPR_STRUCT_ACCESS: {
    break;
  }
  case EXPR_PTR_DEREF: {
    break;
  }
  case EXPR_ADDR_OF: {
    break;
  }
  case EXPR_IF: {
    break;
  }
  case EXPR_FOR: {
    ExprFor expr_for = expr->var.expr_for;
    if (!expr_for.has_range) {
      for (;;) {
        expr_block_eval_comptime(preprocessor, &expr_for.block);
      }
    } else {
      ExprRange range = expr_for.range;
      int min = expr_eval_comptime(preprocessor, range.min, EXPR_PROC_CTX({0}))
                    .var.expr_integer_literal.integer;
      int max = expr_eval_comptime(preprocessor, range.max, EXPR_PROC_CTX({0}))
                    .var.expr_integer_literal.integer;
      for (int i = min; i < max; i++) {
        expr_block_eval_comptime(preprocessor, &expr_for.block);
      }
    }
    return *expr;
  }
  case EXPR_IT: {
    break;
  }
  }
  log_error("Failed to evaluate comptime expression %d, nyi", expr->kind);
  exit(1);
}

static void pp_dir_process(PreProcessor *preprocessor,
                           const PpDirective *pp_dir, bool global) {
  switch (pp_dir->kind) {
  case PP_DIR_IF: {
    PpDirIf pp_dir_if = pp_dir->var.pp_dir_if;
    Expression cond_expr = expr_eval_comptime(
        preprocessor, &pp_dir_if.condition, EXPR_PROC_CTX({0}));
    bool evaluated_cond_expr = false;
    if (cond_expr.kind == EXPR_INTEGER_LIT) {
      evaluated_cond_expr = cond_expr.var.expr_integer_literal.integer;
    } else if (cond_expr.kind == EXPR_BOOLEAN_LIT) {
      evaluated_cond_expr = cond_expr.var.expr_boolean_literal.boolean;
    }
    log_debug("[PREPROCESSOR] Evaluated conditional preprocessor directive, "
              "result: %s",
              evaluated_cond_expr ? "true" : "false");

    if (evaluated_cond_expr) {
      size_t last_line = pp_dir->line + pp_dir_if.lines_amount;
      size_t line = pp_dir->line;
      hashmap_insert(&preprocessor->valid_lines, &line, &last_line);
    }
    break;
  }
  case PP_DIR_COMPTIME: {
    PpDirComptime pp_dir_comptime = pp_dir->var.pp_dir_comptime;
    if (pp_dir_comptime.stmt.kind == STMT_EXPR) {
      expr_eval_comptime(preprocessor, &pp_dir_comptime.stmt.var.stmt_expr.expr,
                         EXPR_PROC_CTX({0}));
    } else if (pp_dir_comptime.stmt.kind == STMT_DECL) {
      Expression *expr = &pp_dir_comptime.stmt.var.stmt_decl.value;
      expr_eval_comptime(
          preprocessor, expr,
          EXPR_PROC_CTX(
              {.decl_name = pp_dir_comptime.stmt.var.stmt_decl.name}));
      if (global) {
        log_debug("Added comptime constant: %s",
                  pp_dir_comptime.stmt.var.stmt_decl.name);
        hashmap_insert(&preprocessor->comptime_constants,
                       &pp_dir_comptime.stmt.var.stmt_decl.name, expr);
      }
    }
  }
  default: {
    break;
  }
  }
}

static ProcessResult stmt_process(PreProcessor *preprocessor, Statement *stmt,
                                  Statement *new_stmt);

static void expr_process(PreProcessor *preprocessor, Expression *expr,
                         ExprProcessContext ctx) {
  switch (expr->kind) {
  case EXPR_CAST: {
    break;
  }
  case EXPR_ARRAY_INIT: {
    break;
  }
  case EXPR_ARRAY_ACCESS: {
    break;
  }
  case EXPR_FUNCTION: {
    ExprFunction *expr_function = &expr->var.expr_function;

    bool comptime_params = false;
    Argument *arg;
    array_foreach(expr_function->desc.args, arg) {
      if (arg->comptime) {
        comptime_params = true;
        break;
      }
    }

    if (comptime_params) {
      if (ctx.decl_name == NULL) {
        panic("Comptime preprocessor directive not supported for anonymous "
              "functions");
      }

      if (preprocessor->comptime_param_functions != NULL)
        array_add(*preprocessor->comptime_param_functions, ctx.decl_name);
    }

    for (size_t i = 0; i < array_len(expr_function->block->statements); i++) {
      stmt_process(preprocessor, &expr_function->block->statements[i], NULL);
    }
    break;
  }
  case EXPR_BLOCK: {
    break;
  }
  case EXPR_CALL: {
    ExprCall expr_call = expr->var.expr_call;
    for (size_t i = 0; i < array_len(expr_call.args); i++) {
      expr_process(preprocessor, &expr_call.args[i], EXPR_PROC_CTX({0}));
    }
    break;
  }
  case EXPR_GENERIC_CALL: {
    break;
  }
  case EXPR_STRING_LIT: {
    break;
  }
  case EXPR_INTEGER_LIT: {
    break;
  }
  case EXPR_BOOLEAN_LIT: {
    break;
  }
  case EXPR_IDENT: {
    Expression *val = hashmap_value(&preprocessor->comptime_constants,
                                    &expr->var.expr_ident.ident.path[0]);
    if (val != NULL) {
      *expr = *val;
    }
    log_debug("Preprocessor - process ident expr %s - found val: %s",
              dyn_string_temp_copy_and_free(expr_format(expr)),
              val != NULL ? "true" : "false");
    break;
  }
  case EXPR_UNIT: {
    break;
  }
  case EXPR_BIN_OP: {
    break;
  }
  case EXPR_STRUCT_INIT: {
    break;
  }
  case EXPR_STRUCT_ACCESS: {
    break;
  }
  case EXPR_PTR_DEREF: {
    break;
  }
  case EXPR_ADDR_OF: {
    break;
  }
  case EXPR_IF: {
    log_debug("[PREPROCESSOR] - Processing if expression");
    ExprIf *expr_if = &expr->var.expr_if;
    expr_process(preprocessor, expr_if->condition, EXPR_PROC_CTX({0}));
    for (size_t i = 0; i < array_len(expr_if->block.statements); i++) {
      stmt_process(preprocessor, &expr_if->block.statements[i], NULL);
    }
    break;
  }
  case EXPR_FOR: {
    ExprFor *expr_for = &expr->var.expr_for;
    for (size_t i = 0; i < array_len(expr_for->block.statements); i++) {
      stmt_process(preprocessor, &expr_for->block.statements[i], NULL);
    }
    break;
  }
  case EXPR_IT: {
    break;
  }
  }
}

// Return true if stmt was sucessfully processed and should be removed
static ProcessResult stmt_process(PreProcessor *preprocessor, Statement *stmt,
                                  Statement *new_stmt) {
  // if (stmt.)
  switch (stmt->kind) {
  case STMT_DECL: {
    StmtDecl *stmt_decl = &stmt->var.stmt_decl;
    Expression *expr_value = &stmt_decl->value;
    expr_process(preprocessor, expr_value,
                 EXPR_PROC_CTX({.decl_name = stmt_decl->name}));

    if (stmt_decl->comptime) {
      log_debug("[PREPROCESSOR] - processing comptime constant %s",
                stmt_decl->name);
      hashmap_insert(&preprocessor->comptime_constants, &stmt_decl->name,
                     expr_value);
    }

    break;
  }
  case STMT_TYPE_DECL: {
  } break;
  case STMT_EXPR: {
    expr_process(preprocessor, &stmt->var.stmt_expr.expr, EXPR_PROC_CTX({0}));
    break;
  }
  case STMT_RETURN: {
    if (stmt->var.stmt_return.has_ret_val) {
      expr_process(preprocessor, &stmt->var.stmt_return.ret_val,
                   EXPR_PROC_CTX({0}));
    }
  } break;
  case STMT_FOREIGN: {
  } break;
  case STMT_ASSIGN: {
    expr_process(preprocessor, &stmt->var.stmt_assign.right_expr,
                 EXPR_PROC_CTX({0}));
  } break;
  }
  //*new_stmt = *stmt;
  return true;
}

void preprocessor_process(PreProcessor *preprocessor) {
  if (debug_flags.print_preprocessor_info) {
    log_info("[PREPROCESSOR] Start preprocessing");
  }

  for (size_t i = 0; i < array_len(preprocessor->pp_dirs); i++) {
    pp_dir_process(preprocessor, &preprocessor->pp_dirs[i], true);
  }

  for (size_t i = 0; i < array_len(preprocessor->stmts); i++) {
    ProcessResult res = stmt_process(preprocessor, &preprocessor->stmts[i], NULL);
  }
}

void module_preprocess(Module *module, PreProcessor *preproc, Statement *stmts,
                       IdentArray *comptime_param_functions,
                       const PpDirective *pp_dirs) {
  preproc->pp_dirs = pp_dirs;
  preproc->stmts = stmts;
  preproc->comptime_param_functions = comptime_param_functions;
  preprocessor_process(preproc);
}
