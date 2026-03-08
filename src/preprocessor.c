#include "../include/preprocess.h"
#include "lilc/log.h"
#include <lilc/alloc.h>
#include <lilc/array.h>
#include <lilc/eq.h>
#include <lilc/hash.h>
#include <lilc/hashmap.h>
#include <stdio.h>

typedef struct {
  char *variable_name;
} PreprocessorExprContext;

static Expression println_execute(Expression *args) {
  if (array_len(args) != 1) {
    log_error("Expected only a single arg for println, received: %zu",
              array_len(args));
    exit(1);
  }

  if (args[0].type != EXPR_STRING_LIT) {
    log_error("Expected a string as the arg for println, received expression "
              "of type %d",
              args[0].type);
    exit(1);
  }

  puts(args[0].var.expr_string_literal.string);
  return (Expression){.type = EXPR_UNIT};
}

PreProcessor preprocessor_new(Statement *stmts, PpDirective *pp_dirs) {
  PreProcessor pp = {
      .stmts = stmts,
      .pp_dirs = pp_dirs,
      .pp_dir_cond_line = -1,
      .comptime_functions =
          hashmap_new(Ident *, ComptimeBuiltinFunction, &HEAP_ALLOCATOR,
                      str_ptrv_hash, str_ptrv_eq, NULL),
      .valid_lines = hashmap_new(size_t, size_t, &HEAP_ALLOCATOR, size_tv_hash,
                                 size_tv_eq, NULL),
      .comptime_constants = hashmap_new(Ident *, Expression, &HEAP_ALLOCATOR,
                                        str_ptrv_hash, str_ptrv_eq, NULL)};
  char *println_name = "println";
  hashmap_insert(
      &pp.comptime_functions, &println_name,
      &(ComptimeBuiltinFunction){.execute = println_execute, .builtin = true});
  return pp;
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
                                     PreprocessorExprContext context);

static void expr_block_eval_comptime(PreProcessor *preprocessor,
                                     const ExprBlock *expr) {
  for (size_t i = 0; i < array_len(expr->statements); i++) {
    if (expr->statements[i].type == STMT_EXPR) {
      expr_eval_comptime(preprocessor, &expr->statements[i].var.stmt_expr.expr,
                         (PreprocessorExprContext){});
    }
  }
}

static Expression expr_eval_comptime(PreProcessor *preprocessor,
                                     const Expression *expr,
                                     PreprocessorExprContext context) {
  switch (expr->type) {
  case EXPR_BIN_OP: {
    ExprBinOp expr_bin_op = expr->var.expr_bin_op;
    uint32_t a = expr_eval_comptime(preprocessor, expr_bin_op.left,
                                    (PreprocessorExprContext){})
                     .var.expr_integer_literal.integer;
    uint32_t b = expr_eval_comptime(preprocessor, expr_bin_op.right,
                                    (PreprocessorExprContext){})
                     .var.expr_integer_literal.integer;

    return (Expression){
        .type = EXPR_INTEGER_LIT,
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
    hashmap_insert(&preprocessor->comptime_functions, context.variable_name,
                   &(ComptimeBuiltinFunction){.builtin = false,
                                              .expr_function = expr_function});
    break;
  }
  case EXPR_BLOCK: {
    break;
  }
  case EXPR_CALL: {
    ExprCall expr_call = expr->var.expr_call;
    ComptimeBuiltinFunction *func =
        hashmap_value(&preprocessor->comptime_functions, &expr_call.function);
    if (func != NULL && func->builtin) {
      func->execute(expr_call.args);
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
      int min = expr_eval_comptime(preprocessor, range.min,
                                   (PreprocessorExprContext){})
                    .var.expr_integer_literal.integer;
      int max = expr_eval_comptime(preprocessor, range.max,
                                   (PreprocessorExprContext){})
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
  log_error("Failed to evaluate comptime expression %d, nyi", expr->type);
  exit(1);
}

static void pp_dir_process(PreProcessor *preprocessor, PpDirective *pp_dir) {
  switch (pp_dir->type) {
  case PP_DIR_IF: {
    PpDirIf pp_dir_if = pp_dir->var.pp_dir_if;
    Expression cond_expr = expr_eval_comptime(
        preprocessor, &pp_dir_if.condition, (PreprocessorExprContext){});
    bool evaluated_cond_expr = false;
    if (cond_expr.type == EXPR_INTEGER_LIT) {
      evaluated_cond_expr = cond_expr.var.expr_integer_literal.integer;
    } else if (cond_expr.type == EXPR_BOOLEAN_LIT) {
      evaluated_cond_expr = cond_expr.var.expr_boolean_literal.boolean;
    }
    log_debug("[PREPROCESSOR] Evaluated conditional preprocessor directive, "
              "result: %s",
              evaluated_cond_expr ? "true" : "false");

    if (evaluated_cond_expr) {
      size_t last_line = pp_dir->line + pp_dir_if.lines_amount;
      hashmap_insert(&preprocessor->valid_lines, &pp_dir->line, &last_line);
    }
    break;
  }
  case PP_DIR_COMPTIME: {
    PpDirComptime pp_dir_comptime = pp_dir->var.pp_dir_comptime;
    if (pp_dir_comptime.stmt.type == STMT_EXPR) {
      expr_eval_comptime(preprocessor, &pp_dir_comptime.stmt.var.stmt_expr.expr,
                         (PreprocessorExprContext){});
    }
  }
  default: {
    break;
  }
  }
}

static bool stmt_process(PreProcessor *preprocessor, Statement *stmt,
                         Statement *new_stmt);

static void expr_process(PreProcessor *preprocessor, Expression *expr) {
  switch (expr->type) {
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
      expr_process(preprocessor, &expr_call.args[i]);
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
                                    &expr->var.expr_ident.ident);
    if (val != NULL) {
      *expr = *val;
    }
    log_debug("Preprocessor - process expression");
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
    expr_process(preprocessor, expr_if->condition);
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

static bool stmt_process(PreProcessor *preprocessor, Statement *stmt,
                         Statement *new_stmt) {
  // if (stmt.)
  switch (stmt->type) {
  case STMT_DECL: {
    StmtDecl *stmt_decl = &stmt->var.stmt_decl;
    Expression *expr_value = &stmt_decl->value.var.expr_var_reg_expr;
    expr_process(preprocessor, expr_value);

    if (stmt_decl->comptime) {
      log_debug("[PREPROCESSOR] - processing comptime constant %s",
                stmt_decl->name);
      hashmap_insert(&preprocessor->comptime_constants, &stmt_decl->name,
                     expr_value);
    }

    break;
  }
  case STMT_EXPR: {
    expr_process(preprocessor, &stmt->var.stmt_expr.expr);
    break;
  }
  case STMT_RETURN: {
    break;
  }
  case STMT_FOREIGN: {
    break;
  }
  case STMT_ASSIGN: {
    break;
  }
  }
  //*new_stmt = *stmt;
  return true;
}

void preprocessor_process(PreProcessor *preprocessor) {
  if (debug_flags.print_preprocessor_info) {
    log_info("[PREPROCESSOR] Start preprocessing");
  }

  for (size_t i = 0; i < array_len(preprocessor->pp_dirs); i++) {
    pp_dir_process(preprocessor, &preprocessor->pp_dirs[i]);
  }

  for (size_t i = 0; i < array_len(preprocessor->stmts); i++) {
    stmt_process(preprocessor, &preprocessor->stmts[i], NULL);
  }
}
