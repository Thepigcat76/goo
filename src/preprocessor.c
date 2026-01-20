#include "../include/preprocess.h"
#include "lilc/log.h"
#include <lilc/alloc.h>
#include <lilc/array.h>
#include <lilc/eq.h>
#include <lilc/hash.h>

PreProcessor preprocessor_new(Statement *stmts, PpDirective *pp_dirs) {
  return (PreProcessor){
      .stmts = stmts,
      .pp_dirs = pp_dirs,
      .pp_dir_cond_line = -1,
      .valid_lines = hashmap_new(size_t, size_t, &HEAP_ALLOCATOR, size_tv_hash,
                                 size_tv_eq, NULL),
      .comptime_constants = hashmap_new(Ident *, Expression, &HEAP_ALLOCATOR,
                                        str_ptrv_hash, str_ptrv_eq, NULL)};
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

static Expression expr_eval_comptime(const Expression *expr) {
  switch (expr->type) {
  case EXPR_BIN_OP: {
    ExprBinOp expr_bin_op = expr->var.expr_bin_op;
    uint32_t a =
        expr_eval_comptime(expr_bin_op.left).var.expr_integer_literal.integer;
    uint32_t b =
        expr_eval_comptime(expr_bin_op.right).var.expr_integer_literal.integer;

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
    break;
  }
  case EXPR_BLOCK: {
    break;
  }
  case EXPR_CALL: {
    break;
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
    break;
  }
  case EXPR_IT: {
    break;
  }
  }
  log_error("Failed to evaluate comptime expression, nyi");
  exit(1);
}

static void pp_dir_process(PreProcessor *preprocessor, PpDirective *pp_dir) {
  switch (pp_dir->type) {
  case PP_DIR_IF: {
    PpDirIf pp_dir_if = pp_dir->var.pp_dir_if;
    Expression cond_expr = expr_eval_comptime(&pp_dir_if.condition);
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
      log_debug("Preprocessor - process call args");
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
    log_debug("Preprocessor - expr stmt");
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
  log_info("[PREPROCESSOR] Start preprocessing");

  for (size_t i = 0; i < array_len(preprocessor->pp_dirs); i++) {
    pp_dir_process(preprocessor, &preprocessor->pp_dirs[i]);
  }

  for (size_t i = 0; i < array_len(preprocessor->stmts); i++) {
    stmt_process(preprocessor, &preprocessor->stmts[i], NULL);
  }
}
