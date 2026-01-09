#include "../include/preprocess.h"
#include "lilc/log.h"

PreProcessor preprocessor_new(Statement *stmts) {
  return (PreProcessor){.stmts = stmts,
                        .comptime_constants =
                            hashmap_new(Ident *, Expression, &HEAP_ALLOCATOR,
                                        str_ptrv_hash, str_ptrv_eq, NULL)};
}

static void stmt_process(PreProcessor *preprocessor, Statement *stmt);

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
      stmt_process(preprocessor, &expr_function->block->statements[i]);
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
    *expr = *val;
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
    break;
  }
  case EXPR_FOR: {
    break;
  }
  case EXPR_IT: {
    break;
  }
  }
}

static void stmt_process(PreProcessor *preprocessor, Statement *stmt) {
  switch (stmt->type) {
  case STMT_DECL: {
    StmtDecl *stmt_decl = &stmt->var.stmt_decl;
    Expression *expr_value = &stmt_decl->value.var.expr_var_reg_expr;
    expr_process(preprocessor, expr_value);
    
    if (stmt_decl->comptime) {
      log_debug("Preprocessor - processing comptime constant");
      hashmap_insert(&preprocessor->comptime_constants, &stmt_decl->name, expr_value);
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
}

void preprocessor_process(PreProcessor *preprocessor) {
  log_info("[PREPROCESSOR] Start preprocessing");

  for (size_t i = 0; i < array_len(preprocessor->stmts); i++) {
    stmt_process(preprocessor, &preprocessor->stmts[i]);
  }
}
