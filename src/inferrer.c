#include "../include/inferrer.h"

static void infer_expr(Expression *expr) {
  switch (expr->kind) {
  case EXPR_CAST: {} break;
  case EXPR_ARRAY_INIT: {} break;
  case EXPR_ARRAY_ACCESS: {} break;
  case EXPR_FUNCTION: {} break;
  case EXPR_BLOCK: {} break;
  case EXPR_CALL: {} break;
  case EXPR_GENERIC_CALL: {} break;
  case EXPR_STRING_LIT: {} break;
  case EXPR_INTEGER_LIT: {} break;
  case EXPR_BOOLEAN_LIT: {} break;
  case EXPR_IDENT: {} break;
  case EXPR_UNIT: {} break;
  case EXPR_BIN_OP: {} break;
  case EXPR_STRUCT_INIT: {} break;
  case EXPR_STRUCT_ACCESS: {} break;
  case EXPR_PTR_DEREF: {} break;
  case EXPR_ADDR_OF: {} break;
  case EXPR_IF: {} break;
  case EXPR_FOR: {} break;
  case EXPR_IT: {} break;
  }
}

static void infer_stmt(Statement *stmt) {
  switch (stmt->kind) {
  case STMT_EXPR: {
    infer_expr(&stmt->var.stmt_expr.expr);
  } break;
  case STMT_DECL: {
  } break;
  case STMT_RETURN: {
  } break;
  case STMT_FOREIGN: {
  } break;
  case STMT_ASSIGN: {
  } break;
  }
}

void inferrer_infer(TypeInferrer *inferrer) {
  for (size_t i = 0; i < array_len(inferrer->stmts); i++) {
    infer_stmt(inferrer->stmts + i);  
  }
}