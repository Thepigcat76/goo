#include "../../include/ast.h"
#include "lilc/str.h"
#include <lilc/alloc.h>
#include <lilc/array.h>
#include <lilc/dynstr.h>
#include <lilc/log.h>
#include <string.h>

typedef struct {
  size_t stmt_indent;
} Formatter;

static dyn_string_t stmt_format(Formatter *fmt, const Statement *stmt);

static dyn_string_t expr_block_format(Formatter *fmt, const ExprBlock *block) {
  dyn_string_t str = {0};
  dyn_string_init(&str, &HEAP_ALLOCATOR);
  fmt->stmt_indent += 2;

  if (block->statements == NULL) {
    log_warn("Statements of block statements are null, cannot print");
    return str;
  }

  for (size_t i = 0; i < array_len(block->statements); i++) {
    Statement stmt = block->statements[i];
    dyn_string_add_str(&str, stmt_format(fmt, &stmt).string);
    dyn_string_add_str(&str, ",\n");
  }

  dyn_string_t wrapped_string = {0};
  dyn_string_init(&wrapped_string, &HEAP_ALLOCATOR);

  dyn_string_printf(&wrapped_string, "ExprBlock{stmts=[\n%s]}", str.string);

  fmt->stmt_indent -= 2;

  return wrapped_string;
}

static dyn_string_t module_path_format(Formatter *fmt, const ModulePath *path) {
  dyn_string_t str = {0};
  dyn_string_init(&str, &HEAP_ALLOCATOR);

  for (size_t i = 0; i < array_len(path->path); i++) {
    dyn_string_add_str(&str, path->path[i]);
    if (i < array_len(path->path) - 1) {
      dyn_string_add_char(&str, '.');
    }
  }
  return str;
}

static dyn_string_t expr_list_format(Formatter *fmt, const Expression *exprs);

static dyn_string_t expr_format0(Formatter *fmt, const Expression *expr);

static dyn_string_t expr_range_format(Formatter *fmt, const ExprRange *range) {
  dyn_string_t s = {0};
  dyn_string_init(&s, &HEAP_ALLOCATOR);

  dyn_string_printf(&s, "ExprRange{%s, %s}",
                    expr_format0(fmt, range->min).string,
                    expr_format0(fmt, range->max).string);

  return s;
}

static dyn_string_t expr_format0(Formatter *fmt, const Expression *expr) {
  dyn_string_t str = {0};
  dyn_string_init(&str, &HEAP_ALLOCATOR);
  switch (expr->kind) {
  case EXPR_CAST: {
    dyn_string_printf(&str, "ExprCast{type=, expr=%s}",
                      expr_format0(fmt, expr->var.expr_cast.expr).string);
    break;
  }
  case EXPR_ARRAY_INIT: {
    break;
  }
  case EXPR_ARRAY_ACCESS: {
    break;
  }
  case EXPR_FUNCTION: {
    dyn_string_printf(
        &str, "ExprFunction{args=, expr=%s}",
        expr_block_format(fmt, expr->var.expr_function.block).string);
    break;
  }
  case EXPR_BLOCK: {
    dyn_string_add_str(&str,
                       expr_block_format(fmt, &expr->var.expr_block).string);
    break;
  }
  case EXPR_CALL: {
    ExprCall expr_call = expr->var.expr_call;
    dyn_string_printf(&str, "ExprCall{function=%s, args=[%s]}",
                      module_path_format(fmt, &expr_call.function).string,
                      expr_list_format(fmt, expr_call.args).string);
    break;
  }
  case EXPR_GENERIC_CALL: {
    break;
  }
  case EXPR_STRING_LIT: {
    dyn_string_printf(&str, "\"%s\"", expr->var.expr_string_literal.string);
    break;
  }
  case EXPR_INTEGER_LIT: {
    dyn_string_printf(&str, "%d", expr->var.expr_integer_literal.integer);
    break;
  }
  case EXPR_BOOLEAN_LIT: {
    dyn_string_add_str(&str, expr->var.expr_boolean_literal.boolean ? "true"
                                                                    : "false");
    break;
  }
  case EXPR_IDENT: {
    dyn_string_printf(
        &str, "%s",
        module_path_format(fmt, &expr->var.expr_ident.ident).string);
    break;
  }
  case EXPR_UNIT: {
    dyn_string_add_str(&str, "()");
    break;
  }
  case EXPR_BIN_OP: {
    char *op;
    ExprBinOp expr_bin_op = expr->var.expr_bin_op;
    switch (expr_bin_op.op) {
    case BIN_OP_ADD:
      op = "+";
      break;
    case BIN_OP_SUB:
      op = "-";
      break;
    case BIN_OP_MUL:
      op = "*";
      break;
    case BIN_OP_DIV:
      op = "/";
      break;
    case BIN_OP_EQ:
      op = "==";
      break;
    case BIN_OP_LT:
      op = "<";
      break;
    case BIN_OP_GT:
      op = ">";
      break;
    case BIN_OP_LTE:
      op = "<=";
      break;
    case BIN_OP_GTE:
      op = ">=";
      break;
    }

    char *left = expr_format0(fmt, expr_bin_op.left).string;
    char *right = expr_format0(fmt, expr_bin_op.right).string;

    dyn_string_printf(&str, "ExprBinOp{%s %s %s}", left, op, right);
    break;
  }
  case EXPR_STRUCT_INIT: {
    break;
  }
  case EXPR_STRUCT_ACCESS: {
    break;
  }
  case EXPR_PTR_DEREF: {
    char *deref_expr = expr_format0(fmt, expr->var.expr_ptr_deref.expr).string;
    dyn_string_printf(&str, "ExprPtrDeref{%s}", deref_expr);
    break;
  }
  case EXPR_ADDR_OF: {
    dyn_string_printf(&str, "ExprAddrOf");
    break;
  }
  case EXPR_IF: {
    dyn_string_printf(&str, "ExprIf");
    break;
  }
  case EXPR_FOR: {
    ExprFor expr_for = expr->var.expr_for;
    dyn_string_printf(
        &str, "ExprFor{iter_var_name=%s, range=%s}", expr_for.variable_name,
        expr_for.has_range ? expr_range_format(fmt, &expr_for.range).string
                           : "(null)");
    break;
  }
  case EXPR_IT: {
    dyn_string_printf(&str, "ExprIt");
  } break;
  }
  return str;
}

dyn_string_t expr_format(const Expression *expr) {
  Formatter fmt = {0};
  return expr_format0(&fmt, expr);
}

static dyn_string_t expr_list_format(Formatter *fmt, const Expression *exprs) {
  dyn_string_t str = {0};
  dyn_string_init(&str, &HEAP_ALLOCATOR);

  for (size_t i = 0; i < array_len(exprs); i++) {
    dyn_string_add_str(&str, expr_format0(fmt, &exprs[i]).string);
    if (i < array_len(exprs) - 1) {
      dyn_string_add_char(&str, ',');
    }
  }
  return str;
}

static void dyn_string_add_ident(dyn_string_t *str, size_t indent) {
  for (size_t i = 0; i < indent; i++) {
    dyn_string_add_char(str, ' ');
  }
}

static dyn_string_t stmt_format(Formatter *fmt, const Statement *stmt) {
  dyn_string_t str = {0};
  dyn_string_init(&str, &HEAP_ALLOCATOR);
  dyn_string_add_ident(&str, fmt->stmt_indent);
  char indent_buf[str.term_len];
  strcpy(indent_buf, str.string);

  switch (stmt->kind) {
  case STMT_DECL: {
    dyn_string_printf(
        &str, "%sStmtDecl{name=%s, val=%s}", indent_buf,
        stmt->var.stmt_decl.name,
        expr_format0(fmt, &stmt->var.stmt_decl.value.var.expr_var_reg_expr)
            .string);
    break;
  }
  case STMT_EXPR: {
    dyn_string_printf(&str, "%sStmtExpr{expr=%s}", indent_buf,
                      expr_format0(fmt, &stmt->var.stmt_expr.expr).string);
    break;
  }
  case STMT_RETURN: {
    dyn_string_printf(&str, "%sStmtReturn{val=%s}", indent_buf,
                      expr_format0(fmt, &stmt->var.stmt_return.ret_val).string);
    break;
  }
  case STMT_FOREIGN: {
    dyn_string_printf(&str, "%sStmtForeign", indent_buf);
    break;
  }
  case STMT_ASSIGN: {
    dyn_string_printf(
        &str, "%sStmtAssign{left=%s, right=%s}", indent_buf,
        expr_format0(fmt, &stmt->var.stmt_assign.left_expr).string,
        expr_format0(fmt, &stmt->var.stmt_assign.right_expr).string);
    break;
  }
  }
  return str;
}

dyn_string_t ast_format(const Statement *stmts) {
  dyn_string_t string = {0};
  dyn_string_init(&string, &HEAP_ALLOCATOR);
  Formatter fmt = {0};
  for (size_t i = 0; i < array_len(stmts); i++) {
    char *str = stmt_format(&fmt, stmts + i).string;
    dyn_string_add_str(&string, str);
    dyn_string_add_char(&string, '\n');
  }
  return string;
}
