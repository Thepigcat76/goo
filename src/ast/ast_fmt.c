#include "../../include/ast.h"
#include <lilc/alloc.h>
#include <lilc/array.h>
#include <lilc/dynstr.h>
#include <lilc/log.h>
#include <lilc/str.h>
#include <lilc/todo.h>
#include <string.h>

typedef struct {
  size_t stmt_indent;
  Allocator fmt_allocator;
  Bump fmt_arena;
} AstFormatter;

static void dyn_string_add_ident(dyn_string_t *str, size_t indent) {
  for (size_t i = 0; i < indent; i++) {
    dyn_string_add_char(str, ' ');
  }
}

static void ast_fmt_init(AstFormatter *fmt) {
  fmt->stmt_indent = 0;
  bump_init(&fmt->fmt_arena, 2048);
  bump_allocator_init(&fmt->fmt_allocator, &fmt->fmt_arena);
}

static void ast_fmt_deinit(AstFormatter *fmt) { bump_free(&fmt->fmt_arena); }

static dyn_string_t stmt_format(AstFormatter *fmt, const Statement *stmt);

static dyn_string_t expr_block_format(AstFormatter *fmt,
                                      const ExprBlock *block) {
  dyn_string_t str = {0};
  dyn_string_init(&str, &fmt->fmt_allocator);
  fmt->stmt_indent += 2;

  if (block->statements == NULL) {
    log_warn("Statements of block statements are null, cannot print");
    return str;
  }

  for (size_t i = 0; i < array_len(block->statements); i++) {
    Statement stmt = block->statements[i];
    dyn_string_t stmt_str = stmt_format(fmt, &stmt);
    dyn_string_add_str(&str, stmt_str.string);
    dyn_string_add_str(&str, ",\n");
  }

  dyn_string_t wrapped_string = {0};
  dyn_string_init(&wrapped_string, &fmt->fmt_allocator);

  dyn_string_printf(&wrapped_string, "ExprBlock{stmts=[\n%s", str.string);

  fmt->stmt_indent -= 2;

  dyn_string_add_ident(&wrapped_string, fmt->stmt_indent);
  dyn_string_add_str(&wrapped_string, "]}");

  return wrapped_string;
}

static dyn_string_t module_path_format(AstFormatter *fmt,
                                       const ModulePath *path) {
  dyn_string_t str = {0};
  dyn_string_init(&str, &fmt->fmt_allocator);

  for (size_t i = 0; i < array_len(path->path); i++) {
    dyn_string_add_str(&str, path->path[i]);
    if (i < array_len(path->path) - 1) {
      dyn_string_add_char(&str, '.');
    }
  }
  return str;
}

static dyn_string_t expr_list_format(AstFormatter *fmt,
                                     const Expression *exprs);

static dyn_string_t expr_format0(AstFormatter *fmt, const Expression *expr);

static dyn_string_t expr_range_format(AstFormatter *fmt,
                                      const ExprRange *range) {
  dyn_string_t s = {0};
  dyn_string_init(&s, &fmt->fmt_allocator);

  dyn_string_t l = expr_format0(fmt, range->min);
  dyn_string_t r = expr_format0(fmt, range->max);

  dyn_string_printf(&s, "ExprRange{%s, %s}", l.string, r.string);

  return s;
}

static dyn_string_t func_args_format(AstFormatter *fmt, Argument *args) {
  dyn_string_t str = {0};
  dyn_string_init(&str, &fmt->fmt_allocator);

  Argument *arg;
  array_foreach(args, arg) {
    if (arg->kind == ARG_TYPED_ARG) {
      dyn_string_add_str(&str,
                         str_fmt_temp("%s: %s", arg->var.typed_arg.ident,
                                      type_format(&TYPE_FORMATTER_DEFAULT,
                                                  &arg->var.typed_arg.type)
                                          .string));
    } else if (arg->kind == ARG_VARARG) {
      dyn_string_add_str(&str, str_fmt_temp("%s: ...", arg->var.vararg));
    }

    if (_arr_foreach_idx < array_len(args) - 1) {
      dyn_string_add_str(&str, ", ");
    }
  }

  return str;
}

static dyn_string_t func_desc_format0(AstFormatter *fmt,
                                      const FuncDescriptor *func_desc) {
  dyn_string_t str = {0};
  dyn_string_init(&str, &fmt->fmt_allocator);

  dyn_string_add_char(&str, '(');

  dyn_string_t args_str = func_args_format(fmt, func_desc->args);

  dyn_string_add_str(&str, args_str.string);

  dyn_string_free(&args_str);

  dyn_string_add_char(&str, ')');

  if (func_desc->has_ret_type) {
    dyn_string_add_str(
        &str,
        str_fmt_temp(
            " -> %s",
            type_format(&TYPE_FORMATTER_DEFAULT, &func_desc->ret_type).string));
  }

  return str;
}

dyn_string_t func_desc_format(const FuncDescriptor *func_desc) {
  return func_desc_format0(&(AstFormatter){.fmt_allocator = HEAP_ALLOCATOR},
                           func_desc);
}

static dyn_string_t expr_format0(AstFormatter *fmt, const Expression *expr) {
  dyn_string_t str = {0};
  dyn_string_init(&str, &fmt->fmt_allocator);
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
        &str, "ExprFunction{args=[%s], block=%s}",
        func_args_format(fmt, expr->var.expr_function.desc.args).string,
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
    dyn_string_t name = module_path_format(fmt, &expr_call.function);
    dyn_string_t args = expr_list_format(fmt, expr_call.args);
    dyn_string_printf(&str, "ExprCall{function=%s, args=[%s]}", name.string,
                      args.string);

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
    dyn_string_printf(&str, "ExprIf{block=%s}",
                      expr_block_format(fmt, &expr->var.expr_if.block).string);
    break;
  }
  case EXPR_FOR: {
    ExprFor expr_for = expr->var.expr_for;
    dyn_string_printf(&str, "ExprFor{iter_var_name=%s, range=%s, block=%s}",
                      expr_for.variable_name,
                      expr_for.has_range
                          ? expr_range_format(fmt, &expr_for.range).string
                          : "(null)",
                      expr_block_format(fmt, &expr->var.expr_for.block).string);
    break;
  }
  case EXPR_IT: {
    dyn_string_printf(&str, "ExprIt");
  } break;
  }
  return str;
}

dyn_string_t expr_format(const Expression *expr) {
  AstFormatter fmt = {0};
  ast_fmt_init(&fmt);
  dyn_string_t expr_str = expr_format0(&fmt, expr);
  dyn_string_t dest = {0};
  dyn_string_init(&dest, &HEAP_ALLOCATOR);
  dyn_string_copy(&dest, &expr_str);
  ast_fmt_deinit(&fmt);
  return dest;
}

static dyn_string_t expr_list_format(AstFormatter *fmt,
                                     const Expression *exprs) {
  dyn_string_t str = {0};
  dyn_string_init(&str, &fmt->fmt_allocator);

  for (size_t i = 0; i < array_len(exprs); i++) {
    dyn_string_add_str(&str, expr_format0(fmt, &exprs[i]).string);
    if (i < array_len(exprs) - 1) {
      dyn_string_add_str(&str, ", ");
    }
  }

  return str;
}

static dyn_string_t typed_ident_list_format(AstFormatter *fmt, const TypedIdent *typed_idents) {
  dyn_string_t str = {0};
  dyn_string_init(&str, &fmt->fmt_allocator);

  const TypedIdent *ti;
  array_foreach((TypedIdent *) typed_idents, ti) {
    dyn_string_t type_str = type_format(&TYPE_FORMATTER_DEFAULT, &ti->type);
    dyn_string_add_str(&str, ti->ident);
    dyn_string_add_str(&str, ": ");
    dyn_string_add_str(&str, type_str.string);
  
    dyn_string_free(&type_str);

    if (_arr_foreach_idx < array_len(ti)) {
      dyn_string_add_str(&str, ", ");
    }

  }

  return str;
}

static dyn_string_t type_expr_format(AstFormatter *fmt,
                                     const TypeExpr *type_expr) {
  dyn_string_t str = {0};
  dyn_string_init(&str, &fmt->fmt_allocator);

  switch (type_expr->kind) {
  case TYPE_EXPR_STRUCT: {
    dyn_string_t fields = typed_ident_list_format(fmt, type_expr->var.type_expr_struct.fields);
    dyn_string_printf(&str, "TypeExprStruct{fields=[%s]}", fields.string);
  } break;
  case TYPE_EXPR_OVERLOAD_SET: {
    TODO();
  } break;
  }

  return str;
}

static dyn_string_t stmt_format(AstFormatter *fmt, const Statement *stmt) {
  dyn_string_t str = {0};
  dyn_string_init(&str, &fmt->fmt_allocator);
  dyn_string_add_ident(&str, fmt->stmt_indent);
  char indent_buf[str.term_len];
  strcpy(indent_buf, str.string);

  switch (stmt->kind) {
  case STMT_DECL: {
    dyn_string_printf(&str, "%sStmtDecl{name=%s, val=%s}", indent_buf,
                      stmt->var.stmt_decl.name,
                      expr_format0(fmt, &stmt->var.stmt_decl.value).string);
  } break;
  case STMT_TYPE_DECL: {
    dyn_string_printf(&str, "%sStmtTypeDecl{name=%s, val=%s}", indent_buf,
                      stmt->var.stmt_type_decl.name, type_expr_format(fmt, &stmt->var.stmt_type_decl.value).string);
  } break;
  case STMT_EXPR: {
    dyn_string_printf(&str, "%sStmtExpr{expr=%s}", indent_buf,
                      expr_format0(fmt, &stmt->var.stmt_expr.expr).string);
  } break;
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
    char *op = "=";
    switch (stmt->var.stmt_assign.assign_kind) {
    case ASSIGN_REGULAR: {
      op = "=";
    } break;
    case ASSIGN_ADD: {
      op = "+=";
    } break;
    case ASSIGN_SUB: {
      op = "-=";
    } break;
    case ASSIGN_MUL: {
      op = "*=";
    } break;
    case ASSIGN_DIV: {
      op = "/=";
    } break;
    }
    dyn_string_printf(
        &str, "%sStmtAssign{left=%s, op='%s', right=%s}", indent_buf,
        expr_format0(fmt, &stmt->var.stmt_assign.left_expr).string, op,
        expr_format0(fmt, &stmt->var.stmt_assign.right_expr).string);
    break;
  }
  }
  return str;
}

dyn_string_t ast_format(const Statement *stmts) {
  dyn_string_t string = {0};
  dyn_string_init(&string, &HEAP_ALLOCATOR);
  AstFormatter fmt = {0};
  ast_fmt_init(&fmt);
  for (size_t i = 0; i < array_len(stmts); i++) {
    char *str = stmt_format(&fmt, stmts + i).string;
    dyn_string_add_str(&string, str);
    dyn_string_add_char(&string, '\n');
  }
  ast_fmt_deinit(&fmt);
  return string;
}
