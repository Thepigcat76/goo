#include "../include/parser.h"
#include "../include/types.h"
#include "../vendor/lilc/array.h"
#include <stdio.h>

typedef struct {
  Statement *stmts;
} Ast;

static Statement *CUR_PROGRAM = NULL;

static void program_begin(Ast *program) {
  program->stmts = array_new(Statement, &HEAP_ALLOCATOR);
  CUR_PROGRAM = program->stmts;
}

static void program_end(void) { CUR_PROGRAM = NULL; }

#define ARG(...)                                                               \
  (TypedIdent) { __VA_ARGS__ }

#define ARGS(...)                                                              \
  (TypedIdent[]) { __VA_ARGS__ }

#define FUNCTION(func_ptr, _args, _ret_type, ...)                              \
  do {                                                                         \
    (func_ptr)->type = EXPR_FUNCTION;                                          \
    ExprFunction *func_expr = &(func_ptr)->var.expr_function;                  \
    (func_expr)->desc.generics = NULL;                                         \
    sizeof(_args);                                                             \
    func_expr->desc.args = _args;                                              \
    func_expr->desc.ret_type = _ret_type;                                      \
    Statement *_internal_block = array_new(Statement, &HEAP_ALLOCATOR);        \
    __VA_ARGS__                                                                \
    ExprBlock block = {.statements = _internal_block};                         \
    func_expr->block = &block;                                                 \
  } while (0)

#define INT(i)                                                                 \
  (Expression) {                                                               \
    .type = EXPR_INTEGER_LIT, .var = {.expr_integer_literal = {.integer = i} } \
  }

#define BLOCK(...)                                                             \
  Statement *_internal_prev_scope = CUR_PROGRAM;                               \
  CUR_PROGRAM = _internal_block;                                               \
  __VA_ARGS__                                                                  \
  CUR_PROGRAM = _internal_prev_scope;

static void function(Expression *func) {}

static void decl_const(Ident name, Expression expr) {
  array_add(
      CUR_PROGRAM,
      (Statement){.type = STMT_DECL,
                  .var = {.stmt_decl = {
                              .name = name,
                              .value = {.type = EXPR_VAR_REG_EXPR,
                                        .var = {.expr_var_reg_expr = expr}}}}});
}

// clang-format off
static void parser_test_functions(void) {
  Ast ast;
  program_begin(&ast);
  {
    Expression func_foo0;
    FUNCTION(&func_foo0, ARGS(ARG("slay", INT_BUILTIN_TYPE), ARG("ballz", STRING_BUILTIN_TYPE)), INT_BUILTIN_TYPE, BLOCK({
      decl_const("ballz", INT(0));
    }));
    decl_const("foo0", func_foo0);
  }
  program_end();

  char print_buf[512];
  parser_stmt_print(print_buf, &ast.stmts[0]);
  printf("Stmt: %s\n", print_buf);
}

//void run_tests(void) {}