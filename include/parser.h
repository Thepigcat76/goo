#pragma once

#include "lexer.h"
#include "lilc/hashmap.h"
#include "types.h"
#include "ast.h"
#include <stdbool.h>

void *_internal_heap_clone(void *ptr, size_t size);

#define heap_clone(ptr) _internal_heap_clone(ptr, sizeof(typeof(*(ptr))))

#define EXPR_VAR_TYPE(expr)                                                    \
  (ExpressionVariant) {                                                        \
    .type = EXPR_VAR_TYPE_EXPR, .var = {.expr_var_type_expr = expr }           \
  }

#define EXPR_VAR_EXPR(expr)                                                    \
  (ExpressionVariant) {                                                        \
    .type = EXPR_VAR_REG_EXPR, .var = {.expr_var_reg_expr = expr }             \
  }

typedef struct {
  const Token *cur_tok;
  const Token *peek_tok;
  Token *tokens;
  Statement *statements;
  Hashmap(Ident *, TypeExpr) custom_types;
  Hashmap(Ident *, ExprFunction) custom_functions;
  Ident *foreign_functions;
  const char *source;
  const char *filename;
} Parser;

Parser parser_new(Token *tokens, const char *source, const char *filename);

void parser_parse(Parser *parser);

void parser_stmt_print(char *buf, const Statement *stmt);

void func_desc_print(char *buf, const FuncDescriptor *desc);

TypeTableValue *type_table_get(TypeTable *table, Ident *ident,
                               TypeTable *global_table);

void type_table_add(TypeTable *table, Ident *ident, ExpressionVariant expr_var,
                    OptionalType opt_type);
