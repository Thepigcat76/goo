#pragma once

#include "lexer.h"
#include "../vendor/lilc/hashmap.h"
#include "types.h"
#include <stdbool.h>

#define EXPR_VAR_TYPE(expr)                                                    \
  (ExpressionVariant) {                                                        \
    .type = EXPR_VAR_TYPE_EXPR, .var = {.expr_var_type_expr = expr }           \
  }

#define EXPR_VAR_EXPR(expr)                                                    \
  (ExpressionVariant) {                                                        \
    .type = EXPR_VAR_REG_EXPR, .var = {.expr_var_reg_expr = expr }             \
  }

typedef struct {
  struct _generic *generics;
  TypedIdent *args;
  Type ret_type;
} FuncDescriptor;

typedef struct {
  struct _stmt *statements;
} ExprBlock;

typedef struct {
  FuncDescriptor desc;
  ExprBlock *block;
  struct _obj (*native_function)(struct _obj *objects);
} ExprFunction;

typedef struct {
  Ident function;
  struct _expr *args;
} ExprCall;

typedef struct {
  TypeArray type;
  struct _expr *items;
} ExprArray;

typedef struct {
  Type type;
  struct _expr *expr;
} ExprCast;

typedef struct {
  Ident generic;
  ExprCall expr_call;
} ExprGenericCall;

typedef struct {
  Ident *functions;
} TypeExprOverloadSet;

typedef struct {
  enum {
    TYPE_EXPR_OVERLOAD_SET,
  } type;
  union {
    TypeExprOverloadSet type_expr_overload_set;
  } var;
} TypeExpr;

typedef struct _expr {
  enum {
    EXPR_CAST,
    EXPR_ARRAY,
    EXPR_FUNCTION,
    EXPR_BLOCK,
    EXPR_CALL,
    EXPR_GENERIC_CALL,
    EXPR_STRING_LIT,
    EXPR_INTEGER_LIT,
    EXPR_IDENT,
    EXPR_UNIT,
  } type;
  union {
    ExprArray expr_array;
    ExprFunction expr_function;
    ExprBlock expr_block;
    ExprCall expr_call;
    ExprGenericCall expr_generic_call;
    ExprCast expr_cast;
    struct {
      Ident ident;
    } expr_ident;
    struct {
      char *string;
    } expr_string_literal;
    struct {
      int integer;
    } expr_integer_literal;
  } var;
} Expression;

extern const Expression UNIT_EXPR;

typedef struct {
  Type type;
  bool present;
} OptionalType;

extern const OptionalType OPT_TYPE_EMPTY;

typedef struct {
  enum _expr_var_type {
    EXPR_VAR_TYPE_EXPR,
    EXPR_VAR_REG_EXPR,
  } type;
  union {
    TypeExpr expr_var_type_expr;
    Expression expr_var_reg_expr;
  } var;
} ExpressionVariant;

typedef struct {
  ExpressionVariant expr_variant;
  OptionalType opt_type;
} TypeTableValue;

typedef struct {
  Hashmap(Ident *, TypeTableValue) type_table;
} TypeTable;

typedef struct {
  Ident name;
  OptionalType type;
  ExpressionVariant value;
  bool mutable;
} StmtDecl;

typedef struct {
  Expression expr;
} StmtExpr;

typedef struct _stmt {
  enum {
    STMT_DECL,
    STMT_EXPR,
  } type;
  union {
    StmtDecl stmt_decl;
    StmtExpr stmt_expr;
  } var;
} Statement;

typedef struct {
  const Token *cur_tok;
  const Token *peek_tok;
  Token *tokens;
  Statement *statements;
} Parser;

Parser parser_new(Token *tokens);

void parser_parse(Parser *parser);

void parser_stmt_print(char *buf, const Statement *stmt);

void func_desc_print(char *buf, const FuncDescriptor *desc);

TypeTableValue *type_table_get(TypeTable *table, Ident *ident,
                               TypeTable *global_table);

void type_table_add(TypeTable *table, Ident *ident, ExpressionVariant expr_var,
                    OptionalType opt_type);
