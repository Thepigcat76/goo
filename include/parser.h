#pragma once

#include "../vendor/lilc/hashmap.h"
#include "lexer.h"
#include "types.h"
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

typedef enum {
  PREC_LOWEST,
  PREC_SUM,
  PREC_PRODUCT,
} Precedence;

typedef struct {
  enum {
    ARG_TYPED_ARG,
    ARG_VARARG,
  } type;
  union {
    TypedIdent typed_arg;
    Ident vararg;
  } var;
} Argument;

typedef struct {
  struct _generic *generics;
  Argument *args;
  Type ret_type;
  bool has_ret_type;
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
  struct _expr *condition;
  ExprBlock block;
} ExprIf;

typedef struct {
  struct _expr *min;
  struct _expr *max;
} ExprRange;

typedef struct {
  Ident variable_name;
  ExprRange range;
  ExprBlock block;
} ExprFor;

typedef struct {
  Ident function;
  struct _expr *args;
} ExprCall;

typedef struct {
  TypeArray type;
  struct _expr *items;
} ExprArrayInit;

typedef struct {
  struct _expr *array_expr;
  struct _expr *index_expr;
} ExprArrayAccess;

typedef struct {
  struct _expr *expr;
} ExprPointerDeref;

typedef struct {
  struct _expr *expr;
} ExprAddrOf;

typedef struct {
  Type type;
  struct _expr *expr;
} ExprCast;

typedef struct {
  Ident generic;
  ExprCall expr_call;
} ExprGenericCall;

typedef struct {
  Ident struct_name;
  struct _labeled_expr *field_inits;
} ExprStructInit;

typedef struct {
  struct _expr *struct_expr;
  Ident *fields;
} ExprStructAccess;

typedef enum {
  BIN_OP_ADD,
  BIN_OP_SUB,
  BIN_OP_MUL,
  BIN_OP_DIV,

  BIN_OP_LT,
  BIN_OP_GT,
  BIN_OP_LTE,
  BIN_OP_GTE,
} BinOperator;

typedef struct {
  struct _expr *left;
  struct _expr *right;
  BinOperator op;
} ExprBinOp;

typedef struct {
  Ident *functions;
} TypeExprOverloadSet;

typedef struct {
  Generic *generics;
  TypedIdent *fields;
} TypeExprStruct;

typedef struct {
  enum {
    TYPE_EXPR_OVERLOAD_SET,
    TYPE_EXPR_STRUCT,
  } type;
  union {
    TypeExprOverloadSet type_expr_overload_set;
    TypeExprStruct type_expr_struct;
  } var;
} TypeExpr;

typedef struct _expr {
  enum {
    EXPR_CAST,
    EXPR_ARRAY_INIT,
    EXPR_ARRAY_ACCESS,
    EXPR_FUNCTION,
    EXPR_BLOCK,
    EXPR_CALL,
    EXPR_GENERIC_CALL,
    EXPR_STRING_LIT,
    EXPR_INTEGER_LIT,
    EXPR_BOOLEAN_LIT,
    EXPR_IDENT,
    EXPR_UNIT,
    EXPR_BIN_OP,
    EXPR_STRUCT_INIT,
    EXPR_STRUCT_ACCESS,
    EXPR_PTR_DEREF,
    EXPR_ADDR_OF,
    EXPR_IF,
    EXPR_FOR,
    EXPR_IT,
  } type;
  union {
    ExprArrayInit expr_array_init;
    ExprArrayAccess expr_array_access;
    ExprFunction expr_function;
    ExprBlock expr_block;
    ExprCall expr_call;
    ExprGenericCall expr_generic_call;
    ExprCast expr_cast;
    ExprBinOp expr_bin_op;
    ExprStructInit expr_struct_init;
    ExprStructAccess expr_struct_access;
    ExprIf expr_if;
    ExprFor expr_for;
    ExprRange expr_range;
    ExprPointerDeref expr_ptr_deref;
    ExprAddrOf expr_addr_of;
    struct {
      Ident ident;
    } expr_ident;
    struct {
      char *string;
    } expr_string_literal;
    struct {
      int integer;
    } expr_integer_literal;
    struct {
      bool boolean;
    } expr_boolean_literal;
  } var;
  const char *begin;
  size_t len;
} Expression;

typedef struct _labeled_expr {
  Ident field;
  Expression expr;
} LabeledExpr;

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
  bool is_generic;
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

typedef struct {
  Expression ret_val;
  bool has_ret_val;
} StmtReturn;

typedef struct _stmt {
  enum {
    STMT_DECL,
    STMT_EXPR,
    STMT_RETURN,
  } type;
  union {
    StmtDecl stmt_decl;
    StmtExpr stmt_expr;
    StmtReturn stmt_return;
  } var;
} Statement;

typedef struct {
  const Token *cur_tok;
  const Token *peek_tok;
  Token *tokens;
  Statement *statements;
  Hashmap(Ident *, TypeExpr) custom_types;
  Hashmap(Ident *, ExprFunction) custom_functions;
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
