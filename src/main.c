#include "alloc.h"
#include "array.h"
#include <ctype.h>
#include <linux/limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef enum {
  TOKEN_IDENT,
  TOKEN_STRING,
  TOKEN_INT,

  TOKEN_DECL_CONST,
  TOKEN_DECL_VAR,
  TOKEN_COLON,
  TOKEN_LPAREN,
  TOKEN_RPAREN,
  TOKEN_LCURLY,
  TOKEN_RCURLY,
  TOKEN_LANGLE,
  TOKEN_RANGLE,
  TOKEN_LSQUARE,
  TOKEN_RSQUARE,
  TOKEN_ARROW,
  TOKEN_COMMA,
  TOKEN_DOT,
  TOKEN_PLUS,
  TOKEN_MINUS,
  TOKEN_ASSIGN,
  TOKEN_CAST,
  TOKEN_EOF,
  TOKEN_ILLEGAL,
} TokenType;

typedef struct {
  TokenType type;
  union {
    char *ident;
    char *string;
    int integer;
  } var;
} Token;

static void tok_print(const Token *tok) {
  switch (tok->type) {
  case TOKEN_IDENT: {
    printf("TOKEN_IDENT{ident=%s}\n", tok->var.ident);
    break;
  }
  case TOKEN_STRING: {
    printf("TOKEN_STRING{string=\"%s\"}\n", tok->var.string);
    break;
  }
  case TOKEN_INT: {
    printf("TOKEN_INT{integer=%d}\n", tok->var.integer);
    break;
  }
  case TOKEN_CAST: {
    printf("TOKEN_CAST ('cast')\n");
    break;
  }
  case TOKEN_DECL_CONST: {
    printf("TOKEN_DECL_CONST ('::')\n");
    break;
  }
  case TOKEN_DECL_VAR: {
    printf("TOKEN_DECL_VAR (':=')\n");
    break;
  }
  case TOKEN_COLON: {
    printf("TOKEN_COLON (':')\n");
    break;
  }
  case TOKEN_LPAREN: {
    printf("TOKEN_LPAREN ('(')\n");
    break;
  }
  case TOKEN_RPAREN: {
    printf("TOKEN_RPAREN (')')\n");
    break;
  }
  case TOKEN_LCURLY: {
    printf("TOKEN_LCURLY ('{')\n");
    break;
  }
  case TOKEN_RCURLY: {
    printf("TOKEN_RCURLY ('}')\n");
    break;
  }
  case TOKEN_LANGLE: {
    printf("TOKEN_LANGLE ('<')\n");
    break;
  }
  case TOKEN_RANGLE: {
    printf("TOKEN_RANGLE ('>')\n");
    break;
  }
  case TOKEN_LSQUARE: {
    printf("TOKEN_LSQUARE ('[')\n");
    break;
  }
  case TOKEN_RSQUARE: {
    printf("TOKEN_RSQUARE (']')\n");
    break;
  }
  case TOKEN_ARROW: {
    printf("TOKEN_ARROW ('->')\n");
    break;
  }
  case TOKEN_COMMA: {
    printf("TOKEN_COMMA (',')\n");
    break;
  }
  case TOKEN_DOT: {
    printf("TOKEN_DOT ('.')\n");
    break;
  }
  case TOKEN_PLUS: {
    printf("TOKEN_PLUS ('+')\n");
    break;
  }
  case TOKEN_MINUS: {
    printf("TOKEN_MINUS ('-')\n");
    break;
  }
  case TOKEN_ASSIGN: {
    printf("TOKEN_ASSIGN ('=')\n");
    break;
  }
  case TOKEN_EOF: {
    printf("TOKEN_EOF\n");
    break;
  }
  case TOKEN_ILLEGAL: {
    printf("TOKEN_ILLEGAL\n");
    break;
  }
  }
}

typedef struct {
  size_t index;
  const char *cur_char;
  Token *tokens;
} Lexer;

static bool next_char(Lexer *lexer) {
  lexer->cur_char++;
  return *lexer->cur_char != '\0';
}

static char *first_ident = NULL;

static void tokenize(Lexer *lexer, const char *src) {
  lexer->cur_char = src;

  while (*lexer->cur_char != '\0') {
    Token tok;
    if (*lexer->cur_char == ' ' || *lexer->cur_char == '\n') {
      do {
        next_char(lexer);
      } while (*lexer->cur_char == ' ');
      continue;
    } else if (*lexer->cur_char == '\0') {
      return;
    } else if (isalpha(*lexer->cur_char) || *lexer->cur_char == '_') {
      size_t cap = 256;
      char ident[cap];

      size_t i = 0;
      do {
        if (i >= cap - 1) {
          fprintf(stderr, "Ident too long\n");
          exit(1);
        }
        ident[i++] = *lexer->cur_char;
        next_char(lexer);
      } while (isalnum(*lexer->cur_char) || *lexer->cur_char == '_');

      lexer->cur_char--;
      ident[i] = '\0';

      if (strcmp(ident, "cast") == 0) {
        tok.type = TOKEN_CAST;
      } else {
        tok.type = TOKEN_IDENT;
        tok.var.ident = malloc(strlen(ident) + 1); // heap-owned copy
        // DEBUG
        if (first_ident == NULL)
          first_ident = tok.var.ident;
        strcpy(tok.var.ident, ident);
      }
    } else if (*lexer->cur_char == '"') {
      char *string = malloc(256 * sizeof(char));
      next_char(lexer);
      size_t i = 0;
      while (*lexer->cur_char != '"') {
        string[i++] = *lexer->cur_char;
        next_char(lexer);
      }
      string[i] = '\0';
      tok = (Token){.type = TOKEN_STRING, .var = {.string = strdup(string)}};
    } else if (*lexer->cur_char >= '0' && *lexer->cur_char <= '9') {
      size_t cap = 32;
      char *int_lit = malloc(cap);
      size_t i = 0;
      do {
        if (i >= cap - 1) {
          fprintf(stderr, "int too long\n");
          exit(1);
        }
        int_lit[i++] = *lexer->cur_char;
        next_char(lexer);
      } while (*lexer->cur_char >= '0' && *lexer->cur_char <= '9');
      lexer->cur_char--;
      int_lit[i] = '\0';
      tok = (Token){.type = TOKEN_INT, .var = {.integer = atoi(int_lit)}};
    } else if (*lexer->cur_char == ':') {
      if (*(lexer->cur_char + 1) == ':') {
        tok = (Token){.type = TOKEN_DECL_CONST};
        next_char(lexer);
      } else if (*(lexer->cur_char + 1) == '=') {
        tok = (Token){.type = TOKEN_DECL_VAR};
        next_char(lexer);
      } else {
        tok = (Token){.type = TOKEN_COLON};
      }
    } else if (*lexer->cur_char == '(') {
      tok = (Token){.type = TOKEN_LPAREN};
    } else if (*lexer->cur_char == ')') {
      tok = (Token){.type = TOKEN_RPAREN};
    } else if (*lexer->cur_char == '{') {
      tok = (Token){.type = TOKEN_LCURLY};
    } else if (*lexer->cur_char == '}') {
      tok = (Token){.type = TOKEN_RCURLY};
    } else if (*lexer->cur_char == '<') {
      tok = (Token){.type = TOKEN_LANGLE};
    } else if (*lexer->cur_char == '>') {
      tok = (Token){.type = TOKEN_RANGLE};
    } else if (*lexer->cur_char == '-' && *(lexer->cur_char + 1) == '>') {
      tok = (Token){.type = TOKEN_ARROW};
      next_char(lexer);
    } else if (*lexer->cur_char == ',') {
      tok = (Token){.type = TOKEN_COMMA};
    } else if (*lexer->cur_char == '+') {
      tok = (Token){.type = TOKEN_PLUS};
    } else if (*lexer->cur_char == '-') {
      tok = (Token){.type = TOKEN_MINUS};
    } else if (*lexer->cur_char == '.') {
      tok = (Token){.type = TOKEN_DOT};
    } else if (*lexer->cur_char == '=') {
      tok = (Token){.type = TOKEN_ASSIGN};
    } else if (*lexer->cur_char == '[') {
      tok = (Token){.type = TOKEN_LSQUARE};
    } else if (*lexer->cur_char == ']') {
      tok = (Token){.type = TOKEN_RSQUARE};
    } else {
      printf("Illegal token cur char: %c\n", *lexer->cur_char);
      tok = (Token){.type = TOKEN_ILLEGAL};
    }
    array_add(lexer->tokens, tok);
    next_char(lexer);
  }
}

typedef char *Ident;

typedef enum {
  TYPE_ARRAY_VARIANT_DYNAMIC,
  TYPE_ARRAY_VARIANT_SIZED,
  TYPE_ARRAY_VARIANT_SIZE_UNKNOWN,
} TypeArrayVariant;

typedef struct {
  TypeArrayVariant variant;
  size_t size;
  struct _type *type;
} TypeArray;

typedef struct {
  struct _generic *generics;
  struct _type *arg_types;
  struct _type *ret_type;
} TypeFunc;

typedef struct {
  struct _type *types;
} TypeTuple;

typedef struct _type {
  enum {
    TYPE_IDENT,
    TYPE_ARRAY,
    TYPE_FUNCTION,
    TYPE_TUPLE,
    // unit is just an empty tuple and used as the "void" type
    TYPE_UNIT,
  } type;
  union {
    Ident type_ident;
    TypeArray type_array;
    TypeFunc type_func;
    TypeTuple type_tuple;
  } var;
} Type;

typedef struct {
  Ident ident;
  Type type;
} TypedIdent;

typedef struct {
  struct _generic *generics;
  TypedIdent *args;
  Type ret_type;
} FuncDescriptor;

typedef struct {
  Ident name;
  struct _generic *generics;
  Type *arg_types;
  Type ret_type;
} FuncSignature;

typedef struct _generic {
  Ident name;
  FuncSignature *bounds;
} Generic;

typedef struct {
  struct _stmt *statements;
} ExprBlock;

typedef struct {
  FuncDescriptor desc;
  ExprBlock *block;
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

static const Expression UNIT_EXPR = {.type = EXPR_UNIT};

typedef struct {
  Type type;
  bool present;
} OptionalType;

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

static void next_token(Parser *parser) {
  parser->cur_tok = parser->peek_tok;
  parser->peek_tok++;
}

static void type_print(char *buf, const Type *type) {
  switch (type->type) {
  case TYPE_IDENT: {
    sprintf(buf, "TypeIdent{ident=%s}", type->var.type_ident);
    break;
  }
  case TYPE_ARRAY: {
    TypeArray type_array = type->var.type_array;
    char *array_variant;
    char size_buf[32];
    switch (type_array.variant) {
    case TYPE_ARRAY_VARIANT_DYNAMIC: {
      array_variant = "DYNAMIC";
      sprintf(size_buf, "dyn");
      break;
    }
    case TYPE_ARRAY_VARIANT_SIZED: {
      array_variant = "SIZED";
      sprintf(size_buf, "%zu", type_array.size);
      break;
    }
    case TYPE_ARRAY_VARIANT_SIZE_UNKNOWN: {
      array_variant = "SIZE_UNKNOWN";
      sprintf(size_buf, "?");
      break;
    }
    }
    char type_buf[256];
    type_print(type_buf, type_array.type);
    sprintf(buf, "TypeArray{variant=%s, size=%s, type=%s}", array_variant,
            size_buf, type_buf);
    break;
  }
  case TYPE_UNIT: {
    sprintf(buf, "TypeUnit");
    break;
  }
  // TODO: Implement both of these
  case TYPE_FUNCTION: {
    sprintf(buf, "TypeFunction - NYI");
    break;
  }
  case TYPE_TUPLE: {
    sprintf(buf, "TypeTuple - NYI");
    break;
  }
  }
}

static void generic_print(char *buf, const Generic *generic);

static void func_signature_print(char *buf, const FuncSignature *desc) {
  char generics_buf[256] = {'\0'};
  if (desc->generics != NULL) {
    for (size_t i = 0; i < array_len(desc->generics); i++) {
      char generic_buf[128];
      generic_print(generic_buf, &desc->generics[i]);
      strcat(generics_buf, generic_buf);
      strcat(generics_buf, ", ");
    }
    if (array_len(desc->generics) >= 1) {
      generics_buf[strlen(generics_buf) - 2] = '\0';
    }
  }
  char args_buf[256] = {'\0'};
  if (desc->arg_types != NULL) {
    for (size_t i = 0; i < array_len(desc->arg_types); i++) {
      char arg_buf[64];
      char type_buf[512];
      type_print(type_buf, &desc->arg_types[i]);
      sprintf(arg_buf, "Type{type=%s}", type_buf);
      strcat(args_buf, arg_buf);
      strcat(args_buf, ", ");
    }
    if (array_len(desc->arg_types) >= 1) {
      args_buf[strlen(args_buf) - 2] = '\0';
    }
  }
  char type_buf[512];
  type_print(type_buf, &desc->ret_type);
  sprintf(buf, "FuncSignature{name=%s, generics=[%s], args=[%s], ret_type=%s}",
          desc->name, generics_buf, args_buf, type_buf);
}

static void generic_print(char *buf, const Generic *generic) {
  char bounds_buf[512] = {'\0'};
  if (generic->bounds != NULL) {
    for (size_t i = 0; i < array_len(generic->bounds); i++) {
      char bound_buf[128] = {'\0'};
      func_signature_print(bound_buf, &generic->bounds[i]);
      strcat(bounds_buf, bound_buf);
      strcat(bounds_buf, ", ");
    }
    bounds_buf[strlen(bounds_buf) - 2] = '\0';
  }
  sprintf(buf, "Generic{name=%s, bounds=[%s]}", generic->name, bounds_buf);
}

static void typed_ident_print(char *buf, const TypedIdent *ident) {
  char type_buf[512];
  type_print(type_buf, &ident->type);
  sprintf(buf, "TypedIdent{ident=%s, type=%s}", ident->ident, type_buf);
}

static void func_desc_print(char *buf, const FuncDescriptor *desc) {
  char generics_buf[512] = {'\0'};
  if (desc->generics != NULL) {
    for (size_t i = 0; i < array_len(desc->generics); i++) {
      char generic_buf[256] = {'\0'};
      generic_print(generic_buf, &desc->generics[i]);
      strcat(generics_buf, generic_buf);
      strcat(generics_buf, ", ");
    }
    if (array_len(desc->generics) >= 1) {
      generics_buf[strlen(generics_buf) - 2] = '\0';
    }
  }
  char args_buf[256] = {'\0'};
  if (desc->args != NULL) {
    for (size_t i = 0; i < array_len(desc->args); i++) {
      char arg_buf[64];
      typed_ident_print(arg_buf, &desc->args[i]);
      strcat(args_buf, arg_buf);
      strcat(args_buf, ", ");
    }
    if (array_len(desc->args) >= 1) {
      args_buf[strlen(args_buf) - 2] = '\0';
    }
  }
  char type_buf[512];
  type_print(type_buf, &desc->ret_type);
  sprintf(buf, "FuncDescriptor{generics=[%s], args=[%s], ret_type=%s}",
          generics_buf, args_buf, type_buf);
}

static void stmt_print(char *buf, const Statement *stmt);

static void expr_print(char *buf, const Expression *expr) {
  switch (expr->type) {
  case EXPR_FUNCTION: {
    char func_desc_buf[512] = {'\0'};
    func_desc_print(func_desc_buf, &expr->var.expr_function.desc);
    char block_buf[4096] = {'\0'};
    if (expr->var.expr_function.block != NULL) {
      Statement *stmts = expr->var.expr_function.block->statements;
      if (stmts != NULL) {
        for (size_t i = 0; i < array_len(stmts); i++) {
          char stmt_buf[512];
          stmt_print(stmt_buf, &stmts[i]);
          strcat(block_buf, stmt_buf);
          strcat(block_buf, ", ");
        }
        if (array_len(stmts) >= 1) {
          block_buf[strlen(block_buf) - 2] = '\0';
        }
      }
    }
    sprintf(buf, "ExprFunction{func_desc=%s, block=[%s]}", func_desc_buf,
            block_buf);
    break;
  }
  case EXPR_STRING_LIT: {
    sprintf(buf, "StringLiteral{value=\"%s\"}",
            expr->var.expr_string_literal.string);
    break;
  }
  case EXPR_INTEGER_LIT: {
    sprintf(buf, "IntegerLiteral{value=%d}",
            expr->var.expr_integer_literal.integer);
    break;
  }
  case EXPR_CALL: {
    char args_buf[512] = {'\0'};
    if (expr->var.expr_call.args != NULL) {
      for (size_t i = 0; i < array_len(expr->var.expr_call.args); i++) {
        char arg_buf[128];
        Expression arg_expr = expr->var.expr_call.args[i];
        expr_print(arg_buf, &arg_expr);
        strcat(args_buf, arg_buf);
        strcat(args_buf, ", ");
      }
      if (array_len(expr->var.expr_call.args) >= 1) {
        args_buf[strlen(args_buf) - 2] = '\0';
      }
    }
    sprintf(buf, "ExprCall{function=%s, args=[%s]}",
            expr->var.expr_call.function, args_buf);
    break;
  }
  case EXPR_GENERIC_CALL: {
    ExprGenericCall generic_call = expr->var.expr_generic_call;
    char print_buf[1024];
    Expression call_expr = {.type = EXPR_CALL,
                            .var = {.expr_call = generic_call.expr_call}};
    expr_print(print_buf, &call_expr);
    sprintf(buf, "ExprGenericCall{generic_ident=%s, call_expr=%s}",
            generic_call.generic, print_buf);
    break;
  }
  case EXPR_BLOCK: {
    char block_buf[4096] = {'\0'};
    Statement *stmts = expr->var.expr_block.statements;
    if (stmts != NULL) {
      for (size_t i = 0; i < array_len(stmts); i++) {
        char stmt_buf[512];
        stmt_print(stmt_buf, &stmts[i]);
        strcat(block_buf, stmt_buf);
        strcat(block_buf, ", ");
      }
      if (array_len(expr->var.expr_block.statements) >= 1) {
        block_buf[strlen(block_buf) - 2] = '\0';
      }
    }
    sprintf(buf, "%s", block_buf);
    break;
  }
  case EXPR_IDENT: {
    sprintf(buf, "ExprIdent{ident=%s}", expr->var.expr_ident.ident);
    break;
  }
  case EXPR_ARRAY: {
    Type type = {.type = TYPE_ARRAY,
                 .var = {.type_array = expr->var.expr_array.type}};
    char type_buf[128];
    type_print(type_buf, &type);
    char exprs_buf[512] = {'\0'};
    for (size_t i = 0; i < array_len(expr->var.expr_array.items); i++) {
      char expr_buf[128];
      expr_print(expr_buf, &expr->var.expr_array.items[i]);
      strcat(exprs_buf, expr_buf);
      strcat(exprs_buf, ", ");
    }
    if (array_len(expr->var.expr_array.items) > 0) {
      exprs_buf[strlen(exprs_buf) - 2] = '\0';
    }
    sprintf(buf, "ExprArray{type=%s, items=%s}", type_buf, exprs_buf);
    break;
  }
  case EXPR_CAST: {
    char type_buf[128];
    type_print(type_buf, &expr->var.expr_cast.type);
    char expr_buf[128];
    expr_print(expr_buf, expr->var.expr_cast.expr);
    sprintf(buf, "ExprCast{type=%s, expr=%s}", type_buf, expr_buf);
    break;
  }
  case EXPR_UNIT: {
    sprintf(buf, "ExprUnit");
    break;
  }
  default: {
    fprintf(stderr, "No type found: %d", expr->type);
    exit(1);
  }
  }
}

static void stmt_print(char *buf, const Statement *stmt) {
  switch (stmt->type) {
  case STMT_DECL: {
    char expr_buf[1024] = {'\0'};
    if (stmt->var.stmt_decl.value.type == EXPR_VAR_REG_EXPR) {
      expr_print(expr_buf, &stmt->var.stmt_decl.value.var.expr_var_reg_expr);
    } else {
      strcpy(expr_buf, "ExprVariantType{...}");
    }
    char type_buf[512] = {'\0'};
    if (stmt->var.stmt_decl.type.present) {
      type_print(type_buf, &stmt->var.stmt_decl.type.type);
    }
    sprintf(buf, "StmtDecl{name=%s, type=%s, mutable=%s, value=%s}",
            stmt->var.stmt_decl.name, type_buf,
            stmt->var.stmt_decl.mutable ? "true" : "false", expr_buf);
    break;
  }
  case STMT_EXPR: {
    char expr_buf[1024];
    expr_print(expr_buf, &stmt->var.stmt_expr.expr);
    sprintf(buf, "StmtExpr{expr=%s}", expr_buf);
    break;
  }
  }
}

#define EXPECTED_TOKEN_ERR(expected, received_ptr)                             \
  fprintf(stderr, "Expected " #expected ", received:");                        \
  tok_print(received_ptr);                                                     \
  exit(1)

#define ILLEGAL_TOKEN_ERR(tok)                                                 \
  fprintf(stderr, "Illegal " #tok " at beginning of stmt");                    \
  exit(1)

static Statement parse_stmt(Parser *parser);

// begin: cur_tok must be first token of type
// end: cur_tok is last token of type
static Type parse_type(Parser *parser) {
  switch (parser->cur_tok->type) {
  case TOKEN_IDENT: {
    return (Type){.type = TYPE_IDENT,
                  .var = {.type_ident = parser->cur_tok->var.ident}};
  }
  case TOKEN_LPAREN: {
    if (parser->peek_tok->type == TOKEN_RPAREN) {
      // cur_tok is right parenthesis
      next_token(parser);
      return (Type){.type = TYPE_UNIT};
    }
    Type *types = array_new(Type, &HEAP_ALLOCATOR);
    while (parser->peek_tok->type != TOKEN_RPAREN) {
      // cur_tok is first token of type
      next_token(parser);
      Type type = parse_type(parser);
      array_add(types, type);
      if (parser->peek_tok->type == TOKEN_COMMA) {
        // cur_tok is comma
        next_token(parser);
      }
    }
    return (Type){.type = TYPE_TUPLE, .var = {.type_tuple = {.types = types}}};
  }
  case TOKEN_LSQUARE: {
    TypeArray type_array = {};
    if (parser->peek_tok->type == TOKEN_IDENT &&
        strcmp(parser->peek_tok->var.ident, "dyn") == 0) {
      type_array.variant = TYPE_ARRAY_VARIANT_DYNAMIC;
      // cur_tok is ident
      next_token(parser);
    } else if (parser->peek_tok->type == TOKEN_INT) {
      type_array.variant = TYPE_ARRAY_VARIANT_SIZED;
      type_array.size = parser->peek_tok->var.integer;
      // cur_tok is int
      next_token(parser);
    } else if (parser->peek_tok->type == TOKEN_RSQUARE) {
      type_array.variant = TYPE_ARRAY_VARIANT_SIZE_UNKNOWN;
    }
    // cur_tok is right parenthesis
    next_token(parser);
    // cur_tok is first token of type
    next_token(parser);
    type_array.type = malloc(sizeof(Type));
    Type type = parse_type(parser);
    memcpy(type_array.type, &type, sizeof(Type));
    return (Type){.type = TYPE_ARRAY, .var = {.type_array = type_array}};
  }
  // case TOKEN_LANGLE: {
  //   break;
  // }
  default: {
    printf("Type parsing nyi for type\n");
    exit(1);
  }
  }
}

// begin: cur_tok must be first ident or end
// end: cur_tok is end
static TypedIdent *parse_typed_ident_list(Parser *parser, TokenType end) {
  TypedIdent *idents = array_new_capacity(TypedIdent, 8, &HEAP_ALLOCATOR);
  while (parser->cur_tok->type != end) {
    TypedIdent ti;
    if (parser->cur_tok->type == TOKEN_IDENT) {
      ti.ident = parser->cur_tok->var.ident;
    }
    // cur_tok is colon
    next_token(parser);
    if (parser->cur_tok->type != TOKEN_COLON) {
      EXPECTED_TOKEN_ERR(TOKEN_COLON, parser->cur_tok);
    }
    // cur_tok is type
    next_token(parser);
    if (parser->cur_tok->type == TOKEN_IDENT) {
      ti.type = parse_type(parser);
    }

    if (parser->peek_tok->type == TOKEN_COMMA) {
      // cur_tok is comma
      next_token(parser);
      // cur_tok is ident or end
      next_token(parser);
    } else if (parser->peek_tok->type == end) {
      // cur_tok is end
      next_token(parser);
    }
    array_add(idents, ti);
  }
  return idents;
}

// begin: cur_tok must be first type or end
// end: cur_tok is end
static Type *parse_type_list(Parser *parser, TokenType end) {
  Type *types = array_new_capacity(Type, 8, &HEAP_ALLOCATOR);
  while (parser->cur_tok->type != end) {
    Type t = {};
    if (parser->cur_tok->type == TOKEN_IDENT) {
      t = parse_type(parser);
    } else {
      tok_print(parser->cur_tok);
      fprintf(stderr, "Expected type");
      exit(1);
    }

    if (parser->peek_tok->type == TOKEN_COMMA) {
      // cur_tok is comma
      next_token(parser);
      // cur_tok is ident or end
      next_token(parser);
    } else if (parser->peek_tok->type == end) {
      // cur_tok is end
      next_token(parser);
    }
    array_add(types, t);
  }
  return types;
}

// begin: cur_tok must be first token of first statement
// end: cur_tok is end
static Statement *parse_block_statements(Parser *parser, TokenType end) {
  Statement *stmts = array_new_capacity(Statement, 16, &HEAP_ALLOCATOR);
  while (parser->cur_tok->type != end) {
    Statement stmt = parse_stmt(parser);
    array_add(stmts, stmt);
    next_token(parser);
  }
  return stmts;
}

static Expression parse_expr(Parser *parser);

static Expression *parse_expr_list(Parser *parser, TokenType end) {
  Expression *exprs = array_new_capacity(Expression, 8, &HEAP_ALLOCATOR);
  while (parser->cur_tok->type != end) {
    Expression expr = parse_expr(parser);
    if (parser->peek_tok->type == TOKEN_COMMA) {
      // cur_tok is comma
      next_token(parser);
    }
    array_add(exprs, expr);
    // cur_tok is next expr
    next_token(parser);
  }
  return exprs;
}

// TODO: Generic functions
// begin: cur_tok must be left parenthesis
// end: cur_tok is return_type ident or right parenthesis
static FuncDescriptor parse_func_desc(Parser *parser);

// begin: cur_tok must be function name
// end: cur_tok is return_type ident or right parenthesis
static FuncSignature parse_func_signature(Parser *parser) {
  FuncSignature signature = {.name = parser->cur_tok->var.ident};
  // cur_tok is left parenthesis
  next_token(parser);
  // cur_tok is first ident or end of args
  next_token(parser);
  // cur_tok is end
  signature.arg_types = parse_type_list(parser, TOKEN_RPAREN);
  if (parser->peek_tok->type == TOKEN_ARROW) {
    // cur_tok is arrow
    next_token(parser);

    if (parser->peek_tok->type == TOKEN_IDENT) {
      // cur_tok is ident
      next_token(parser);
      signature.ret_type = parse_type(parser);
    } else {
      EXPECTED_TOKEN_ERR(TOKEN_IDENT, parser->peek_tok);
    }
  }

  return signature;
}

// begin: cur_tok must be generic name
// end: cur_tok is end of func descriptor or generic ident
static Generic parse_generic(Parser *parser) {
  Generic generic = {.name = parser->cur_tok->var.ident};
  if (parser->peek_tok->type == TOKEN_COLON) {
    // cur_tok is colon
    next_token(parser);
    // cur_tok is first tok of func descriptor
    next_token(parser);
    generic.bounds = array_new(FuncSignature, &HEAP_ALLOCATOR);
    while (parser->cur_tok->type != TOKEN_COMMA &&
           parser->cur_tok->type != TOKEN_RANGLE) {
      FuncSignature signature = parse_func_signature(parser);
      array_add(generic.bounds, signature);

      if (parser->peek_tok->type == TOKEN_PLUS) {
        // cur_tok is plus
        next_token(parser);
      } else if (parser->peek_tok->type == TOKEN_RANGLE) {
        break;
      }

      // next token is next function name or comma or rangle
      next_token(parser);
    }
  }
  return generic;
}

// TODO: Generic functions
// begin: cur_tok must be left parenthesis
// end: cur_tok is return_type ident or right parenthesis
static FuncDescriptor parse_func_desc(Parser *parser) {
  FuncDescriptor desc = {};
  // cur_tok is first ident or end of args
  next_token(parser);
  desc.args = parse_typed_ident_list(parser, TOKEN_RPAREN);
  if (parser->peek_tok->type == TOKEN_ARROW) {
    // cur_tok is arrow
    next_token(parser);

    if (parser->peek_tok->type == TOKEN_IDENT) {
      // cur_tok is ident
      next_token(parser);
      desc.ret_type = parse_type(parser);
    } else {
      EXPECTED_TOKEN_ERR(TOKEN_IDENT, parser->peek_tok);
    }
  }

  return desc;
}

static Expression parse_expr(Parser *parser) {
  switch (parser->cur_tok->type) {
  case TOKEN_STRING: {
    return (Expression){
        .type = EXPR_STRING_LIT,
        .var = {.expr_string_literal = parser->cur_tok->var.string}};
  }
  case TOKEN_LPAREN: {
    FuncDescriptor desc = parse_func_desc(parser);
    ExprBlock *block_expr = malloc(sizeof(ExprBlock));

    if (parser->peek_tok->type == TOKEN_LCURLY) {
      // cur_tok is left curly
      next_token(parser);
      // cur_tok is first stmt
      next_token(parser);

      Statement *stmts = parse_block_statements(parser, TOKEN_RCURLY);
      ExprBlock block = {.statements = stmts};
      memcpy(block_expr, &block, sizeof(ExprBlock));
    } else {
      EXPECTED_TOKEN_ERR(TOKEN_LCURLY, parser->peek_tok);
    }

    // cur_tok is rcurly
    return (Expression){
        .type = EXPR_FUNCTION,
        .var = {.expr_function = {.desc = desc, .block = block_expr}}};
  }
  case TOKEN_LCURLY: {
    // cur_tok is first tok of first stmt of block
    next_token(parser);
    Statement *stmts = parse_block_statements(parser, TOKEN_RCURLY);
    return (Expression){.type = EXPR_BLOCK,
                        .var = {.expr_block = {.statements = stmts}}};
  }
  case TOKEN_IDENT: {
    Ident ident = parser->cur_tok->var.ident;
    if (parser->peek_tok->type == TOKEN_LPAREN) {
      // cur_tok is left parenthesis
      next_token(parser);
      // cur_tok is first expr
      next_token(parser);

      Expression *exprs = parse_expr_list(parser, TOKEN_RPAREN);
      // end: right parenthesis
      return (Expression){
          .type = EXPR_CALL,
          .var = {.expr_call = {.function = ident, .args = exprs}}};
    } else if (parser->peek_tok->type == TOKEN_DOT) {
      // cur_tok is dot
      next_token(parser);
      // cur_tok is call name
      next_token(parser);

      Ident call_name = parser->cur_tok->var.ident;

      // cur_tok is left parenthesis
      next_token(parser);
      // cur_tok is first token of first expr
      next_token(parser);

      Expression *exprs = parse_expr_list(parser, TOKEN_RPAREN);
      // end: right parenthesis
      return (Expression){
          .type = EXPR_GENERIC_CALL,
          .var = {.expr_generic_call = {
                      .generic = ident,
                      .expr_call = {.function = call_name, .args = exprs}}}};
    }
    return (Expression){.type = EXPR_IDENT,
                        .var = {.expr_ident = {.ident = ident}}};
  }
  case TOKEN_INT: {
    return (Expression){.type = EXPR_INTEGER_LIT,
                        .var = {.expr_integer_literal = {
                                    .integer = parser->cur_tok->var.integer}}};
  }
  case TOKEN_LANGLE: {
    // cur_tok is generic name
    next_token(parser);
    Generic generic = parse_generic(parser);
    // cur_tok is rangle
    next_token(parser);
    // cur_tok is left paren
    next_token(parser);
    FuncDescriptor desc = parse_func_desc(parser);
    desc.generics = array_new(Generic, &HEAP_ALLOCATOR);
    array_add(desc.generics, generic);
    ExprBlock *block_expr = malloc(sizeof(ExprBlock));

    if (parser->peek_tok->type == TOKEN_LCURLY) {
      // cur_tok is left curly
      next_token(parser);
      // cur_tok is first stmt
      next_token(parser);

      Statement *stmts = parse_block_statements(parser, TOKEN_RCURLY);
      ExprBlock block = {.statements = stmts};
      memcpy(block_expr, &block, sizeof(ExprBlock));
    } else {
      EXPECTED_TOKEN_ERR(TOKEN_LCURLY, parser->peek_tok);
    }

    // cur_tok is rcurly
    return (Expression){
        .type = EXPR_FUNCTION,
        .var = {.expr_function = {.desc = desc, .block = block_expr}}};
  }
  case TOKEN_LSQUARE: {
    Type type = parse_type(parser);
    if (parser->peek_tok->type != TOKEN_LCURLY) {
      EXPECTED_TOKEN_ERR(TOKEN_LCURLY, parser->peek_tok);
    }
    // cur_tok is left curly
    next_token(parser);
    // cur_tok is first token of expr
    next_token(parser);
    Expression *exprs = array_new(Expression, &HEAP_ALLOCATOR);
    while (parser->cur_tok->type != TOKEN_RCURLY) {
      array_add(exprs, parse_expr(parser));
      if (parser->peek_tok->type == TOKEN_COMMA) {
        // cur_tok is comma
        next_token(parser);
      }
      // cur_tok is right parenthesis or next expr
      next_token(parser);
    }
    return (Expression){
        .type = EXPR_ARRAY,
        .var = {.expr_array = {.type = type.var.type_array, .items = exprs}}};
  }
  case TOKEN_CAST: {
    if (parser->peek_tok->type != TOKEN_LANGLE) {
      EXPECTED_TOKEN_ERR(TOKEN_LPAREN, parser->peek_tok);
    }
    // cur_tok is left angle
    next_token(parser);
    // cur_tok is first token of type
    next_token(parser);
    Type type = parse_type(parser);

    if (parser->peek_tok->type != TOKEN_RANGLE) {
      EXPECTED_TOKEN_ERR(TOKEN_RANGLE, parser->peek_tok);
    }
    // cur_tok is right angle
    next_token(parser);

    if (parser->peek_tok->type != TOKEN_LPAREN) {
      EXPECTED_TOKEN_ERR(TOKEN_LPAREN, parser->peek_tok);
    }
    // cur_tok is left parenthesis
    next_token(parser);
    // cur_tok is first token of expr
    next_token(parser);
    Expression expr = parse_expr(parser);

    if (parser->peek_tok->type != TOKEN_RPAREN) {
      EXPECTED_TOKEN_ERR(TOKEN_RPAREN, parser->peek_tok);
    }

    // cur_tok is right parenthesis
    next_token(parser);

    ExprCast expr_cast = {.type = type, .expr = malloc(sizeof(Expression))};
    memcpy(expr_cast.expr, &expr, sizeof(Expression));
    return (Expression){.type = EXPR_CAST, .var = {.expr_cast = expr_cast}};
  }
  case TOKEN_RANGLE:
  case TOKEN_ARROW:
  case TOKEN_COMMA:
  case TOKEN_RPAREN:
  case TOKEN_RCURLY:
  case TOKEN_DECL_CONST:
  case TOKEN_DECL_VAR:
  case TOKEN_COLON:
  case TOKEN_EOF:
  case TOKEN_DOT:
  case TOKEN_PLUS:
  case TOKEN_MINUS:
  case TOKEN_ASSIGN:
  case TOKEN_RSQUARE:
  case TOKEN_ILLEGAL: {
    printf("nyi/illegal token: ");
    tok_print(parser->cur_tok);
    exit(1);
  }
  }
}

static Statement parse_stmt(Parser *parser) {
  switch (parser->cur_tok->type) {
  case TOKEN_IDENT: {
    if (parser->peek_tok->type == TOKEN_DECL_CONST ||
        parser->peek_tok->type == TOKEN_DECL_VAR) {
      Ident name = parser->cur_tok->var.ident;
      bool mutable = parser->peek_tok->type == TOKEN_DECL_VAR;
      // cur token is DECL
      next_token(parser);
      // cur token is EXPR
      next_token(parser);
      Statement stmt;
      if (parser->cur_tok->type == TOKEN_IDENT &&
          !(parser->peek_tok->type == TOKEN_LPAREN ||
            parser->peek_tok->type == TOKEN_DOT)) {
        Ident *idents = array_new(Ident, &HEAP_ALLOCATOR);
        while (parser->cur_tok->type == TOKEN_IDENT) {
          array_add(idents, parser->cur_tok->var.ident);
          if (parser->peek_tok->type == TOKEN_COMMA) {
            // cur_tok is comma
            next_token(parser);
            if (parser->peek_tok->type == TOKEN_IDENT) {
              // cur_tok is next ident
              next_token(parser);
            } else {
              break;
            }
          } else {
            break;
          }
        }
        stmt = (Statement){
            .type = STMT_DECL,
            .var = {.stmt_decl = {
                        .name = name,
                        .mutable = mutable,
                        .value = (ExpressionVariant){
                            .type = EXPR_VAR_TYPE_EXPR,
                            .var = {.expr_var_type_expr = {
                                        .type = TYPE_EXPR_OVERLOAD_SET,
                                        .var = {.type_expr_overload_set = {
                                                    .functions = idents}}}}}}}};
      } else {
        Expression value = parse_expr(parser);
        stmt = (Statement){
            .type = STMT_DECL,
            .var = {.stmt_decl = {.name = name,
                                  .mutable = mutable,
                                  .value = (ExpressionVariant){
                                      .type = EXPR_VAR_REG_EXPR,
                                      .var = {.expr_var_reg_expr = value}}}}};
      }
      return stmt;
    } else if (parser->peek_tok->type == TOKEN_COLON) {
      StmtDecl stmt_decl = {0};
      stmt_decl.name = parser->cur_tok->var.ident;
      // cur_tok is colon
      next_token(parser);
      // cur_tok is first token of type
      next_token(parser);
      stmt_decl.type =
          (OptionalType){.type = parse_type(parser), .present = true};

      if (parser->peek_tok->type == TOKEN_ASSIGN ||
          parser->peek_tok->type == TOKEN_COLON) {
        // cur_tok is assign/colon
        next_token(parser);

        stmt_decl.mutable = parser->cur_tok->type == TOKEN_ASSIGN;
      } else {
        EXPECTED_TOKEN_ERR(TOKEN_ASSIGN | TOKEN_COLON, parser->peek_tok);
      }

      next_token(parser);
      Expression value = parse_expr(parser);
      stmt_decl.value = (ExpressionVariant){
          .type = EXPR_VAR_REG_EXPR, .var = {.expr_var_reg_expr = value}};
      return (Statement){.type = STMT_DECL, .var = {.stmt_decl = stmt_decl}};
    } else {
      goto parse_expr;
    }
    exit(1);
  }
  case TOKEN_CAST:
  case TOKEN_LSQUARE:
  case TOKEN_STRING:
  case TOKEN_INT:
  parse_expr: {
    Expression expr = parse_expr(parser);
    return (Statement){.type = STMT_EXPR, .var = {.stmt_expr = {.expr = expr}}};
  }
  case TOKEN_DECL_CONST: {
    ILLEGAL_TOKEN_ERR(TOKEN_DECL_CONST);
  }
  case TOKEN_DECL_VAR: {
    ILLEGAL_TOKEN_ERR(TOKEN_DECL_VAR);
  }
  case TOKEN_COLON: {
    ILLEGAL_TOKEN_ERR(TOKEN_COLON);
  }
  case TOKEN_LPAREN: {
    ILLEGAL_TOKEN_ERR(TOKEN_LPAREN);
  }
  case TOKEN_RPAREN: {
    ILLEGAL_TOKEN_ERR(TOKEN_RPAREN);
  }
  case TOKEN_LCURLY: {
    ILLEGAL_TOKEN_ERR(TOKEN_LCURLY);
  }
  case TOKEN_RCURLY: {
    ILLEGAL_TOKEN_ERR(TOKEN_RCURLY);
  }
  case TOKEN_LANGLE: {
    ILLEGAL_TOKEN_ERR(TOKEN_LANGLE);
  }
  case TOKEN_RANGLE: {
    ILLEGAL_TOKEN_ERR(TOKEN_RANGLE);
  }
  case TOKEN_ARROW: {
    ILLEGAL_TOKEN_ERR(TOKEN_ARROW);
  }
  case TOKEN_COMMA: {
    ILLEGAL_TOKEN_ERR(TOKEN_COMMA);
  }
  case TOKEN_DOT: {
    ILLEGAL_TOKEN_ERR(TOKEN_DOT);
  }
  case TOKEN_PLUS: {
    ILLEGAL_TOKEN_ERR(TOKEN_PLUS);
  }
  case TOKEN_MINUS: {
    ILLEGAL_TOKEN_ERR(TOKEN_MINUS);
  }
  case TOKEN_EOF: {
    ILLEGAL_TOKEN_ERR(TOKEN_EOF);
  }
  case TOKEN_ILLEGAL: {
    ILLEGAL_TOKEN_ERR(TOKEN_ILLEGAL);
  }
  case TOKEN_ASSIGN: {
    ILLEGAL_TOKEN_ERR(TOKEN_ASSIGN);
    break;
  }
  case TOKEN_RSQUARE: {
    ILLEGAL_TOKEN_ERR(TOKEN_RSQUARE);
    break;
  }
  }
}

static void parse(Parser *parser) {
  parser->cur_tok = parser->tokens;
  parser->peek_tok = parser->tokens + 1;

  while (parser->cur_tok->type != TOKEN_EOF) {
    Statement stmt = parse_stmt(parser);
    array_add(parser->statements, stmt);
    next_token(parser);
  }
}

// Why do we have the types here?
typedef struct {
  TypedIdent *args;
  ExprBlock *block;
} ObjectFunction;

typedef struct {
  enum {
    OBJECT_INT,
    OBJECT_STRING,
    OBJECT_FUNCTION,
    OBJECT_UNIT,
  } type;
  union {
    int obj_int;
    char *obj_string;
    ObjectFunction obj_function;
  } var;
} Object;

typedef struct {
  Ident *symbols;
  Object *objects;
} Environment;

typedef struct {
  Statement *stmts;

  // Basically our version of a stack. Each environment represents a "stack
  // frame"
  Environment *environments;
  // Very first entry of the 'environments' field. Stores variables that are
  // global aka will never go out of scope
  Environment *global_env;
  // The current environment (last environment on the environments stack)
  Environment *cur_env;
} Evaluator;

static void environment_add(Environment *env, Ident symbol, Object obj) {
  array_add(env->symbols, symbol);
  array_add(env->objects, obj);
}

static Object *environment_get(Environment *environments, Ident symbol,
                               Environment *global_env) {
  for (size_t i = 0; i < array_len(environments->symbols); i++) {
    if (strcmp(environments->symbols[i], symbol) == 0) {
      return &environments->objects[i];
    }
  }

  if (global_env != NULL) {

    for (size_t i = 0; i < array_len(global_env->symbols); i++) {
      if (strcmp(global_env->symbols[i], symbol) == 0) {
        return &global_env->objects[i];
      }
    }
  }

  return NULL;
}

static void evaluator_envs_push(Evaluator *evaluator) {
  Environment new_env = {.symbols = array_new(Ident, &HEAP_ALLOCATOR),
                         .objects = array_new(Object, &HEAP_ALLOCATOR)};
  array_add(evaluator->environments, new_env);
  evaluator->cur_env++;
}

static void evaluator_envs_pop(Evaluator *evaluator) {
  size_t len = array_len(evaluator->environments);
  if (len == 1)
    // We don't want to pop the global env
    return;

  Environment last_env = evaluator->environments[len - 1];
  _internal_array_set_len(evaluator->environments, len - 1);
  array_free(last_env.symbols);
  array_free(last_env.objects);
  evaluator->cur_env--;
}

static const Object UNIT_OBJ = {.type = OBJECT_UNIT};

#define BUILTIN_FUNCTION_DEFINE(_ret_type)                                     \
  (Expression) {                                                               \
    .type = EXPR_FUNCTION, .var = {                                            \
      .expr_function = {.desc = {.ret_type = _ret_type,                        \
                                 .args =                                       \
                                     array_new(TypedIdent, &HEAP_ALLOCATOR)}}  \
    }                                                                          \
  }

#define BUILTIN_FUNCTION_SET_ARG_TYPES(func, ...)                              \
  do {                                                                         \
    TypedIdent *args = func.var.expr_function.desc.args;                       \
    TypedIdent provided[] = {__VA_ARGS__ __VA_OPT__(, )(TypedIdent){0}};       \
    for (size_t i = 0; provided[i].ident != NULL; i++) {                       \
      array_add(args, provided[i]);                                            \
    }                                                                          \
  } while (0)

#define BUILTIN_FUNCTION(func, _ret_type, ...)                                 \
  do {                                                                         \
    func = BUILTIN_FUNCTION_DEFINE(_ret_type);                                 \
    BUILTIN_FUNCTION_SET_ARG_TYPES(func, __VA_ARGS__);                         \
  } while (0)

#define ARG(_ident, _type)                                                     \
  (TypedIdent) { .ident = _ident, .type = _type }

#define BUILTIN_TYPE_IDENT(_ident)                                             \
  (Type) {                                                                     \
    .type = TYPE_IDENT, .var = {.type_ident = _ident }                         \
  }

static const Type UNIT_BUILTIN_TYPE = {.type = TYPE_UNIT};
static const Type STRING_BUILTIN_TYPE = BUILTIN_TYPE_IDENT("string");
static const Type INT_BUILTIN_TYPE = BUILTIN_TYPE_IDENT("i32");

static Expression PRINTLN_FUNCTION_EXPR;
static Expression EXIT_FUNCTION_EXPR;

static void builtin_functions_init(void) {
  BUILTIN_FUNCTION(PRINTLN_FUNCTION_EXPR, UNIT_BUILTIN_TYPE,
                   ARG("value", STRING_BUILTIN_TYPE));
  BUILTIN_FUNCTION(EXIT_FUNCTION_EXPR, UNIT_BUILTIN_TYPE,
                   ARG("code", INT_BUILTIN_TYPE));
}

static Object eval_expr(Evaluator *evaluator, const Expression *expr);

static void eval_stmt_decl(Evaluator *evaluator, StmtDecl *stmt_decl) {
  OptionalType type = stmt_decl->type;
  if (stmt_decl->value.type == EXPR_VAR_REG_EXPR) {
    environment_add(
        evaluator->cur_env, stmt_decl->name,
        eval_expr(evaluator, &stmt_decl->value.var.expr_var_reg_expr));
  }
}

static void eval_stmt(Evaluator *evaluator, Statement *stmt);

static Object eval_expr_block(Evaluator *evaluator,
                              const ExprBlock *expr_block) {
  size_t len = array_len(expr_block->statements);
  for (size_t i = 0; i < len; i++) {
    if (i == len - 1) {
      Statement *stmt = &expr_block->statements[i];
      if (stmt->type == STMT_EXPR) {
        return eval_expr(evaluator, &stmt->var.stmt_expr.expr);
      } else {
        eval_stmt(evaluator, &expr_block->statements[i]);
      }
    } else {
      eval_stmt(evaluator, &expr_block->statements[i]);
    }
  }
  return UNIT_OBJ;
}

static Object eval_expr_call(Evaluator *evaluator, const ExprCall *expr_call) {
  Ident function = expr_call->function;
  if (strcmp(function, "println") == 0) {
    Object arg0 = eval_expr(evaluator, &expr_call->args[0]);
    if (arg0.type == OBJECT_STRING) {
      char *expr_string = arg0.var.obj_string;
      puts(expr_string);
      return UNIT_OBJ;
    } else {
      printf("Arg to println not a string\n");
    }
  } else if (strcmp(function, "exit") == 0) {
    Expression *arg0 = &expr_call->args[0];
    if (arg0->type == EXPR_INTEGER_LIT) {
      exit(arg0->var.expr_integer_literal.integer);
      return UNIT_OBJ;
    }
  }

  Object *value = environment_get(evaluator->cur_env, expr_call->function,
                                  evaluator->global_env);
  if (value != NULL && value->type == OBJECT_FUNCTION) {
    ObjectFunction obj_function = value->var.obj_function;
    Object return_value;
    // We create a new environment for the scope of the function
    evaluator_envs_push(evaluator);
    {
      // Push function arguments to environment in case there are any
      if (expr_call->args != NULL) {
        for (size_t i = 0; i < array_len(expr_call->args); i++) {
          environment_add(evaluator->cur_env, obj_function.args[i].ident,
                          eval_expr(evaluator, &expr_call->args[i]));
        }
      }
      return_value = eval_expr_block(evaluator, obj_function.block);
    }
    // We pop the scope of the function from the environment after it returns
    evaluator_envs_pop(evaluator);
    return return_value;
  } else {
    fprintf(stderr,
            "Invalid name: %s for function call (func-ptr: %p), type: %d\n",
            expr_call->function, value, value->type);
    exit(1);
  }
  return UNIT_OBJ;
}

static bool type_eq(const Type *a, const Type *b) {
  if (a->type != b->type)
    return false;

  switch (a->type) {
  case TYPE_IDENT: {
    return strcmp(a->var.type_ident, b->var.type_ident) == 0;
  }
  case TYPE_ARRAY: {
    bool sizes_match = false;
    if (a->var.type_array.variant == b->var.type_array.variant) {
      if (a->var.type_array.variant == TYPE_ARRAY_VARIANT_SIZED) {
        sizes_match = a->var.type_array.size == b->var.type_array.size;
      } else {
        sizes_match = true;
      }
    }
    return type_eq(a->var.type_array.type, b->var.type_array.type) &&
           sizes_match;
  }
  case TYPE_FUNCTION: {
    return false;
  }
  case TYPE_TUPLE: {
    // TODO: Implement this case
    bool tuple_types_match = false;
    return tuple_types_match;
  }
  case TYPE_UNIT: {
    return true;
  }
  }
}

// TODO: symbol_table should be char * -> Object

static Object eval_expr(Evaluator *evaluator, const Expression *expr) {
  switch (expr->type) {
  case EXPR_IDENT: {
    Object *value = environment_get(
        evaluator->cur_env, expr->var.expr_ident.ident, evaluator->global_env);
    if (value != NULL) {
      return *value;
    } else {
      fprintf(stderr, "Error: Unknown identifier: %s\n",
              expr->var.expr_ident.ident);
      exit(1);
    }
  }
  // TODO: Function types and expressions (maybe)
  case EXPR_FUNCTION: {
    ExprBlock *block = expr->var.expr_function.block;
    return (Object){
        .type = OBJECT_FUNCTION,
        .var = {.obj_function = {.args = expr->var.expr_function.desc.args,
                                 .block = block}}};
  }
  case EXPR_CALL: {
    ExprCall expr_call = expr->var.expr_call;
    return eval_expr_call(evaluator, &expr_call);
  }
  case EXPR_BLOCK: {
    return eval_expr_block(evaluator, &expr->var.expr_block);
  }
  case EXPR_STRING_LIT: {
    return (Object){
        .type = OBJECT_STRING,
        .var = {.obj_string = expr->var.expr_string_literal.string}};
  }
  case EXPR_INTEGER_LIT: {
    return (Object){.type = OBJECT_INT,
                    .var = {.obj_int = expr->var.expr_integer_literal.integer}};
  }
  case EXPR_CAST: {
    Expression *val = expr->var.expr_cast.expr;
    Object obj = eval_expr(evaluator, val);
    switch (obj.type) {
    case OBJECT_INT: {
      switch (expr->var.expr_cast.type.type) {
      case TYPE_IDENT: {
        if (type_eq(&expr->var.expr_cast.type, &STRING_BUILTIN_TYPE)) {
          char *string = malloc(32);
          sprintf(string, "%d", obj.var.obj_int);
          return (Object){.type = OBJECT_STRING, .var = {.obj_string = string}};
        } else if (type_eq(&expr->var.expr_cast.type, &INT_BUILTIN_TYPE)) {
          return obj;
        } else {
          fprintf(stderr,
                  "Casting to custom types is currently not supported\n");
          exit(1);
        }
      }
      default: {
        fprintf(stderr, "Casting is only supported for int and string types\n");
        exit(1);
      }
      }
    }
    case OBJECT_STRING: {
      switch (expr->var.expr_cast.type.type) {
      case TYPE_IDENT: {
        if (type_eq(&expr->var.expr_cast.type, &INT_BUILTIN_TYPE)) {
          return (Object){.type = OBJECT_INT,
                          .var = {.obj_int = atoi(obj.var.obj_string)}};
        } else if (type_eq(&expr->var.expr_cast.type, &STRING_BUILTIN_TYPE)) {
          return obj;
        } else {
          fprintf(stderr,
                  "Casting to custom types is currently not supported\n");
          exit(1);
        }
      }
      default: {
        fprintf(stderr, "Casting is only supported for int and string types\n");
        exit(1);
      }
      }
    }
    case OBJECT_UNIT: {
      return UNIT_OBJ;
    }
    case OBJECT_FUNCTION: {
      break;
    }
    }
    fprintf(stderr, "Invalid cast\n");
    exit(1);
  }
  case EXPR_GENERIC_CALL: {
    ExprCall expr_call = expr->var.expr_generic_call.expr_call;
    printf("Evaluating generic call\n");
    return eval_expr_call(evaluator, &expr_call);
  }
  case EXPR_ARRAY: {
    return UNIT_OBJ;
  }
  case EXPR_UNIT: {
    return UNIT_OBJ;
  }
  }
}

static void eval_stmt(Evaluator *evaluator, Statement *stmt) {
  switch (stmt->type) {
  case STMT_DECL: {
    eval_stmt_decl(evaluator, &stmt->var.stmt_decl);
    break;
  }
  case STMT_EXPR: {
    Expression expr = stmt->var.stmt_expr.expr;
    eval_expr(evaluator, &expr);
    break;
  }
  }
}

static void eval(Evaluator *evaluator) {
  for (size_t i = 0; i < array_len(evaluator->stmts); i++) {
    eval_stmt(evaluator, &evaluator->stmts[i]);
  }
}

typedef struct {
  ExpressionVariant expr_variant;
  OptionalType opt_type;
} TypeTableValue;

typedef struct {
  Ident *symbols;
  TypeTableValue *values;
} TypeTable;

typedef struct {
  Statement *stmts;

  // Works like environemnts in the evaluator but for type checking
  TypeTable *type_tables;
  TypeTable *cur_type_table;
  TypeTable *global_type_table;
} TypeChecker;

static void type_table_add(TypeTable *table, Ident ident,
                           ExpressionVariant expr_var, OptionalType opt_type) {
  TypeTableValue val = {.expr_variant = expr_var, .opt_type = opt_type};
  array_add(table->symbols, ident);
  array_add(table->values, val);
}

static TypeTableValue *type_table_get(TypeTable *table, Ident ident,
                                      TypeTable *global_table) {
  for (size_t i = 0; i < array_len(table->symbols); i++) {
    if (strcmp(table->symbols[i], ident) == 0) {
      return &table->values[i];
    }
  }

  if (global_table != NULL) {
    for (size_t i = 0; i < array_len(global_table->symbols); i++) {
      if (strcmp(global_table->symbols[i], ident) == 0) {
        return &global_table->values[i];
      }
    }
  }

  return NULL;
}

static void checker_type_table_push(TypeChecker *checker) {
  array_add(checker->type_tables,
            (TypeTable){.symbols = array_new(Ident, &HEAP_ALLOCATOR),
                        .values = array_new(TypeTableValue, &HEAP_ALLOCATOR)});
  checker->cur_type_table++;
}

static void checker_type_table_pop(TypeChecker *checker) {
  size_t len = array_len(checker->type_tables);
  if (len == 1) {
    // We don't want to pop the global env
    return;
  } else if (len == 0) {
    fprintf(stderr, "Checker type table is empty.");
    exit(1);
  }

  TypeTable last_table = checker->type_tables[len - 1];
  _internal_array_set_len(checker->type_tables, len - 1);
  array_free(last_table.symbols);
  array_free(last_table.values);
  checker->cur_type_table--;
}

static Type check_stmt(TypeChecker *checker, Statement *stmt);

static Type check_expr(TypeChecker *checker, Expression *expr);

// Returns the name of the correct function
static Ident resolve_overloaded_function(TypeChecker *checker,
                                         ExprCall *expr_call) {
  Type *call_arg_types = array_new(Type, &HEAP_ALLOCATOR);
  for (size_t i = 0; i < array_len(expr_call->args); i++) {
    array_add(call_arg_types, check_expr(checker, &expr_call->args[i]));
  }

  TypeTableValue *type_val = type_table_get(
      checker->cur_type_table, expr_call->function, checker->global_type_table);
  if (type_val != NULL) {
    if (type_val->expr_variant.type == TYPE_EXPR_OVERLOAD_SET) {
      TypeExprOverloadSet overload_set =
          type_val->expr_variant.var.expr_var_type_expr.var
              .type_expr_overload_set;
      size_t i;
      for (i = 0; i < array_len(overload_set.functions); i++) {
        Ident ident = overload_set.functions[i];
        TypeTableValue *value = type_table_get(checker->cur_type_table, ident,
                                               checker->global_type_table);
        if (value != NULL) {
          ExpressionVariant expr_var = value->expr_variant;
          if (expr_var.type == EXPR_VAR_REG_EXPR) {
            Expression overloaded_function = expr_var.var.expr_var_reg_expr;
            if (overloaded_function.type == EXPR_FUNCTION) {
              ExprFunction overloaded_func_expr =
                  overloaded_function.var.expr_function;
              TypedIdent *args = overloaded_func_expr.desc.args;
              for (size_t i = 0; i < array_len(args); i++) {
                if (array_len(call_arg_types) != array_len(args) ||
                    !(i < array_len(call_arg_types) &&
                      type_eq(&call_arg_types[i], &args[i].type))) {
                  goto end_of_outerloop;
                }
              }
              break;
            } else {
              fprintf(stderr, "Symbol is not a function: %s\n", ident);
              exit(1);
            }
          } else {
            fprintf(stderr, "Nested overloads are not supported atm\n");
            exit(1);
          }
        } else {
          fprintf(stderr, "Could not find symbol: %s\n", ident);
          exit(1);
        }
      end_of_outerloop: {}
      }
      Ident resolved_func_ident = overload_set.functions[i];
      return resolved_func_ident;
    } else {
      printf("Type val not overload set: %s\n", expr_call->function);
    }
  } else {
    printf("Type value null\n");
  }
  fprintf(stderr, "Could not find function with name: %s\n",
          expr_call->function);
  exit(1);
}

static void type_table_dump(const TypeTable *type_table) {
  for (size_t i = 0; i < array_len(type_table->symbols); i++) {
    TypeTableValue val = type_table->values[i];
    if (val.opt_type.present) {
      char type_buf[1024];
      type_print(type_buf, &val.opt_type.type);
      printf("Key: %s, Val: %s\n", type_table->symbols[i], type_buf);
    }
  }
}

static Type check_call_expr(TypeChecker *checker, ExprCall *expr_call) {
  TypeTableValue *val = type_table_get(
      checker->cur_type_table, expr_call->function, checker->global_type_table);
  ExprFunction expr_function;

  if (val != NULL) {
    if (val->expr_variant.type != EXPR_VAR_REG_EXPR) {
      Ident resolved_overload_function =
          resolve_overloaded_function(checker, expr_call);
      expr_call->function = resolved_overload_function;
      expr_function =
          type_table_get(checker->cur_type_table, resolved_overload_function,
                         checker->global_type_table)
              ->expr_variant.var.expr_var_reg_expr.var.expr_function;
    } else {
      if (val->expr_variant.var.expr_var_reg_expr.type == EXPR_FUNCTION) {
        expr_function =
            val->expr_variant.var.expr_var_reg_expr.var.expr_function;
      } else {
        fprintf(stderr, "Expr is not a function\n");
        exit(1);
      }
    }
  } else {
    fprintf(stderr, "Could not find symbol %s\n", expr_call->function);
    exit(1);
  }

  size_t args_len = array_len(expr_call->args);
  size_t func_args_len = 0;
  if (expr_function.desc.args != NULL) {
    func_args_len = array_len(expr_function.desc.args);
  }
  if (args_len != func_args_len) {
    fprintf(stderr,
            "Type error: Arg count for caller (%zu) and function (%zu) do not "
            "match, "
            "function: %s\n",
            args_len, func_args_len, expr_call->function);
    exit(1);
  }
  for (size_t i = 0; i < args_len; i++) {
    Type arg_type = check_expr(checker, &expr_call->args[i]);
    if (!type_eq(&arg_type, &expr_function.desc.args[i].type)) {
      type_table_dump(checker->cur_type_table);
      char caller_arg_type_buf[512];
      type_print(caller_arg_type_buf, &arg_type);
      char func_arg_type_buf[512];
      type_print(func_arg_type_buf, &expr_function.desc.args[i].type);
      fprintf(
          stderr,
          "Type error: Arg type of caller (%s) and function (%s) do not match, "
          "function: %s, "
          "arg: %zu\n",
          caller_arg_type_buf, func_arg_type_buf, expr_call->function, i);
      exit(1);
    }
  }
  return expr_function.desc.ret_type;
}

// TODO: Create a type table ident -> type
static Type check_expr(TypeChecker *checker, Expression *expr) {
  switch (expr->type) {
  case EXPR_ARRAY: {
    Type *expected_item_type = expr->var.expr_array.type.type;
    size_t declared_items_len = array_len(expr->var.expr_array.items);
    for (size_t i = 0; i < declared_items_len; i++) {
      Type item_type = check_expr(checker, &expr->var.expr_array.items[i]);
      if (!type_eq(&item_type, expected_item_type)) {
        fprintf(stderr, "Type error: Expected and provided array item types do "
                        "not match\n");
        exit(1);
      }
    }
    return (Type){.type = TYPE_ARRAY,
                  .var = {.type_array = expr->var.expr_array.type}};
  }
  case EXPR_FUNCTION: {
    // TODO: implement function types
    ExprFunction expr_function = expr->var.expr_function;
    checker_type_table_push(checker);
    {
      for (size_t i = 0; i < array_len(expr_function.desc.args); i++) {
        Type type = expr_function.desc.args[i].type;
        char print_buf[1024];
        type_print(print_buf, &type);
        //printf("arg (%zu, %s) type: %s\n", i, expr_function.desc.args[i].ident,
        //       print_buf);
        type_table_add(
            checker->cur_type_table, expr_function.desc.args[i].ident,
            (ExpressionVariant){.type = EXPR_VAR_REG_EXPR,
                                .var = {.expr_var_reg_expr = UNIT_EXPR}},
            (OptionalType){.type = type, .present = true});
      }

      for (size_t i = 0; i < array_len(expr_function.block->statements); i++) {
        check_stmt(checker, &expr_function.block->statements[i]);
      }
    }
    checker_type_table_pop(checker);
    return UNIT_BUILTIN_TYPE;
  }
  case EXPR_BLOCK: {
    if (expr->var.expr_block.statements != NULL) {
      size_t len = array_len(expr->var.expr_block.statements);
      Type last_type = UNIT_BUILTIN_TYPE;
      for (size_t i = 0; i < len; i++) {
        Statement stmt = expr->var.expr_block.statements[i];
        last_type = check_stmt(checker, &stmt);
      }
      return last_type;
    }
    return UNIT_BUILTIN_TYPE;
  }
  case EXPR_CALL: {
    return check_call_expr(checker, &expr->var.expr_call);
  }
  case EXPR_CAST: {
    Type expr_type = check_expr(checker, expr->var.expr_cast.expr);
    Type cast_type = expr->var.expr_cast.type;
    if (type_eq(&expr_type, &cast_type))
      goto return_type;
    if (type_eq(&expr_type, &STRING_BUILTIN_TYPE) &&
            type_eq(&cast_type, &INT_BUILTIN_TYPE) ||
        type_eq(&cast_type, &STRING_BUILTIN_TYPE) &&
            type_eq(&expr_type, &INT_BUILTIN_TYPE)) {
    } else {
      fprintf(stderr, "Cannot cast expr to this type\n");
    }
  return_type:
    return expr->var.expr_cast.type;
  }
  case EXPR_STRING_LIT: {
    return STRING_BUILTIN_TYPE;
  }
  case EXPR_INTEGER_LIT: {
    return INT_BUILTIN_TYPE;
  }
  case EXPR_IDENT: {
    TypeTableValue *val =
        type_table_get(checker->cur_type_table, expr->var.expr_ident.ident,
                       checker->global_type_table);
    if (val != NULL) {

      if (val->opt_type.present) {
        return val->opt_type.type;
      } else if (val->expr_variant.type == EXPR_VAR_REG_EXPR) {
        return check_expr(checker, &val->expr_variant.var.expr_var_reg_expr);
      } else {
        fprintf(stderr, "Could not find expression with symbol: %s",
                expr->var.expr_ident.ident);
        exit(1);
      }
    }
  }
  case EXPR_GENERIC_CALL: {
    // TODO: More advanced checking (does generic definition contain bounds for
    // method call)
    return check_call_expr(checker, &expr->var.expr_generic_call.expr_call);
  }
  case EXPR_UNIT: {
    return UNIT_BUILTIN_TYPE;
  }
  }
}

#define EXPR_VAR_TYPE(expr)                                                    \
  (ExpressionVariant) {                                                        \
    .type = EXPR_VAR_TYPE_EXPR, .var = {.expr_var_type_expr = expr }           \
  }

#define EXPR_VAR_EXPR(expr)                                                    \
  (ExpressionVariant) {                                                        \
    .type = EXPR_VAR_REG_EXPR, .var = {.expr_var_reg_expr = expr }             \
  }

static Type check_stmt(TypeChecker *checker, Statement *stmt) {
  char print_buf[1024];
  stmt_print(print_buf, stmt);
  switch (stmt->type) {
  case STMT_DECL: {
    OptionalType opt_type = stmt->var.stmt_decl.type;
    if (stmt->var.stmt_decl.value.type != EXPR_VAR_TYPE_EXPR) {
      Type value_type =
          check_expr(checker, &stmt->var.stmt_decl.value.var.expr_var_reg_expr);

      if (opt_type.present) {
        if (!type_eq(&value_type, &opt_type.type)) {
          fprintf(
              stderr,
              "Type error: Type of declaration and value do not match, decl "
              "name: %s\n",
              stmt->var.stmt_decl.name);
          exit(1);
        }
      } else {
        opt_type.type = value_type;
        opt_type.present = true;
      }
    }

    if (stmt->var.stmt_decl.value.type == EXPR_VAR_REG_EXPR) {
      type_table_add(
          checker->cur_type_table, stmt->var.stmt_decl.name,
          (ExpressionVariant){
              .type = EXPR_VAR_REG_EXPR,
              .var = {.expr_var_reg_expr =
                          stmt->var.stmt_decl.value.var.expr_var_reg_expr}},
          opt_type);
    } else {
      type_table_add(
          checker->cur_type_table, stmt->var.stmt_decl.name,
          EXPR_VAR_TYPE(stmt->var.stmt_decl.value.var.expr_var_type_expr),
          opt_type);
    }

    return UNIT_BUILTIN_TYPE;
  }
  case STMT_EXPR: {
    return check_expr(checker, &stmt->var.stmt_expr.expr);
  }
  }
}

static void check(TypeChecker *checker) {
  for (size_t i = 0; i < array_len(checker->stmts); i++) {
    check_stmt(checker, &checker->stmts[i]);
  }
}

static const OptionalType EMPTY_OPT_TYPE = (OptionalType){.present = false};

int main(void) {
  alloc_init();
  builtin_functions_init();

  char file_buf[4096];
  FILE *file = fopen("test.goo", "r");
  size_t n = fread(file_buf, 1, sizeof(file_buf) - 1, file);
  file_buf[n] = '\0';

  printf("File: %s\n", file_buf);

  Lexer lexer = {.tokens = array_new(Token, &HEAP_ALLOCATOR)};

  tokenize(&lexer, file_buf);
  array_add(lexer.tokens, (Token){.type = TOKEN_EOF});

  // for (size_t i = 0; i < array_len(lexer.tokens); i++) {
  //   tok_print(&lexer.tokens[i]);
  // }

  Parser parser = {.tokens = lexer.tokens,
                   .statements = array_new(Statement, &HEAP_ALLOCATOR)};

  parse(&parser);

  for (size_t i = 0; i < array_len(parser.statements); i++) {
    char print_buf[8192] = {'\0'};
    stmt_print(print_buf, &parser.statements[i]);
    puts(print_buf);
  }

  puts("");

  TypeTable *type_tables = array_new(TypeTable, &HEAP_ALLOCATOR);
  TypeChecker checker = {.stmts = parser.statements,
                         .type_tables = type_tables};
  // Push the global type table
  checker_type_table_push(&checker);
  checker.global_type_table = &checker.type_tables[0];
  checker.cur_type_table = checker.global_type_table;

  type_table_add(checker.global_type_table, "println",
                 EXPR_VAR_EXPR(PRINTLN_FUNCTION_EXPR), EMPTY_OPT_TYPE);
  type_table_add(checker.global_type_table, "exit",
                 EXPR_VAR_EXPR(EXIT_FUNCTION_EXPR), EMPTY_OPT_TYPE);

  check(&checker);

  puts("-- -- --");

  Environment *environments = array_new(Environment, &HEAP_ALLOCATOR);
  Evaluator evaluator = {
      .stmts = checker.stmts,
      .environments = environments,
  };
  // Push the global env
  evaluator_envs_push(&evaluator);
  // Do proper assigning
  evaluator.global_env = &evaluator.environments[0];
  evaluator.cur_env = evaluator.global_env;

  for (size_t i = 0; i < array_len(checker.global_type_table->symbols); i++) {
    TypeTableValue val = checker.global_type_table->values[i];
    if (val.expr_variant.type == EXPR_VAR_REG_EXPR) {
      environment_add(
          evaluator.global_env, checker.global_type_table->symbols[i],
          eval_expr(&evaluator, &val.expr_variant.var.expr_var_reg_expr));
    }
  }

  // for (size_t i = 0;
  //      i < array_len(checker.symbol_table_overloaded_funcs.symbols); i++)
  //      {
  //   symbol_table_expr_insert(&evaluator.table,
  //                            checker.symbol_table_overloaded_funcs.symbols[i],
  //                            checker.symbol_table_overloaded_funcs.values[i]);
  // }

  Expression call_main_expr = {
      .type = EXPR_CALL,
      .var = {.expr_call = {.function = "main", .args = NULL}}};
  eval_expr(&evaluator, &call_main_expr);

  // for (size_t i = 0; i < array_len(evaluator.table.symbols); i++) {
  //   printf("Symbol: %s -> Value: \n", evaluator.table.symbols[i]);
  //   char print_buf[256];
  //   expr_print(print_buf, &evaluator.table.values[i]);
  //   puts(print_buf);
  // }
}
