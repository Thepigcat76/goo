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
      tok.type = TOKEN_IDENT;
      tok.var.ident = malloc(strlen(ident) + 1); // heap-owned copy
      if (first_ident == NULL)
        first_ident = tok.var.ident;
      strcpy(tok.var.ident, ident);
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

typedef struct _expr {
  enum {
    EXPR_ARRAY,
    EXPR_FUNCTION,
    EXPR_BLOCK,
    EXPR_CALL,
    EXPR_STRING_LIT,
    EXPR_INTEGER_LIT,
    EXPR_IDENT,
  } type;
  union {
    ExprArray expr_array;
    ExprFunction expr_function;
    ExprBlock expr_block;
    ExprCall expr_call;
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

typedef struct {
  Type type;
  bool present;
} OptionalType;

typedef struct {
  Ident name;
  OptionalType type;
  Expression value;
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
  }
}

static void stmt_print(char *buf, const Statement *stmt) {
  switch (stmt->type) {
  case STMT_DECL: {
    char expr_buf[1024];
    expr_print(expr_buf, &stmt->var.stmt_decl.value);
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
      Expression value = parse_expr(parser);
      Statement stmt = {
          .type = STMT_DECL,
          .var = {
              .stmt_decl = {.name = name, .mutable = mutable, .value = value}}};
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
      stmt_decl.value = value;
      return (Statement){.type = STMT_DECL, .var = {.stmt_decl = stmt_decl}};
    } else {
      goto parse_expr;
    }
    exit(1);
  }
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

typedef struct {
  Expression expr;
  OptionalType type;
} SymbolTableValue;

#define SYMBOL_TABLE_VAL(_expr, _type)                                         \
  (SymbolTableValue) { .expr = _expr, .type = _type }

typedef struct {
  char **symbols;
  SymbolTableValue *values;
} SymbolTable;

typedef struct {
  Statement *stmts;

  SymbolTable table;
} Evaluator;

typedef struct {
  TypedIdent *args;
  ExprBlock block;
} ObjectFunction;

typedef struct {
  enum {
    OBJECT_INT,
    OBJECT_STRING,
    OBJECT_FUNCTION,
    OBJECT_NULL,
  } type;
  union {
    int obj_int;
    char *obj_string;
    ObjectFunction obj_function;
  } var;
} Object;

static const Object NULL_OBJ = {.type = OBJECT_NULL};

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

static void symbol_table_insert(SymbolTable *table, const char *symbol,
                                SymbolTableValue value) {
  array_add(table->symbols, symbol);
  array_add(table->values, value);
}

static SymbolTableValue *symbol_table_get(SymbolTable *table,
                                          const char *symbol) {
  for (size_t i = 0; i < array_len(table->symbols); i++) {
    if (strcmp(table->symbols[i], symbol) == 0) {
      return &table->values[i];
    }
  }
  return NULL;
}

static void eval_stmt_decl(Evaluator *evaluator, StmtDecl *stmt_decl) {
  OptionalType type = stmt_decl->type;
  symbol_table_insert(&evaluator->table, stmt_decl->name,
                      SYMBOL_TABLE_VAL(stmt_decl->value, type));
}

static void eval_stmt(Evaluator *evaluator, Statement *stmt);

static Object eval_expr(Evaluator *evaluator, const Expression *expr);

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
  return NULL_OBJ;
}

static Object eval_expr_function(Evaluator *evaluator,
                                 const ExprFunction *expr_function) {
  return eval_expr_block(evaluator, expr_function->block);
}

static Object eval_expr_call(Evaluator *evaluator, const ExprCall *expr_call) {
  Ident function = expr_call->function;
  if (strcmp(function, "println") == 0) {
    Object arg0 = eval_expr(evaluator, &expr_call->args[0]);
    if (arg0.type == OBJECT_STRING) {
      char *expr_string = arg0.var.obj_string;
      puts(expr_string);
      return NULL_OBJ;
    } else {
      printf("Arg to println not a string\n");
    }
  } else if (strcmp(function, "exit") == 0) {
    Expression *arg0 = &expr_call->args[0];
    if (arg0->type == EXPR_INTEGER_LIT) {
      exit(arg0->var.expr_integer_literal.integer);
      return NULL_OBJ;
    }
  }

  SymbolTableValue *value =
      symbol_table_get(&evaluator->table, expr_call->function);
  if (value->expr.type == EXPR_FUNCTION) {
    return eval_expr_function(evaluator, &value->expr.var.expr_function);
  }
  return NULL_OBJ;
}

// TODO: symbol_table should be char * -> Object

static Object eval_expr(Evaluator *evaluator, const Expression *expr) {
  switch (expr->type) {
  case EXPR_IDENT: {
    return eval_expr(
        evaluator,
        &symbol_table_get(&evaluator->table, expr->var.expr_ident.ident)->expr);
  }
  case EXPR_FUNCTION: {
    return eval_expr_function(evaluator, &expr->var.expr_function);
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
  case EXPR_ARRAY:
    return NULL_OBJ;
  }
}

static void eval_stmt(Evaluator *evaluator, Statement *stmt) {
  switch (stmt->type) {
  case STMT_DECL: {
    StmtDecl stmt_decl = stmt->var.stmt_decl;
    eval_stmt_decl(evaluator, &stmt_decl);
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
  Statement *stmts;
  SymbolTable symbol_table;
} TypeChecker;

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

static Type check_stmt(TypeChecker *checker, Statement *stmt);

static void symbol_table_print_symbols(SymbolTable *table) {
  for (size_t i = 0; i < array_len(table->symbols); i++) {
    printf("Symbol table %zu: %s\n", i, table->symbols[i]);
  }
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
        fprintf(stderr,
                "Expected and provided array item types do not match\n");
        exit(1);
      }
    }
    return (Type){.type = TYPE_ARRAY,
                  .var = {.type_array = expr->var.expr_array.type}};
  }
  case EXPR_FUNCTION: {
    // TODO: implement function types
    Expression block_expr = {
        .type = EXPR_BLOCK,
        .var = {.expr_block = expr->var.expr_function.block->statements}};
    check_expr(checker, &block_expr);
    return UNIT_BUILTIN_TYPE;
  }
  case EXPR_BLOCK: {
    size_t len = array_len(expr->var.expr_block.statements);
    Type last_type = UNIT_BUILTIN_TYPE;
    for (size_t i = 0; i < len; i++) {
      Statement stmt = expr->var.expr_block.statements[i];
      last_type = check_stmt(checker, &stmt);
    }
    return last_type;
  }
  case EXPR_CALL: {
    ExprFunction expr_function =
        symbol_table_get(&checker->symbol_table, expr->var.expr_call.function)
            ->expr.var.expr_function;
    size_t args_len = array_len(expr->var.expr_call.args);
    if (args_len != array_len(expr_function.desc.args)) {
      fprintf(stderr,
              "Arg count for caller and function do not match, function: %s\n",
              expr->var.expr_call.function);
      exit(1);
    }
    for (size_t i = 0; i < args_len; i++) {
      Type arg_type = check_expr(checker, &expr->var.expr_call.args[i]);
      if (!type_eq(&arg_type, &expr_function.desc.args[i].type)) {
        fprintf(stderr,
                "Arg type of caller and function do not match, function: %s, "
                "arg: %zu\n",
                expr->var.expr_call.function, i);
        exit(1);
      }
    }
    return expr_function.desc.ret_type;
  }
  case EXPR_STRING_LIT: {
    return STRING_BUILTIN_TYPE;
  }
  case EXPR_INTEGER_LIT: {
    return INT_BUILTIN_TYPE;
  }
  case EXPR_IDENT: {
    SymbolTableValue *expr1 =
        symbol_table_get(&checker->symbol_table, expr->var.expr_ident.ident);
    return check_expr(checker, &expr1->expr);
  }
  }
}

static Type check_stmt(TypeChecker *checker, Statement *stmt) {
  switch (stmt->type) {
  case STMT_DECL: {
    Type value_type = check_expr(checker, &stmt->var.stmt_decl.value);

    OptionalType opt_type = stmt->var.stmt_decl.type;
    if (opt_type.present) {
      if (!type_eq(&value_type, &opt_type.type)) {
        fprintf(stderr,
                "Type of declaration and value do not match, decl name: %s\n",
                stmt->var.stmt_decl.name);
        exit(1);
      }
    } else {
      opt_type.type = value_type;
      opt_type.present = true;
    }
    symbol_table_insert(&checker->symbol_table, stmt->var.stmt_decl.name,
                        SYMBOL_TABLE_VAL(stmt->var.stmt_decl.value, opt_type));
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

  TypeChecker checker = {
      .stmts = parser.statements,
      .symbol_table = {.symbols = array_new(char *, &HEAP_ALLOCATOR),
                       .values = array_new(SymbolTableValue, &HEAP_ALLOCATOR)}};

  symbol_table_insert(
      &checker.symbol_table, "println",
      SYMBOL_TABLE_VAL(PRINTLN_FUNCTION_EXPR, UNIT_BUILTIN_TYPE));
  symbol_table_insert(&checker.symbol_table, "exit",
                      SYMBOL_TABLE_VAL(EXIT_FUNCTION_EXPR, UNIT_BUILTIN_TYPE));

  check(&checker);

  puts("-- -- --");

  Evaluator evaluator = {.stmts = checker.stmts, .table = checker.symbol_table};
  eval(&evaluator);

  // for (size_t i = 0; i < array_len(evaluator.table.symbols); i++) {
  //   printf("Symbol: %s -> Value: \n", evaluator.table.symbols[i]);
  //   char print_buf[256];
  //   expr_print(print_buf, &evaluator.table.values[i]);
  //   puts(print_buf);
  // }
}