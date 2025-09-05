#include "alloc.h"
#include "array.h"
#include <ctype.h>
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
  TOKEN_ARROW,
  TOKEN_COMMA,
  TOKEN_DOT,
  TOKEN_PLUS,
  TOKEN_MINUS,
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
    } else {
      printf("%c", *lexer->cur_char);
      tok = (Token){.type = TOKEN_ILLEGAL};
    }
    array_add(lexer->tokens, tok);
    next_char(lexer);
    // tok_print(&tok);
    // printf("First token: %s\n", first_ident);
  }
}

typedef char *Ident;

typedef Ident Type;

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

typedef struct _expr {
  enum {
    EXPR_FUNCTION,
    EXPR_STRING_LIT,
    EXPR_INTEGER_LIT,
    EXPR_CALL,
    EXPR_BLOCK,
  } type;
  union {
    ExprFunction expr_function;
    ExprBlock expr_block;
    struct {
      char *string;
    } expr_string_literal;
    struct {
      int integer;
    } expr_integer_literal;
    ExprCall expr_call;
  } var;
} Expression;

typedef struct {
  Ident name;
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
      sprintf(arg_buf, "Type{type=%s}", desc->arg_types[i]);
      strcat(args_buf, arg_buf);
      strcat(args_buf, ", ");
    }
    if (array_len(desc->arg_types) >= 1) {
      args_buf[strlen(args_buf) - 2] = '\0';
    }
  }
  sprintf(buf, "FuncSignature{name=%s, generics=[%s], args=[%s], ret_type=%s}",
          desc->name, generics_buf, args_buf, desc->ret_type);
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
  sprintf(buf, "TypedIdent{ident=%s, type=%s}", ident->ident, ident->type);
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
  sprintf(buf, "FuncDescriptor{generics=[%s], args=[%s], ret_type=%s}",
          generics_buf, args_buf, desc->ret_type);
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
  }
  }
}

static void stmt_print(char *buf, const Statement *stmt) {
  switch (stmt->type) {
  case STMT_DECL: {
    char expr_buf[1024];
    expr_print(expr_buf, &stmt->var.stmt_decl.value);
    sprintf(buf, "StmtDecl{name=%s, mutable=%s, value=%s}",
            stmt->var.stmt_decl.name,
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
      ti.type = parser->cur_tok->var.ident;
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
      t = parser->cur_tok->var.ident;
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
      signature.ret_type = parser->cur_tok->var.ident;
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
      desc.ret_type = parser->cur_tok->var.ident;
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
    Ident function = parser->cur_tok->var.ident;
    if (parser->peek_tok->type == TOKEN_LPAREN) {
      // cur_tok is left parenthesis
      next_token(parser);
      // cur_tok is first expr
      next_token(parser);

      Expression *exprs = parse_expr_list(parser, TOKEN_RPAREN);
      // end: right parenthesis
      return (Expression){
          .type = EXPR_CALL,
          .var = {.expr_call = {.function = function, .args = exprs}}};
    }
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
  case TOKEN_ILLEGAL: {
    printf("nyi/illegal token\n");
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
    } else if (parser->peek_tok->type == TOKEN_LPAREN) {
      goto parse_expr;
    }
    exit(1);
  }
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
  char **symbols;
  Expression *values;
} SymbolTable;

typedef struct {
  Statement *cur_stmt;
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

static Object OBJ_NULL = {.type = OBJECT_NULL};

static void symbol_table_insert(SymbolTable *table, const char *symbol,
                                Expression value) {
  array_add(table->symbols, symbol);
  array_add(table->values, value);
}

static Expression *symbol_table_get(SymbolTable *table, const char *symbol) {
  for (size_t i = 0; i < array_len(table->symbols); i++) {
    if (strcmp(table->symbols[i], symbol) == 0) {
      return &table->values[i];
    }
  }
  return NULL;
}

static void eval_stmt_decl(Evaluator *evaluator, StmtDecl *stmt_decl) {
  symbol_table_insert(&evaluator->table, stmt_decl->name, stmt_decl->value);
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
  return OBJ_NULL;
}

static Object eval_expr_function(Evaluator *evaluator,
                                 const ExprFunction *expr_function) {
  return eval_expr_block(evaluator, expr_function->block);
}

static Object eval_expr_call(Evaluator *evaluator, const ExprCall *expr_call) {
  Ident function = expr_call->function;
  if (strcmp(function, "println") == 0) {
    Expression *arg0 = &expr_call->args[0];
    if (arg0->type == EXPR_STRING_LIT) {
      char *expr_string = arg0->var.expr_string_literal.string;
      puts(expr_string);
      return OBJ_NULL;
    } else {
      printf("Arg to println not a string\n");
    }
  } else if (strcmp(function, "exit") == 0) {
    Expression *arg0 = &expr_call->args[0];
    if (arg0->type == EXPR_INTEGER_LIT) {
      exit(arg0->var.expr_integer_literal.integer);
      return OBJ_NULL;
    }
  }

  Expression *expr = symbol_table_get(&evaluator->table, expr_call->function);
  char print_buf[2048];
  expr_print(print_buf, expr);
  puts(print_buf);
  if (expr->type == EXPR_FUNCTION) {
    return eval_expr_function(evaluator, &expr->var.expr_function);
  }
  return OBJ_NULL;
}

static Object eval_expr(Evaluator *evaluator, const Expression *expr) {
  switch (expr->type) {
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
  evaluator->cur_stmt = evaluator->stmts;

  eval_stmt(evaluator, evaluator->cur_stmt++);
  eval_stmt(evaluator, evaluator->cur_stmt++);
  eval_stmt(evaluator, evaluator->cur_stmt);
}

int main(void) {
  alloc_init();

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

  // for (size_t i = 0; i < array_len(parser.statements); i++) {
  //   char print_buf[8192] = {'\0'};
  //   stmt_print(print_buf, &parser.statements[i]);
  //   puts(print_buf);
  // }

  puts("-- -- --");

  Evaluator evaluator = {
      .stmts = parser.statements,
      .table = {.symbols = array_new(char *, &HEAP_ALLOCATOR),
                .values = array_new(Expression, &HEAP_ALLOCATOR)}};
  eval(&evaluator);

  // for (size_t i = 0; i < array_len(evaluator.table.symbols); i++) {
  //   printf("Symbol: %s -> Value: \n", evaluator.table.symbols[i]);
  //   char print_buf[256];
  //   expr_print(print_buf, &evaluator.table.values[i]);
  //   puts(print_buf);
  // }
}