#include "alloc.h"
#include "array.h"
#include <stdbool.h>
#include <stdio.h>

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

static void tokenize(Lexer *lexer, const char *src) {
  lexer->cur_char = src;

  while (*lexer->cur_char + 1 != '\0') {
    Token tok;
    if (*lexer->cur_char == ' ' || *lexer->cur_char == '\n') {
      do {
        next_char(lexer);
      } while (*lexer->cur_char == ' ');
      continue;
    } else if (*lexer->cur_char == '\0') {
      return;
    } else if ((*lexer->cur_char >= 'a' && *lexer->cur_char <= 'z') ||
               (*lexer->cur_char >= 'A' && *lexer->cur_char <= 'Z') ||
               *lexer->cur_char == '_') {
      char *ident = malloc(256 * sizeof(char));
      size_t i = 0;
      do {
        ident[i++] = *lexer->cur_char;
        next_char(lexer);
      } while ((*lexer->cur_char >= 'a' && *lexer->cur_char <= 'z') ||
               (*lexer->cur_char >= 'A' && *lexer->cur_char <= 'Z') ||
               *lexer->cur_char == '_');
      lexer->cur_char--;
      ident[i] = '\0';
      tok = (Token){.type = TOKEN_IDENT, .var = {.ident = ident}};
    } else if (*lexer->cur_char == '"') {
      char *string = malloc(256 * sizeof(char));
      next_char(lexer);
      size_t i = 0;
      while (*lexer->cur_char != '"') {
        string[i++] = *lexer->cur_char;
        next_char(lexer);
      }
      tok = (Token){.type = TOKEN_STRING, .var = {.string = string}};
    } else if (*lexer->cur_char >= '0' && *lexer->cur_char <= '9') {
      char *int_lit = malloc(256);
      size_t i = 0;
      do {
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
    } else {
      tok = (Token){.type = TOKEN_ILLEGAL};
    }
    array_add(lexer->tokens, tok);
    tok_print(&lexer->tokens[array_len(lexer->tokens) - 1]);
    next_char(lexer);
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

typedef struct _generic {
  Ident name;
  FuncDescriptor *bounds;
} Generic;

typedef struct _expr {
  enum {
    EXPR_FUNCTION,
    EXPR_STRING_LIT,
    EXPR_INTEGER_LIT,
    EXPR_CALL,
    EXPR_BLOCK,
  } type;
  union {
    struct {
      FuncDescriptor desc;
      struct _expr *block;
    } expr_function;
    struct {
      char *string;
    } expr_string_literal;
    struct {
      int integer;
    } expr_integer_literal;
    struct {
      Ident function;
      struct _expr *args;
    } expr_call;
    struct {
      struct _stmt *statements;
    } expr_block;
  } var;
} Expression;

typedef struct _stmt {
  enum {
    STMT_DECL,
    STMT_EXPR,
  } type;
  union {
    struct {
      Ident name;
      Expression value;
      bool mutable;
    } stmt_decl;
    struct {
      Expression expr;
    } stmt_expr;
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

static void expr_print(const Expression *expr, int indent);

static void indent_print(int indent) {
  for (int i = 0; i < indent; i++) {
    putchar(' ');
  }
}

static void stmt_print(const Statement *stmt, int indent) {
  indent_print(indent);
  switch (stmt->type) {
  case STMT_DECL:
    printf("STMT_DECL{name=%s, mutable=%s, value=\n", stmt->var.stmt_decl.name,
           stmt->var.stmt_decl.mutable ? "true" : "false");
    expr_print(&stmt->var.stmt_decl.value, indent + 2);
    indent_print(indent);
    printf("}\n");
    break;

  case STMT_EXPR:
    printf("STMT_EXPR{expr=\n");
    expr_print(&stmt->var.stmt_expr.expr, indent + 2);
    indent_print(indent);
    printf("}\n");
    break;
  }
}

static void expr_print(const Expression *expr, int indent) {
  indent_print(indent);
  switch (expr->type) {
  case EXPR_FUNCTION:
    printf("EXPR_FUNCTION{desc=..., block=\n");
    if (expr->var.expr_function.block) {
      // print the block’s statements
      Statement *stmts =
          expr->var.expr_function.block->var.expr_block.statements;
      if (stmts) {
        for (size_t i = 0; stmts[i].type;
             i++) { // assume array terminated or tracked elsewhere
          stmt_print(&stmts[i], indent + 2);
        }
      }
    }
    indent_print(indent);
    printf("}\n");
    break;

  case EXPR_STRING_LIT:
    printf("EXPR_STRING_LIT{string=\"%s\"}\n",
           expr->var.expr_string_literal.string);
    break;

  case EXPR_INTEGER_LIT:
    printf("EXPR_INTEGER_LIT{integer=%d}\n",
           expr->var.expr_integer_literal.integer);
    break;

  case EXPR_CALL:
    printf("EXPR_CALL{function=%s, args=\n", expr->var.expr_call.function);
    if (expr->var.expr_call.args) {
      Expression *args = expr->var.expr_call.args;
      for (size_t i = 0; args[i].type; i++) { // same termination assumption
        expr_print(&args[i], indent + 2);
      }
    }
    indent_print(indent);
    printf("}\n");
    break;

  case EXPR_BLOCK:
    printf("EXPR_BLOCK{statements=\n");
    if (expr->var.expr_block.statements) {
      Statement *stmts = expr->var.expr_block.statements;
      for (size_t i = 0; stmts[i].type; i++) {
        stmt_print(&stmts[i], indent + 2);
      }
    }
    indent_print(indent);
    printf("}\n");
    break;
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

// begin: cur_tok must be generic name
// end: cur_tok is end of func descriptor or generic ident
static Generic parse_generic(Parser *parser) {
  Generic generic = {.name = parser->cur_tok->var.ident};
  if (parser->peek_tok->type == TOKEN_COLON) {
    // cur_tok is colon
    next_token(parser);
    // cur_tok is first tok of func descriptor
    next_token(parser);
    generic.bounds = array_new(FuncDescriptor, &HEAP_ALLOCATOR);
    FuncDescriptor desc = parse_func_desc(parser);
    array_add(generic.bounds, desc);
  }
  return generic;
}

// TODO: Generic functions
// begin: cur_tok must be left parenthesis
// end: cur_tok is return_type ident or right parenthesis
static FuncDescriptor parse_func_desc(Parser *parser) {
  FuncDescriptor desc;
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
    Expression *block_expr = malloc(sizeof(Expression));

    if (parser->peek_tok->type == TOKEN_LCURLY) {
      // cur_tok is left curly
      next_token(parser);
      // cur_tok is first stmt
      next_token(parser);

      Statement *stmts = parse_block_statements(parser, TOKEN_RCURLY);
      Expression block = {.type = EXPR_BLOCK,
                          .var = {.expr_block = {.statements = stmts}}};
      memcpy(block_expr, &block, sizeof(Expression));
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
    Expression *block_expr = malloc(sizeof(Expression));

    if (parser->peek_tok->type == TOKEN_LCURLY) {
      // cur_tok is left curly
      next_token(parser);
      // cur_tok is first stmt
      next_token(parser);

      Statement *stmts = parse_block_statements(parser, TOKEN_RCURLY);
      Expression block = {.type = EXPR_BLOCK,
                          .var = {.expr_block = {.statements = stmts}}};
      memcpy(block_expr, &block, sizeof(Expression));
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
    printf("ident without decl, cur:\n");
    tok_print(parser->cur_tok);
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
    stmt_print(&stmt, 0);
    array_add(parser->statements, stmt);
  }
}

int main(void) {
  alloc_init();

  char file_buf[4096];
  FILE *file = fopen("test.goo", "r");
  fread(file_buf, 4096, sizeof(char), file);
  printf("%s\n", file_buf);

  Lexer lexer = {.tokens = array_new(Token, &HEAP_ALLOCATOR)};

  tokenize(&lexer, file_buf);
  array_add(lexer.tokens, (Token){.type = TOKEN_EOF});

  for (size_t i = 0; i < array_len(lexer.tokens); i++) {
    tok_print(&lexer.tokens[i]);
  }

  Parser parser = {.tokens = lexer.tokens,
                   .statements = array_new(Statement, &HEAP_ALLOCATOR)};

  parse(&parser);

  for (size_t i = 0; i < array_len(parser.statements); i++) {
    stmt_print(&parser.statements[i], 0);
  }
}