#pragma once

#include <stdlib.h>

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

typedef struct {
  size_t index;
  const char *cur_char;
  Token *tokens;
} Lexer;

Lexer lexer_new(void);

void lexer_tok_print(char *buf, const Token *tok);

void lexer_tokenize(Lexer *lexer, const char *buf);
