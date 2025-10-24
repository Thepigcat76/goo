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
  TOKEN_LTE,
  TOKEN_GTE,
  TOKEN_LSQUARE,
  TOKEN_RSQUARE,
  TOKEN_ARROW,
  TOKEN_COMMA,
  TOKEN_DOT,
  TOKEN_PLUS,
  TOKEN_MINUS,
  TOKEN_SLASH,
  TOKEN_ASTERISK,
  TOKEN_ASSIGN,
  TOKEN_CAST,
  TOKEN_STRUCT,
  TOKEN_IF,
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
  // Beginning character of this token
  const char *begin;
  // Length of this token in the src text
  size_t len;
} Token;

typedef struct {
  size_t index;
  const char *cur_char;
  Token *tokens;
} Lexer;

Lexer lexer_new(void);

void lexer_tok_print(char *buf, const Token *tok);

void lexer_tokenize(Lexer *lexer, const char *buf);
