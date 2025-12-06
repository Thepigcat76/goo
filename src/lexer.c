#include "../include/lexer.h"
#include "../vendor/lilc/alloc.h"
#include "../vendor/lilc/array.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

Lexer lexer_new(void) {
  return (Lexer){
      .tokens = array_new(Token, &HEAP_ALLOCATOR),
  };
}

void lexer_tok_print(char *buf, const Token *tok) {
  switch (tok->type) {
  case TOKEN_IDENT: {
    sprintf(buf, "TOKEN_IDENT{ident=%s}", tok->var.ident);
    break;
  }
  case TOKEN_STRING: {
    sprintf(buf, "TOKEN_STRING{string=\"%s\"}", tok->var.string);
    break;
  }
  case TOKEN_INT: {
    sprintf(buf, "TOKEN_INT{integer=%d}", tok->var.integer);
    break;
  }
  case TOKEN_CAST: {
    sprintf(buf, "TOKEN_CAST ('cast')");
    break;
  }
  case TOKEN_IF: {
    sprintf(buf, "TOKEN_IF ('if')");
    break;
  }
  case TOKEN_FOR: {
    sprintf(buf, "TOKEN_FOR ('for')");
    break;
  }
  case TOKEN_IN: {
    sprintf(buf, "TOKEN_IN ('in')");
    break;
  }
  case TOKEN_IT: {
    sprintf(buf, "TOKEN_IT ('it')");
    break;
  }
  case TOKEN_DECL_CONST: {
    sprintf(buf, "TOKEN_DECL_CONST ('::')");
    break;
  }
  case TOKEN_DECL_VAR: {
    sprintf(buf, "TOKEN_DECL_VAR (':=')");
    break;
  }
  case TOKEN_COLON: {
    sprintf(buf, "TOKEN_COLON (':')");
    break;
  }
  case TOKEN_LPAREN: {
    sprintf(buf, "TOKEN_LPAREN ('(')");
    break;
  }
  case TOKEN_RPAREN: {
    sprintf(buf, "TOKEN_RPAREN (')')");
    break;
  }
  case TOKEN_LCURLY: {
    sprintf(buf, "TOKEN_LCURLY ('{')");
    break;
  }
  case TOKEN_RCURLY: {
    sprintf(buf, "TOKEN_RCURLY ('}')");
    break;
  }
  case TOKEN_LANGLE: {
    sprintf(buf, "TOKEN_LANGLE ('<')");
    break;
  }
  case TOKEN_RANGLE: {
    sprintf(buf, "TOKEN_RANGLE ('>')");
    break;
  }
  case TOKEN_LSQUARE: {
    sprintf(buf, "TOKEN_LSQUARE ('[')");
    break;
  }
  case TOKEN_RSQUARE: {
    sprintf(buf, "TOKEN_RSQUARE (']')");
    break;
  }
  case TOKEN_ARROW: {
    sprintf(buf, "TOKEN_ARROW ('->')");
    break;
  }
  case TOKEN_COMMA: {
    sprintf(buf, "TOKEN_COMMA (',')");
    break;
  }
  case TOKEN_DOT: {
    sprintf(buf, "TOKEN_DOT ('.')");
    break;
  }
  case TOKEN_PLUS: {
    sprintf(buf, "TOKEN_PLUS ('+')");
    break;
  }
  case TOKEN_MINUS: {
    sprintf(buf, "TOKEN_MINUS ('-')");
    break;
  }
  case TOKEN_ASTERISK: {
    sprintf(buf, "TOKEN_ASTERISK ('*')");
    break;
  }
  case TOKEN_SLASH: {
    sprintf(buf, "TOKEN_SLASH ('/')");
    break;
  }
  case TOKEN_LTE: {
    sprintf(buf, "TOKEN_LTE ('<=')");
    break;
  }
  case TOKEN_GTE: {
    sprintf(buf, "TOKEN_GTE ('>=')");
    break;
  }
  case TOKEN_ASSIGN: {
    sprintf(buf, "TOKEN_ASSIGN ('=')");
    break;
  }
  case TOKEN_STRUCT: {
    sprintf(buf, "TOKEN_STRUCT ('struct')");
    break;
  }
  case TOKEN_BOOL: {
    sprintf(buf, "TOKEN_BOOL {boolean=%s}",
            tok->var.boolean ? "true" : "false");
    break;
  }
  case TOKEN_RANGE: {
    sprintf(buf, "TOKEN_RANGE ('..')");
    break;
  }
  case TOKEN_EOF: {
    sprintf(buf, "TOKEN_EOF");
    break;
  }
  case TOKEN_ILLEGAL: {
    sprintf(buf, "TOKEN_ILLEGAL");
    break;
  }
  }
}

static bool next_char(Lexer *lexer) {
  lexer->cur_char++;
  return *lexer->cur_char != '\0';
}

void lexer_tokenize(Lexer *lexer, const char *src) {
  lexer->cur_char = src;

  while (*lexer->cur_char != '\0') {
    Token tok;
    if (*lexer->cur_char == ' ' || *lexer->cur_char == '\n') {
      do {
        next_char(lexer);
      } while (*lexer->cur_char == ' ');
      continue;
    } else if (*lexer->cur_char == '#') {
      size_t len = 0;
      while (*(lexer->cur_char + 1) != '\n' && *(lexer->cur_char + 1) != '\0') {
        next_char(lexer);
        len++;
      }
      next_char(lexer);
      continue;
    } else if (*lexer->cur_char == '\0') {
      return;
    } else if (isalpha(*lexer->cur_char) || *lexer->cur_char == '_') {
      const char *begin = lexer->cur_char;
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
      } else if (strcmp(ident, "struct") == 0) {
        tok.type = TOKEN_STRUCT;
      } else if (strcmp(ident, "if") == 0) {
        tok.type = TOKEN_IF;
      } else if (strcmp(ident, "in") == 0) {
        tok.type = TOKEN_IN;
      } else if (strcmp(ident, "it") == 0) {
        tok.type = TOKEN_IT;
      } else if (strcmp(ident, "for") == 0) {
        tok.type = TOKEN_FOR;
      } else if (strcmp(ident, "true") == 0 || strcmp(ident, "false") == 0) {
        tok.type = TOKEN_BOOL;
        tok.var.boolean = strcmp(ident, "true") == 0;
      } else {
        tok.type = TOKEN_IDENT;
        tok.var.ident = malloc(strlen(ident) + 1);
        strcpy(tok.var.ident, ident);
      }
      tok.begin = begin;
      tok.len = i;
    } else if (*lexer->cur_char == '"') {
      const char *begin = lexer->cur_char;
      char *string = malloc(256 * sizeof(char));
      next_char(lexer);
      size_t i = 0;
      while (*lexer->cur_char != '"') {
        string[i++] = *lexer->cur_char;
        next_char(lexer);
      }
      string[i] = '\0';
      tok = (Token){.type = TOKEN_STRING,
                    .var = {.string = strdup(string)},
                    .begin = begin,
                    .len = i};
    } else if (*lexer->cur_char >= '0' && *lexer->cur_char <= '9') {
      const char *begin = lexer->cur_char;
      size_t cap = 32;
      char int_lit[cap];
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
      tok = (Token){.type = TOKEN_INT,
                    .var = {.integer = atoi(int_lit)},
                    .begin = begin,
                    .len = i};
    } else if (*lexer->cur_char == ':') {
      if (*(lexer->cur_char + 1) == ':') {
        tok = (Token){
            .type = TOKEN_DECL_CONST, .begin = lexer->cur_char, .len = 2};
        next_char(lexer);
      } else if (*(lexer->cur_char + 1) == '=') {
        tok =
            (Token){.type = TOKEN_DECL_VAR, .begin = lexer->cur_char, .len = 2};
        next_char(lexer);
      } else {
        tok = (Token){.type = TOKEN_COLON, .begin = lexer->cur_char, .len = 1};
      }
    } else if (*lexer->cur_char == '(') {
      tok = (Token){.type = TOKEN_LPAREN, .begin = lexer->cur_char, .len = 1};
    } else if (*lexer->cur_char == ')') {
      tok = (Token){.type = TOKEN_RPAREN, .begin = lexer->cur_char, .len = 1};
    } else if (*lexer->cur_char == '{') {
      tok = (Token){.type = TOKEN_LCURLY, .begin = lexer->cur_char, .len = 1};
    } else if (*lexer->cur_char == '}') {
      tok = (Token){.type = TOKEN_RCURLY, .begin = lexer->cur_char, .len = 1};
    } else if (*lexer->cur_char == '<') {
      if (*(lexer->cur_char + 1) == '=') {
        tok = (Token){.type = TOKEN_LTE, .begin = lexer->cur_char, .len = 2};
        next_char(lexer);
      } else {
        tok = (Token){.type = TOKEN_LANGLE, .begin = lexer->cur_char, .len = 1};
      }
    } else if (*lexer->cur_char == '>') {
      if (*(lexer->cur_char + 1) == '=') {
        tok = (Token){.type = TOKEN_GTE, .begin = lexer->cur_char, .len = 2};
        next_char(lexer);
      } else {
        tok = (Token){.type = TOKEN_RANGLE, .begin = lexer->cur_char, .len = 1};
      }
    } else if (*lexer->cur_char == ',') {
      tok = (Token){.type = TOKEN_COMMA, .begin = lexer->cur_char, .len = 1};
    } else if (*lexer->cur_char == '+') {
      tok = (Token){.type = TOKEN_PLUS, .begin = lexer->cur_char, .len = 1};
    } else if (*lexer->cur_char == '+') {
      tok = (Token){.type = TOKEN_PLUS, .begin = lexer->cur_char, .len = 1};
    } else if (*lexer->cur_char == '-') {
      if (*(lexer->cur_char + 1) == '>') {
        tok = (Token){.type = TOKEN_ARROW, .begin = lexer->cur_char, .len = 2};
        next_char(lexer);
      } else {
        tok = (Token){.type = TOKEN_MINUS, .begin = lexer->cur_char, .len = 1};
      }
    } else if (*lexer->cur_char == '.') {
      if (*(lexer->cur_char + 1) == '.') {
        tok = (Token){.type = TOKEN_RANGE, .begin = lexer->cur_char, .len = 2};
        next_char(lexer);
      } else {
        tok = (Token){.type = TOKEN_DOT, .begin = lexer->cur_char, .len = 1};
      }
    } else if (*lexer->cur_char == '=') {
      tok = (Token){.type = TOKEN_ASSIGN, .begin = lexer->cur_char, .len = 1};
    } else if (*lexer->cur_char == '[') {
      tok = (Token){.type = TOKEN_LSQUARE, .begin = lexer->cur_char, .len = 1};
    } else if (*lexer->cur_char == ']') {
      tok = (Token){.type = TOKEN_RSQUARE, .begin = lexer->cur_char, .len = 1};
    } else if (*lexer->cur_char == '*') {
      tok = (Token){.type = TOKEN_ASTERISK, .begin = lexer->cur_char, .len = 1};
    } else if (*lexer->cur_char == '/') {
      tok = (Token){.type = TOKEN_SLASH, .begin = lexer->cur_char, .len = 1};
    } else if (*lexer->cur_char == '~') {
      tok = (Token){.type = TOKEN_TILDE, .begin = lexer->cur_char, .len = 1};
    } else if (*lexer->cur_char == '&') {
      tok = (Token){.type = TOKEN_AMPERSAND, .begin = lexer->cur_char, .len = 1};
    } else {
      printf("Illegal token cur char: %c\n", *lexer->cur_char);
      tok = (Token){.type = TOKEN_ILLEGAL, .begin = lexer->cur_char, .len = 0};
    }
    array_add(lexer->tokens, tok);
    next_char(lexer);
  }
}
