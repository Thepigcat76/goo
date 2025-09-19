#include "lilc/array.h"
#include <lilc/alloc.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdbool.h>
#include "../include/lexer.h"

Lexer lexer_new(void) {
  return (Lexer){
    .tokens = array_new(Token, &HEAP_ALLOCATOR),
  };
}

void lexer_tok_print(char *buf, const Token *tok) {
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
        tok.var.ident = malloc(strlen(ident) + 1);
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
