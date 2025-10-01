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
    sprintf(buf, "TOKEN_IDENT{ident=%s}\n", tok->var.ident);
    break;
  }
  case TOKEN_STRING: {
    sprintf(buf, "TOKEN_STRING{string=\"%s\"}\n", tok->var.string);
    break;
  }
  case TOKEN_INT: {
    sprintf(buf, "TOKEN_INT{integer=%d}\n", tok->var.integer);
    break;
  }
  case TOKEN_CAST: {
    sprintf(buf, "TOKEN_CAST ('cast')\n");
    break;
  }
  case TOKEN_DECL_CONST: {
    sprintf(buf, "TOKEN_DECL_CONST ('::')\n");
    break;
  }
  case TOKEN_DECL_VAR: {
    sprintf(buf, "TOKEN_DECL_VAR (':=')\n");
    break;
  }
  case TOKEN_COLON: {
    sprintf(buf, "TOKEN_COLON (':')\n");
    break;
  }
  case TOKEN_LPAREN: {
    sprintf(buf, "TOKEN_LPAREN ('(')\n");
    break;
  }
  case TOKEN_RPAREN: {
    sprintf(buf, "TOKEN_RPAREN (')')\n");
    break;
  }
  case TOKEN_LCURLY: {
    sprintf(buf, "TOKEN_LCURLY ('{')\n");
    break;
  }
  case TOKEN_RCURLY: {
    sprintf(buf, "TOKEN_RCURLY ('}')\n");
    break;
  }
  case TOKEN_LANGLE: {
    sprintf(buf, "TOKEN_LANGLE ('<')\n");
    break;
  }
  case TOKEN_RANGLE: {
    sprintf(buf, "TOKEN_RANGLE ('>')\n");
    break;
  }
  case TOKEN_LSQUARE: {
    sprintf(buf, "TOKEN_LSQUARE ('[')\n");
    break;
  }
  case TOKEN_RSQUARE: {
    sprintf(buf, "TOKEN_RSQUARE (']')\n");
    break;
  }
  case TOKEN_ARROW: {
    sprintf(buf, "TOKEN_ARROW ('->')\n");
    break;
  }
  case TOKEN_COMMA: {
    sprintf(buf, "TOKEN_COMMA (',')\n");
    break;
  }
  case TOKEN_DOT: {
    sprintf(buf, "TOKEN_DOT ('.')\n");
    break;
  }
  case TOKEN_PLUS: {
    sprintf(buf, "TOKEN_PLUS ('+')\n");
    break;
  }
  case TOKEN_MINUS: {
    sprintf(buf, "TOKEN_MINUS ('-')\n");
    break;
  }
  case TOKEN_ASTERISK: {
    sprintf(buf, "TOKEN_ASTERISK ('*')\n");
    break;
  }
  case TOKEN_SLASH: {
    sprintf(buf, "TOKEN_SLASH ('/')\n");
    break;
  }
  case TOKEN_LTE: {
    sprintf(buf, "TOKEN_LTE ('<=')\n");
    break;
  }
  case TOKEN_GTE: {
    sprintf(buf, "TOKEN_GTE ('>=')\n");
    break;
  }
  case TOKEN_ASSIGN: {
    sprintf(buf, "TOKEN_ASSIGN ('=')\n");
    break;
  }
  case TOKEN_STRUCT: {
    sprintf(buf, "TOKEN_STRUCT ('struct')\n");
    break;
  }
  case TOKEN_EOF: {
    sprintf(buf, "TOKEN_EOF\n");
    break;
  }
  case TOKEN_ILLEGAL: {
    sprintf(buf, "TOKEN_ILLEGAL\n");
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
      tok = (Token){.type = TOKEN_STRING, .var = {.string = strdup(string)}, .begin = begin, .len = i};
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
      tok = (Token){.type = TOKEN_INT, .var = {.integer = atoi(int_lit)}, .begin = begin, .len = i};
    } else if (*lexer->cur_char == ':') {
      if (*(lexer->cur_char + 1) == ':') {
        tok = (Token){.type = TOKEN_DECL_CONST, .begin = lexer->cur_char, .len = 2};
        next_char(lexer);
      } else if (*(lexer->cur_char + 1) == '=') {
        tok = (Token){.type = TOKEN_DECL_VAR, .begin = lexer->cur_char, .len = 2};
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
    } else if (*lexer->cur_char == '-') {
      if (*(lexer->cur_char + 1) == '>') {
        tok = (Token){.type = TOKEN_ARROW, .begin = lexer->cur_char, .len = 12};
        next_char(lexer);
      } else {
        tok = (Token){.type = TOKEN_MINUS, .begin = lexer->cur_char, .len = 1};
      }
    } else if (*lexer->cur_char == '.') {
      tok = (Token){.type = TOKEN_DOT, .begin = lexer->cur_char, .len = 1};
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
    } else {
      printf("Illegal token cur char: %c\n", *lexer->cur_char);
      tok = (Token){.type = TOKEN_ILLEGAL, .begin = lexer->cur_char, .len = 0};
    }
    array_add(lexer->tokens, tok);
    next_char(lexer);
  }
}
