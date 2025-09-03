#include "alloc.h"
#include "array.h"
#include <stdbool.h>
#include <stdio.h>

typedef struct {
  enum {
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
    TOKEN_ILLEGAL,
  } type;
  union {
    char *ident;
    char *string;
    int integer;
  } var;
} Token;

static void tok_print(Token *tok) {
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

int main(void) {
  alloc_init();

  char file_buf[4096];
  FILE *file = fopen("test.goo", "r");
  fread(file_buf, 4096, sizeof(char), file);
  printf("%s\n", file_buf);

  Lexer lexer = {.tokens = array_new(Token, &HEAP_ALLOCATOR)};

  tokenize(&lexer, file_buf);

  for (size_t i = 0; i < array_len(lexer.tokens); i++) {
  }
}