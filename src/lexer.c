#include "../include/lexer.h"
#include "lilc/alloc.h"
#include "lilc/array.h"
#include <ctype.h>
#include <lilc/log.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

Lexer lexer_new(void) {
  return (Lexer){
      .tokens = array_new(Token, &HEAP_ALLOCATOR),
      .lines = array_new(LexerLine, &HEAP_ALLOCATOR),
      .line = 1,
      .pos = 1,
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
  case TOKEN_HASH: {
    sprintf(buf, "TOKEN_HASH ('#')");
    break;
  }
  case TOKEN_FOREIGN: {
    sprintf(buf, "TOKEN_FOREIGN ('foreign')");
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

static bool next_char_count_newline(Lexer *lexer) {
  if (*lexer->cur_char == '\n') {
    lexer->pos = 1;
    lexer->line++;
    size_t lines = array_len(lexer->lines);
    if (lines > 0) {
      lexer->lines[lines - 1].len =
          lexer->cur_char - lexer->lines[lines - 1].begin;
    }
    array_add(lexer->lines, (LexerLine){.begin = lexer->cur_char + 1});
  } else {
    lexer->pos++;
  }
  lexer->cur_char++;
  return *lexer->cur_char != '\0';
}

static bool next_char(Lexer *lexer) { return next_char_count_newline(lexer); }

void lexer_tokenize(Lexer *lexer, const char *src, const char *filename) {
  if (filename == NULL) {
    filename = "<inline>";
  }

  log_info("[LEXER] Start tokenization of file: %s", filename);

  lexer->cur_char = src;

  array_add(lexer->lines, (LexerLine){.begin = lexer->cur_char});

  while (*lexer->cur_char != '\0') {
    Token tok;
    if (*lexer->cur_char == ' ' || *lexer->cur_char == '\n') {
      do {
        next_char(lexer);
      } while (*lexer->cur_char == ' ' || *lexer->cur_char == '\n');
      continue;
    } else if (*lexer->cur_char == '/' && *(lexer->cur_char + 1) == '/') {
      while (*(lexer->cur_char + 1) != '\n' && *(lexer->cur_char + 1) != '\0') {
        next_char(lexer);
      }
      next_char(lexer);
      continue;
    } else if (*lexer->cur_char == '\0') {
      return;
    } else if (isalpha(*lexer->cur_char) || *lexer->cur_char == '_') {
      const char *begin = lexer->cur_char;
      size_t begin_pos = lexer->pos;
      size_t cap = 256;
      char *ident = malloc(cap);

      size_t i = 0;
      while (isalnum(*lexer->cur_char) || *lexer->cur_char == '_') {
        if (i >= cap - 1) {
          fprintf(stderr, "Ident too long\n");
          exit(1);
        }
        ident[i++] = *lexer->cur_char;

        if (*(lexer->cur_char + 1) != '\0' &&
            (isalnum(*(lexer->cur_char + 1)) ||
             *(lexer->cur_char + 1) == '_')) {
          next_char(lexer);
        } else {
          break;
        }
      }
      ident[i] = '\0';

      if (strcmp(ident, "cast") == 0) {
        tok.type = TOKEN_CAST;
      } else if (strcmp(ident, "struct") == 0) {
        tok.type = TOKEN_STRUCT;
      } else if (strcmp(ident, "if") == 0) {
        tok.type = TOKEN_IF;
      } else if (strcmp(ident, "comptime") == 0) {
        tok.type = TOKEN_COMPTIME;
      } else if (strcmp(ident, "in") == 0) {
        tok.type = TOKEN_IN;
      } else if (strcmp(ident, "it") == 0) {
        tok.type = TOKEN_IT;
      } else if (strcmp(ident, "foreign") == 0) {
        tok.type = TOKEN_FOREIGN;
      } else if (strcmp(ident, "for") == 0) {
        tok.type = TOKEN_FOR;
      } else if (strcmp(ident, "return") == 0) {
        tok.type = TOKEN_RETURN;
      } else if (strcmp(ident, "true") == 0 || strcmp(ident, "false") == 0) {
        tok.type = TOKEN_BOOL;
        tok.var.boolean = strcmp(ident, "true") == 0;
      } else {
        tok.type = TOKEN_IDENT;
        tok.var.ident = ident;
      }
      tok.begin_pos = begin_pos;
      tok.line = lexer->line;
      tok.begin = begin;
      tok.len = i;
    } else if (*lexer->cur_char == '"') {
      const char *begin = lexer->cur_char;
      size_t begin_pos = lexer->pos;
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
                    .begin_pos = begin_pos,
                    .line = lexer->line,
                    .len = i + 2};
    } else if (*lexer->cur_char >= '0' && *lexer->cur_char <= '9') {
      const char *begin = lexer->cur_char;
      size_t begin_pos = lexer->pos;
      size_t cap = 32;
      char int_lit[cap];
      size_t i = 0;

      while (isdigit(*lexer->cur_char)) {
        if (i >= cap - 1) {
          fprintf(stderr, "int too long\n");
          exit(1);
        }
        int_lit[i++] = *lexer->cur_char;

        if (isdigit(*(lexer->cur_char + 1))) {
          next_char(lexer);
        } else {
          break;
        }
      }
      int_lit[i] = '\0';
      tok = (Token){.type = TOKEN_INT,
                    .var = {.integer = atoi(int_lit)},
                    .begin = begin,
                    .begin_pos = begin_pos,
                    .line = lexer->line,
                    .len = i};

    } else if (*lexer->cur_char == ':') {
      if (*(lexer->cur_char + 1) == ':') {
        tok = (Token){.type = TOKEN_DECL_CONST,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 2};
        next_char(lexer);
      } else if (*(lexer->cur_char + 1) == '=') {
        tok = (Token){.type = TOKEN_DECL_VAR,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 2};
        next_char(lexer);
      } else {
        tok = (Token){.type = TOKEN_COLON,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 1};
      }
    } else if (*lexer->cur_char == '(') {
      tok = (Token){.type = TOKEN_LPAREN,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == ')') {
      tok = (Token){.type = TOKEN_RPAREN,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == '{') {
      tok = (Token){.type = TOKEN_LCURLY,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == '}') {
      tok = (Token){.type = TOKEN_RCURLY,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == '<') {
      if (*(lexer->cur_char + 1) == '=') {
        tok = (Token){.type = TOKEN_LTE,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 2};
        next_char(lexer);
      } else {
        tok = (Token){.type = TOKEN_LANGLE,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 1};
      }
    } else if (*lexer->cur_char == '>') {
      if (*(lexer->cur_char + 1) == '=') {
        tok = (Token){.type = TOKEN_GTE,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 2};
        next_char(lexer);
      } else {
        tok = (Token){.type = TOKEN_RANGLE,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 1};
      }
    } else if (*lexer->cur_char == ',') {
      tok = (Token){.type = TOKEN_COMMA,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == '+') {
      tok = (Token){.type = TOKEN_PLUS,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == '#') {
      tok = (Token){.type = TOKEN_HASH,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == '-') {
      if (*(lexer->cur_char + 1) == '>') {
        tok = (Token){.type = TOKEN_ARROW,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 2};
        next_char(lexer);
      } else {
        tok = (Token){.type = TOKEN_MINUS,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 1};
      }
    } else if (*lexer->cur_char == '.') {
      if (*(lexer->cur_char + 1) == '.') {
        tok = (Token){.type = TOKEN_RANGE,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 2};
        next_char(lexer);
      } else {
        tok = (Token){.type = TOKEN_DOT,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 1};
      }
    } else if (*lexer->cur_char == '=') {
      if (*(lexer->cur_char + 1) == '=') {
        tok = (Token){.type = TOKEN_EQUALS,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 2};
        next_char(lexer);
      } else {
        tok = (Token){.type = TOKEN_ASSIGN,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 1};
      }
    } else if (*lexer->cur_char == '[') {
      tok = (Token){.type = TOKEN_LSQUARE,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == ']') {
      tok = (Token){.type = TOKEN_RSQUARE,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == '*') {
      tok = (Token){.type = TOKEN_ASTERISK,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == '/') {
      tok = (Token){.type = TOKEN_SLASH,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == '~') {
      tok = (Token){.type = TOKEN_TILDE,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == '&') {
      tok = (Token){.type = TOKEN_AMPERSAND,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else {
      printf("Illegal token cur char: %c at %s:%d:%d\n", *lexer->cur_char,
             filename, lexer->line, lexer->pos);
      tok = (Token){.type = TOKEN_ILLEGAL,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 0};
    }
    array_add(lexer->tokens, tok);
    next_char(lexer);
  }
  log_debug("[LEXER] Lines in file: %d", lexer->line);
  size_t lines = array_len(lexer->lines);
  if (lines > 0) {
    lexer->lines[lines - 1].len =
        lexer->cur_char - lexer->lines[lines - 1].begin;
  }
}
