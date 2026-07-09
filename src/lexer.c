#include "../include/lexer.h"
#include "../include/shared.h"
#include "lilc/alloc.h"
#include "lilc/array.h"
#include <ctype.h>
#include <lilc/assert.h>
#include <lilc/dynstr.h>
#include <lilc/log.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

void lexer_init(Lexer *lexer) {
  lexer->line = 1;
  lexer->pos = 1;

  bump_init(&lexer->tok_arena, 16000);
  bump_allocator_init(&lexer->tok_arena_allocator, &lexer->tok_arena);
}

void lexer_deinit(Lexer *lexer) { bump_free(&lexer->tok_arena); }

void lexer_tok_print(char *buf, const Token *tok) {
  switch (tok->kind) {
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

static inline void lines_add(SourceLine **lines, SourceLine line) {
  if (lines != NULL)
    array_add(*lines, line);
}

static inline void tokens_add(TokenStream *tokens, Token tok) {
  if (tokens != NULL)
    array_add(*tokens, tok);
}

static bool next_char_count_newline(Lexer *lexer, SourceLine **out_lines) {
  if (*lexer->cur_char == '\n') {
    lexer->pos = 1;
    lexer->line++;
    size_t lines = array_len(*out_lines);
    if (lines > 0) {
      (*out_lines)[lines - 1].len = lexer->cur_char - (*out_lines)[lines - 1].begin;
    }
    lines_add(out_lines, (SourceLine){.begin = lexer->cur_char + 1});
  } else {
    lexer->pos++;
  }
  lexer->cur_char++;
  return *lexer->cur_char != '\0';
}

static bool next_char(Lexer *lexer, SourceLine **out_lines) {
  return next_char_count_newline(lexer, out_lines);
}

void lexer_tokenize(Lexer *lexer, const char *src, const char *filename,
                    TokenStream *out_tokens, SourceLine **out_lines) {
  ASSERT(src != NULL, "Source for tokenization cannot be (null)");

  if (filename == NULL) {
    filename = "<inline>";
  }

  if (debug_flags.print_tokens) {
    log_info("[LEXER] Start tokenization of file: %s", filename);
  }

  lexer->cur_char = src;

  lines_add(out_lines, (SourceLine){.begin = lexer->cur_char});

  while (*lexer->cur_char != '\0') {
    Token tok;
    if (*lexer->cur_char == ' ' || *lexer->cur_char == '\n') {
      do {
        next_char(lexer, out_lines);
      } while (*lexer->cur_char == ' ' || *lexer->cur_char == '\n');
      continue;
    } else if (*lexer->cur_char == '/' && *(lexer->cur_char + 1) == '/') {
      while (*(lexer->cur_char + 1) != '\n' && *(lexer->cur_char + 1) != '\0') {
        next_char(lexer, out_lines);
      }
      next_char(lexer, out_lines);
      continue;
    } else if (*lexer->cur_char == '\0') {
      return;
    } else if (isalpha(*lexer->cur_char) || *lexer->cur_char == '_') {
      const char *begin = lexer->cur_char;
      size_t begin_pos = lexer->pos;

      dyn_string_t ident = {0};
      dyn_string_init(&ident, &lexer->tok_arena_allocator);

      while (isalnum(*lexer->cur_char) || *lexer->cur_char == '_') {
        dyn_string_add_char(&ident, *lexer->cur_char);

        char peek_char = *(lexer->cur_char + 1);
        if (peek_char != '\0' && (isalnum(peek_char) || peek_char == '_')) {
          next_char(lexer, out_lines);
        } else {
          break;
        }
      }

      char *ident_str = ident.string;

      if (strcmp(ident_str, "cast") == 0) {
        tok.kind = TOKEN_CAST;
      } else if (strcmp(ident_str, "struct") == 0) {
        tok.kind = TOKEN_STRUCT;
      } else if (strcmp(ident_str, "if") == 0) {
        tok.kind = TOKEN_IF;
      } else if (strcmp(ident_str, "comptime") == 0) {
        tok.kind = TOKEN_COMPTIME;
      } else if (strcmp(ident_str, "in") == 0) {
        tok.kind = TOKEN_IN;
      } else if (strcmp(ident_str, "it") == 0) {
        tok.kind = TOKEN_IT;
      } else if (strcmp(ident_str, "foreign") == 0) {
        tok.kind = TOKEN_FOREIGN;
      } else if (strcmp(ident_str, "for") == 0) {
        tok.kind = TOKEN_FOR;
      } else if (strcmp(ident_str, "return") == 0) {
        tok.kind = TOKEN_RETURN;
      } else if (strcmp(ident_str, "true") == 0 ||
                 strcmp(ident_str, "false") == 0) {
        tok.kind = TOKEN_BOOL;
        tok.var.boolean = strcmp(ident_str, "true") == 0;
      } else {
        tok.kind = TOKEN_IDENT;
        tok.var.ident = ident_str;
      }
      tok.begin_pos = begin_pos;
      tok.line = lexer->line;
      tok.begin = begin;
      tok.len = ident.len;
    } else if (*lexer->cur_char == '"') {
      const char *begin = lexer->cur_char;
      size_t begin_pos = lexer->pos;
      size_t cap = 256;
      dyn_string_t string = {.capacity = cap};
      dyn_string_init(&string, &lexer->tok_arena_allocator);
      next_char(lexer, out_lines);
      size_t i = 0;
      while (*lexer->cur_char != '"') {
        dyn_string_add_char(&string, *lexer->cur_char);
        next_char(lexer, out_lines);
      }

      tok = (Token){
          .kind = TOKEN_STRING,
          .var = {.string = string.string},
          .begin = begin,
          .begin_pos = begin_pos,
          .line = lexer->line,
          .len = i + 2,
      };
    } else if (isdigit(*lexer->cur_char)) {
      const char *begin = lexer->cur_char;
      size_t begin_pos = lexer->pos;
      size_t cap = 32;
      
      dyn_string_t int_lit = {.capacity = cap};
      dyn_string_init(&int_lit, &lexer->tok_arena_allocator);

      size_t i = 0;
      while (isdigit(*lexer->cur_char)) {
        dyn_string_add_char(&int_lit, *lexer->cur_char);

        char peek_char = *(lexer->cur_char + 1);
        if (peek_char != '\0' && isdigit(peek_char)) {
          next_char(lexer, out_lines);
        } else {
          break;
        }
      }
      tok = (Token){
          .kind = TOKEN_INT,
          .var = {.integer = atoi(int_lit.string)},
          .begin = begin,
          .begin_pos = begin_pos,
          .line = lexer->line,
          .len = i,
      };
    } else if (*lexer->cur_char == ':') {
      if (*(lexer->cur_char + 1) == ':') {
        tok = (Token){.kind = TOKEN_DECL_CONST,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 2};
        next_char(lexer, out_lines);
      } else if (*(lexer->cur_char + 1) == '=') {
        tok = (Token){.kind = TOKEN_DECL_VAR,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 2};
        next_char(lexer, out_lines);
      } else {
        tok = (Token){.kind = TOKEN_COLON,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 1};
      }
    } else if (*lexer->cur_char == '(') {
      tok = (Token){.kind = TOKEN_LPAREN,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == ')') {
      tok = (Token){.kind = TOKEN_RPAREN,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == '{') {
      tok = (Token){.kind = TOKEN_LCURLY,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == '}') {
      tok = (Token){.kind = TOKEN_RCURLY,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == '<') {
      if (*(lexer->cur_char + 1) == '=') {
        tok = (Token){.kind = TOKEN_LTE,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 2};
        next_char(lexer, out_lines);
      } else {
        tok = (Token){.kind = TOKEN_LANGLE,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 1};
      }
    } else if (*lexer->cur_char == '>') {
      if (*(lexer->cur_char + 1) == '=') {
        tok = (Token){.kind = TOKEN_GTE,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 2};
        next_char(lexer, out_lines);
      } else {
        tok = (Token){.kind = TOKEN_RANGLE,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 1};
      }
    } else if (*lexer->cur_char == ',') {
      tok = (Token){.kind = TOKEN_COMMA,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == '+') {
      tok = (Token){.kind = TOKEN_PLUS,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == '#') {
      tok = (Token){.kind = TOKEN_HASH,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == '-') {
      if (*(lexer->cur_char + 1) == '>') {
        tok = (Token){.kind = TOKEN_ARROW,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 2};
        next_char(lexer, out_lines);
      } else {
        tok = (Token){.kind = TOKEN_MINUS,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 1};
      }
    } else if (*lexer->cur_char == '.') {
      if (*(lexer->cur_char + 1) == '.') {
        tok = (Token){.kind = TOKEN_RANGE,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 2};
        next_char(lexer, out_lines);
      } else {
        tok = (Token){.kind = TOKEN_DOT,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 1};
      }
    } else if (*lexer->cur_char == '=') {
      if (*(lexer->cur_char + 1) == '=') {
        tok = (Token){.kind = TOKEN_EQUALS,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 2};
        next_char(lexer, out_lines);
      } else {
        tok = (Token){.kind = TOKEN_ASSIGN,
                      .begin_pos = lexer->pos,
                      .line = lexer->line,
                      .begin = lexer->cur_char,
                      .len = 1};
      }
    } else if (*lexer->cur_char == '[') {
      tok = (Token){.kind = TOKEN_LSQUARE,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == ']') {
      tok = (Token){.kind = TOKEN_RSQUARE,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == '*') {
      tok = (Token){.kind = TOKEN_ASTERISK,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == '/') {
      tok = (Token){.kind = TOKEN_SLASH,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == '~') {
      tok = (Token){.kind = TOKEN_TILDE,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else if (*lexer->cur_char == '&') {
      tok = (Token){.kind = TOKEN_AMPERSAND,
                    .begin_pos = lexer->pos,
                    .line = lexer->line,
                    .begin = lexer->cur_char,
                    .len = 1};
    } else {
      log_error("Illegal token cur char: '%s' at %s:%d:%d", lexer->cur_char,
                filename, lexer->line, lexer->pos);
      tok = (Token){
          .kind = TOKEN_ILLEGAL,
          .begin_pos = lexer->pos,
          .line = lexer->line,
          .begin = lexer->cur_char,
          .len = 0,
      };
    }
    tokens_add(out_tokens, tok);
    next_char(lexer, out_lines);
  }
  size_t lines = array_len(*out_lines);
  if (lines > 0) {
    (*out_lines)[lines - 1].len = lexer->cur_char - (*out_lines)[lines - 1].begin;
  }
  tokens_add(out_tokens, (Token){.kind = TOKEN_EOF});
}

static void lexer_reset(Lexer *lexer) {
  lexer->cur_char = NULL;
  lexer->index = 0;
  lexer->line = 1;
  lexer->pos = 1;

  bump_reset(&lexer->tok_arena);
}

void module_tokenize(Module *module, Lexer *lexer, TokenStream *out_tokens,
                     SourceLine **out_lines) {
  lexer_reset(lexer);

  lexer_tokenize(lexer, module->source, module->filename, out_tokens,
                 out_lines);
}
