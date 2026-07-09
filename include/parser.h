#pragma once

#include "module.h"
#include "lexer.h"
#include "preprocess.h"
#include "shared.h"
#include "ast.h"
#include "errors.h"
#include <stdbool.h>

void *_internal_bump_clone(Bump *bump, void *ptr, size_t size);

#define bump_clone(bump, ptr) _internal_bump_clone(bump, ptr, sizeof(typeof(*(ptr))))

#define EXPR_VAR_TYPE(expr)                                                    \
  (ExpressionVariant) {                                                        \
    .kind = EXPR_VAR_TYPE_EXPR, .var = {.expr_var_type_expr = expr }           \
  }

#define EXPR_VAR_EXPR(expr)                                                    \
  (ExpressionVariant) {                                                        \
    .kind = EXPR_VAR_REG_EXPR, .var = {.expr_var_reg_expr = expr }             \
  }

extern Hashmap mangled_functions; // ModulePath -> Ident

typedef struct {
  const Token *cur_tok;
  const Token *peek_tok;
  Token *tokens;
  Statement *statements;
  Hashmap custom_types; // Ident -> TypeExpr
  Hashmap custom_functions; // Ident * -> ExprFunction
  ModulePath *foreign_functions;
  // Imports
  Hashmap imported_functions; // ModulePath -> FuncDescriptor
  ModulePath *imported_modules;
  // Preprocessor
  PpDirective *pp_dirs;
  size_t *pp_dir_conditionals;
  // Debugging info
  const char *source;
  const char *filename;
  LexerLine *lines;
  // Module
  Module module;
  ModulePath path;

  ErrorSink sink;

  // Stores additional ast data like arrays
  Bump ast_arena;
  Allocator ast_arena_allocator;
} Parser;

typedef struct {
  char *error_msg;
  bool success;
  i32 line;
  i32 pos;
  i32 len;
} ParseResult;

void parser_init(Parser *parser, Token *tokens, const char *source, const char *filename, ModulePath path);

void parser_deinit(Parser *parser);

void parser_parse(Parser *parser);

TypeTableValue *type_table_get(TypeTable *table, ModulePath *path,
                               TypeTable *global_table);

void type_table_add(TypeTable *table, ModulePath *path, ExpressionVariant expr_var,
                    OptionalType opt_type);

// Uses the default parser
Module parser_parse_module(const char *source, const char *filename, ModulePath path);

// Takes in a custom parser
Module parser_parse_module_ex(Parser *parser, const char *source, const char *filename);
