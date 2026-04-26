#pragma once

#include "module.h"
#include "lexer.h"
#include "lilc/hashmap.h"
#include "preprocess.h"
#include "shared.h"
#include "ast.h"
#include <stdbool.h>

void *_internal_heap_clone(void *ptr, size_t size);

#define heap_clone(ptr) _internal_heap_clone(ptr, sizeof(typeof(*(ptr))))

#define EXPR_VAR_TYPE(expr)                                                    \
  (ExpressionVariant) {                                                        \
    .kind = EXPR_VAR_TYPE_EXPR, .var = {.expr_var_type_expr = expr }           \
  }

#define EXPR_VAR_EXPR(expr)                                                    \
  (ExpressionVariant) {                                                        \
    .kind = EXPR_VAR_REG_EXPR, .var = {.expr_var_reg_expr = expr }             \
  }

extern Hashmap(ModulePath, Ident) mangled_functions;

typedef struct {
  const Token *cur_tok;
  const Token *peek_tok;
  Token *tokens;
  Statement *statements;
  Hashmap(Ident *, TypeExpr) custom_types;
  Hashmap(Ident *, ExprFunction) custom_functions;
  ModulePath *foreign_functions;
  // Imports
  Hashmap(ModulePath, FuncDescriptor) imported_functions;
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

  // Stores additional ast data like arrays
  Bump ast_arena;
} Parser;

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
