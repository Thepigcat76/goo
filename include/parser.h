#pragma once

#include "module.h"
#include "lexer.h"
#include "preprocess.h"
#include "ast.h"
#include "errors.h"
#include <lilc/hashmap0.h>
#include <stdbool.h>

#define EXPR_VAR_TYPE(expr)                                                    \
  (ExpressionVariant) {                                                        \
    .kind = EXPR_VAR_TYPE_EXPR, .var = {.expr_var_type_expr = expr }           \
  }

#define EXPR_VAR_EXPR(expr)                                                    \
  (ExpressionVariant) {                                                        \
    .kind = EXPR_VAR_REG_EXPR, .var = {.expr_var_reg_expr = expr }             \
  }

extern Hashmap mangled_functions; // ModulePath -> Ident

typedef SourceLine *SourceLines;

typedef struct {
  // TOKENS
  const Token *cur_tok;
  const Token *peek_tok;
  const Token *tokens;
  // MODULES
  Module *cur_module;

  Hashmap imported_functions; // ModulePath -> FuncDescriptor
  ModulePath *imported_modules;
  // MODULES CACHE
  Hashmap cached_modules; // ModulePath -> Module
  // SOURCE-INFO
  const SourceLine *lines;
  // PREPROCESSOR
  PpDirective **pp_dirs;
  // TODO: Merge this with pp-dirs
  size_t *pp_dir_conditionals;
  // DECLARATIONS
  Hashmap custom_types; // Ident -> TypeExpr
  Hashmap custom_functions; // Ident * -> ExprFunction
  ModulePath *foreign_functions;
  // ERRORS
  ErrorSink sink;
  // PARSE-OUTPUT
  Statement **statements;

  // MEMORY
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

void parser_init(Parser *parser);

void parser_deinit(Parser *parser);

// Return false if errors occured
bool module_parse(Module *module, Parser *parser, Statement **out_stmts, PpDirective **out_pp_dirs, const TokenStream tokens, const SourceLines lines);

TypeTableValue *type_table_get(TypeTable *table, ModulePath *path,
                               TypeTable *global_table);

void type_table_add(TypeTable *table, ModulePath *path, ExpressionVariant expr_var,
                    OptionalType opt_type);

// Uses the default parser
Module _parser_parse_module(const char *source, const char *filename, ModulePath path);

// Takes in a custom parser
Module _parser_parse_module_ex(Parser *parser, const char *source, const char *filename);
