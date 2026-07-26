#pragma once

#include "ast.h"
#include "errors.h"
#include "lexer.h"
#include "module.h"
#include "preprocess.h"
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

// TODO: DONT COPY ARRAYS

typedef struct {
  // Input
  const SourceLine *lines;
  const Token *tokens;

  // Output
  PpDirective **pp_dirs;
  Statement **stmts;

  // Others
  ModulePath *foreign_functions;
  // DECLARATIONS
  Hashmap custom_types;     // Ident -> TypeExpr
  Hashmap custom_functions; // Ident * -> ExprFunction
  // TODO: Merge this with pp-dirs
  size_t *pp_dir_conditionals;
  // Module specifics
  Hashmap imported_functions; // ModulePath -> FuncDescriptor
  ModulePath *imported_modules;
} ModuleParse;

void module_parse_init(ModuleParse *mod_parse);

typedef struct {
  // TOKENS
  const Token *cur_tok;
  const Token *peek_tok;
  // MODULES
  Module *cur_module;
  ModuleParse cur_mod_parse;

  // MODULES CACHE
  Hashmap cached_modules; // ModulePath -> Module

  // ERRORS
  ErrorSink sink;

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
bool module_parse(Module *module, Parser *parser, ModuleParse mod_parse);

void type_table_add(TypeTable *table, ModulePath *path,
                    ExpressionVariant expr_var, OptionalType opt_type);

// Uses the default parser
Module _parser_parse_module(const char *source, const char *filename,
                            ModulePath path);

// Takes in a custom parser
Module _parser_parse_module_ex(Parser *parser, const char *source,
                               const char *filename);
