#pragma once

#include "ast.h"
#include <lilc/alloc.h>
#include <lilc/eq.h>
#include <lilc/hash.h>
#include "lilc/hashmap0.h"
#include "module.h"

typedef struct {
  Expression condition;
  size_t lines_amount;
} PpDirIf;

typedef struct {
  Ident *path;
} PpDirImport;

typedef struct {
  char *filepath;
} PpDirInclude;

typedef struct {
  char *filepath;
} PpDirIncludeStr;

typedef struct {
  char *filepath;
} PpDirIncludeBytes;

typedef struct {
  char *function_name;
  Statement stmt;
} PpDirComptime;

typedef struct {
  enum {
    PP_DIR_COMPTIME,
    PP_DIR_IF,
    PP_DIR_IMPORT,
    PP_DIR_INCLUDE,
    PP_DIR_INCLUDE_STR,
    PP_DIR_INCLUDE_BYTES,
  } kind;
  union {
    PpDirIf pp_dir_if;
    PpDirImport pp_dir_import;
    PpDirInclude pp_dir_include;
    PpDirIncludeStr pp_dir_include_str;
    PpDirIncludeBytes pp_dir_include_bytes;
    PpDirComptime pp_dir_comptime;
  } var;
  size_t line;
} PpDirective;

typedef struct {
  bool builtin;
  Expression (*execute)(Expression *objects);
  ExprFunction expr_function;
} ComptimeBuiltinFunction;

typedef struct {
  Statement *stmts;
  Hashmap comptime_constants; // Ident -> Expression
  const PpDirective *pp_dirs;
  Hashmap valid_lines; // size_t -> size_t
  ssize_t pp_dir_cond_line;
  Hashmap comptime_functions; // Ident -> ComptimeBuiltinFunction
} PreProcessor;

void preprocessor_init(PreProcessor *preprocessor);

void preprocessor_deinit(PreProcessor *pp);

void module_preprocess(Module *module, PreProcessor *preproc, Statement *stms, const PpDirective *pp_dirs);

void preprocessor_process(PreProcessor *preprocessor);
