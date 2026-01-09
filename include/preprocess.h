#pragma once

#include "ast.h"
#include <lilc/alloc.h>
#include <lilc/eq.h>
#include <lilc/hash.h>

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
  enum {
    PP_DIR_COMPTIME,
    PP_DIR_IF,
    PP_DIR_IMPORT,
    PP_DIR_INCLUDE,
    PP_DIR_INCLUDE_STR,
    PP_DIR_INCLUDE_BYTES,
  } type;
  union {
    PpDirIf pp_dir_if;
    PpDirImport pp_dir_import;
    PpDirInclude pp_dir_include;
    PpDirIncludeStr pp_dir_include_str;
    PpDirIncludeBytes pp_dir_include_bytes;
  } var;
  size_t line;
} PpDirective;

typedef struct {
  Statement *stmts;
  Hashmap(Ident *, Expression) comptime_constants;
  PpDirective *pp_dirs;
} PreProcessor;

PreProcessor preprocessor_new(Statement *stmts, PpDirective *pp_dirs);

void preprocessor_process(PreProcessor *preprocessor);
