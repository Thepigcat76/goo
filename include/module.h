#pragma once

#include "ast.h"
#include <lilc/alloc.h>

typedef struct {
  const char *filename;
  const char *source;
  Statement *program_stmts;
} Module;

inline Module module_new(const char *filename, const char *source, Statement *program_stmts);
