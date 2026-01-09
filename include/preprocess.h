#pragma once

#include "parser.h"
#include <lilc/alloc.h>
#include <lilc/eq.h>
#include <lilc/hash.h>

typedef struct {
  Statement *stmts;
  Hashmap(Ident *, Expression) comptime_constants;
} PreProcessor;

PreProcessor preprocessor_new(Statement *stmts);

void preprocessor_process(PreProcessor *preprocessor);
