/*
 * Responsible for inferring types
 */

#pragma once

#include "ast.h"

typedef struct {
  Statement *stmts;

  // Works like environemnts in the evaluator but for type inferring
  TypeTable *type_tables;
  TypeTable *cur_type_table;
  TypeTable *global_type_table;
  
  
} TypeInferrer;

void inferrer_infer(TypeInferrer *inferrer);
