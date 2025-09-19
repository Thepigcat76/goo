#pragma once

#include "lilc/hashmap.h"
#include "parser.h"
#include "generics.h"

typedef struct {
  Statement *stmts;

  // Works like environemnts in the evaluator but for type checking
  TypeTable *type_tables;
  TypeTable *cur_type_table;
  TypeTable *global_type_table;

  // Table of all functions that have generics
  // Maps the name of the function to the names
  // of the generics as well as all the callers
  // (just their args) of the function
  GenericFunctionsTable generic_functions_table;
  Hashmap(Ident *, Expression *) generated_generic_functions;
} TypeChecker;

TypeChecker checker_new(Statement *stmts);

void checker_check(TypeChecker *checker);

void checker_gen_functions(TypeChecker *checker);
