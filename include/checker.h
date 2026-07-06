#pragma once

#include "lexer.h"
#include "lilc/hashmap.h"
#include "parser.h"
#include "generics.h"
#include "types.h"

typedef struct {
  const Type *hint;
} TypeHint;

typedef struct {
  Statement *stmts;
  const char *source;
  const char *filename;
  LexerLine *lines;

  // Works like environemnts in the evaluator but for type checking
  TypeTable *type_tables;
  TypeTable *cur_type_table;
  TypeTable *global_type_table;

  TypeHint hint;
  bool infer_types;

  ErrorSink sink;

  // Table of all functions that have generics
  // Maps the name of the function to the names
  // of the generics as well as all the callers
  // (just their args) of the function
  GenericFunctionsTable generic_functions_table;
  Hashmap(Ident *, Expression *) generated_generic_functions;
  ModulePath *imported_modules;
  
  TypeFormatter type_fmt;

  Bump checker_arena;
  Allocator checker_arena_allocator;
} TypeChecker;

typedef struct {
  FuncDescriptor *cur_func_desc;
} CheckerContext;

void checker_init(TypeChecker *checker, Parser *parser);

void checker_deinit(TypeChecker *checker);

void checker_check(TypeChecker *checker);

void checker_gen_functions(TypeChecker *checker);
