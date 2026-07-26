#pragma once

#include "ast.h"
#include "errors.h"
#include "lexer.h"
#include "lilc/hashmap0.h"
#include "module.h"
#include "module_path.h"
#include "types.h"

typedef struct {
  // Input
  Statement *stmts;
  const SourceLine *lines;
  const ModulePath *imported_modules;

  // Output
  Hashmap function_type_tables;/* Ident -> TypeTables */
  TypeTable global_type_table;
} ModuleCheck;

typedef struct {
  const Type *hint;
} TypeHint;

typedef struct {
  Module *cur_module;
  ModuleCheck cur_mod_check;

  TypeHint hint;
  bool infer_types;

  ErrorSink sink;

  Bump checker_arena;
  Allocator checker_arena_allocator;
} TypeChecker;

typedef struct {
  Ident func_name;
  FuncDescriptor *cur_func_desc;
} CheckerContext;

void checker_init(TypeChecker *checker);

void checker_deinit(TypeChecker *checker);

// Return false if errors occured
bool module_check(Module *module, TypeChecker *checker, ModuleCheck mod_check);

void checker_gen_functions(TypeChecker *checker);
