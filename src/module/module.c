#include "../../include/module.h"
#include "../../include/ast.h"
#include "../../include/checker.h"
#include "../../include/lexer.h"
#include "../../include/parser.h"
#include <lilc/alloc.h>

void module_init(Module *module, ModulePath mod_path, const char *filename,
                 const char *source) {
  module->filename = filename;
  module->source = source;
  module->path = mod_path;
  hashmap_init(&module->functions, &HEAP_ALLOCATOR, ModulePath, FuncDescriptor,
               mod_path_ptrv_hash, mod_path_ptrv_eq, NULL);
  module->decls = array_new(TypedIdent, &HEAP_ALLOCATOR);
}

void module_parse_standalone(Module *module) {
  Lexer lexer = {0};
  lexer_init(&lexer);

  TokenStream tokens = array_new(Token, &HEAP_ALLOCATOR);
  SourceLine *lines = array_new(SourceLine, &HEAP_ALLOCATOR);
  module_tokenize(module, &lexer, &tokens, &lines);

  Parser parser = {0};
  parser_init(&parser);

  Statement *stmts = array_new(Statement, &HEAP_ALLOCATOR);
  PpDirective *pp_dirs = array_new(PpDirective, &HEAP_ALLOCATOR);
  module_parse(module, &parser, &stmts, &pp_dirs, tokens, lines);

  PreProcessor preproc = {0};
  preprocessor_init(&preproc);

  module_preprocess(module, &preproc, stmts, pp_dirs);

  TypeChecker checker = {0};
  checker_init(&checker);

  array_free(pp_dirs);
  array_free(stmts);
  array_free(lines);
  array_free(tokens);

  //checker_deinit(&checker);
  //preprocessor_deinit(&preproc);
  //parser_deinit(&parser);
  //lexer_deinit(&lexer);
}

void module_deinit(Module *module) {
  hashmap_deinit(&module->functions);
  array_free(module->decls);
}
