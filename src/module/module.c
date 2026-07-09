#include "../include/module.h"
#include "../include/ast.h"
#include <lilc/alloc.h>

void module_init(Module *module, const char *filename, const char *source) {
  module->filename = filename;
  module->source = source;
  hashmap_init(&module->functions, &HEAP_ALLOCATOR, ModulePath, FuncDescriptor,
               module_path_ptrv_hash, module_path_ptrv_eq, NULL);
  module->decls = array_new(TypedIdent, &HEAP_ALLOCATOR);
}

void module_deinit(Module *module) {
  // hashmap_free(&module->functions);
  // array_free(module->decls);
}
