#include "../include/module.h"

void module_init(Module *module, const char *filename, const char *source) {
  module->filename = filename;
  module->source = source;
  module->functions =
      hashmap_new(ModulePath, FuncDescriptor, &HEAP_ALLOCATOR,
                  module_path_ptrv_hash, module_path_ptrv_eq, NULL);
  module->decls = array_new(TypedIdent, &HEAP_ALLOCATOR);
}

void module_deinit(Module *module) {
  hashmap_free(&module->functions);
  array_free(module->decls);
}
