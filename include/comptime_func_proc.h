#pragma once

#include "ast.h"
#include "lilc/hashmap0.h"
#include "module.h"
#include "shared.h"

typedef struct {
  const Ident *comptime_params_process;

  Hashmap function_type_tables; /* Ident -> TypeTables */
  TypeTable global_type_table;
} ModuleComptimeParamProcess;

typedef struct {
  Module *cur_mod;
  ModuleComptimeParamProcess cur_mod_process;

  Bump proc_arena;
  Allocator proc_arena_alloc;
} ComptimeFuncProcessor;

void cfp_init(ComptimeFuncProcessor *proc);

void cfp_deinit(ComptimeFuncProcessor *proc);

bool module_process_comptime_func_params(Module *module,
                                         ComptimeFuncProcessor *proc,
                                         ModuleComptimeParamProcess comptime_param_proc);
