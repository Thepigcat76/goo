#include "../../include/comptime_func_proc.h"
#include <lilc/alloc.h>
#include <lilc/bump.h>
#include <lilc/panic.h>

void cfp_init(ComptimeFuncProcessor *proc) {
  bump_init(&proc->proc_arena, 80000);
  bump_allocator_init(&proc->proc_arena_alloc, &proc->proc_arena);
}

void cfp_deinit(ComptimeFuncProcessor *proc) { bump_free(&proc->proc_arena); }

static bool func_process(ComptimeFuncProcessor *proc, Ident func_name) {
  ModulePath func_mod_path = mod_path_root(func_name, &proc->proc_arena_alloc);
  TypeTableValue *val = type_table_get(&proc->cur_mod_process.global_type_table,
                                       &func_mod_path, NULL);
  if (val == NULL) {
    panic("Function for comptime param processing doesnt exist");
    return false;
  }

  if (val->expr_variant.kind != EXPR_VAR_REG_EXPR ||
      val->expr_variant.var.expr_var_reg_expr.kind != EXPR_FUNCTION) {
    panic("Function for comptime param processing isnt a function");
    return false;
  }

  ExprFunction func_expr =
      val->expr_variant.var.expr_var_reg_expr.var.expr_function;

  Argument *arg;
  array_foreach(func_expr.desc.args, arg) {
    
  }

  return true;
}

bool module_process_comptime_func_params(
    Module *module, ComptimeFuncProcessor *proc,
    ModuleComptimeParamProcess comptime_param_proc) {
  bool success = true;

  proc->cur_mod = module;
  proc->cur_mod_process = comptime_param_proc;

  Ident *comptime_param_func;
  array_foreach(comptime_param_proc.comptime_params_process,
                comptime_param_func) {
    success = func_process(proc, *comptime_param_func);
  }

  return success;
}