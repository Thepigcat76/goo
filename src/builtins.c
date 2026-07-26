#include "../include/builtins/functions.h"
#include "../include/builtins/types.h"
#include "../include/parser.h"
#include <lilc/alloc.h>
#include <lilc/array.h>
#include <lilc/panic.h>
#include <lilc/todo.h>
#include <stdio.h>

#define BUILTIN_FUNCTION_DEFINE(_ret_type, _native_function)                   \
  (Expression) {                                                               \
    .kind = EXPR_FUNCTION, .var =                                              \
    {.expr_function = {.desc = {.ret_type = _ret_type,                         \
                                .args = array_new(Argument, &HEAP_ALLOCATOR)}, \
                       .block = NULL,                                          \
                       .native_function = _native_function} }                  \
  }

#define BUILTIN_FUNCTION_SET_ARG_TYPES(_expr, ...)                             \
  do {                                                                         \
    Argument *args = _expr.var.expr_function.desc.args;                        \
    Argument provided[] = {__VA_ARGS__ __VA_OPT__(, )(Argument){0}};           \
    size_t i;                                                                  \
    for (i = 0;                                                                \
         provided[i].kind != ARG_VARARG && provided[i].arg_name != NULL;       \
         i++) {                                                                \
      array_add(args, provided[i]);                                            \
    }                                                                          \
    if (provided[i].kind == ARG_VARARG) {                                      \
      array_add(args, provided[i]);                                            \
    }                                                                          \
  } while (0)

#define BUILTIN_FUNCTION(func, _name, _execute_func, _ret_type, ...)           \
  do {                                                                         \
    Expression expr = BUILTIN_FUNCTION_DEFINE(_ret_type, _execute_func);       \
    BUILTIN_FUNCTION_SET_ARG_TYPES(expr, __VA_ARGS__);                         \
    func = (BuiltinFunction){                                                  \
        .expr = expr, .name = _name, .execute = _execute_func};                \
    array_add(BUILTIN_FUNCTIONS, func);                                        \
  } while (0)

#define ARG(_ident, _type)                                                     \
  (Argument) { .kind = ARG_REGULAR_ARG, .arg_name = _ident, .arg_type = _type }

#define VARARG(_ident)                                                         \
  (Argument) { .kind = ARG_VARARG, .arg_name = _ident }

BuiltinFunction BUILTIN_FUNCTIONS[_amount_builtin_funcs] = {0};

void builtin_functions_init(Allocator *alloc, TypeTable *type_table) {
  for (BuiltinFunctionKind i = 0; i < _amount_builtin_funcs; i++) {
    BuiltinFunction func = {0};
    func.expr.kind = EXPR_FUNCTION;
    FuncDescriptor *func_desc = &func.expr.var.expr_function.desc;
    func_desc->args = array_new(Argument, alloc);
    func_desc->has_ret_type = true;
    func_desc->ret_type = BUILTIN_TYPES[BUILTIN_TYPE_UNIT];

    Ident name = NULL;

    switch (i) {
    case BUILTIN_FUNC_PRINTFN: {
      name = "printfn";

      array_add(func_desc->args,
                ARG("value", BUILTIN_TYPES[BUILTIN_TYPE_STRING]));
    } break;
    case BUILTIN_FUNC_FORMAT: {
      name = "format";
      func_desc->ret_type = BUILTIN_TYPES[BUILTIN_TYPE_STRING];

      array_add(func_desc->args,
                ARG("format", BUILTIN_TYPES[BUILTIN_TYPE_STRING]));
      array_add(func_desc->args, VARARG("args"));
    } break;
    case BUILTIN_FUNC_EXIT: {
      name = "exit";

      array_add(func_desc->args,
                ARG("code", BUILTIN_TYPES[BUILTIN_TYPE_STRING]));
    } break;
    default: {
      panic("Illegal value %d for builtin type", i);
    } break;
    }

    func.name = mod_path_make(alloc, name);

    BUILTIN_FUNCTIONS[i] = func;

    type_table_add(type_table, &func.name, EXPR_VAR_EXPR(func.expr),
                   OPT_TYPE_EMPTY);
  }
}

void builtin_functions_deinit(TypeTable *global_type_table) {
  for (BuiltinFunctionKind i = 0; i < _amount_builtin_funcs; i++) {
    ExprFunction expr_func = BUILTIN_FUNCTIONS[i].expr.var.expr_function;
    if (expr_func.desc.generics != NULL) {
      array_free(expr_func.desc.generics);
    }
    array_free(expr_func.desc.args);
  }
}

Type BUILTIN_TYPES[_amount_builtin_types] = {0};

static inline void type_deinit(Type *type) {
  if (type->kind == TYPE_IDENT) {
    mod_path_deinit(&type->var.type_ident);
  }
}

void builtin_types_init(Allocator *alloc) {
  for (BuiltinType i = 0; i < _amount_builtin_types; i++) {
    Type type = {0};

    switch (i) {
    case BUILTIN_TYPE_I8: {
      type.kind = TYPE_IDENT;
      type.var.type_ident = mod_path_make(alloc, "i8");
    } break;
    case BUILTIN_TYPE_I16: {
      type.kind = TYPE_IDENT;
      type.var.type_ident = mod_path_make(alloc, "i16");
    } break;
    case BUILTIN_TYPE_I32: {
      type.kind = TYPE_IDENT;
      type.var.type_ident = mod_path_make(alloc, "i32");
    } break;
    case BUILTIN_TYPE_I64: {
      type.kind = TYPE_IDENT;
      type.var.type_ident = mod_path_make(alloc, "i64");
    } break;
    case BUILTIN_TYPE_U8: {
      type.kind = TYPE_IDENT;
      type.var.type_ident = mod_path_make(alloc, "u8");
    } break;
    case BUILTIN_TYPE_U16: {
      type.kind = TYPE_IDENT;
      type.var.type_ident = mod_path_make(alloc, "u16");
    } break;
    case BUILTIN_TYPE_U32: {
      type.kind = TYPE_IDENT;
      type.var.type_ident = mod_path_make(alloc, "u32");
    } break;
    case BUILTIN_TYPE_U64: {
      type.kind = TYPE_IDENT;
      type.var.type_ident = mod_path_make(alloc, "u64");
    } break;
    case BUILTIN_TYPE_UNIT: {
      type.kind = TYPE_UNIT;
    } break;
    case BUILTIN_TYPE_ANY: {
      type.kind = TYPE_IDENT;
      type.var.type_ident = mod_path_make(alloc, "any");
    } break;
    case BUILTIN_TYPE_STRING: {
      type.kind = TYPE_ARRAY;
      type.var.type_array.type = &BUILTIN_TYPES[BUILTIN_TYPE_U8];
      type.var.type_array.variant = TYPE_ARRAY_VARIANT_SIZE_UNKNOWN;
    } break;
    case BUILTIN_TYPE_BOOL: {
      type.kind = TYPE_IDENT;
      type.var.type_ident = mod_path_make(alloc, "bool");
    } break;
    case BUILTIN_TYPE_TYPE: {
      type.kind = TYPE_IDENT;
      type.var.type_ident = mod_path_make(alloc, "type");
    } break;
    default: {
      panic("Illegal value %d for builtin type", i);
    } break;
    }

    BUILTIN_TYPES[i] = type;
  }
}

void builtin_types_deinit(void) {
  for (BuiltinType i = 0; i < _amount_builtin_types; i++) {
    type_deinit(&BUILTIN_TYPES[i]);
  }
}
