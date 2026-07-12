#include "../../include/types.h"
#include "lilc/array.h"
#include "lilc/eq.h"
#include "lilc/todo.h"
#include <lilc/alloc.h>
#include <stdio.h>
#include <string.h>

static ModulePath module_path_primitive(char *ident) {
  ModulePath path = {.path = array_new(Ident, &HEAP_ALLOCATOR)};
  array_add(path.path, ident);
  return path;
}

#define BUILTIN_TYPE_IDENT(_ident, ...)                                        \
  (Type) {                                                                     \
    .kind = TYPE_IDENT, .var = {                                               \
      .type_ident = module_path_primitive(_ident) __VA_OPT__(, ) __VA_ARGS__   \
    }                                                                          \
  }

#define BUILTIN_TYPE_ARRAY(_ident, _variant, _type)                            \
  (Type) {                                                                     \
    .kind = TYPE_ARRAY, .var = {                                               \
      .type_array = {.variant = _variant, .type = _type}                       \
    }                                                                          \
  }

const Type UNIT_BUILTIN_TYPE = {.kind = TYPE_UNIT};
/* Integers */
Type I8_BUILTIN_TYPE;
Type I16_BUILTIN_TYPE;
Type I32_BUILTIN_TYPE;
Type I64_BUILTIN_TYPE;
/* Unsigned Integers */
Type U8_BUILTIN_TYPE;
Type U16_BUILTIN_TYPE;
Type U32_BUILTIN_TYPE;
Type U64_BUILTIN_TYPE;

Type ANY_BUILTIN_TYPE;
Type STRING_BUILTIN_TYPE;
Type BOOL_BUILTIN_TYPE;

static void type_deinit(Type *type) {
  switch (type->kind) {
  case TYPE_IDENT: {
    array_free(type->var.type_ident.path);
  } break;
  case TYPE_ARRAY: {
  } break;
  default: {
    TODO("Cannot free type: %d", type->kind);
    break;
  }
  }
}

void builtin_types_init(void) {
  I8_BUILTIN_TYPE = BUILTIN_TYPE_IDENT("i8");
  I16_BUILTIN_TYPE = BUILTIN_TYPE_IDENT("i16");
  I32_BUILTIN_TYPE = BUILTIN_TYPE_IDENT("i32");
  I64_BUILTIN_TYPE = BUILTIN_TYPE_IDENT("i64");
  /* Unsigned Integers */
  U8_BUILTIN_TYPE = BUILTIN_TYPE_IDENT("u8");
  U16_BUILTIN_TYPE = BUILTIN_TYPE_IDENT("u16");
  U32_BUILTIN_TYPE = BUILTIN_TYPE_IDENT("u32");
  U64_BUILTIN_TYPE = BUILTIN_TYPE_IDENT("u64");
  ANY_BUILTIN_TYPE = BUILTIN_TYPE_IDENT("any");
  STRING_BUILTIN_TYPE = BUILTIN_TYPE_ARRAY(
      "string", TYPE_ARRAY_VARIANT_SIZE_UNKNOWN, &U8_BUILTIN_TYPE);
  BOOL_BUILTIN_TYPE = BUILTIN_TYPE_IDENT("bool");
}

void builtin_types_deinit(void) {
  type_deinit(&I8_BUILTIN_TYPE);
  type_deinit(&I16_BUILTIN_TYPE);
  type_deinit(&I32_BUILTIN_TYPE);
  type_deinit(&I64_BUILTIN_TYPE);

  type_deinit(&U8_BUILTIN_TYPE);
  type_deinit(&U16_BUILTIN_TYPE);
  type_deinit(&U32_BUILTIN_TYPE);
  type_deinit(&U64_BUILTIN_TYPE);

  type_deinit(&ANY_BUILTIN_TYPE);
  type_deinit(&BOOL_BUILTIN_TYPE);

  type_deinit(&STRING_BUILTIN_TYPE);
}

bool type_eq(const Type *a, const Type *b) {
  if (a == NULL || b == NULL || a->kind != b->kind)
    return false;

  switch (a->kind) {
  case TYPE_IDENT: {
    if (array_len(a->var.type_ident.path) != array_len(b->var.type_ident.path))
      return false;

    for (size_t i = 0; i < array_len(a->var.type_ident.path); i++) {
      if (strcmp(a->var.type_ident.path[i], b->var.type_ident.path[i]) != 0)
        return false;
    }
    return true;
  }
  case TYPE_ARRAY: {
    bool sizes_match = false;
    if (a->var.type_array.variant == b->var.type_array.variant) {
      if (a->var.type_array.variant == TYPE_ARRAY_VARIANT_SIZED) {
        sizes_match = a->var.type_array.size == b->var.type_array.size;
      } else {
        sizes_match = true;
      }
    }
    return type_eq(a->var.type_array.type, b->var.type_array.type) &&
           sizes_match;
  }
  case TYPE_FUNCTION: {
    return false;
  }
  case TYPE_TUPLE: {
    // TODO: Implement this case
    bool tuple_types_match = false;
    return tuple_types_match;
  }
  case TYPE_UNIT: {
    return true;
  }
  case TYPE_POINTER: {
    return type_eq(a->var.type_pointer.type, b->var.type_pointer.type);
  }
  case TYPE_STRUCT: {
    TypeStruct a_struct = a->var.type_struct;
    TypeStruct b_struct = b->var.type_struct;

    size_t a_fields = array_len(a_struct.fields);
    size_t b_fields = array_len(b_struct.fields);
    if (a_fields != b_fields)
      return false;

    for (size_t i = 0; i < array_len(a_struct.fields); i++) {
      if (strv_eq(a_struct.fields[i].ident, b_struct.fields[i].ident)) {
        if (!type_eq(&a_struct.fields[i].type, &b_struct.fields[i].type)) {
          return false;
        }
      } else {
        return false;
      }
    }

    return true;
  }
  }
}
