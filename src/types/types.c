#include "../../include/types.h"
#include "../../include/builtins/types.h"
#include "lilc/array.h"
#include "lilc/eq.h"
#include <lilc/alloc.h>
#include <lilc/panic.h>
#include <stdio.h>
#include <string.h>

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
