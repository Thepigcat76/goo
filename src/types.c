#include "../include/types.h"
#include <string.h>
#include <stdio.h>

#define BUILTIN_TYPE_IDENT(_ident)                                             \
  (Type) {                                                                     \
    .type = TYPE_IDENT, .var = {.type_ident = _ident }                         \
  }

const Type UNIT_BUILTIN_TYPE = {.type = TYPE_UNIT};
const Type STRING_BUILTIN_TYPE = BUILTIN_TYPE_IDENT("string");
const Type INT_BUILTIN_TYPE = BUILTIN_TYPE_IDENT("i32");

bool type_eq(const Type *a, const Type *b) {
  if (a->type != b->type)
    return false;

  switch (a->type) {
  case TYPE_IDENT: {
    return strcmp(a->var.type_ident, b->var.type_ident) == 0;
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
  }
}

void type_print(char *buf, const Type *type) {
  switch (type->type) {
  case TYPE_IDENT: {
    sprintf(buf, "TypeIdent{ident=%s}", type->var.type_ident);
    break;
  }
  case TYPE_ARRAY: {
    TypeArray type_array = type->var.type_array;
    char *array_variant;
    char size_buf[32];
    switch (type_array.variant) {
    case TYPE_ARRAY_VARIANT_DYNAMIC: {
      array_variant = "DYNAMIC";
      sprintf(size_buf, "dyn");
      break;
    }
    case TYPE_ARRAY_VARIANT_SIZED: {
      array_variant = "SIZED";
      sprintf(size_buf, "%zu", type_array.size);
      break;
    }
    case TYPE_ARRAY_VARIANT_SIZE_UNKNOWN: {
      array_variant = "SIZE_UNKNOWN";
      sprintf(size_buf, "?");
      break;
    }
    }
    char type_buf[256];
    type_print(type_buf, type_array.type);
    sprintf(buf, "TypeArray{variant=%s, size=%s, type=%s}", array_variant,
            size_buf, type_buf);
    break;
  }
  case TYPE_UNIT: {
    sprintf(buf, "TypeUnit");
    break;
  }
  // TODO: Implement both of these
  case TYPE_FUNCTION: {
    sprintf(buf, "TypeFunction - NYI");
    break;
  }
  case TYPE_TUPLE: {
    sprintf(buf, "TypeTuple - NYI");
    break;
  }
  }
}
