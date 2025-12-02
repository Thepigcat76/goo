#include "../include/types.h"
#include "../vendor/lilc/array.h"
#include "../vendor/lilc/eq.h"
#include <stdio.h>
#include <string.h>

#define BUILTIN_TYPE_IDENT(_ident)                                             \
  (Type) {                                                                     \
    .type = TYPE_IDENT, .var = {.type_ident = _ident }                         \
  }

const Type UNIT_BUILTIN_TYPE = {.type = TYPE_UNIT};
const Type STRING_BUILTIN_TYPE = BUILTIN_TYPE_IDENT("string");
const Type INT_BUILTIN_TYPE = BUILTIN_TYPE_IDENT("i32");
const Type BOOL_BUILTIN_TYPE = BUILTIN_TYPE_IDENT("bool");

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
  case TYPE_STRUCT: {
    TypeStruct a_struct = a->var.type_struct;
    TypeStruct b_struct = b->var.type_struct;

    for (size_t i = 0; i < array_len(a_struct.fields); i++) {
      for (size_t j = 0; j < array_len(b_struct.fields); j++) {
        if (strv_eq(a_struct.fields[i].ident, b_struct.fields[j].ident)) {
          if (!type_eq(&a_struct.fields[i].type, &b_struct.fields[j].type)) {
            return false;
          } else {
            goto outer_continue;
          }
        }
        // struct B contains a field that is not in struct A
        return false;
      }

      // struct A contains a field that is not in struct B
      return false;

    // Continue to next field
    outer_continue:
      continue;
    }

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
  case TYPE_STRUCT: {
    TypeStruct type_struct = type->var.type_struct;
    char fields_buf[512] = "";
    for (size_t i = 0; i < array_len(type_struct.fields); i++) {
      char type_buf[64];
      type_print(type_buf, &type_struct.fields[i].type);
      char ti_buf[128];
      sprintf(ti_buf, "TypedIdent={ident=%s, type=%s}", type_struct.fields[i].ident, type_buf);
      strcat(fields_buf, ti_buf);
      if (i < array_len(type_struct.fields) - 1) {
        strcat(fields_buf, ", ");
      }
    }
    sprintf(buf, "TypeStruct{fields=[%s]}", fields_buf);
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
