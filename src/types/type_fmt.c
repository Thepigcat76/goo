#include "../../include/types.h"
#include <lilc/alloc.h>
#include <lilc/ansi.h>
#include <lilc/assert.h>
#include <lilc/dynstr.h>
#include <lilc/str.h>
#include <lilc/todo.h>
#include <stdbool.h>

dyn_string_t type_format(const TypeFormatter *fmt, const Type *type) {
  ASSERT(type != NULL, "Type for formatting cannot be (null)");

  dyn_string_t str = {0};
  dyn_string_init(&str, &HEAP_ALLOCATOR);

  if (fmt->color) {
    dyn_string_add_str(&str, ANSI_YELLOW);
  }

  switch (type->kind) {
  case TYPE_IDENT: {
    dyn_string_t path = mod_path_fmt(&type->var.type_ident);
    if (fmt->debug) {
      dyn_string_printf(&str, "TypeIdent{'%s'}", path.string);
    } else {
      dyn_string_add_str(&str, path.string);
    }
    dyn_string_free(&path);
  } break;
  case TYPE_ARRAY: {
    if (!fmt->debug && type_eq(type, &STRING_BUILTIN_TYPE)) {
      dyn_string_printf(&str, "string");
    } else {
      dyn_string_printf(&str, "ARRAY");
    }
  } break;
  case TYPE_UNIT: {
    if (fmt->debug) {
      dyn_string_printf(&str, "TypeUnit");
    } else {
      dyn_string_printf(&str, "()");
    }
  } break;
  case TYPE_POINTER: {
    char *type_str = dyn_string_temp_copy_and_free(
        type_format(fmt, type->var.type_pointer.type));

    if (fmt->debug) {
      dyn_string_printf(&str, "TypePointer{%s}", type_str);
    } else {
      dyn_string_printf(&str, "*%s", type_str);
    }
  } break;
  case TYPE_STRUCT: {
    dyn_string_printf(&str, "STRUCT");
  } break;
  case TYPE_FUNCTION:
  case TYPE_TUPLE: {
    TODO("Formatting not implemented for type of kind %d", type->kind);
  } break;
  }

  if (fmt->color) {
    dyn_string_add_str(&str, ANSI_RESET);
  }
  return str;
}
