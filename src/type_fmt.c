#include "../include/types.h"
#include <lilc/str.h>
#include <stdbool.h>

dyn_string_t type_format(const TypeFormatter *fmt, const Type *type) {
  dyn_string_t str = {0};
  dyn_string_init(&str);

  switch (type->type) {
  case TYPE_IDENT: {
    dyn_string_t path = module_path_fmt(&type->var.type_ident);
    if (fmt->debug) {
      dyn_string_printf(&str, "TypeIdent{%s}", path.string);
    } else {
      dyn_string_add_str(&str, path.string);
    }
    dyn_string_free(&path);
  } break;
  case TYPE_ARRAY: {
    if (type_eq(type, &STRING_BUILTIN_TYPE)) {
      dyn_string_add_str(&str, "string");
    } else {

    }
  } break;
  case TYPE_FUNCTION:
  case TYPE_TUPLE:
  case TYPE_UNIT:
  case TYPE_STRUCT:
  case TYPE_POINTER:
    break;
  }
  return str;
}
