#include "lilc/alloc.h"
#include "../types.h"

typedef enum {
  BUILTIN_TYPE_I8,
  BUILTIN_TYPE_I16,
  BUILTIN_TYPE_I32,
  BUILTIN_TYPE_I64,

  BUILTIN_TYPE_U8,
  BUILTIN_TYPE_U16,
  BUILTIN_TYPE_U32,
  BUILTIN_TYPE_U64,
  
  BUILTIN_TYPE_UNIT,
  BUILTIN_TYPE_ANY,
  BUILTIN_TYPE_STRING,
  BUILTIN_TYPE_BOOL,
  BUILTIN_TYPE_TYPE,

  _amount_builtin_types,
} BuiltinType;

extern Type BUILTIN_TYPES[_amount_builtin_types];

void builtin_types_init(Allocator *alloc);

void builtin_types_deinit(void);
