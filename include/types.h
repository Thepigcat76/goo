#pragma once

#include <lilc/alloc.h>
#include <stdbool.h>
#include <stdlib.h>
#include "shared.h"
#include "module_path.h"

typedef enum {
  TYPE_ARRAY_VARIANT_SIZED,
  TYPE_ARRAY_VARIANT_SIZE_UNKNOWN,
} TypeArrayVariant;

typedef struct {
  TypeArrayVariant variant;
  size_t size;
  struct _type *type;
} TypeArray;

typedef struct {
  struct _type *type;
} TypePointer;

typedef struct {
  struct _generic *generics;
  struct _type *arg_types;
  struct _type *ret_type;
} TypeFunc;

typedef struct {
  struct _type *types;
} TypeTuple;

typedef struct {
  struct _typed_ident *fields;
} TypeStruct;

typedef enum {
  TYPE_SIZE_SIZED,
  TYPE_SIZE_UNKNOWN,
} TypeSize;

typedef struct _type {
  enum {
    TYPE_IDENT,
    TYPE_ARRAY,
    TYPE_FUNCTION,
    TYPE_TUPLE,
    TYPE_UNIT, // unit is just an empty tuple and used as the "void" type
    TYPE_STRUCT,
    TYPE_POINTER,
  } kind;
  union {
    ModulePath type_ident;
    TypeArray type_array;
    TypeFunc type_func;
    TypeTuple type_tuple;
    TypeStruct type_struct;
    TypePointer type_pointer;
  } var;
} Type;

typedef struct {
  char *error_msg;
  bool success;
  int line;
  int pos;
} CheckResult;

typedef struct {
  Ident name;
  Type *arg_types;
  Type ret_type;
} FuncSignature;

typedef struct _typed_ident {
  Ident ident;
  Type type;
} TypedIdent;

bool type_eq(const Type *a, const Type *b);

typedef struct {
  bool debug;
  bool color;
} TypeFormatter;

#define TYPE_FORMATTER_DEFAULT_COLOR (TypeFormatter){.debug = false, .color = true}

#define TYPE_FORMATTER_DEFAULT (TypeFormatter){0}

#define TYPE_FORMATTER_DEBUG (TypeFormatter){.debug = true}

dyn_string_t type_format(const TypeFormatter *fmt, const Type *type);
