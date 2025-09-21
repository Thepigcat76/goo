#include "../hash.h"

int32_t strv_hash(const void *a) {
  const char *str = (char *)a;
  int hash = 5381;
  int c;

  while ((c = (unsigned char)*str++)) {
    hash = ((hash << 5) + hash) + c;
  }

  if (hash < 0) {
    hash = -hash;
  }

  return hash;
}

int32_t str_ptrv_hash(const void *str_ptr) {
  return strv_hash(*(char **)str_ptr);
}
