#include "../include/module.h"

inline Module module_new(const char *filename, const char *source,
                  Statement *program_stmts) {
  return (Module){
      .filename = filename, .source = source, .program_stmts = program_stmts};
}