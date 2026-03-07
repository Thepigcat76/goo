#include "../../include/compiler.h"
#include "lilc/log.h"
#include <elf.h>

#define WRITE(fp, ptr) fwrite(ptr, 1, sizeof(*ptr), fp)

static const char shstrtab_data[] = "\0"
                                    ".text\0"      // Index 1
                                    ".data\0"      // Index 7
                                    ".rodata\0"    // Index 13
                                    ".strtab\0"    // Index 21
                                    ".symtab\0"    // Index 29
                                    ".rela.text\0" // Index 37
                                    ".shstrtab\0"; // Index 48

#define TEXT_INDEX 1
#define DATA_INDEX 2
#define RODATA_INDEX 3
#define STRTAB_INDEX 4
#define SYMTAB_INDEX 5

#define OFF_TEXT_NAME 1
#define OFF_DATA_NAME 7
#define OFF_RODATA_NAME 13
#define OFF_STRTAB_NAME 21
#define OFF_SYMTAB_NAME 29
#define OFF_RELA_TEXT_NAME 37
#define OFF_SHSTRTAB_NAME 48

typedef struct {
  Elf64_Ehdr eh;
  uint8_t *text_section_data;
  size_t text_section_size;
  uint8_t *data_section_data;
  size_t data_section_size;
  uint8_t *rodata_section_data;
  size_t rodata_section_size;
  char *strtab_section_data;
  size_t strtab_section_size;
  size_t strtab_section_capacity;
  const char *shstrtab_section_data;
  Elf64_Sym *symbols;
  Elf64_Rela *relocations;
  Elf64_Shdr sh_null;
  Elf64_Shdr sh_text;
  Elf64_Shdr sh_data;
  Elf64_Shdr sh_rodata;
  Elf64_Shdr sh_strtab;
  Elf64_Shdr sh_symtab;
  Elf64_Shdr sh_rela_text;
  Elf64_Shdr sh_shstrtab;
} Object;

static void obj_write(const Object *obj, FILE *file) {
  WRITE(file, &obj->eh);
  fwrite(obj->text_section_data, 1, obj->text_section_size, file);
  fwrite(obj->data_section_data, 1, obj->data_section_size, file);
  fwrite(obj->rodata_section_data, 1, obj->rodata_section_size, file);
  fwrite(obj->strtab_section_data, 1, obj->strtab_section_size, file);
  // fwrite(obj->symtab_section_data, 1, obj->symtab_section_size, file);
  for (size_t i = 0; i < array_len(obj->symbols); i++) {
    WRITE(file, &obj->symbols[i]);
    log_info("Writing symbol %zu", i);
  }
  for (size_t i = 0; i < array_len(obj->relocations); i++) {
    WRITE(file, &obj->relocations[i]);
    log_info("Writing relocation %zu", i);
  }
  fwrite(shstrtab_data, 1, sizeof(shstrtab_data), file);
  WRITE(file, &obj->sh_null);
  WRITE(file, &obj->sh_text);
  WRITE(file, &obj->sh_data);
  WRITE(file, &obj->sh_rodata);
  WRITE(file, &obj->sh_strtab);
  WRITE(file, &obj->sh_symtab);
  WRITE(file, &obj->sh_rela_text);
  WRITE(file, &obj->sh_shstrtab);
}

static inline void data_section_write_bytes(const DataSection *section,
                                            uint8_t *bytes) {
  memcpy(bytes, section->data_bytes, section->data_len);
}

static void obj_add_data(Object *obj, const Compiler *compiler) {
  obj->text_section_data = compiler->program_data;
  obj->text_section_size = compiler->program_data_size;

  obj->data_section_data = malloc(compiler->data_section.data_len);
  obj->data_section_size = compiler->data_section.data_len;
  data_section_write_bytes(&compiler->data_section, obj->data_section_data);

  obj->rodata_section_data = malloc(compiler->rodata_section.data_len);
  obj->rodata_section_size = compiler->rodata_section.data_len;
  data_section_write_bytes(&compiler->rodata_section, obj->rodata_section_data);
}

static size_t obj_string_table_add(Object *obj, char *symbol) {
  size_t symbol_len = strlen(symbol);
  if (obj->strtab_section_capacity <= obj->strtab_section_size + symbol_len) {
    obj->strtab_section_capacity *= 2;
    obj->strtab_section_data =
        realloc(obj->strtab_section_data, obj->strtab_section_capacity + 1);
  }
  memcpy(obj->strtab_section_data + obj->strtab_section_size, symbol,
         symbol_len + 1);
  memcpy(obj->strtab_section_data + obj->strtab_section_size + symbol_len + 2,
         "\0", 1);
  size_t old_size = obj->strtab_section_size;
  obj->strtab_section_size += symbol_len + 1;
  return old_size;
}

static void obj_symbol_table_add_foreign_func(Object *obj, char *func_name) {
  size_t name_idx = obj_string_table_add(obj, func_name);

  Elf64_Sym foreign_func_sym = {0};
  foreign_func_sym.st_name = name_idx;
  foreign_func_sym.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE);
  foreign_func_sym.st_shndx = SHN_UNDEF;
  array_add(obj->symbols, foreign_func_sym);
}

void compiler_write(Compiler *compiler, FILE *file) {
  if (compiler->step != COMPILE_STEP_GENERATE_MACHINE)
    return;
  compiler->step = COMPILE_STEP_OUTPUT_OBJECT;

  log_info("[COMPILER] Start writing object file");

  Object obj = {0};

  obj.strtab_section_data = malloc(512 + 1);
  memcpy(obj.strtab_section_data, "\0", 2);
  obj.strtab_section_size = 1;
  obj.strtab_section_capacity = 512;

  obj.symbols = array_new(Elf64_Sym, &HEAP_ALLOCATOR);
  obj.relocations = array_new(Elf64_Rela, &HEAP_ALLOCATOR);

  /* Section contents */
  obj_add_data(&obj, compiler);

  /* --- Symbols --- */
  Elf64_Sym sym_null = {0};
  array_add(obj.symbols, sym_null);

  Elf64_Sym sym_text = {0}; // section symbol (.text)
  sym_text.st_info = ELF64_ST_INFO(STB_LOCAL, STT_SECTION);
  sym_text.st_shndx = TEXT_INDEX; // section index of .text
  array_add(obj.symbols, sym_text);

  Elf64_Sym sym_rodata = {0}; // section symbol (.rodata)
  sym_rodata.st_info = ELF64_ST_INFO(STB_LOCAL, STT_SECTION);
  sym_rodata.st_shndx = RODATA_INDEX;
  array_add(obj.symbols, sym_rodata);

  Elf64_Sym sym_data = {0}; // section symbol (.data)
  sym_data.st_info = ELF64_ST_INFO(STB_LOCAL, STT_SECTION);
  sym_data.st_shndx = DATA_INDEX;
  array_add(obj.symbols, sym_data);

  /* Symbols */
  hashmap_foreach(&compiler->symbols, Ident * key, size_t *val, {
    size_t name_idx = obj_string_table_add(&obj, *key);

    Elf64_Sym sym = {0};
    sym.st_name = name_idx;
    sym.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    sym.st_other = STV_DEFAULT;
    sym.st_shndx = TEXT_INDEX;
    sym.st_value = *val; // start of section
    sym.st_size = obj.text_section_size;
    array_add(obj.symbols, sym);
  });

  /* Relocations */
  for (size_t i = 0; i < array_len(compiler->elf64_relocations); i++) {
    Elf64_Relocation reloc = compiler->elf64_relocations[i];

    Elf64_Rela rela = {0};
    switch (reloc.rel_type) {
    case RELOCATION_FUNCTION: {
      size_t sym_idx = array_len(obj.symbols);
      log_debug("Function reloc symbol: %s", reloc.symbol);
      obj_symbol_table_add_foreign_func(&obj, reloc.symbol);
      /* Uses 1 as an additional offset because thats the opcode length of the
       * call instruction */
      rela.r_offset = reloc.program_offset + 1;
      rela.r_info = ELF64_R_INFO(sym_idx, R_X86_64_PLT32);
      rela.r_addend = -4;
      break;
    }
    case RELOCATION_DATA:
    case RELOCATION_RODATA: {
      rela.r_offset = reloc.program_offset + reloc.r_offset;
      rela.r_info = ELF64_R_INFO(reloc.rel_type == RELOCATION_DATA ? 3 : 2,
                                 R_X86_64_PC32);
      rela.r_addend = -4 + reloc.data_offset;
      log_debug("RODATA/DATA with offset: %zu, symbol shndx: %hu",
                rela.r_offset, obj.symbols[2].st_shndx);
      break;
    }
    default: {
      fprintf(stderr, "Failed to create relocation");
      exit(1);
    }
    }
    log_debug("Created relocation %zu for r-offset: %zu, type: %s, "
              "data_offset: %zu, symbol: %s",
              i, rela.r_offset,
              reloc.rel_type == RELOCATION_DATA ||
                      reloc.rel_type == RELOCATION_RODATA
                  ? "DATA"
                  : "FUNCTION",
              reloc.data_offset,
              reloc.rel_type == RELOCATION_FUNCTION ? reloc.symbol : "<EMPTY>");
    array_add(obj.relocations, rela);
  }

  const Elf64_Off elf_header_offset = 0x0;
  const Elf64_Off text_offset = elf_header_offset + sizeof(Elf64_Ehdr);
  const Elf64_Off data_offset = text_offset + obj.text_section_size;
  const Elf64_Off rodata_offset = data_offset + obj.data_section_size;
  const Elf64_Off strtab_offset = rodata_offset + obj.rodata_section_size;
  const Elf64_Off symtab_offset = strtab_offset + obj.strtab_section_size;
  const Elf64_Off rela_text_off =
      symtab_offset + sizeof(Elf64_Sym) * array_len(obj.symbols);
  const Elf64_Off shstrtab_offset =
      rela_text_off + sizeof(Elf64_Rela) * array_len(obj.relocations);
  const Elf64_Off sh_table_offset = shstrtab_offset + sizeof(shstrtab_data);

  /* Elf Header */
  Elf64_Ehdr *eh = &obj.eh;
  memcpy(eh->e_ident, ELFMAG, SELFMAG);
  eh->e_ident[EI_CLASS] = ELFCLASS64;
  eh->e_ident[EI_DATA] = ELFDATA2LSB;
  eh->e_ident[EI_VERSION] = EV_CURRENT;
  eh->e_ident[EI_OSABI] = ELFOSABI_SYSV;

  eh->e_type = ET_REL;
  eh->e_machine = EM_X86_64;
  eh->e_version = EV_CURRENT;
  eh->e_ehsize = sizeof(Elf64_Ehdr);
  eh->e_shentsize = sizeof(Elf64_Shdr);
  eh->e_shnum = 8; /* 8 Sections: NULL, .text, .data, .rodata, .strtab,
                      .symtab, .rela.text, .shstrtab */
  eh->e_shstrndx = 7;
  eh->e_shoff = sh_table_offset;

  log_info("Symbols: %zu, Relocations: %zu - SH Table offset: %zu, Size: %zu",
           array_len(obj.symbols) + 2, array_len(obj.relocations),
           sh_table_offset, eh->e_shoff + eh->e_shentsize * eh->e_shnum);

  /* Section Header */

  /* Text Section */
  Elf64_Shdr *sh_text = &obj.sh_text;
  sh_text->sh_name = OFF_TEXT_NAME;
  sh_text->sh_type = SHT_PROGBITS;
  sh_text->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
  sh_text->sh_offset = text_offset;
  sh_text->sh_size = obj.text_section_size;
  sh_text->sh_addralign = 16;

  /* Data Section */
  Elf64_Shdr *sh_data = &obj.sh_data;
  sh_data->sh_name = OFF_DATA_NAME;
  sh_data->sh_type = SHT_PROGBITS;
  sh_data->sh_flags = SHF_ALLOC | SHF_WRITE;
  sh_data->sh_offset = data_offset;
  sh_data->sh_size = obj.data_section_size;
  sh_data->sh_addralign = 8;

  Elf64_Shdr *sh_rodata = &obj.sh_rodata;
  sh_rodata->sh_name = OFF_RODATA_NAME;
  sh_rodata->sh_type = SHT_PROGBITS;
  sh_rodata->sh_flags = SHF_ALLOC;
  sh_rodata->sh_offset = rodata_offset;
  sh_rodata->sh_size = obj.rodata_section_size;
  sh_rodata->sh_addralign = 8;

  Elf64_Shdr *sh_strtab = &obj.sh_strtab;
  sh_strtab->sh_name = OFF_STRTAB_NAME;
  sh_strtab->sh_type = SHT_STRTAB;
  sh_strtab->sh_offset = strtab_offset;
  sh_strtab->sh_size = obj.strtab_section_size;
  sh_strtab->sh_addralign = 1;

  Elf64_Shdr *sh_symtab = &obj.sh_symtab;
  sh_symtab->sh_name = OFF_SYMTAB_NAME;
  sh_symtab->sh_type = SHT_SYMTAB;
  sh_symtab->sh_offset = symtab_offset;
  sh_symtab->sh_size = sizeof(Elf64_Sym) * array_len(obj.symbols);
  sh_symtab->sh_link = STRTAB_INDEX;
  sh_symtab->sh_info = 4; // 5 because that is the index of the main symbol. All
                          // symbols >= 4 are global
  sh_symtab->sh_addralign = 8;
  sh_symtab->sh_entsize = sizeof(Elf64_Sym);

  Elf64_Shdr *sh_rela_text = &obj.sh_rela_text;
  sh_rela_text->sh_name = OFF_RELA_TEXT_NAME;
  sh_rela_text->sh_type = SHT_RELA;
  sh_rela_text->sh_offset = rela_text_off;
  sh_rela_text->sh_size =
      sizeof(Elf64_Rela) * array_len(compiler->elf64_relocations);
  sh_rela_text->sh_link = SYMTAB_INDEX;
  sh_rela_text->sh_info = TEXT_INDEX;
  sh_rela_text->sh_addralign = 8;
  sh_rela_text->sh_entsize = sizeof(Elf64_Rela);

  /* String Table Section */
  Elf64_Shdr *sh_shstrtab = &obj.sh_shstrtab;
  sh_shstrtab->sh_name = OFF_SHSTRTAB_NAME;
  sh_shstrtab->sh_type = SHT_STRTAB;
  sh_shstrtab->sh_offset = shstrtab_offset;
  sh_shstrtab->sh_size = sizeof(shstrtab_data);
  sh_shstrtab->sh_addralign = 1;

  obj_write(&obj, file);
}
