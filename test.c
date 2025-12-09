#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <elf.h>

#define WRITE(fp, ptr) fwrite(ptr, 1, sizeof(*(ptr)), fp)

/* Section name string table */
static const char shstrtab_data[] = "\0.text\0.strtab\0.symtab\0.shstrtab\0";
/* Symbol string table */
static const char strtab_data[] = "\0main\0";

/* Machine code: ret */
static const uint8_t text_bytes[] = {0xC3};

int main(void) {
    FILE *fp = fopen("minimal_main.o", "wb");
    if (!fp) { perror("fopen"); return 1; }

    /* --- File layout --- */
    const Elf64_Off elf_header_off = 0x0;
    const Elf64_Off text_off       = sizeof(Elf64_Ehdr);
    const Elf64_Off shstrtab_off   = text_off + sizeof(text_bytes);
    const Elf64_Off strtab_off     = shstrtab_off + sizeof(shstrtab_data);
    const Elf64_Off symtab_off     = strtab_off + sizeof(strtab_data);
    const Elf64_Off sh_table_off   = symtab_off + sizeof(Elf64_Sym) * 3;

    /* --- ELF Header --- */
    Elf64_Ehdr eh = {0};
    memcpy(eh.e_ident, ELFMAG, SELFMAG);
    eh.e_ident[EI_CLASS] = ELFCLASS64;
    eh.e_ident[EI_DATA] = ELFDATA2LSB;
    eh.e_ident[EI_VERSION] = EV_CURRENT;
    eh.e_ident[EI_OSABI] = ELFOSABI_SYSV;

    eh.e_type = ET_REL;
    eh.e_machine = EM_X86_64;
    eh.e_version = EV_CURRENT;
    eh.e_ehsize = sizeof(Elf64_Ehdr);
    eh.e_shentsize = sizeof(Elf64_Shdr);
    eh.e_shnum = 5;          // null + .text + .strtab + .symtab + .shstrtab
    eh.e_shstrndx = 4;       // index of .shstrtab
    eh.e_shoff = sh_table_off;

    /* --- Section headers --- */
    Elf64_Shdr sh_null = {0};

    Elf64_Shdr sh_text = {0};
    sh_text.sh_name = 1;                 // ".text"
    sh_text.sh_type = SHT_PROGBITS;
    sh_text.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    sh_text.sh_offset = text_off;
    sh_text.sh_size = sizeof(text_bytes);
    sh_text.sh_addralign = 16;

    Elf64_Shdr sh_strtab = {0};
    sh_strtab.sh_name = 7;               // ".strtab"
    sh_strtab.sh_type = SHT_STRTAB;
    sh_strtab.sh_offset = strtab_off;
    sh_strtab.sh_size = sizeof(strtab_data);
    sh_strtab.sh_addralign = 1;

    Elf64_Shdr sh_symtab = {0};
    sh_symtab.sh_name = 15;              // ".symtab"
    sh_symtab.sh_type = SHT_SYMTAB;
    sh_symtab.sh_offset = symtab_off;
    sh_symtab.sh_size = sizeof(Elf64_Sym) * 3;
    sh_symtab.sh_link = 2;               // link to .strtab section
    sh_symtab.sh_info = 2;               // one local symbol (null + section)
    sh_symtab.sh_addralign = 8;
    sh_symtab.sh_entsize = sizeof(Elf64_Sym);

    Elf64_Shdr sh_shstrtab = {0};
    sh_shstrtab.sh_name = 23;            // ".shstrtab"
    sh_shstrtab.sh_type = SHT_STRTAB;
    sh_shstrtab.sh_offset = shstrtab_off;
    sh_shstrtab.sh_size = sizeof(shstrtab_data);
    sh_shstrtab.sh_addralign = 1;

    /* --- Symbols --- */
    Elf64_Sym sym_null = {0};

    Elf64_Sym sym_text = {0}; // section symbol (.text)
    sym_text.st_name = 0;
    sym_text.st_info = ELF64_ST_INFO(STB_LOCAL, STT_SECTION);
    sym_text.st_shndx = 1; // section index of .text

    Elf64_Sym sym_main = {0}; // "main" symbol
    sym_main.st_name = 1; // offset in .strtab ("main")
    sym_main.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    sym_main.st_other = STV_DEFAULT;
    sym_main.st_shndx = 1; // .text
    sym_main.st_value = 0; // start of section
    sym_main.st_size = sizeof(text_bytes);

    /* --- Write all sections --- */
    WRITE(fp, &eh);
    fwrite(text_bytes, 1, sizeof(text_bytes), fp);
    fwrite(shstrtab_data, 1, sizeof(shstrtab_data), fp);
    fwrite(strtab_data, 1, sizeof(strtab_data), fp);
    WRITE(fp, &sym_null);
    WRITE(fp, &sym_text);
    WRITE(fp, &sym_main);
    WRITE(fp, &sh_null);
    WRITE(fp, &sh_text);
    WRITE(fp, &sh_strtab);
    WRITE(fp, &sh_symtab);
    WRITE(fp, &sh_shstrtab);

    fclose(fp);
    printf("✅ Wrote minimal_main.o successfully\n");
    return 0;
}