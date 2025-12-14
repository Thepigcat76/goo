#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <elf.h>

#define WRITE(fp, ptr) fwrite(ptr, 1, sizeof(*(ptr)), fp)

/* Section name string table */
static const char shstrtab_data[] =
    "\0.text\0.rodata\0.strtab\0.symtab\0.shstrtab\0.rela.text\0";

/* Symbol string table */
static const char strtab_data[] = "\0main\0printf\0";

/* Read-only data (.rodata) */
static const char rodata_data[] = "Hello, world :3!\n";

/*
 * Code:
 *   lea rdi, [rip + msg]      ; 48 8D 3D ?? ?? ?? ??
 *   xor eax, eax              ; 31 C0
 *   call printf@PLT           ; E8 ?? ?? ?? ??
 *   ret                       ; C3
 */
static const uint8_t text_bytes[] = {
    0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00,
    0x31, 0xC0,
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0xC3
};

int main(void) {
    FILE *fp = fopen("hello_printf.o", "wb");
    if (!fp) { perror("fopen"); return 1; }

    /* --- Layout --- */
    const Elf64_Off elf_header_off = 0;
    const Elf64_Off text_off       = sizeof(Elf64_Ehdr);
    const Elf64_Off rodata_off     = text_off + sizeof(text_bytes);
    const Elf64_Off shstrtab_off   = rodata_off + sizeof(rodata_data);
    const Elf64_Off strtab_off     = shstrtab_off + sizeof(shstrtab_data);
    const Elf64_Off symtab_off     = strtab_off + sizeof(strtab_data);
    const Elf64_Off rela_text_off  = symtab_off + sizeof(Elf64_Sym) * 5;
    const Elf64_Off sh_table_off   = rela_text_off + sizeof(Elf64_Rela) * 2;

    /* --- ELF header --- */
    Elf64_Ehdr eh = {0};
    memcpy(eh.e_ident, ELFMAG, SELFMAG);
    eh.e_ident[EI_CLASS] = ELFCLASS64;
    eh.e_ident[EI_DATA]  = ELFDATA2LSB;
    eh.e_ident[EI_VERSION] = EV_CURRENT;
    eh.e_ident[EI_OSABI] = ELFOSABI_SYSV;
    eh.e_type      = ET_REL;
    eh.e_machine   = EM_X86_64;
    eh.e_version   = EV_CURRENT;
    eh.e_ehsize    = sizeof(Elf64_Ehdr);
    eh.e_shentsize = sizeof(Elf64_Shdr);
    eh.e_shnum     = 7;   // null + .text + .rodata + .strtab + .symtab + .shstrtab + .rela.text
    eh.e_shstrndx  = 5;   // index of .shstrtab
    eh.e_shoff     = sh_table_off;

    /* --- Section headers --- */
    Elf64_Shdr sh_null = {0};

    Elf64_Shdr sh_text = {0};
    sh_text.sh_name = 1; // ".text"
    sh_text.sh_type = SHT_PROGBITS;
    sh_text.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    sh_text.sh_offset = text_off;
    sh_text.sh_size = sizeof(text_bytes);
    sh_text.sh_addralign = 16;

    Elf64_Shdr sh_rodata = {0};
    sh_rodata.sh_name = 7; // ".rodata"
    sh_rodata.sh_type = SHT_PROGBITS;
    sh_rodata.sh_flags = SHF_ALLOC;
    sh_rodata.sh_offset = rodata_off;
    sh_rodata.sh_size = sizeof(rodata_data);
    sh_rodata.sh_addralign = 4;

    Elf64_Shdr sh_strtab = {0};
    sh_strtab.sh_name = 15; // ".strtab"
    sh_strtab.sh_type = SHT_STRTAB;
    sh_strtab.sh_offset = strtab_off;
    sh_strtab.sh_size = sizeof(strtab_data);
    sh_strtab.sh_addralign = 1;

    Elf64_Shdr sh_symtab = {0};
    sh_symtab.sh_name = 23; // ".symtab"
    sh_symtab.sh_type = SHT_SYMTAB;
    sh_symtab.sh_offset = symtab_off;
    sh_symtab.sh_size = sizeof(Elf64_Sym) * 5;
    sh_symtab.sh_link = 3;  // link to .strtab
    sh_symtab.sh_info = 3;  // local symbols: null + .text
    sh_symtab.sh_addralign = 8;
    sh_symtab.sh_entsize = sizeof(Elf64_Sym);

    Elf64_Shdr sh_shstrtab = {0};
    sh_shstrtab.sh_name = 31; // ".shstrtab"
    sh_shstrtab.sh_type = SHT_STRTAB;
    sh_shstrtab.sh_offset = shstrtab_off;
    sh_shstrtab.sh_size = sizeof(shstrtab_data);
    sh_shstrtab.sh_addralign = 1;

    Elf64_Shdr sh_rela_text = {0};
    sh_rela_text.sh_name = 41; // ".rela.text"
    sh_rela_text.sh_type = SHT_RELA;
    sh_rela_text.sh_offset = rela_text_off;
    sh_rela_text.sh_size = sizeof(Elf64_Rela) * 2;
    sh_rela_text.sh_link = 4; // link to .symtab
    sh_rela_text.sh_info = 1; // applies to .text
    sh_rela_text.sh_addralign = 8;
    sh_rela_text.sh_entsize = sizeof(Elf64_Rela);

    /* --- Symbols --- */
    Elf64_Sym sym_null = {0};

    Elf64_Sym sym_text = {0};
    sym_text.st_info = ELF64_ST_INFO(STB_LOCAL, STT_SECTION);
    sym_text.st_shndx = 1;

    Elf64_Sym sym_rodata = {0};
    sym_rodata.st_info = ELF64_ST_INFO(STB_LOCAL, STT_SECTION);
    sym_rodata.st_shndx = 2;

    Elf64_Sym sym_main = {0};
    sym_main.st_name = 1; // "main"
    sym_main.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    sym_main.st_other = STV_DEFAULT;
    sym_main.st_shndx = 1; // .text
    sym_main.st_value = 0;
    sym_main.st_size = sizeof(text_bytes);

    Elf64_Sym sym_printf = {0};
    sym_printf.st_name = 6; // "printf"
    sym_printf.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE);
    sym_printf.st_other = STV_DEFAULT;
    sym_printf.st_shndx = SHN_UNDEF;

    /* --- Relocations --- */
    Elf64_Rela rela_lea = {0};
    rela_lea.r_offset = 3; // offset in lea rdi,[rip+...]
    rela_lea.r_info = ELF64_R_INFO(2, R_X86_64_PC32); // symbol index 2 (.rodata)
    rela_lea.r_addend = -4;

    Elf64_Rela rela_printf = {0};
    rela_printf.r_offset = 10; // offset of call displacement
    rela_printf.r_info = ELF64_R_INFO(4, R_X86_64_PLT32); // printf symbol
    rela_printf.r_addend = -4;

    /* --- Write sections --- */
    WRITE(fp, &eh);
    fwrite(text_bytes, 1, sizeof(text_bytes), fp);
    fwrite(rodata_data, 1, sizeof(rodata_data), fp);
    fwrite(shstrtab_data, 1, sizeof(shstrtab_data), fp);
    fwrite(strtab_data, 1, sizeof(strtab_data), fp);
    WRITE(fp, &sym_null);
    WRITE(fp, &sym_text);
    WRITE(fp, &sym_rodata);
    WRITE(fp, &sym_main);
    WRITE(fp, &sym_printf);
    WRITE(fp, &rela_lea);
    WRITE(fp, &rela_printf);
    WRITE(fp, &sh_null);
    WRITE(fp, &sh_text);
    WRITE(fp, &sh_rodata);
    WRITE(fp, &sh_strtab);
    WRITE(fp, &sh_symtab);
    WRITE(fp, &sh_shstrtab);
    WRITE(fp, &sh_rela_text);

    fclose(fp);
    printf("✅ Wrote hello_printf.o successfully\n");
    return 0;
}
