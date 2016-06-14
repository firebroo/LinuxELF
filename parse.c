/*
 * =====================================================================================
 *        Created:  06/13/2016 08:02:53 PM
 * =====================================================================================
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

/***
 *    Author:    firebroo
***/

#define bool unsigned char
#define false 0
#define true !0

typedef uint16_t Elf32_Half;
typedef uint16_t Elf64_Half;

/* Types for signed and unsigned 32-bit quantities.  */
typedef uint32_t Elf32_Word;
typedef int32_t  Elf32_Sword;
typedef uint32_t Elf64_Word;
typedef int32_t  Elf64_Sword;

/* Types for signed and unsigned 64-bit quantities.  */
typedef uint64_t Elf32_Xword;
typedef int64_t  Elf32_Sxword;
typedef uint64_t Elf64_Xword;
typedef int64_t  Elf64_Sxword;

/* Type of addresses.  */
typedef uint32_t Elf32_Addr;
typedef uint64_t Elf64_Addr;

/* Type of file offsets.  */
typedef uint32_t Elf32_Off;
typedef uint64_t Elf64_Off;

/* Type for section indices, which are 16-bit quantities.  */
typedef uint16_t Elf32_Section;
typedef uint16_t Elf64_Section;

#define EI_NIDENT (16)



typedef struct
{
    unsigned char e_ident[EI_NIDENT]; /* Magic number and other info */
    Elf32_Half  e_type;         /* Object file type */
    Elf32_Half    e_machine;      /* Architecture */
    Elf32_Word  e_version;      /* Object file version */
    Elf32_Addr    e_entry;        /* Entry point virtual address */
    Elf32_Off   e_phoff;        /* Program header table file offset */
    Elf32_Off e_shoff;        /* Section header table file offset */
    Elf32_Word  e_flags;        /* Processor-specific flags */
    Elf32_Half    e_ehsize;       /* ELF header size in bytes */
    Elf32_Half  e_phentsize;        /* Program header table entry size */
    Elf32_Half    e_phnum;        /* Program header table entry count */
    Elf32_Half  e_shentsize;        /* Section header table entry size */
    Elf32_Half    e_shnum;        /* Section header table entry count */
    Elf32_Half  e_shstrndx;     /* Section header string table index */
} Elf32_Ehdr;

typedef struct
{
    unsigned char e_ident[EI_NIDENT]; /* Magic number and other info */
    Elf64_Half  e_type;         /* Object file type */
    Elf64_Half    e_machine;      /* Architecture */
    Elf64_Word  e_version;      /* Object file version */
    Elf64_Addr    e_entry;        /* Entry point virtual address */
    Elf64_Off   e_phoff;        /* Program header table file offset */
    Elf64_Off e_shoff;        /* Section header table file offset */
    Elf64_Word  e_flags;        /* Processor-specific flags */
    Elf64_Half    e_ehsize;       /* ELF header size in bytes */
    Elf64_Half  e_phentsize;        /* Program header table entry size */
    Elf64_Half    e_phnum;        /* Program header table entry count */
    Elf64_Half  e_shentsize;        /* Section header table entry size */
    Elf64_Half    e_shnum;        /* Section header table entry count */
    Elf64_Half  e_shstrndx;     /* Section header string table index */
} Elf64_Ehdr;

#define EI_MAG0     0       /* File identification byte 0 index */
#define ELFMAG0     0x7f        /* Magic number byte 0 */

#define EI_MAG1     1       /* File identification byte 1 index */
#define ELFMAG1     'E'     /* Magic number byte 1 */

#define EI_MAG2     2       /* File identification byte 2 index */
#define ELFMAG2     'L'     /* Magic number byte 2 */

#define EI_MAG3     3       /* File identification byte 3 index */
#define ELFMAG3     'F'     /* Magic number byte 3 */

/* Conglomeration of the identification bytes, for easy testing as a word.  */
#define ELFMAG      "\177ELF"
#define SELFMAG     4

#define EI_CLASS    4       /* File class byte index */
#define ELFCLASSNONE    0       /* Invalid class */
#define ELFCLASS32  1       /* 32-bit objects */
#define ELFCLASS64  2       /* 64-bit objects */
#define ELFCLASSNUM 3

#define EI_DATA     5       /* Data encoding byte index */
#define ELFDATANONE 0       /* Invalid data encoding */
#define ELFDATA2LSB 1       /* 2's complement, little endian */
#define ELFDATA2MSB 2       /* 2's complement, big endian */
#define ELFDATANUM  3

#define EI_VERSION  6       /* File version byte index */
                    /* Value must be EV_CURRENT */

#define EI_OSABI            7   /* OS ABI identification */
#define ELFOSABI_NONE       0   /* UNIX System V ABI */
#define ELFOSABI_SYSV       0   /* Alias.  */
#define ELFOSABI_HPUX       1   /* HP-UX */
#define ELFOSABI_NETBSD     2   /* NetBSD.  */
#define ELFOSABI_LINUX      3   /* Linux.  */
#define ELFOSABI_SOLARIS    6   /* Sun Solaris.  */
#define ELFOSABI_AIX        7   /* IBM AIX.  */
#define ELFOSABI_IRIX       8   /* SGI Irix.  */
#define ELFOSABI_FREEBSD    9   /* FreeBSD.  */
#define ELFOSABI_TRU64      10  /* Compaq TRU64 UNIX.  */
#define ELFOSABI_MODESTO    11  /* Novell Modesto.  */
#define ELFOSABI_OPENBSD    12  /* OpenBSD.  */
#define ELFOSABI_ARM_AEABI  64  /* ARM EABI */
#define ELFOSABI_ARM        97  /* ARM */
#define ELFOSABI_STANDALONE 255 /* Standalone (embedded) application */

#define EI_ABIVERSION       8   /* ABI version */

#define EI_PAD              9   /* Byte index of padding bytes */

#define ET_REL              1
#define ET_EXEC             2 
#define ET_DYN              3

#define EM_M32              1
#define EM_SPARC            2
#define EM_386              3
#define EM_68k              4 
#define EM_88k              5
#define EM_860              6


bool
check_magic_hdr(unsigned char *ident)
{
    /*brefore 4 bytes*/
    return (ident[EI_MAG0] == ELFMAG0
            && ident[EI_MAG1] == ELFMAG1
            && ident[EI_MAG2] == ELFMAG2
            && ident[EI_MAG3] == ELFMAG3)? true: false;
}

bool
check_os_version(unsigned char *ident)
{
    /*5th byte*/
    printf("\t%-36s", "OS VERSION:");
    switch(ident[EI_CLASS]) {
        case ELFCLASS32:
            printf("32 os\n");
            break;
        case ELFCLASS64:
            printf("64 os\n");
            break;
        default:
            printf("unknow os\n");
            return false;
    }
    return true;
}

bool
check_big_or_small_edian(unsigned char *ident)
{
    /*6th byte*/
    printf("\t%-36s", "CPU Endian:");
    switch(ident[EI_DATA]) {
        case ELFDATA2LSB:
            printf("little endian\n");
            break;
        case ELFDATA2MSB:
            printf("big endian\n");
            break;
        default:
            printf("unknow endian\n");
            return false;
    }
    return true;
}

bool
check_osabi(unsigned char *ident)
{
    printf("\t%-36s", "OS/ABI:");
    switch(ident[EI_OSABI]) {
            case ELFOSABI_SYSV:
                printf("UNIX System V ABI");
                break;

            case ELFOSABI_HPUX:
                printf("HP-UX");
                break;

            case ELFOSABI_NETBSD:
                printf("NetBSD.");
                break;

            case ELFOSABI_LINUX:
                printf("Linux.");
                break;

            case ELFOSABI_SOLARIS:
                printf("Sun Solaris.");
                break;

            case ELFOSABI_AIX:
                printf("IBM AIX.");
                break;

            case ELFOSABI_IRIX:
                printf("SGI Irix.");
                break;

            case ELFOSABI_FREEBSD:
                printf("FreeBSD.");
                break;

            case ELFOSABI_TRU64:
                printf("Compaq TRU64 UNIX.");
                break;

            case ELFOSABI_MODESTO:
                printf("Novell Modesto.");
                break;

            case ELFOSABI_OPENBSD:
                printf("OpenBSD.");
                break;

            case ELFOSABI_ARM_AEABI:
                printf("ARM EABI");
                break;

            case ELFOSABI_ARM:
                printf("ARM");
                break;

            case ELFOSABI_STANDALONE:
                printf("Standalone (embedded) application");
                break;

            default:
                printf("unknow osabi\n");
                return false;
        }
    printf("\n");
    return true;
}

bool
check_elf_class(Elf64_Half type)
{
    printf("\t%-36s", "File Type:");
    switch(type) {
        case ET_REL:
            printf("Relocatable file\n");
            break;
        case ET_EXEC:
            printf("EXEC (Executable file))\n");
            break;
        case ET_DYN:
            printf("Shared object file\n");
            break;
        default:
            printf("unkonw file type\n");
            return false;
    }
    return true;
}

bool
check_cpu_type (Elf64_Half type)
{
    printf("\t%-36s", "Machine:");
    switch(type) {
        case 3:
            printf("intel x86\n");
            break;
        case 0x3E:
            printf("AMD x86_64\n");
            break;
        default:
            printf("unknow cpu type\n");
            return false;
    }
    return true;
}

void greate_print_hdr_info(Elf64_Ehdr elf64_endr) {
    printf("\t%-36s", "ELF Version:");
    printf("%#x\n", elf64_endr.e_version);

    printf("\t%-36s", "Entry point address:");
    printf("%#lx\n", elf64_endr.e_entry);

    printf("\t%-36s", "Start of program headers:");
    printf("%ld (bytes into file))\n", elf64_endr.e_phoff);

    printf("\t%-36s", "Start of section headers:");
    printf("%ld (bytes into file))\n", elf64_endr.e_shoff);

    printf("\t%-36s", "Flags: ");
    printf("%#x\n", (int)elf64_endr.e_flags);

    printf("\t%-36s", "Size of this header:");
    printf("%d (bytes)\n", elf64_endr.e_ehsize);

    printf("\t%-36s", "Size of program headers:");
    printf("%d (bytes)\n", elf64_endr.e_phentsize);

    printf("\t%-36s", "Number of program headers:");
    printf("%d\n", elf64_endr.e_phnum);

    printf("\t%-36s", "Size of section headers:");
    printf("%d (bytes)\n", elf64_endr.e_shentsize);

    printf("\t%-36s", "Number of section headers:");
    printf("%d\n", elf64_endr.e_shnum);

    printf("\t%-36s", "Section header string table index:");
    printf("%d\n", elf64_endr.e_shstrndx);
 
}

void greate_print_hdr_magic(Elf64_Ehdr elf64_endr) {
    int     i;

    printf("ELF Header:\n");
    printf("\t%-36s", "maigc header bytes: ");
    for (i = 0; i < EI_NIDENT; i++) {
        printf("%02x ", elf64_endr.e_ident[i]);
    }
    printf("\n");
}

int
main(int argc, char *argv[])
{
    int         fd, ret;
    Elf64_Ehdr  elf64_endr;

    if (argc != 2) {
        printf("Usage: ./parse file\n");
        exit(-1);
    }

    if ( (fd = open(argv[1], O_RDONLY)) < 0 ) {
        perror("open");
        exit(-1);
    }
    if ( (ret = read(fd, &elf64_endr, sizeof(Elf64_Ehdr))) < 0) {
        perror("read");
        exit(-1);
    }
    assert(check_magic_hdr(elf64_endr.e_ident));

    greate_print_hdr_magic(elf64_endr);

    assert(check_os_version(elf64_endr.e_ident));
    assert(check_big_or_small_edian(elf64_endr.e_ident));
    printf("\t%-36s%d(current)\n", "Data:", elf64_endr.e_ident[EI_VERSION]);
    assert(check_osabi(elf64_endr.e_ident));
    printf("\t%-36s%d\n", "ABI Version:", elf64_endr.e_ident[EI_ABIVERSION]);
    assert(check_elf_class(elf64_endr.e_type));
    assert(check_cpu_type(elf64_endr.e_machine));
    greate_print_hdr_info(elf64_endr);
    return 0;
}
