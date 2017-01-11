

#include <errno.h>
#include <sys/exec_elf.h>
#include "linker.h"
#include "stdio.h"

#define SO_MAX 128

soinfo soList[SO_MAX];
#define LDPRELOAD_MAX 8
static soinfo *preloads[LDPRELOAD_MAX + 1];
int soNumber = 0;

char header[PAGE_SIZE];

#define MAYBE_MAP_FLAG(x,from,to)    (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
                                      MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
                                      MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))





Linker::Linker() {

    this->soPaths.push_back("/system/lib");
    //this->ldpreloadNames.push_back("");
}

Linker::~Linker() {

}

soinfo *Linker::loadLibrary(Byte *buffer, size_t length) {
    return NULL;
}

soinfo *Linker::loadLibrary(const char *name) {

    int fd = openLibrary(name);
    Elf32_Ehdr *hdr;
    unsigned int base;
    soinfo *info;
    unsigned int size;
    char *bname;

    if (fd == -1) {
        fprintf(stderr, "can not find library: %s \n", name);
    }

    // 分析elf，计算总的内存大小
    if (read(fd, header, PAGE_SIZE) < 0) {
        fprintf(stderr, "read header: %s", strerror(errno));
        goto fail;
    }

    base = parseLibrary((Elf32_Ehdr*)header, &size);

    if (base == (unsigned int)-1) {
        goto fail;
    }

    fprintf(stdout, "load base = %p \n", base);

    bname = strrchr(name, '/');
    info = allocSoinfo(bname ? bname + 1 : name);
    if (info == NULL) {
        goto fail;
    }

    info->base = base;
    info->size = size;
    info->flags = 0;
    info->entry = 0;
    info->dynamic = (unsigned int*)-1;

    if (allocMemoryRegion(info) < 0) {
        fprintf(stderr, "can not alloc memory for library! \n");
        goto fail;
    }

    if (loadSegments(fd, (Elf32_Ehdr *)header,info) < 0) {
        goto fail;
    }

    hdr = (Elf32_Ehdr *)info->base;
    info->phdr = (Elf32_Phdr *)((unsigned char*)info->base + hdr->e_phoff);
    info->phnum = hdr->e_phnum;

    close(fd);

    return info;

    fail:
    return NULL;
}

int Linker::openLibrary(const char *name) {
    int fd;
    if (name[0] == '/') {
        fd = open(name, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "open so: %s failed: %s \n", name, strerror(errno));
            return -1;
        }
        return fd;
    }

    for (vector<string>::iterator it = this->soPaths.begin();
        it != this->soPaths.end(); it++) {
        char SO[PATH_MAX];
        sprintf(SO, "%s/%s", it->c_str(), name);
        fd = open(SO, O_RDONLY);

        if (fd < 0) {
            fprintf(stderr, "open so: %s failed: %s \n", SO, strerror(errno));
            return -1;
        }
        return fd;
    }

    return -1;
}

unsigned int Linker::parseLibrary(Elf32_Ehdr *hdr, unsigned int *totalSize) {

    Elf32_Phdr *phdr;
    unsigned int minVaddr = 0xffffffff;
    unsigned int maxVaddr = 0;
    int count;

    if (memcmp(hdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "not a elf! \n");
        return -1;
    }

    if (hdr->e_machine != EM_ARM) {
        fprintf(stderr, "not a arm elf! \n");
        return -1;
    }

    phdr = (Elf32_Phdr *)((char *)hdr + hdr->e_phoff);

    for (count = 0; count < hdr->e_phnum; count++, phdr++) {
        if (phdr->p_type == PT_LOAD) {
            if ((phdr->p_vaddr + phdr->p_memsz) > maxVaddr) {
                maxVaddr = phdr->p_vaddr + phdr->p_memsz;
            }
            if (phdr->p_vaddr < minVaddr) {
                minVaddr = phdr->p_vaddr;
            }
        }
    }

    if ((minVaddr == 0xffffffff) && (maxVaddr == 0)) {
        fprintf(stderr, "No loadable segments found! \n");
        return -1;
    }

    minVaddr &= ~PAGE_MASK;
    maxVaddr = (maxVaddr + PAGE_SIZE - 1) & ~PAGE_MASK;

    *totalSize = (maxVaddr - minVaddr);
    fprintf(stdout, "totalSize = %p \n", *totalSize);
    return 0;
}

soinfo *Linker::allocSoinfo(const char *name) {
    soinfo *si;

    if (strlen(name) >= SOINFO_NAME_LEN) {
        fprintf(stderr, "so name too long: %s \n", name);
        return NULL;
    }

    if (soNumber == SO_MAX - 1) {
        fprintf(stderr, "too many libraries when loading %s", name);
        return NULL;
    }

    si = &soList[soNumber++];
    memset(si, 0, sizeof(soinfo));
    strlcpy((char*)si->name, name, sizeof(si->name));
    si->next = NULL;
    si->refcount = 0;
    fprintf(stdout, "allocated soinfo for %s \n", name);
    return si;
}

int Linker::allocMemoryRegion(soinfo *si) {

    void *base = mmap(NULL, si->size, PROT_NONE,
    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        fprintf(stderr, "mmap failed! \n");
        return -1;
    }
    si->base = (unsigned)base;
    return 0;
}

int Linker::loadSegments(int fd, Elf32_Ehdr *hdr, soinfo *si) {
    Elf32_Phdr *phdr = (Elf32_Phdr*)((char *)hdr + hdr->e_phoff);
    Elf32_Addr base = (Elf32_Addr)si->base;
    Elf32_Addr temp;
    int count;
    unsigned int length;
    unsigned char *pbase, *extraBase;
    unsigned int extraLength;
    unsigned int totalSize = 0;

    si->wrprotect_start = 0xffffffff;
    si->wrprotect_end = 0;

    printf("load base = %p \n", base);
    for(count = 0; count < hdr->e_phnum; count++, phdr++) {
        if (phdr->p_type == PT_LOAD) {
            temp = base + (phdr->p_vaddr & (~PAGE_MASK));
            length = phdr->p_filesz + (phdr->p_vaddr & PAGE_MASK);

            pbase = (unsigned char*)mmap((void*)temp, length, PFLAGS_TO_PROT(phdr->p_flags),
            MAP_PRIVATE | MAP_FIXED, fd, phdr->p_offset & (~PAGE_MASK));
            if (pbase == MAP_FAILED) {
                fprintf(stderr, "failed to map segment from 0x%08x , len 0x%08x, p_vaddr = 0x%08x"
                "p_offset = 0x%08x \n", temp, length, phdr->p_vaddr, phdr->p_offset);
                goto fail;
            }

            printf("load length = %p \n", length);

            // 将非页对齐的剩余部分初始化为0
            if ((length & PAGE_MASK) && (phdr->p_flags & PF_W)) {
                memset((void*)(pbase + length), 0, PAGE_SIZE - (length & PAGE_MASK));
            }

            temp = (Elf32_Addr)(((unsigned int)pbase + length + PAGE_SIZE - 1) &
                    (~PAGE_MASK));

            if (temp < (base + phdr->p_vaddr + phdr->p_memsz)) {
                extraLength = base + phdr->p_vaddr + phdr->p_memsz - temp;
                extraBase = (unsigned char *)mmap((void*)temp, extraLength, PFLAGS_TO_PROT(phdr->p_flags),
                MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);

                if (extraBase == MAP_FAILED) {
                    fprintf(stderr, "failed to extend segment from 0x%08x to 0x%08x \n",
                    temp, extraLength);
                    goto fail;
                }
            }

            length = (((unsigned int)base + phdr->p_vaddr + phdr->p_memsz + PAGE_SIZE - 1) & (~PAGE_MASK))
                    - (unsigned int)pbase;

            fprintf(stdout, "successfully loaded segment from 0x%08x, length 0x%08x \n",
                    (unsigned int)pbase, length);

            totalSize += length;

            if (!(phdr->p_flags & PF_W)) {
                if ((unsigned int)pbase < si->wrprotect_start) {
                    si->wrprotect_start = (unsigned int)pbase;
                }

                if (((unsigned int)pbase + length) > si->wrprotect_end) {
                    si->wrprotect_end = (unsigned int)pbase + length;
                }
                // 将区域设置成可写
                mprotect(pbase, length, PFLAGS_TO_PROT(phdr->p_flags) | PROT_WRITE);
            }

        }
        else if (phdr->p_type == PT_DYNAMIC) {
            si->dynamic = (unsigned int*)(base + phdr->p_vaddr);
        }
        /*
        else if (phdr->p_type == PT_G) {

        }
         */
#ifdef ANDROID_ARM_LINKER
        else {
            if (phdr->p_type == PT_ARM_EXIDX) {
                si->ARM_exidx = (unsigned int*)phdr->p_vaddr;
                si->ARM_exidx_count = phdr->p_memsz / 8;
            }
        }
#endif
    }

    if (totalSize > si->size) {
        fprintf(stderr, "total length 0x%08x of mapped segments greater than "
        "what was allocated 0x%08x. \n", totalSize, si->size);
        goto fail;
    }

    fprintf(stdout, "finish loading segments from 0x%08x, 0x%08x bytes \n",
        si->base, si->size);

    return 0;

    fail:
    munmap((void*)si->base, si->size);
    return -1;
}

int Linker::linkImage(soinfo *si, unsigned int offset) {
    Elf32_Phdr *phdr = si->phdr;
    int phnum = si->phnum;
    if (si->flags & (FLAG_EXE | FLAG_LINKER)) {

        si->size = 0;
        for (; phnum > 0; --phnum, phdr++) {
#ifdef ANDROID_ARM_LINKER
            if (phdr->p_type == PT_ARM_EXIDX) {
                si->ARM_exidx = (unsigned*)phdr->p_vaddr;
                si->ARM_exidx_count = phdr->p_memsz / 8;
            }
#endif
            if (phdr->p_type == PT_LOAD) {

                if (phdr->p_vaddr + phdr->p_memsz > si->size) {
                    si->size = phdr->p_vaddr + phdr->p_memsz;
                }

                if (!(phdr->p_flags & PF_W)) {
                    unsigned int end;
                    if (si->base + phdr->p_vaddr < si->wrprotect_start) {
                        si->wrprotect_start = si->base + phdr->p_vaddr;
                    }
                    end = (((si->base + phdr->p_vaddr + phdr->p_memsz + PAGE_SIZE - 1) & (~PAGE_MASK)));
                    if (end > si->wrprotect_end) {
                        si->wrprotect_end = end;
                    }
                    mprotect((void *) (si->base + phdr->p_vaddr), phdr->p_memsz,
                             PFLAGS_TO_PROT(phdr->p_flags) | PROT_WRITE);
                }
            } else if (phdr->p_type == PT_DYNAMIC) {
                if (si->dynamic != (unsigned int *)-1) {
                    goto fail;
                }
                si->dynamic = (unsigned int *)(si->base + phdr->p_vaddr);
            }

        }
    }
    if (si->dynamic == (unsigned int*)-1) {
        goto fail;
    }
    unsigned int *d;
    for(d = si->dynamic; *d; d++) {
        fprintf(stdout, "d = %p, d[0] = 0x%08x, d[1] = 0x%08x \n", d, d[0], d[1]);
        switch(*d++) {
            case DT_HASH:
                si->nbucket = ((unsigned int *)(si->base + *d))[0];
                si->nchain = ((unsigned int *)(si->base + *d))[1];
                si->bucket = (unsigned int *)(si->base + *d + 8);
                si->chain = (unsigned int *)(si->base + *d + 8 + si->nbucket * 4);
                break;
            case DT_STRTAB:
                si->strtab = (const char *)(si->base + *d);
                break;
            case DT_SYMTAB:
                si->symtab = (Elf32_Sym *)(si->base + *d);
                break;
            case DT_PLTREL:
                if (*d != DT_REL) {
                    goto fail;
                }
                break;
            case DT_JMPREL:
                si->plt_rel = (Elf32_Rel *)(si->base + *d);
                break;
            case DT_PLTRELSZ:
                si->plt_rel_count = *d / 8;
                break;
            case DT_REL:
                si->rel = (Elf32_Rel *)(si->base + *d);
                break;
            case DT_RELSZ:
                si->rel_count = *d / 8;
                break;
            case DT_PLTGOT:
                si->plt_got = (unsigned int *)(si->base + *d);
                break;
            case DT_DEBUG:
                break;
            case DT_RELA:
                goto fail;
            case DT_INIT:
                si->init_func = (void (*)(void))(si->base + *d);
                break;
            case DT_FINI:
                si->fini_func = (void (*)(void))(si->base + *d);
                break;
            case DT_INIT_ARRAY:
                si->init_array = (unsigned int *)(si->base + *d);
                break;
            case DT_INIT_ARRAYSZ:
                si->init_array_count = ((unsigned int)*d) / sizeof(Elf32_Addr);
                break;
            case DT_PREINIT_ARRAY:
                si->preinit_array = (unsigned int *)(si->base + *d);
                break;
            case DT_PREINIT_ARRAYSZ:
                si->preinit_array_count = ((unsigned int)*d) / sizeof(Elf32_Addr);
                break;
            case DT_TEXTREL:
                break;
        }

    }

    if ((si->strtab == 0) || (si->symtab == 0)) {
        goto fail;
    }

    if (si->flags & FLAG_EXE) {
        int i = 0;
        memset(preloads, 0, sizeof(preloads));
        for (vector<string>::iterator it = ldpreloadNames.begin();
                it != ldpreloadNames.end(); it++) {
            soinfo *lsi = findLibrary(it->c_str());
            if (lsi == NULL) {
                fprintf(stderr, "failed to load needed library %s for %s \n",
                it->c_str(), si->name);
                goto fail;
            }
            lsi->refcount++;
            preloads[i++] = lsi;
        }
    }

    for (d = si->dynamic; *d; d += 2) {
        if (d[0] == DT_NEEDED) {
            soinfo *lsi = findLibrary(si->strtab + d[1]);
            if (lsi == NULL) {
                fprintf(stderr, "count not load needed library %s for %s \n",
                si->strtab + d[1], si->name);
                goto fail;
            }

            d[1] = (unsigned int)lsi;
            lsi->refcount++;
        }
    }

    if (si->plt_rel) {
        fprintf(stdout, "relocating %s plt \n", si->name);
        if (relocLibrary(si, si->plt_rel, si->plt_rel_count)) {
            goto fail;
        }
    }

    if (si->rel) {
        fprintf(stdout, "relocating %s \n", si->name);
        if(relocLibrary(si, si->rel, si->rel_count)) {
            goto fail;
        }
    }
    si->flags |= FLAG_LINKED;
    fprintf(stdout, "Finishing linking %s \n", si->name);

    if (si->wrprotect_start != 0xffffffff && si->wrprotect_end != 0) {
        mprotect((void*)si->wrprotect_start,
        si->wrprotect_end = si->wrprotect_start,
        PROT_READ | PROT_EXEC);
    }

    return 0;
    fail:
    fprintf(stderr, "faild to link %s \n", si->name);
    si->flags |= FLAG_ERROR;
    return -1;
}

int Linker::relocLibrary(soinfo *si, Elf32_Rel *rel, unsigned count, int boot) {
    Elf32_Sym *symtab = si->symtab;
    const char *strtab = si->strtab;
    Elf32_Sym *s;
    unsigned int base;
    Elf32_Rel *start = rel;
    unsigned index;

    for (index = 0; index < count; index++) {
        unsigned type = ELF32_R_TYPE(rel->r_info);
        unsigned sym = ELF32_R_SYM(rel->r_info);
        unsigned reloc = (unsigned)(rel->r_offset + si->base);
        unsigned sym_addr = 0;
        char *symName = NULL;

        fprintf(stdout, "Processing %s relocation at index %d \n",
        si->name, index);

        if (sym != 0) {
            symName = (char*)(strtab + symtab[sym].st_name);
            fprintf(stderr, "locating symbol: %s \n", symName);
            s = doLookup(si, symName, &base);
            if (s == NULL) {
                if (!boot && (strncmp(si->name, "libdl.so", strlen("libdl.so")) == 0)) {
                    fprintf(stderr, "Relocating from libc.so \n");
                    soinfo *csi = getSoinfo("libc.so");
                    if (csi == NULL) {
                        csi = findLibrary("libc.so");
                    }
                    s = doLookup(csi, symName, &base);
                    if (s != NULL) {
                        sym_addr = (unsigned) (s->st_value + base);
                        goto doREl;
                    }
                    else {
                        fprintf(stderr, "Relocating form libc.so failed !\n");
                    }
                }
                s = &symtab[sym];
                if (ELF32_ST_BIND(s->st_info) != STB_WEAK) {
                    fprintf(stderr, "can not locate %s \n", symName);
                    if (boot) {
                        if (strcmp(symName, "__cxa_finalize") == 0 ||
                            strcmp(symName, "__cxa_atexit") == 0 ||
                            strcmp(symName, "abort") == 0 ||
                            strcmp(symName, "memcpy") == 0) {
                            fprintf(stderr, "Locating later \n");
                        }
                    }
                    else {
                        return -1;
                    }
                }

                switch (type) {
#if defined(ANDROID_ARM_LINKER)
                    case R_ARM_JUMP_SLOT:
                    case R_ARM_GLOB_DAT:
                    case R_ARM_ABS32:
                    case R_ARM_RELATIVE:
#endif
                        break;
                    case R_ARM_COPY:
                    default:
                        fprintf(stderr, "unkonw weak reloc type %d \n", type);
                }
            }
            else {
                sym_addr = (unsigned)(s->st_value + base);
            }

        }
        else {
            s = NULL;
        }

        doREl:
        switch (type) {
#if defined(ANDROID_ARM_LINKER)
            case R_ARM_JUMP_SLOT:
                fprintf(stdout, "RELO JMP_SLOT 0x%08x <- 0x%08x %s \n",
                reloc, sym_addr, symName);
                *((unsigned*)reloc) = sym_addr;
                break;
            case R_ARM_GLOB_DAT:
                fprintf(stdout, "RELO GLOB_DAT 0x%08x <- 0x%08x %s \n",
                        reloc, sym_addr, symName);
                *((unsigned*)reloc) = sym_addr;
                break;
            case R_ARM_ABS32:
                fprintf(stdout, "RELO ABS 0x%08x <- 0x%08x %s \n",
                        reloc, sym_addr, symName);
                *((unsigned*)reloc) += sym_addr;
                break;
            case R_ARM_REL32:
                fprintf(stdout, "RELO REL32 0x%08x <- 0x%08x - 0x%08x %s \n",
                        reloc, sym_addr, rel->r_offset, symName);
                *((unsigned*)reloc) += sym_addr - rel->r_offset;
                break;
            case R_ARM_RELATIVE:
                if (sym) {
                    fprintf(stderr, "Odd RELATIVE form \n");
                    return -1;
                }
                fprintf(stdout, "RELO RELATIVE 0x%08x <- +0x%08x \n",
                        reloc, si->base);
                *((unsigned*)reloc) += si->base;
                break;
            case R_ARM_COPY:
                fprintf(stdout, "RELO COPY 0x%08x <- %d 0x%08x %s \n",
                        reloc, s->st_size, sym_addr, symName);
                memcpy((void*)reloc, (void*)sym_addr, s->st_size);
                break;
#endif
            default:
                fprintf(stderr, "unkonw weak reloc type %d @ %p (%d)\n",
                        type, rel, (int)(rel - start));
                return -1;
        }
        rel++;
    }
    return 0;
}

int Linker::validateSoinfo(soinfo *si) {
    return (si >= soList && si < soList + SO_MAX);
}

Elf32_Sym *Linker::elfLookup(soinfo *si, unsigned hash, const char *name) {
    Elf32_Sym *sym;
    Elf32_Sym *symtab = si->symtab;
    const char *strtab = si->strtab;
    unsigned n;

    for( n = si->bucket[hash % si->nbucket]; n != 0; n = si->chain[n]) {
        sym = symtab + n;

        if (strcmp(strtab + sym->st_name, name)) {
            continue;
        }
        switch (ELF32_ST_BIND(sym->st_info)) {
            case STB_GLOBAL:
            case STB_WEAK:
                if (sym->st_shndx == 0) {

                    continue;
                }
                return sym;
        }
    }
    return NULL;
}

unsigned Linker::elfHash(const char *name) {
    const unsigned char *Name = (const unsigned char*)name;
    unsigned g, h = 0;
    while(*Name) {
        h = (h << 4) + *Name++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }
    return h;
}

Elf32_Sym *Linker::doLookup(soinfo *si, const char *name, unsigned *base) {
    unsigned elfhash = elfHash(name);
    Elf32_Sym *sym;
    unsigned *d;
    soinfo *lsi = si;
    int i;

    sym = elfLookup(si, elfhash, name);
    if (sym != NULL) {
        goto done;
    }

    for (i = 0; preloads[i] != NULL; i++) {
        lsi = preloads[i];
        sym = elfLookup(lsi, elfhash, name);
        if (sym != NULL) {
            goto done;
        }
    }
    for (d = si->dynamic; *d; d += 2) {
        if (d[0] == DT_NEEDED) {
            lsi = (soinfo *)d[1];
            if (!validateSoinfo(lsi)) {
                fprintf(stderr, "bad DT_NEEDED pointer in %s \n", si->name);
                return NULL;
            }
            fprintf(stdout, "looking up %s in %s \n",
            name, lsi->name);
            sym = elfLookup(lsi, elfhash, name);
            if ((sym != NULL) && (sym->st_shndx != SHN_UNDEF)) {
                goto done;
            }
        }
    }

    done:
    if (sym != NULL) {
        fprintf(stdout, "found %s st_value = 0x%08x in %s, base = 0x%08x \n",
        name, sym->st_value, lsi->name, lsi->base);
        *base = lsi->base;
        return sym;
    }
    return NULL;
}

soinfo *Linker::initLibrary(soinfo *si) {
    unsigned wr_offset = 0xffffffff;

    fprintf(stdout, "init library base=0x%08x size = 0x%08x name = %s \n",
    si->base, si->size, si->name);
    if (linkImage(si, wr_offset) < 0) {
        munmap((void*)si->base, si->size);
        return NULL;
    }
    return si;
}

soinfo *Linker::findLibrary(const char *name) {
    soinfo *si;
    int i = 0;
    const char *bname;
    if (name == NULL) {
        return NULL;
    }
    bname = strrchr(name, '/');
    bname = bname ? bname + 1 : name;
    for(si = &soList[i]; i < soNumber; si = &soList[++i]) {
        if (!strcmp(bname, si->name)) {
            if (si->flags & FLAG_ERROR) {
                fprintf(stderr, "%s: faild to load previoursly", bname);
                return NULL;
            }
            if (si->flags & FLAG_LINKED) {
                return si;
            }
            fprintf(stderr, "recursive link to %s \n", name);
            return NULL;
        }
    }
    fprintf(stdout, "%s has not been loaded yet. Locating ... \n", name);
    si = loadLibrary(name);
    if (si == NULL) {
        return NULL;
    }
    return initLibrary(si);
}

soinfo *Linker::getSoinfo(const char *soName) {
    for(int i = 0; i < soNumber; i++) {
        if (strcmp(soList[i].name, soName) == 0) {
            return &soList[i];
        }
    }
    return NULL;
}
