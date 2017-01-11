//
// Created by 佟劲纬 on 17/1/9.
//

#include "linker.h"

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("usage: %s <elf> \n", argv[0]);
        return -1;
    }

    Linker linker;
    soinfo *si = linker.findLibrary(argv[1]);
    soinfo *dl = linker.getSoinfo("libdl.so");
    if (dl != NULL) {
        printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ \n");
        printf("patch missing symbols in libdl. \n");
        linker.relocLibrary(dl, dl->plt_rel, dl->plt_rel_count, 0);
    }

    if (si == NULL) {
        printf("load error! \n");
    }
    else {
        printf("load ok! \n");
    }

    return 0;

}