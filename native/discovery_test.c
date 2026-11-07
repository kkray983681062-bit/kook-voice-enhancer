#include <stdio.h>
#include <stdlib.h>
#include "host.h"
int main(int argc,char **argv) {
    DWORD expected=argc>1?(DWORD)strtoul(argv[1],NULL,10):0;
    KHost host={0};int found=kh_find_target(&host);
    printf("found=%d error=%lu expected=%lu pid=%lu\n",found,host.error,expected,host.pid);
    int ok=expected?(!found&&host.error==expected):found;
    kh_close(&host);return ok?0:1;
}
