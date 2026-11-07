/* Test-only initial startup delay. This file is never linked into the shipped EXE. */
#include <string.h>
#include "host.h"
int kh_connect_real(KHost *host);
int kh_connect(KHost *host) {
    static ULONGLONG first;
    ULONGLONG now=GetTickCount64();if(!first)first=now;
    if(now-first<7000){memset(host,0,sizeof(*host));host->error=10007;return 0;}
    return kh_connect_real(host);
}
