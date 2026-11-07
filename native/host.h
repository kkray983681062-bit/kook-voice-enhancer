#ifndef KOOK_HOST_H
#define KOOK_HOST_H
#include "protocol.h"
typedef struct { HANDLE process,mapping;KShared *shared;DWORD pid,error; } KHost;
int kh_connect(KHost *host);
int kh_find_target(KHost *host);
LONG kh_command(KHost *host,int command,int argument,int keep);
void kh_close(KHost *host);
#endif
