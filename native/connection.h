#ifndef KOOK_CONNECTION_H
#define KOOK_CONNECTION_H
#include <windows.h>
static inline DWORD k_retry_delay(DWORD error) {
    switch(error) {
    case 10001:case 10007:case ERROR_BAD_LENGTH:case ERROR_PARTIAL_COPY:return 2000;
    case ERROR_ACCESS_DENIED:return 5000;
    default:return 0;
    }
}
static inline int k_retry_due(ULONGLONG now,ULONGLONG next,int connected,int connecting,int closing) {
    return next&&now>=next&&!connected&&!connecting&&!closing;
}
#endif
