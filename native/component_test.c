#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include "chart.h"
#include "locator.h"
#include "connection.h"
int wmain(int argc,wchar_t **argv) {
    assert(k_retry_delay(10001)==2000&&k_retry_delay(10007)==2000);
    assert(k_retry_delay(ERROR_ACCESS_DENIED)==5000);
    assert(k_retry_delay(10003)==0&&k_retry_delay(10005)==0&&k_retry_delay(10008)==0);
    assert(!k_retry_due(1999,2000,0,0,0)&&k_retry_due(2000,2000,0,0,0));
    assert(!k_retry_due(3000,2000,1,0,0)&&!k_retry_due(3000,2000,0,1,0)&&!k_retry_due(3000,2000,0,0,1));
    printf("connection: delayed retries, safe failure classes, no parallel connect, no retry during close passed\n");
    KChart c={0};kc_sample(&c,10000,1,10000,10,1);assert(!c.live);
    kc_sample(&c,11000,1,50000,27,1);assert(c.live&&fabs(c.latest-320.0)<0.001);
    kc_sample(&c,12250,1,75000,48,1);assert(c.live&&fabs(c.latest-160.0)<0.001&&c.low==160.0&&c.high==320.0);
    kc_sample(&c,13250,1,75000,48,0);assert(!c.live);
    kc_sample(&c,14250,2,80000,65,1);assert(!c.live&&c.high==0);
    kc_sample(&c,15250,2,120000,82,1);assert(c.live&&c.high==320);
    kc_sample(&c,46251,2,120000,82,0);assert(!c.live&&c.high==0);
    printf("chart: byte/time units, variable interval, gaps, connection reset, 30-second expiry passed\n");
    if(argc>1) {
        wchar_t path[K_PATH_CAP];assert(kl_validate(argv[1],path));wprintf(L"normalized=%ls\n",path);
        assert(!kl_validate(L"C:\\Windows\\System32\\notepad.exe",path));
        KLocation location=kl_find();assert(location.code==K_PATH_FOUND);wprintf(L"automatic=%ls\n",location.path);
        printf("locator: valid KOOK, stable launcher, non-KOOK rejection, active install discovery passed\n");
    }
    return 0;
}
