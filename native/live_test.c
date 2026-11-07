#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "host.h"
int main(int argc,char **argv) {
    int kbps=argc>1?atoi(argv[1]):0,seconds=argc>2?atoi(argv[2]):12;
    KHost host;if(!kh_connect(&host)){printf("connect_error=%lu\n",host.error);return 1;}
    ULONGLONG deadline=GetTickCount64()+8000;
    while(host.shared->status!=K_READY && GetTickCount64()<deadline)Sleep(50);
    printf("ready=%ld channels=%ld rate=%ld bitrate=%ld ctl=%lx encode=%lx offset=%ld\n",
           host.shared->status,host.shared->channels,host.shared->sample_rate,host.shared->bitrate,
           host.shared->feature_control,host.shared->feature_encode,host.shared->feature_channels_offset);fflush(stdout);
    if(host.shared->status!=K_READY){kh_close(&host);return 2;}
    LONG sequence=kbps?kh_command(&host,K_CMD_APPLY,kbps,1):0;
    int good=1;LONG64 last_bytes=host.shared->payload_bytes;ULONGLONG last_time=GetTickCount64();
    for(int i=0;i<seconds;++i) {
        Sleep(1000);
        ULONGLONG now=GetTickCount64();LONG64 bytes=host.shared->payload_bytes;
        double measured=now>last_time?(double)(bytes-last_bytes)*8.0/(double)(now-last_time):0;
        last_bytes=bytes;last_time=now;
        printf("{\"second\":%d,\"channels\":%ld,\"bps\":%ld,\"holding\":%ld,\"error\":%ld,\"applied\":%ld,\"frames\":%lld,\"encode_errors\":%lld,\"upstream_bps\":%ld,\"capacity\":%ld,\"samples\":%ld,\"kbps\":%.3f}\n",
               i+1,host.shared->channels,host.shared->bitrate,host.shared->holding,host.shared->error,
               host.shared->applied,(long long)host.shared->frames,(long long)host.shared->encoding_errors,
               host.shared->upstream_bitrate,host.shared->output_capacity,host.shared->packet_samples,measured);fflush(stdout);
        int expected=kbps*1000;if(expected>300000*host.shared->channels)expected=300000*host.shared->channels;
        if(kbps && i>1 && (host.shared->applied!=sequence||host.shared->bitrate!=expected||host.shared->encoding_errors||
           host.shared->upstream_bitrate!=kbps*1000 || host.shared->error ||
           (LONG64)host.shared->output_capacity*host.shared->sample_rate*8<(LONG64)expected*host.shared->packet_samples))good=0;
    }
    if(kbps) {
        LONG restore=kh_command(&host,K_CMD_RESTORE,0,0);deadline=GetTickCount64()+5000;
        while(host.shared->applied!=restore&&GetTickCount64()<deadline)Sleep(50);
        printf("restored=%ld expected=%ld holding=%ld upstream=%ld original_upstream=%ld\n",host.shared->bitrate,host.shared->original_bitrate,host.shared->holding,
               host.shared->upstream_bitrate,host.shared->original_upstream_bitrate);
        if(host.shared->applied!=restore||host.shared->bitrate!=host.shared->original_bitrate||host.shared->holding||
           host.shared->upstream_bitrate!=host.shared->original_upstream_bitrate)good=0;
    }
    kh_close(&host);printf("test_passed=%s\n",good?"true":"false");return good?0:3;
}
