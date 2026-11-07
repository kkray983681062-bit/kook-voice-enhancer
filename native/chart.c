#include <string.h>
#include "chart.h"
void kc_sample(KChart *c,ULONGLONG now,LONG generation,LONG64 bytes,LONG64 frames,int active) {
    ULONGLONG elapsed=now-c->time;int same=generation==c->generation;
    int valid=active&&same&&c->time&&elapsed>=250&&elapsed<=2500&&bytes>=c->bytes&&frames>c->frames;
    if(!same) {memset(c->valid,0,sizeof(c->valid));memset(c->values,0,sizeof(c->values));}
    memmove(c->values,c->values+1,(K_CHART_POINTS-1)*sizeof(c->values[0]));
    memmove(c->valid,c->valid+1,K_CHART_POINTS-1);
    memmove(c->ticks,c->ticks+1,(K_CHART_POINTS-1)*sizeof(c->ticks[0]));c->ticks[K_CHART_POINTS-1]=now;
    c->live=valid;c->valid[K_CHART_POINTS-1]=(unsigned char)valid;
    c->latest=valid?(bytes-c->bytes)*8.0/elapsed:0;c->values[K_CHART_POINTS-1]=c->latest;
    c->time=now;c->generation=generation;c->bytes=bytes;c->frames=frames;
    int found=0;c->low=c->high=0;
    for(int i=0;i<K_CHART_POINTS;i++) {
        if(now-c->ticks[i]>30000)c->valid[i]=0;
        if(c->valid[i]) {double v=c->values[i];if(!found||v<c->low)c->low=v;if(!found||v>c->high)c->high=v;found=1;}
    }
}
