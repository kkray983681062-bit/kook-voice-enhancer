#ifndef KOOK_CHART_H
#define KOOK_CHART_H
#include <windows.h>
#define K_CHART_POINTS 31
typedef struct { double values[K_CHART_POINTS];unsigned char valid[K_CHART_POINTS];ULONGLONG ticks[K_CHART_POINTS],time;LONG64 bytes,frames;LONG generation;double latest,low,high;int live; } KChart;
void kc_sample(KChart *chart,ULONGLONG now,LONG generation,LONG64 bytes,LONG64 frames,int active);
#endif
