/* Isolated real-codec test. The caller supplies verified fixture constructor
   and destructor RVAs; they are not used by the shipping feature finder. */
#include "agent.c"
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

typedef void *(__cdecl *CreateEncoderFn)(int,int,int,int *);
typedef void (__cdecl *DestroyEncoderFn)(void *);

static int exercise(const char *label,void *encoder,void *selected,int channels,int bps,int adjust,int expected) {
    InterlockedExchangePointer(&target,selected);desired=bps;celt_adjust=adjust;hold_wanted=0;
    shared->frames=shared->payload_bytes=shared->encoding_errors=0;shared->celt_bitrate=0;
    if(original_ctl(encoder,4028,0) || original_ctl(encoder,4002,bps) ||
       original_ctl(encoder,4006,1) || original_ctl(encoder,4016,1))return 0;
    short pcm[2880*2];unsigned char output[6000];uint32_t rng=9762;LONG64 bytes=0;int errors=0,max_packet=0;
    for(int frame=0;frame<120;++frame) {
        for(int i=0;i<2880*channels;++i){rng=rng*1664525u+1013904223u;pcm[i]=(short)((int)((rng>>16)&32767)-16384);}
        int size=encode_hook(encoder,pcm,2880,output,sizeof(output));
        if(size<0){errors++;continue;}
        if(frame>=20){bytes+=size;if(size>max_packet)max_packet=size;}
    }
    int vbr=0,dtx=0;original_ctl(encoder,4007,(intptr_t)&vbr);original_ctl(encoder,4017,(intptr_t)&dtx);
    double mean=(double)bytes*8/6/1000;
    int good=!errors && mean>expected-2 && mean<expected+2 && vbr==1 && dtx==1;
    if(encoder==selected && adjust && shared->celt_bitrate!=bps)good=0;
    printf("{\"phase\":\"%s\",\"channels\":%d,\"mean_kbps\":%.3f,\"max_packet_bytes\":%d,\"celt_bps\":%ld,\"errors\":%d,\"vbr\":%d,\"dtx\":%d,\"passed\":%s}\n",
           label,channels,mean,max_packet,shared->celt_bitrate,errors,vbr,dtx,good?"true":"false");fflush(stdout);
    return good;
}
int wmain(int argc,wchar_t **argv) {
    if(argc!=4){fprintf(stderr,"Usage: celt-test.exe ENGINE_DLL CREATE_RVA DESTROY_RVA\n");return 2;}
    HMODULE engine=LoadLibraryExW(argv[1],NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if(!engine){printf("load_error=%lu\n",GetLastError());return 3;}
    IMAGE_DOS_HEADER *dos=(void *)engine;IMAGE_NT_HEADERS64 *nt=(void *)((char *)engine+dos->e_lfanew);
    if(!k_find_features((const void *)engine,nt->OptionalHeader.SizeOfImage,&features))return 4;
    unsigned long create_rva=wcstoul(argv[2],NULL,0),destroy_rva=wcstoul(argv[3],NULL,0);
    if(!create_rva || !destroy_rva || create_rva>=nt->OptionalHeader.SizeOfImage || destroy_rva>=nt->OptionalHeader.SizeOfImage)return 5;
    CreateEncoderFn create=(CreateEncoderFn)((char *)engine+create_rva);
    DestroyEncoderFn destroy=(DestroyEncoderFn)((char *)engine+destroy_rva);
    original_ctl=(CtlFn)((char *)engine+features.control_rva);original_encode=(EncodeFn)((char *)engine+features.encode_rva);
    KShared local={0};shared=&local;local.generation=1;
    int error=0;void *mono=create(48000,1,2048,&error);if(!mono||error)return 6;
    void *other=create(48000,1,2048,&error);if(!other||error)return 6;
    void *stereo=create(48000,2,2048,&error);if(!stereo||error)return 6;
    if(MH_Initialize()!=MH_OK || MH_CreateHook((char *)engine+features.celt_control_rva,(void *)celt_control_hook,(void **)&original_celt_ctl)!=MH_OK ||
       MH_EnableHook(MH_ALL_HOOKS)!=MH_OK)return 7;
    int good=exercise("baseline",mono,mono,1,300000,0,260);
    good=exercise("selected_mono",mono,mono,1,300000,1,300)&&good;
    good=exercise("unselected_mono",other,mono,1,300000,1,260)&&good;
    good=exercise("restored",mono,mono,1,300000,0,260)&&good;
    good=exercise("selected_stereo",stereo,stereo,2,320000,1,320)&&good;
    MH_DisableHook(MH_ALL_HOOKS);MH_RemoveHook(MH_ALL_HOOKS);MH_Uninitialize();
    destroy(mono);destroy(other);destroy(stereo);FreeLibrary(engine);return good?0:8;
}
