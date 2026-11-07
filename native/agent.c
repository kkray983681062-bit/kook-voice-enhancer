#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <string.h>
#include "protocol.h"
#include "features.h"
#include "vendor/minhook/include/MinHook.h"

typedef int (__cdecl *CtlFn)(void *,int,intptr_t);
typedef int (__cdecl *EncodeFn)(void *,const short *,int,unsigned char *,int);
typedef int (__cdecl *StartFn)(void *,int,const char *,int);
typedef void *(__cdecl *UpstreamEncodeFn)(void *,void *,uint32_t,const void *,void *);
typedef unsigned char (__cdecl *UpstreamRateFn)(void *,int);
typedef struct {void *state;ULONGLONG seen;int channels,rate,bitrate;} Seen;
static HMODULE self_module;
static HANDLE mapping,parent_process;
static KShared *shared;
static KFeatures features;
static CtlFn original_ctl;
static CtlFn original_celt_ctl;
static EncodeFn original_encode;
static StartFn original_start;
static UpstreamEncodeFn original_upstream_encode;
static UpstreamRateFn upstream_set_rate;
static SRWLOCK seen_lock=SRWLOCK_INIT;
static Seen seen[8];
static void *volatile target;
static volatile LONG active_calls,stopping,running;
static volatile LONG desired,hold_wanted,pending_sequence,armed_channels;
static volatile LONG profile_sequence,profile_keep,profile_generation;
static volatile LONG restoring;
static volatile LONG celt_adjust;
static _Thread_local void *encoding_state;

static int readable(const void *p,size_t size) {
    MEMORY_BASIC_INFORMATION info;
    if(!p || !VirtualQuery(p,&info,sizeof(info)) || info.State!=MEM_COMMIT ||
       (info.Protect&(PAGE_NOACCESS|PAGE_GUARD)))return 0;
    uintptr_t start=(uintptr_t)p,base=(uintptr_t)info.BaseAddress;
    return start>=base && size<=info.RegionSize && start-base<=info.RegionSize-size;
}
static void *current_target(void) {return InterlockedCompareExchangePointer(&target,NULL,NULL);}
static int metadata(void *state,int *channels,int *rate,int *bitrate) {
    if(!readable((char *)state+features.channels_offset,4))return 0;
    memcpy(channels,(char *)state+features.channels_offset,4);
    if(*channels!=1 && *channels!=2)return 0;
    if(original_ctl(state,4029,(intptr_t)rate) || original_ctl(state,4003,(intptr_t)bitrate))return 0;
    return (*rate==8000||*rate==12000||*rate==16000||*rate==24000||*rate==48000) &&
           *bitrate>=500 && *bitrate<=600000;
}
static int __cdecl control_hook(void *state,int request,intptr_t value) {
    InterlockedIncrement(&active_calls);
    if(!stopping && request==4002 && state==current_target() && hold_wanted)value=desired;
    int result=original_ctl(state,request,value);
    InterlockedDecrement(&active_calls);
    return result;
}
static int __cdecl celt_control_hook(void *state,int request,intptr_t value) {
    InterlockedIncrement(&active_calls);
    int result=original_celt_ctl(state,request,value);
    /* CELT can also serve unrelated streams. Scope to this thread's selected
       opus_encode invocation, not to a guessed embedded encoder address. */
    if(!stopping && request==4002 && !result && encoding_state && encoding_state==current_target() &&
       readable((char *)state+features.celt_channels_offset,4) && readable((char *)state+features.celt_bitrate_offset,4)) {
        int channels=0,actual=0;
        memcpy(&channels,(char *)state+features.celt_channels_offset,4);
        memcpy(&actual,(char *)state+features.celt_bitrate_offset,4);
        if((channels==1||channels==2) && celt_adjust && value>260000*channels && value<=desired && value<=320000 &&
           actual==260000*channels) {
            actual=(int)value;
            /* The original control call already validated the request. This
               field and its 260000*channels clamp are derived from its code. */
            memcpy((char *)state+features.celt_bitrate_offset,&actual,4);
        }
        shared->celt_bitrate=actual;
    }
    InterlockedDecrement(&active_calls);return result;
}
static void remember_encoder(void *state,ULONGLONG now,int channels,int rate,int bitrate) {
    if(!TryAcquireSRWLockExclusive(&seen_lock))return;
    int slot=-1;
    for(int i=0;i<8;++i)if(seen[i].state==state){slot=i;break;}
    if(slot<0)for(int i=0;i<8;++i)if(!seen[i].state || now-seen[i].seen>2000){slot=i;break;}
    if(slot>=0)seen[slot]=(Seen){state,now,channels,rate,bitrate};
    ReleaseSRWLockExclusive(&seen_lock);
}
static int __cdecl encode_hook(void *state,const short *pcm,int frame_size,unsigned char *data,int capacity) {
    InterlockedIncrement(&active_calls);
    int channels=0,rate=0,bitrate=0;
    int valid=!stopping && metadata(state,&channels,&rate,&bitrate);
    if(valid)remember_encoder(state,GetTickCount64(),channels,rate,bitrate);
    void *previous=encoding_state;
    encoding_state=valid&&state==current_target()?state:NULL;
    int result=original_encode(state,pcm,frame_size,data,capacity);
    encoding_state=previous;
    if(!stopping && valid && state==current_target()) {
        int current=0;
        if(!original_ctl(state,4003,(intptr_t)&current))shared->bitrate=current;
        shared->channels=channels;shared->sample_rate=rate;
        shared->output_capacity=capacity;shared->last_packet_bytes=result;shared->packet_samples=frame_size;
        InterlockedIncrement64(&shared->frames);
        if(result<0)InterlockedIncrement64(&shared->encoding_errors);
        if(result>0)InterlockedAdd64(&shared->payload_bytes,result);
        InterlockedExchange64(&shared->last_frame,(LONG64)GetTickCount64());
    }
    InterlockedDecrement(&active_calls);
    return result;
}
static void *owner_encoder(void *owner) {
    void *wrapper=NULL,*state=NULL;
    if(!readable((char *)owner+features.upstream_encoder_offset,sizeof(wrapper)))return NULL;
    memcpy(&wrapper,(char *)owner+features.upstream_encoder_offset,sizeof(wrapper));
    if(!readable(wrapper,sizeof(state)))return NULL;
    memcpy(&state,wrapper,sizeof(state));return state;
}
static void *__cdecl upstream_encode_hook(void *owner,void *result,uint32_t timestamp,const void *pcm,void *buffer) {
    InterlockedIncrement(&active_calls);
    void *state=NULL;
    if(!stopping && (state=owner_encoder(owner)) && state==current_target() &&
       readable((char *)owner+features.upstream_bitrate_offset,4)) {
        int configured=0;memcpy(&configured,(char *)owner+features.upstream_bitrate_offset,4);
        if(configured>=6000 && configured<=510000) {
            LONG seq=InterlockedExchange(&pending_sequence,0);
            if(seq || hold_wanted) {
                int restore=seq?InterlockedExchange(&restoring,0):0;
                int actual=0,channels=0,rate=0,bitrate=0;
                if(metadata(state,&channels,&rate,&bitrate)) {
                    if(seq && shared->original_generation!=shared->generation) {
                        shared->original_bitrate=bitrate;shared->original_upstream_bitrate=configured;
                        shared->original_generation=shared->generation;
                    }
                    int upstream=restore?shared->original_upstream_bitrate:desired;
                    /* This is before the SDK computes capacity and reserves its buffer.
                       Never enlarge opus_encode's capacity past the actual allocation. */
                    upstream_set_rate(owner,upstream);
                    int ctl_result=original_ctl(state,4002,desired);
                    int read_result=original_ctl(state,4003,(intptr_t)&actual);
                    memcpy(&configured,(char *)owner+features.upstream_bitrate_offset,4);
                    int effective=desired<300000*channels?desired:300000*channels;
                    shared->error=(ctl_result||read_result||actual!=effective||configured!=upstream)?3:0;
                    if(!shared->error)shared->bitrate=actual;
                    shared->upstream_bitrate=configured;
                    if(seq && !shared->error)shared->applied=seq;
                } else shared->error=3;
            }
            shared->upstream_bitrate=configured;
        } else shared->error=3;
    }
    void *value=original_upstream_encode(owner,result,timestamp,pcm,buffer);
    InterlockedDecrement(&active_calls);return value;
}
static int __cdecl start_hook(void *context,int kit,const char *peer,int channels) {
    InterlockedIncrement(&active_calls);
    int requested=0;
    if(!stopping && kit==0 && channels>=0 && channels<=2) {
        InterlockedExchange(&hold_wanted,0);InterlockedExchange(&celt_adjust,0);shared->holding=0;
        InterlockedExchange(&pending_sequence,0);
        InterlockedExchangePointer(&target,NULL);
        AcquireSRWLockExclusive(&seen_lock);memset(seen,0,sizeof(seen));ReleaseSRWLockExclusive(&seen_lock);
        InterlockedIncrement(&shared->generation);
        shared->original_generation=0;shared->original_bitrate=0;shared->original_upstream_bitrate=0;
        requested=InterlockedExchange(&armed_channels,0);
        if(requested) {channels=requested;profile_generation=shared->generation;}
        else {profile_generation=0;shared->pending_channels=0;}
    }
    int result=original_start(context,kit,peer,channels);
    if(!stopping && requested && result) {
        profile_generation=0;shared->pending_channels=0;shared->error=4;shared->status=K_FAILURE;
    }
    InterlockedDecrement(&active_calls);return result;
}
static HMODULE find_engine(void) {
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,GetCurrentProcessId());
    if(snap==INVALID_HANDLE_VALUE)return NULL;
    MODULEENTRY32W m={.dwSize=sizeof(m)};HMODULE result=NULL;unsigned count=0;
    if(Module32FirstW(snap,&m))do {
        if(GetProcAddress(m.hModule,"KL_StartPushAudioStream") && GetProcAddress(m.hModule,"KL_SetPushAudioBitratebps")) {
            result=m.hModule;count++;
        }
    }while(Module32NextW(snap,&m));
    CloseHandle(snap);return count==1?result:NULL;
}
static void schedule_apply(LONG seq,int bps,int keep,int restore) {
    if(!current_target() || shared->status==K_AMBIGUOUS) {shared->error=2;return;}
    InterlockedExchange(&desired,bps);shared->desired=bps;
    InterlockedExchange(&hold_wanted,keep);shared->holding=keep;
    InterlockedExchange(&restoring,restore);
    InterlockedExchange(&celt_adjust,!restore);
    InterlockedExchange(&pending_sequence,seq);
}
static void select_encoder(void) {
    Seen selected={0};int count=0;ULONGLONG now=GetTickCount64();
    AcquireSRWLockShared(&seen_lock);
    for(int i=0;i<8;++i)if(seen[i].state && now-seen[i].seen<1500) {selected=seen[i];count++;}
    ReleaseSRWLockShared(&seen_lock);
    if(count>1) {
        InterlockedExchange(&celt_adjust,0);
        InterlockedExchange(&hold_wanted,0);InterlockedExchange(&pending_sequence,0);
        InterlockedExchangePointer(&target,NULL);shared->holding=0;shared->status=K_AMBIGUOUS;return;
    }
    if(!count) {shared->status=shared->pending_channels?K_WAIT_REJOIN:K_NO_AUDIO;return;}
    InterlockedExchangePointer(&target,selected.state);
    shared->channels=selected.channels;shared->sample_rate=selected.rate;
    /* The hook publishes fresh bitrate after encoding; the candidate may be one frame older. */
    if(!shared->last_frame)shared->bitrate=selected.bitrate;
    if(profile_generation && profile_generation==shared->generation &&
       shared->pending_channels==selected.channels) {
        int bps=selected.channels==1?300000:320000;
        shared->pending_channels=0;profile_generation=0;
        schedule_apply(profile_sequence,bps,profile_keep,0);
    }
    shared->status=shared->pending_channels?K_WAIT_REJOIN:K_READY;
}
static int in_agent_code(uintptr_t ip) {
    IMAGE_DOS_HEADER *dos=(void *)self_module;
    IMAGE_NT_HEADERS64 *nt=(void *)((char *)self_module+dos->e_lfanew);
    uintptr_t base=(uintptr_t)self_module;
    if(ip>=base && ip<base+nt->OptionalHeader.SizeOfImage)return 1;
    const void *functions[]={(const void *)original_ctl,(const void *)original_encode,(const void *)original_start,(const void *)original_upstream_encode,(const void *)original_celt_ctl};
    for(unsigned i=0;i<sizeof(functions)/sizeof(functions[0]);++i) {
        MEMORY_BASIC_INFORMATION info;
        if(VirtualQuery(functions[i],&info,sizeof(info))) {
            base=(uintptr_t)info.BaseAddress;
            if(ip>=base && ip<base+info.RegionSize)return 1;
        }
    }
    return 0;
}
static int safe_to_unload(void) {
    if(active_calls)return 0;
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if(snap==INVALID_HANDLE_VALUE)return 0;
    THREADENTRY32 t={.dwSize=sizeof(t)};HANDLE suspended[1024];unsigned n=0;int safe=1;
    if(Thread32First(snap,&t))do {
        if(t.th32OwnerProcessID!=GetCurrentProcessId() || t.th32ThreadID==GetCurrentThreadId())continue;
        HANDLE h=OpenThread(THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT,FALSE,t.th32ThreadID);
        if(!h){safe=0;break;}
        if(n==1024 || SuspendThread(h)==(DWORD)-1){CloseHandle(h);safe=0;break;}
        suspended[n++]=h;CONTEXT c={.ContextFlags=CONTEXT_CONTROL};
        if(!GetThreadContext(h,&c) || in_agent_code((uintptr_t)c.Rip))safe=0;
    }while(Thread32Next(snap,&t));
    if(active_calls)safe=0;
    for(unsigned i=0;i<n;++i){ResumeThread(suspended[i]);CloseHandle(suspended[i]);}
    CloseHandle(snap);return safe;
}
static DWORD WINAPI worker(void *unused) {
    (void)unused;LONG processed=0;
    while(WaitForSingleObject(parent_process,100)==WAIT_TIMEOUT && !stopping) {
        select_encoder();
        LONG seq=shared->sequence;
        if(seq==processed)continue;
        processed=seq;shared->error=0;LONG command=shared->command,arg=shared->argument,keep=shared->keep;
        if(command==K_CMD_APPLY && arg>=6 && arg<=320) {
            schedule_apply(seq,arg*1000,keep!=0,0);
        } else if(command==K_CMD_RESTORE) {
            if(shared->original_generation==shared->generation && shared->original_bitrate>0)
                schedule_apply(seq,shared->original_bitrate,0,1);
            else shared->error=5;
        } else if(command==K_CMD_PROFILE && (arg==1||arg==2)) {
            if(shared->channels==arg && shared->status==K_READY)schedule_apply(seq,arg==1?300000:320000,keep!=0,0);
            else {
                InterlockedExchange(&hold_wanted,0);shared->holding=0;
                InterlockedExchange(&pending_sequence,0);
                profile_sequence=seq;profile_keep=keep!=0;profile_generation=0;
                shared->pending_channels=arg;InterlockedExchange(&armed_channels,arg);shared->status=K_WAIT_REJOIN;
            }
        } else if(command==K_CMD_RELEASE) {
            InterlockedExchange(&hold_wanted,0);InterlockedExchange(&pending_sequence,0);
            InterlockedExchange(&armed_channels,0);profile_generation=0;
            shared->holding=0;shared->pending_channels=0;shared->applied=seq;
        } else if(command==K_CMD_STOP) {
            InterlockedExchange(&stopping,1);
        } else shared->error=1;
        shared->acknowledged=seq;
    }
    InterlockedExchange(&stopping,1);InterlockedExchange(&hold_wanted,0);
    shared->holding=0;shared->pending_channels=0;
    MH_STATUS disabled=MH_DisableHook(MH_ALL_HOOKS);
    ULONGLONG deadline=GetTickCount64()+5000;int safe=0;
    while(disabled==MH_OK && GetTickCount64()<deadline) {
        if(safe_to_unload()){safe=1;break;}Sleep(20);
    }
    shared->status=K_STOPPED;
    if(!safe) { /* Leave disabled code resident rather than freeing an active return path. */
        shared->error=7;InterlockedExchange(&running,0);return 0;
    }
    MH_RemoveHook(MH_ALL_HOOKS);MH_Uninitialize();
    KShared *view=shared;shared=NULL;UnmapViewOfFile(view);CloseHandle(mapping);CloseHandle(parent_process);
    InterlockedExchange(&running,0);FreeLibraryAndExitThread(self_module,0);return 0;
}

__declspec(dllexport) DWORD WINAPI AgentInitialize(KInit *input) {
    if(!input || input->magic!=K_MAGIC || InterlockedCompareExchange(&running,1,0))return 1;
    mapping=input->mapping;parent_process=input->parent;
    shared=MapViewOfFile(mapping,FILE_MAP_ALL_ACCESS,0,0,sizeof(*shared));
    if(!shared || shared->magic!=K_MAGIC || shared->version!=4)goto failed;
    HMODULE engine=find_engine();if(!engine)goto failed;
    IMAGE_DOS_HEADER *dos=(void *)engine;
    IMAGE_NT_HEADERS64 *nt=(void *)((char *)engine+dos->e_lfanew);
    if(!k_find_features((const void *)engine,nt->OptionalHeader.SizeOfImage,&features))goto unsupported;
    if(!k_entry_matches_file(engine,features.control_rva)||!k_entry_matches_file(engine,features.encode_rva)||
       !k_entry_matches_file(engine,features.start_rva) || !k_entry_matches_file(engine,features.upstream_encode_rva) ||
       !k_entry_matches_file(engine,features.upstream_rate_rva) || !k_entry_matches_file(engine,features.celt_control_rva))goto unsupported;
    upstream_set_rate=(UpstreamRateFn)((char *)engine+features.upstream_rate_rva);
    shared->feature_control=(LONG)features.control_rva;shared->feature_encode=(LONG)features.encode_rva;
    shared->feature_channels_offset=(LONG)features.channels_offset;shared->generation=1;
    if(MH_Initialize()!=MH_OK)goto failed;
    if(MH_CreateHook((char *)engine+features.control_rva,(void *)control_hook,(void **)&original_ctl)!=MH_OK ||
       MH_CreateHook((char *)engine+features.encode_rva,(void *)encode_hook,(void **)&original_encode)!=MH_OK ||
       MH_CreateHook((char *)engine+features.start_rva,(void *)start_hook,(void **)&original_start)!=MH_OK ||
       MH_CreateHook((char *)engine+features.upstream_encode_rva,(void *)upstream_encode_hook,(void **)&original_upstream_encode)!=MH_OK ||
       MH_CreateHook((char *)engine+features.celt_control_rva,(void *)celt_control_hook,(void **)&original_celt_ctl)!=MH_OK ||
       MH_EnableHook(MH_ALL_HOOKS)!=MH_OK) {
        MH_DisableHook(MH_ALL_HOOKS);MH_RemoveHook(MH_ALL_HOOKS);MH_Uninitialize();goto failed;
    }
    shared->status=K_NO_AUDIO;
    HANDLE thread=CreateThread(NULL,0,worker,NULL,0,NULL);
    if(!thread){MH_DisableHook(MH_ALL_HOOKS);MH_RemoveHook(MH_ALL_HOOKS);MH_Uninitialize();goto failed;}
    CloseHandle(thread);return 0;
unsupported:
    shared->status=K_UNSUPPORTED;shared->error=1;
failed:
    if(shared){if(shared->status!=K_UNSUPPORTED)shared->status=K_FAILURE;UnmapViewOfFile(shared);shared=NULL;}
    if(mapping)CloseHandle(mapping);if(parent_process)CloseHandle(parent_process);
    InterlockedExchange(&running,0);return 2;
}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved) {
    (void)reserved;
    if(reason==DLL_PROCESS_ATTACH){self_module=module;DisableThreadLibraryCalls(module);}return TRUE;
}
