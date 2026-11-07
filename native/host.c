#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>
#include "host.h"

static int read_bytes(HANDLE p,uintptr_t address,void *out,size_t n) {
    SIZE_T done=0;return ReadProcessMemory(p,(const void *)address,out,n,&done)&&done==n;
}
static DWORD remote_export(HANDLE p,uintptr_t base,DWORD size,const char *name) {
    IMAGE_DOS_HEADER dos;IMAGE_NT_HEADERS64 nt;IMAGE_EXPORT_DIRECTORY ex;
    if(size<sizeof(nt)||!read_bytes(p,base,&dos,sizeof(dos))||dos.e_magic!=IMAGE_DOS_SIGNATURE||dos.e_lfanew<0||
       (DWORD)dos.e_lfanew>size-sizeof(nt)||!read_bytes(p,base+dos.e_lfanew,&nt,sizeof(nt))||
       nt.Signature!=IMAGE_NT_SIGNATURE)return 0;
    IMAGE_DATA_DIRECTORY d;
    if(nt.OptionalHeader.Magic==IMAGE_NT_OPTIONAL_HDR64_MAGIC)d=nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    else if(nt.OptionalHeader.Magic==IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_NT_HEADERS32 nt32;if(!read_bytes(p,base+dos.e_lfanew,&nt32,sizeof(nt32)))return 0;
        d=nt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }else return 0;
    if(!d.VirtualAddress||d.VirtualAddress>size-sizeof(ex)||!read_bytes(p,base+d.VirtualAddress,&ex,sizeof(ex))||
       !ex.NumberOfNames||ex.NumberOfNames>100000||ex.NumberOfFunctions>100000)return 0;
    if((uint64_t)ex.AddressOfNames+ex.NumberOfNames*4ull>size ||
       (uint64_t)ex.AddressOfNameOrdinals+ex.NumberOfNames*2ull>size ||
       (uint64_t)ex.AddressOfFunctions+ex.NumberOfFunctions*4ull>size)return 0;
    DWORD *names=malloc(ex.NumberOfNames*4ull);WORD *ord=malloc(ex.NumberOfNames*2ull);
    DWORD *functions=malloc(ex.NumberOfFunctions*4ull);DWORD found=0;
    if(names&&ord&&functions && read_bytes(p,base+ex.AddressOfNames,names,ex.NumberOfNames*4ull)&&
       read_bytes(p,base+ex.AddressOfNameOrdinals,ord,ex.NumberOfNames*2ull)&&
       read_bytes(p,base+ex.AddressOfFunctions,functions,ex.NumberOfFunctions*4ull)) {
        size_t len=strlen(name)+1;char text[128];
        for(DWORD i=0;i<ex.NumberOfNames;++i)if((uint64_t)names[i]+len<=size&&ord[i]<ex.NumberOfFunctions) {
            if(read_bytes(p,base+names[i],text,len)&&!memcmp(text,name,len)) {
                DWORD r=functions[ord[i]];
                if(r<size && !(r>=d.VirtualAddress && r<d.VirtualAddress+d.Size))found=r;
                break;
            }
        }
    }
    free(names);free(ord);free(functions);return found;
}
static int process_has_engine(DWORD pid,HANDLE process) {
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid);
    if(snap==INVALID_HANDLE_VALUE)return -1;
    MODULEENTRY32W m={.dwSize=sizeof(m)};int found=0;
    if(Module32FirstW(snap,&m))do {
        if(remote_export(process,(uintptr_t)m.modBaseAddr,m.modBaseSize,"KL_StartPushAudioStream") &&
           remote_export(process,(uintptr_t)m.modBaseAddr,m.modBaseSize,"KL_SetPushAudioBitratebps")){found++;}
    }while(Module32NextW(snap,&m));
    CloseHandle(snap);return found;
}
#ifndef K_TARGET_EXE
#define K_TARGET_EXE L"KOOK.exe"
#endif
int kh_find_target(KHost *host) {
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snap==INVALID_HANDLE_VALUE){host->error=GetLastError();return 0;}
    PROCESSENTRY32W e={.dwSize=sizeof(e)};unsigned count=0,processes=0,denied=0,wrong_arch=0;
    DWORD selected=0;
    if(Process32FirstW(snap,&e))do {
        if(_wcsicmp(e.szExeFile,K_TARGET_EXE))continue;
        processes++;
        HANDLE p=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_VM_READ,FALSE,e.th32ProcessID);
        if(!p){if(GetLastError()==ERROR_ACCESS_DENIED)denied++;continue;}
        int engines=process_has_engine(e.th32ProcessID,p);BOOL wow64=FALSE;
        if(engines>0) {
            if(!IsWow64Process(p,&wow64)){denied++;}
            else if(wow64)wrong_arch++;
            else {count+=(unsigned)engines;selected=e.th32ProcessID;}
        }else if(engines<0&&GetLastError()==ERROR_ACCESS_DENIED)denied++;
        CloseHandle(p);
    }while(Process32NextW(snap,&e));
    CloseHandle(snap);
    host->error=count>1?10002:count==1?0:wrong_arch?10008:denied?ERROR_ACCESS_DENIED:processes?10007:10001;
    if(host->error)return 0;
    host->process=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_VM_WRITE|
                            PROCESS_VM_OPERATION|PROCESS_CREATE_THREAD|PROCESS_DUP_HANDLE|SYNCHRONIZE,FALSE,selected);
    if(!host->process){host->error=GetLastError();if(host->error==ERROR_INVALID_PARAMETER)host->error=10007;return 0;}
    host->pid=selected;return 1;
}
static uintptr_t module_base(DWORD pid,const wchar_t *wanted) {
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid);
    if(snap==INVALID_HANDLE_VALUE)return 0;
    MODULEENTRY32W m={.dwSize=sizeof(m)};uintptr_t base=0;
    if(Module32FirstW(snap,&m))do {
        if(!_wcsicmp(m.szModule,wanted)){base=(uintptr_t)m.modBaseAddr;break;}
    }while(Module32NextW(snap,&m));
    CloseHandle(snap);return base;
}
static uintptr_t remote_system_function(DWORD pid,const char *name) {
    FARPROC fn=GetProcAddress(GetModuleHandleW(L"kernel32.dll"),name);HMODULE owner=NULL;
    if(!fn || !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                (LPCWSTR)(uintptr_t)fn,&owner))return 0;
    wchar_t path[MAX_PATH];if(!GetModuleFileNameW(owner,path,MAX_PATH))return 0;
    const wchar_t *filename=wcsrchr(path,L'\\');filename=filename?filename+1:path;
    uintptr_t base=module_base(pid,filename);return base?base+((uintptr_t)fn-(uintptr_t)owner):0;
}
static int remote_call(KHost *host,uintptr_t function,void *argument,DWORD *result) {
    HANDLE thread=CreateRemoteThread(host->process,NULL,0,(LPTHREAD_START_ROUTINE)function,argument,0,NULL);
    if(!thread){host->error=GetLastError();return 0;}
    DWORD wait=WaitForSingleObject(thread,8000);
    int ok=wait==WAIT_OBJECT_0 && GetExitCodeThread(thread,result);
    if(!ok)host->error=wait==WAIT_TIMEOUT?10003:GetLastError();
    CloseHandle(thread);return ok;
}
static int extract_agent(wchar_t *path,size_t cap) {
    HRSRC resource=FindResourceW(NULL,MAKEINTRESOURCEW(201),MAKEINTRESOURCEW(10));
    HGLOBAL loaded=resource?LoadResource(NULL,resource):NULL;
    const unsigned char *data=loaded?LockResource(loaded):NULL;DWORD size=resource?SizeofResource(NULL,resource):0;
    if(!data||!size)return 0;
    uint64_t hash=1469598103934665603ull;for(DWORD i=0;i<size;++i){hash^=data[i];hash*=1099511628211ull;}
    wchar_t folder[MAX_PATH];DWORD n=GetTempPathW(MAX_PATH,folder);if(!n||n>MAX_PATH-32)return 0;
    wcscat_s(folder,MAX_PATH,L"KookVoiceEnhancer");
    if(!CreateDirectoryW(folder,NULL)&&GetLastError()!=ERROR_ALREADY_EXISTS)return 0;
    if(swprintf_s(path,cap,L"%ls\\agent-%016llx.dll",folder,(unsigned long long)hash)<0)return 0;
    HANDLE f=CreateFileW(path,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(f==INVALID_HANDLE_VALUE && GetLastError()==ERROR_FILE_EXISTS) {
        f=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);
        if(f==INVALID_HANDLE_VALUE)return 0;
        LARGE_INTEGER length;unsigned char *copy=malloc(size);DWORD read=0;
        int same=copy&&GetFileSizeEx(f,&length)&&length.QuadPart==size&&ReadFile(f,copy,size,&read,NULL)&&read==size&&!memcmp(copy,data,size);
        free(copy);CloseHandle(f);return same;
    }
    if(f==INVALID_HANDLE_VALUE)return 0;
    DWORD written=0;int ok=WriteFile(f,data,size,&written,NULL)&&written==size;CloseHandle(f);return ok;
}
int kh_connect(KHost *host) {
    memset(host,0,sizeof(*host));if(!kh_find_target(host))return 0;
    wchar_t path[MAX_PATH];if(!extract_agent(path,MAX_PATH)){host->error=GetLastError();kh_close(host);return 0;}
    host->mapping=CreateFileMappingW(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,0,sizeof(KShared),NULL);
    host->shared=host->mapping?MapViewOfFile(host->mapping,FILE_MAP_ALL_ACCESS,0,0,sizeof(KShared)):NULL;
    if(!host->shared){host->error=GetLastError();kh_close(host);return 0;}
    memset(host->shared,0,sizeof(KShared));host->shared->magic=K_MAGIC;host->shared->version=3;
    KInit init={.magic=K_MAGIC};
    if(!DuplicateHandle(GetCurrentProcess(),host->mapping,host->process,&init.mapping,0,FALSE,DUPLICATE_SAME_ACCESS)||
       !DuplicateHandle(GetCurrentProcess(),GetCurrentProcess(),host->process,&init.parent,SYNCHRONIZE,FALSE,0)) {
        host->error=GetLastError();kh_close(host);return 0;
    }
    size_t bytes=(wcslen(path)+1)*sizeof(wchar_t);SIZE_T written=0;
    void *remote=VirtualAllocEx(host->process,NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    DWORD result=0;uintptr_t loader=remote_system_function(host->pid,"LoadLibraryW");
    if(!remote||!loader||!WriteProcessMemory(host->process,remote,path,bytes,&written)||written!=bytes||
       !remote_call(host,loader,remote,&result))goto fail;
    const wchar_t *filename=wcsrchr(path,L'\\');filename=filename?filename+1:path;
    uintptr_t base=module_base(host->pid,filename);if(!base){host->error=10004;goto fail;}
    HMODULE local=LoadLibraryExW(path,NULL,DONT_RESOLVE_DLL_REFERENCES);
    FARPROC entry=local?GetProcAddress(local,"AgentInitialize"):NULL;
    uintptr_t init_rva=entry?(uintptr_t)entry-(uintptr_t)local:0;if(local)FreeLibrary(local);
    if(!init_rva||!WriteProcessMemory(host->process,remote,&init,sizeof(init),&written)||written!=sizeof(init)||
       !remote_call(host,base+init_rva,remote,&result))goto fail;
    VirtualFreeEx(host->process,remote,0,MEM_RELEASE);remote=NULL;
    if(result) {
        host->error=host->shared->status==K_UNSUPPORTED?10005:10006;
        uintptr_t unload=remote_system_function(host->pid,"FreeLibrary");
        if(unload)remote_call(host,unload,(void *)base,&result);
        kh_close(host);return 0;
    }
    return 1;
fail:
    if(!host->error)host->error=GetLastError();
    if(remote && host->error!=10003)VirtualFreeEx(host->process,remote,0,MEM_RELEASE);
    kh_close(host);return 0;
}
LONG kh_command(KHost *host,int command,int argument,int keep) {
    if(!host->shared)return 0;
    host->shared->argument=argument;host->shared->keep=keep;host->shared->command=command;
    MemoryBarrier();return InterlockedIncrement(&host->shared->sequence);
}
void kh_close(KHost *host) {
    if(host->shared) {
        if(host->shared->status!=K_STOPPED && host->shared->status!=K_FAILURE && host->shared->status!=K_UNSUPPORTED) {
            kh_command(host,K_CMD_STOP,0,0);ULONGLONG deadline=GetTickCount64()+6000;
            while(host->shared->status!=K_STOPPED && GetTickCount64()<deadline &&
                  host->process && WaitForSingleObject(host->process,50)==WAIT_TIMEOUT) {}
        }
        UnmapViewOfFile(host->shared);host->shared=NULL;
    }
    if(host->mapping){CloseHandle(host->mapping);host->mapping=NULL;}
    if(host->process){CloseHandle(host->process);host->process=NULL;}
}
