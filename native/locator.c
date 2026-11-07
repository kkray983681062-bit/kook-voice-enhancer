#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <objbase.h>
#include <strsafe.h>
#include <wchar.h>
#include <wctype.h>
#include <string.h>
#include "locator.h"

typedef struct {wchar_t paths[2][K_PATH_CAP];int count,incomplete;ULONGLONG deadline;unsigned visited;} Candidates;
static const wchar_t config_key[]=L"Software\\Kekemi\\KookVoiceEnhancer";
static int contains(const wchar_t *text,const wchar_t *part) {
    size_t n=wcslen(part);for(;*text;text++)if(!_wcsnicmp(text,part,n))return 1;return 0;
}
static int kook_name(const wchar_t *name){return contains(name,L"KOOK")||contains(name,L"开黑啦");}
static int valid_exe(const wchar_t *path) {
    const wchar_t *name=wcsrchr(path,L'\\');if(!name||_wcsicmp(name+1,L"KOOK.exe"))return 0;
    DWORD attr=GetFileAttributesW(path),type=0;
    return attr!=INVALID_FILE_ATTRIBUTES && !(attr&FILE_ATTRIBUTE_DIRECTORY) &&
           GetBinaryTypeW(path,&type) && (type==SCS_32BIT_BINARY||type==SCS_64BIT_BINARY);
}
int kl_validate(const wchar_t *path,wchar_t *out) {
    if(!path||!*path||!out)return 0;
    wchar_t full[K_PATH_CAP];DWORD n=GetFullPathNameW(path,K_PATH_CAP,full,NULL);
    if(!n||n>=K_PATH_CAP||!valid_exe(full))return 0;
    /* Squirrel's stable launcher survives app-version directory changes. */
    wchar_t parent[K_PATH_CAP];wcscpy_s(parent,K_PATH_CAP,full);wchar_t *slash=wcsrchr(parent,L'\\');*slash=0;
    slash=wcsrchr(parent,L'\\');
    if(slash&&!_wcsnicmp(slash+1,L"app-",4)) {
        *slash=0;wchar_t launcher[K_PATH_CAP];
        if(SUCCEEDED(StringCchPrintfW(launcher,K_PATH_CAP,L"%ls\\KOOK.exe",parent))&&valid_exe(launcher))wcscpy_s(full,K_PATH_CAP,launcher);
    }
    return wcscpy_s(out,K_PATH_CAP,full)==0;
}
int kl_load(wchar_t *path) {
    wchar_t stored[K_PATH_CAP];DWORD bytes=sizeof(stored);HKEY key=NULL;
    if(RegOpenKeyExW(HKEY_CURRENT_USER,config_key,0,KEY_QUERY_VALUE,&key)!=ERROR_SUCCESS)return 0;
    LONG result=RegGetValueW(key,NULL,L"ExecutablePath",RRF_RT_REG_SZ,NULL,stored,&bytes);RegCloseKey(key);
    return result==ERROR_SUCCESS && kl_validate(stored,path);
}
int kl_save(const wchar_t *path) {
    wchar_t normalized[K_PATH_CAP];if(!kl_validate(path,normalized))return 0;HKEY key=NULL;
    if(RegCreateKeyExW(HKEY_CURRENT_USER,config_key,0,NULL,0,KEY_SET_VALUE,NULL,&key,NULL)!=ERROR_SUCCESS)return 0;
    LONG result=RegSetValueExW(key,L"ExecutablePath",0,REG_SZ,(const BYTE *)normalized,(DWORD)((wcslen(normalized)+1)*sizeof(wchar_t)));
    RegCloseKey(key);return result==ERROR_SUCCESS;
}
static void add_file(Candidates *set,const wchar_t *path) {
    if(set->count>=2)return;wchar_t normalized[K_PATH_CAP];if(!kl_validate(path,normalized))return;
    for(int i=0;i<set->count;i++)if(!_wcsicmp(set->paths[i],normalized))return;
    wcscpy_s(set->paths[set->count++],K_PATH_CAP,normalized);
}
static void add_directory(Candidates *set,const wchar_t *path) {
    wchar_t exe[K_PATH_CAP];
    if(SUCCEEDED(StringCchPrintfW(exe,K_PATH_CAP,L"%ls\\KOOK.exe",path)))add_file(set,exe);
    if(SUCCEEDED(StringCchPrintfW(exe,K_PATH_CAP,L"%ls\\KOOK\\KOOK.exe",path)))add_file(set,exe);
}
static void add_hint(Candidates *set,const wchar_t *hint) {
    if(!hint||!*hint)return;wchar_t expanded[K_PATH_CAP],path[K_PATH_CAP];
    DWORD n=ExpandEnvironmentStringsW(hint,expanded,K_PATH_CAP);if(!n||n>K_PATH_CAP)return;
    const wchar_t *start=expanded;while(iswspace(*start))start++;
    if(*start==L'"') {start++;const wchar_t *end=wcschr(start,L'"');if(!end||(size_t)(end-start)>=K_PATH_CAP)return;wmemcpy(path,start,end-start);path[end-start]=0;}
    else {wcscpy_s(path,K_PATH_CAP,start);wchar_t *comma=wcschr(path,L',');if(comma)*comma=0;size_t length=wcslen(path);while(length&&iswspace(path[length-1]))path[--length]=0;}
    DWORD attr=GetFileAttributesW(path);if(attr==INVALID_FILE_ATTRIBUTES)return;
    if(attr&FILE_ATTRIBUTE_DIRECTORY)add_directory(set,path);
    else {add_file(set,path);wchar_t *slash=wcsrchr(path,L'\\');if(slash){*slash=0;add_directory(set,path);}}
}
static void running(Candidates *set) {
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);if(snap==INVALID_HANDLE_VALUE){set->incomplete=1;return;}
    PROCESSENTRY32W e={.dwSize=sizeof(e)};
    if(Process32FirstW(snap,&e)) { do {
        if(_wcsicmp(e.szExeFile,L"KOOK.exe"))continue;
        HANDLE p=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,e.th32ProcessID);if(!p)continue;
        wchar_t path[K_PATH_CAP];DWORD size=K_PATH_CAP;if(QueryFullProcessImageNameW(p,0,path,&size))add_file(set,path);CloseHandle(p);
    }while(set->count<2&&Process32NextW(snap,&e)); }
    CloseHandle(snap);
}
static int registry_string(HKEY key,const wchar_t *name,wchar_t *text) {
    DWORD bytes=K_PATH_CAP*sizeof(wchar_t);LONG r=RegGetValueW(key,NULL,name,RRF_RT_REG_SZ|RRF_RT_REG_EXPAND_SZ|RRF_NOEXPAND,NULL,text,&bytes);
    text[K_PATH_CAP-1]=0;return r==ERROR_SUCCESS;
}
static void registry_paths(Candidates *set) {
    const HKEY roots[]={HKEY_CURRENT_USER,HKEY_LOCAL_MACHINE};const REGSAM views[]={KEY_WOW64_64KEY,KEY_WOW64_32KEY};
    for(unsigned i=0;i<2&&set->count<2;i++)for(unsigned j=0;j<2&&set->count<2;j++) {
        HKEY key=NULL;wchar_t value[K_PATH_CAP];
        if(RegOpenKeyExW(roots[i],L"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\KOOK.exe",0,KEY_READ|views[j],&key)==ERROR_SUCCESS) {
            if(registry_string(key,NULL,value))add_hint(set,value);RegCloseKey(key);
        }
        if(RegOpenKeyExW(roots[i],L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",0,KEY_READ|views[j],&key)!=ERROR_SUCCESS)continue;
        for(DWORD index=0;set->count<2;index++) {
            wchar_t name[512];DWORD length=512;LONG r=RegEnumKeyExW(key,index,name,&length,NULL,NULL,NULL,NULL);
            if(r==ERROR_NO_MORE_ITEMS)break;if(r!=ERROR_SUCCESS)continue;HKEY child=NULL;
            if(RegOpenKeyExW(key,name,0,KEY_READ|views[j],&child)!=ERROR_SUCCESS)continue;
            if(registry_string(child,L"DisplayName",value)&&kook_name(value)) {
                if(registry_string(child,L"InstallLocation",value))add_hint(set,value);
                if(registry_string(child,L"DisplayIcon",value))add_hint(set,value);
                if(registry_string(child,L"UninstallString",value))add_hint(set,value);
            }
            RegCloseKey(child);
        }
        RegCloseKey(key);
    }
}
static void shortcut(Candidates *set,const wchar_t *path) {
    IShellLinkW *link=NULL;IPersistFile *persist=NULL;
    if(FAILED(CoCreateInstance(&CLSID_ShellLink,NULL,CLSCTX_INPROC_SERVER,&IID_IShellLinkW,(void **)&link)))return;
    if(SUCCEEDED(IShellLinkW_QueryInterface(link,&IID_IPersistFile,(void **)&persist))&&
       SUCCEEDED(IPersistFile_Load(persist,path,STGM_READ))) {
        wchar_t target[K_PATH_CAP]={0};WIN32_FIND_DATAW data;
        if(SUCCEEDED(IShellLinkW_GetPath(link,target,K_PATH_CAP,&data,SLGP_RAWPATH)))add_hint(set,target);
    }
    if(persist)IPersistFile_Release(persist);IShellLinkW_Release(link);
}
static void scan_shortcuts(Candidates *set,const wchar_t *dir,unsigned depth) {
    if(depth>3||set->count>=2||set->incomplete)return;
    if(++set->visited>4000||GetTickCount64()>set->deadline){set->incomplete=1;return;}
    wchar_t pattern[K_PATH_CAP],path[K_PATH_CAP];if(FAILED(StringCchPrintfW(pattern,K_PATH_CAP,L"%ls\\*",dir)))return;
    WIN32_FIND_DATAW item;HANDLE f=FindFirstFileW(pattern,&item);if(f==INVALID_HANDLE_VALUE)return;
    do {
        if(!wcscmp(item.cFileName,L".")||!wcscmp(item.cFileName,L"..")||(item.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT))continue;
        if(FAILED(StringCchPrintfW(path,K_PATH_CAP,L"%ls\\%ls",dir,item.cFileName)))continue;
        if(item.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)scan_shortcuts(set,path,depth+1);
        else {const wchar_t *ext=wcsrchr(item.cFileName,L'.');if(ext&&!_wcsicmp(ext,L".lnk")&&kook_name(item.cFileName))shortcut(set,path);}
    }while(set->count<2&&!set->incomplete&&FindNextFileW(f,&item));FindClose(f);
}
static void shortcut_paths(Candidates *set) {
    if(FAILED(CoInitializeEx(NULL,COINIT_APARTMENTTHREADED)))return;
    const int folders[]={CSIDL_PROGRAMS,CSIDL_COMMON_PROGRAMS,CSIDL_DESKTOPDIRECTORY,CSIDL_COMMON_DESKTOPDIRECTORY};set->deadline=GetTickCount64()+2500;
    for(unsigned i=0;i<4&&!set->incomplete&&set->count<2;i++) {
        wchar_t dir[K_PATH_CAP];if(SUCCEEDED(SHGetFolderPathW(NULL,folders[i],NULL,SHGFP_TYPE_CURRENT,dir)))scan_shortcuts(set,dir,0);
    }
    CoUninitialize();
}
static void known_paths(Candidates *set) {
    const wchar_t *dirs[]={L"KOOK",L"Kook语音\\KOOK",L"开黑啦",L"Program Files\\KOOK",L"Program Files (x86)\\KOOK"};DWORD drives=GetLogicalDrives();
    for(int i=0;i<26&&set->count<2;i++)if(drives&(1u<<i)) {
        wchar_t root[]=L"A:\\";root[0]=(wchar_t)(L'A'+i);if(GetDriveTypeW(root)!=DRIVE_FIXED)continue;
        for(unsigned j=0;j<sizeof(dirs)/sizeof(dirs[0]);j++) {wchar_t path[K_PATH_CAP];if(SUCCEEDED(StringCchPrintfW(path,K_PATH_CAP,L"%ls%ls",root,dirs[j])))add_directory(set,path);}
    }
    wchar_t local[K_PATH_CAP],path[K_PATH_CAP];if(SUCCEEDED(SHGetFolderPathW(NULL,CSIDL_LOCAL_APPDATA,NULL,SHGFP_TYPE_CURRENT,local))) {
        if(SUCCEEDED(StringCchPrintfW(path,K_PATH_CAP,L"%ls\\KOOK",local)))add_directory(set,path);
        if(SUCCEEDED(StringCchPrintfW(path,K_PATH_CAP,L"%ls\\Programs\\KOOK",local)))add_directory(set,path);
    }
}
static KLocation result_of(Candidates *set) {
    KLocation result={0};result.code=set->count>1?K_PATH_MULTIPLE:set->incomplete?K_PATH_INCOMPLETE:set->count?K_PATH_FOUND:K_PATH_NONE;
    if(result.code==K_PATH_FOUND)wcscpy_s(result.path,K_PATH_CAP,set->paths[0]);return result;
}
KLocation kl_find(void) {
    KLocation result={0};Candidates set={0};running(&set);
    if(set.count)return result_of(&set);
    if(kl_load(result.path)){result.code=K_PATH_FOUND;return result;}
    memset(&set,0,sizeof(set));registry_paths(&set);if(set.count)return result_of(&set);
    memset(&set,0,sizeof(set));shortcut_paths(&set);if(set.count||set.incomplete)return result_of(&set);
    memset(&set,0,sizeof(set));known_paths(&set);return result_of(&set);
}
int kl_start(const wchar_t *path,DWORD *error) {
    *error=0;Candidates set={0};running(&set);if(set.count)return 2;
    wchar_t exe[K_PATH_CAP],dir[K_PATH_CAP],command[K_PATH_CAP+4];
    if(!kl_validate(path,exe)){*error=ERROR_FILE_NOT_FOUND;return 0;}
    wcscpy_s(dir,K_PATH_CAP,exe);*wcsrchr(dir,L'\\')=0;StringCchPrintfW(command,K_PATH_CAP+4,L"\"%ls\"",exe);
    STARTUPINFOW start={.cb=sizeof(start)};PROCESS_INFORMATION process;
    if(!CreateProcessW(exe,command,NULL,NULL,FALSE,0,NULL,dir,&start,&process)){*error=GetLastError();return 0;}
    CloseHandle(process.hThread);CloseHandle(process.hProcess);return 1;
}
