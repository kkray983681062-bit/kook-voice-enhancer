#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
int wmain(int argc,wchar_t **argv) {
    if(argc<4)return 2;
    Sleep((DWORD)_wtoi(argv[2]));
    HMODULE module=LoadLibraryW(argv[1]);if(!module)return 3;
    Sleep((DWORD)_wtoi(argv[3]));FreeLibrary(module);return 0;
}
