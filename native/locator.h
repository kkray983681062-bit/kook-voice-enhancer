#ifndef KOOK_LOCATOR_H
#define KOOK_LOCATOR_H
#include <windows.h>
#define K_PATH_CAP 1024
enum { K_PATH_NONE,K_PATH_FOUND,K_PATH_MULTIPLE,K_PATH_INCOMPLETE };
typedef struct {int code;wchar_t path[K_PATH_CAP];} KLocation;
int kl_validate(const wchar_t *path,wchar_t *normalized);
int kl_load(wchar_t *path);
int kl_save(const wchar_t *path);
KLocation kl_find(void);
int kl_start(const wchar_t *path,DWORD *error);
#endif
