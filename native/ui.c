#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include <commdlg.h>
#include <math.h>
#include "host.h"
#include "locator.h"
#include "chart.h"
#include "connection.h"

enum { ID_MONO=101,ID_STEREO,ID_APPLY,ID_RESTORE,ID_READ,ID_KEEP,ID_TARGET,ID_FIND,ID_CHOOSE,ID_START,ID_LICENSE=0x1e10 };
enum { WM_CONNECTED=WM_APP+1,WM_CLOSED,WM_LOCATED };
static const wchar_t window_class[]=L"KookVoiceEnhancerNativeWindow";
static const COLORREF bg=RGB(21,25,31),card=RGB(32,39,49),fg=RGB(237,242,247),muted=RGB(165,175,189),accent=RGB(136,215,189);
static HWND window,mono,stereo,apply,restore,read_button,keep_button,target_edit;
static HWND find_button,choose_button,start_button;
static HFONT normal_font,title_font,value_font,small_font;
static HBRUSH bg_brush,card_brush;
static KHost host;
static KChart chart;
static wchar_t kook_path[K_PATH_CAP],location_text[K_PATH_CAP+32]=L"KOOK：正在自动查找…";
static int locating;
static int dpi=96,connecting,closing,keep_checked=1;
static LONG last_sequence,last_generation;
static ULONGLONG wait_started,retry_at;
static wchar_t value_text[64]=L"— kbps",detail_text[128]=L"正在读取当前 KOOK 编码器…";
static wchar_t status_text[256]=L"正在连接…";
static int px(int x){return MulDiv(x,dpi,96);}
static void label(HDC dc,const wchar_t *text,int x,int y,int w,int h,HFONT font,COLORREF color,UINT flags) {
    RECT r={px(x),px(y),px(x+w),px(y+h)};
    SelectObject(dc,font);SetTextColor(dc,color);SetBkMode(dc,TRANSPARENT);DrawTextW(dc,text,-1,&r,flags);
}
static void set_status(const wchar_t *text) {wcsncpy_s(status_text,256,text,_TRUNCATE);InvalidateRect(window,NULL,FALSE);}
static const wchar_t *connection_error(DWORD error) {
    switch(error) {
    case 10001:return L"KOOK 尚未启动，正在自动等待；可点击下方「启动 KOOK」。";
    case 10002:return L"检测到多个语音进程，请保留一个 KOOK 后重新读取。";
    case 10005:return L"当前引擎特征无法唯一确认，或已有其他增强器在运行。请先关闭其他增强器。";
    case 10007:return L"KOOK 已运行，正在等待语音引擎；请进入语音频道，将自动重试连接。";
    case 10008:return L"检测到 32 位 KOOK 音频引擎。此增强器支持 64 位 KOOK，请使用 64 位客户端。";
    case 10004:return L"临时控制模块未能载入 KOOK，请检查两者权限是否一致。";
    case 5:return L"KOOK 进程访问受限。请让两者权限一致；若 KOOK 以管理员运行，增强器也需同级权限。";
    default:return L"连接未完成，请关闭其他增强器后重新读取。";
    }
}
static DWORD WINAPI connect_job(void *unused) {
    (void)unused;KHost *result=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(KHost));
    if(result)kh_connect(result);
    PostMessageW(window,WM_CONNECTED,0,(LPARAM)result);return 0;
}
static DWORD WINAPI close_job(void *unused) {
    (void)unused;kh_close(&host);PostMessageW(window,WM_CLOSED,0,0);return 0;
}
static void begin_close(void) {
    closing=1;EnableWindow(window,FALSE);set_status(L"正在停止保持并释放临时控制…");
    if(connecting||locating)return;
    HANDLE t=CreateThread(NULL,0,close_job,NULL,0,NULL);
    if(t)CloseHandle(t);else {kh_close(&host);DestroyWindow(window);}
}
static DWORD WINAPI locate_job(void *unused) {
    (void)unused;KLocation *result=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(KLocation));
    if(result)*result=kl_find();PostMessageW(window,WM_LOCATED,0,(LPARAM)result);return 0;
}
static void find_location(void) {
    if(locating||closing)return;locating=1;
    wcscpy_s(location_text,K_PATH_CAP+32,L"KOOK：正在自动查找…");
    EnableWindow(find_button,FALSE);EnableWindow(choose_button,FALSE);
    HANDLE thread=CreateThread(NULL,0,locate_job,NULL,0,NULL);
    if(thread)CloseHandle(thread);else {locating=0;wcscpy_s(location_text,K_PATH_CAP+32,L"KOOK：自动查找失败，请手动选择");}
    InvalidateRect(window,NULL,FALSE);
}
static void show_location(const wchar_t *path) {
    wcscpy_s(kook_path,K_PATH_CAP,path);swprintf_s(location_text,K_PATH_CAP+32,L"KOOK：%ls",path);
}
static void choose_location(void) {
    wchar_t path[K_PATH_CAP]={0},normalized[K_PATH_CAP];if(*kook_path)wcscpy_s(path,K_PATH_CAP,kook_path);
    OPENFILENAMEW dialog={.lStructSize=sizeof(dialog),.hwndOwner=window,
        .lpstrFilter=L"KOOK 程序 (KOOK.exe)\0KOOK.exe\0可执行文件 (*.exe)\0*.exe\0\0",
        .lpstrFile=path,.nMaxFile=K_PATH_CAP,.lpstrTitle=L"选择 KOOK.exe",
        .Flags=OFN_EXPLORER|OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST|OFN_NOCHANGEDIR};
    if(!GetOpenFileNameW(&dialog))return;
    if(!kl_validate(path,normalized)){set_status(L"请选择有效的 KOOK.exe 程序。");return;}
    show_location(normalized);set_status(kl_save(normalized)?L"已选择并记住 KOOK 的启动位置。":L"已选择 KOOK，但无法保存位置。");
}
static void begin_connect(void) {
    if(connecting||closing||host.shared)return;
    connecting=1;retry_at=0;
    if(!host.error)set_status(L"正在识别当前音频引擎…");
    HANDLE t=CreateThread(NULL,0,connect_job,NULL,0,NULL);
    if(t)CloseHandle(t);else {connecting=0;retry_at=GetTickCount64()+5000;set_status(L"无法创建连接任务，将自动重试。");}
}
static void send_command(int command,int arg) {
    if(!host.shared||closing)return;
    last_sequence=kh_command(&host,command,arg,keep_checked);
    if(command==K_CMD_PROFILE){wait_started=GetTickCount64();SetWindowTextW(target_edit,arg==1?L"300":L"320");}
    set_status(command==K_CMD_PROFILE?L"正在准备预设…":L"正在应用并回读实际值…");
}
static void refresh(void) {
    if(closing)return;
    int ready=0,pending=0,connected=host.shared!=NULL;
    if(connected && WaitForSingleObject(host.process,0)==WAIT_OBJECT_0) {
        kh_close(&host);connected=0;last_sequence=0;last_generation=0;
        wcscpy_s(value_text,64,L"— kbps");wcscpy_s(detail_text,128,L"KOOK 已退出");
        memset(&chart,0,sizeof(chart));host.error=10001;retry_at=GetTickCount64()+1000;
        set_status(L"KOOK 已退出，重新启动后将自动连接。");
    }
    if(connected) {
        KShared *s=host.shared;ready=s->status==K_READY;pending=s->pending_channels!=0;
        if(s->generation!=last_generation) {last_generation=s->generation;if(!pending)last_sequence=0;}
        if(ready||pending) {
            if(s->channels)swprintf_s(detail_text,128,L"当前配置：%ld kHz  ·  %ls  ·  %ld kbps",s->sample_rate/1000,s->channels==1?L"单声道":L"双声道",s->bitrate/1000);
        }else {wcscpy_s(value_text,64,L"— kbps");wcscpy_s(detail_text,128,L"等待正在编码的语音流");}
        if(pending) {
            swprintf_s(status_text,256,L"请离开并重新进入 KOOK 语音频道一次。\n重连后自动应用%ls %d kbps。",s->pending_channels==1?L"单声道":L"双声道",s->pending_channels==1?300:320);
            if(wait_started && GetTickCount64()-wait_started>180000) {
                send_command(K_CMD_RELEASE,0);wait_started=0;set_status(L"等待重连已超时，声道切换已取消。需要时可重新选择预设。");
            }
        } else if(s->status==K_AMBIGUOUS) {
            set_status(L"检测到多个音频编码器，已停止保持。请结束其他推流后重新读取。");
        } else if(s->status==K_NO_AUDIO) {
            set_status(L"请进入 KOOK 语音频道。未识别到正在编码的语音流。");
        } else if(s->status==K_FAILURE||s->status==K_UNSUPPORTED||s->status==K_STOPPED) {
            set_status(L"当前音频引擎无法安全控制，请关闭工具后重新打开。");
        } else if(s->error && s->acknowledged==last_sequence) {
            set_status(s->error==5?L"还没有本次连接的原值。首次应用时会自动保存。":L"设置没有通过实际回读验证，请重新读取后再试。");
        } else if(ready && (!last_sequence||s->applied==last_sequence)) {
            if(s->holding)swprintf_s(status_text,256,L"已生效：当前连接保持 %ld kbps。",s->bitrate/1000);
            else wcscpy_s(status_text,256,L"当前配置已读取，保持已关闭。可选择预设或应用码率。");
        }
    }
    if(!connected && host.error) {
        swprintf_s(detail_text,128,L"未连接到 KOOK · 错误 %lu%ls",host.error,k_retry_delay(host.error)?L" · 自动重试中":L"");
    }
    if(k_retry_due(GetTickCount64(),retry_at,connected,connecting,closing))begin_connect();
    EnableWindow(mono,connected&&!pending&&!connecting);
    EnableWindow(stereo,connected&&!pending&&!connecting);
    EnableWindow(apply,ready&&!pending&&!connecting);
    EnableWindow(restore,ready&&!pending&&!connecting);
    EnableWindow(target_edit,ready&&!pending&&!connecting);
    EnableWindow(read_button,!connecting);
    SetWindowTextW(read_button,pending?L"取消切换":L"读取当前");
    EnableWindow(find_button,!locating);EnableWindow(choose_button,!locating);EnableWindow(start_button,!locating&&*kook_path);
    InvalidateRect(window,NULL,FALSE);
}
static void chart_tick(void) {
    if(closing)return;ULONGLONG now=GetTickCount64();KShared *s=host.shared;
    if(s)kc_sample(&chart,now,s->generation,InterlockedCompareExchange64(&s->payload_bytes,0,0),InterlockedCompareExchange64(&s->frames,0,0),
                   (s->status==K_READY||s->status==K_WAIT_REJOIN)&&now-(ULONGLONG)s->last_frame<2000);
    else kc_sample(&chart,now,0,0,0,0);
    if(chart.live)swprintf_s(value_text,64,L"%.2f kbps",chart.latest);else wcscpy_s(value_text,64,L"— kbps");
    InvalidateRect(window,NULL,FALSE);
}
static void paint_chart(HDC dc) {
    const int left=26,right=534,top=180,bottom=311;RECT r={px(left),px(top),px(right),px(bottom)};FillRect(dc,&r,card_brush);
    HPEN grid=CreatePen(PS_DOT,1,RGB(59,69,82));HGDIOBJ old=SelectObject(dc,grid);
    for(int i=1;i<6;i++){int x=px(left+(right-left)*i/6);MoveToEx(dc,x,px(top),NULL);LineTo(dc,x,px(bottom));}
    for(int i=1;i<4;i++){int y=px(top+(bottom-top)*i/4);MoveToEx(dc,px(left),y,NULL);LineTo(dc,px(right),y);}
    SelectObject(dc,old);DeleteObject(grid);double scale=ceil(chart.high/32.0)*32.0;if(scale<64)scale=64;
    HPEN line=CreatePen(PS_SOLID,px(2),accent);old=SelectObject(dc,line);int preceding=0,last_x=0,last_y=0;
    for(int i=0;i<K_CHART_POINTS;i++) {
        if(!chart.valid[i]){preceding=0;continue;}int x=px(right-(int)((right-left)*(chart.time-chart.ticks[i])/30000));
        int y=px(bottom-3-(int)((bottom-top-7)*chart.values[i]/scale));
        if(preceding)LineTo(dc,x,y);else MoveToEx(dc,x,y,NULL);preceding=1;last_x=x;last_y=y;
    }
    if(chart.live) {HBRUSH brush=CreateSolidBrush(accent);HGDIOBJ oldbrush=SelectObject(dc,brush);Ellipse(dc,last_x-px(3),last_y-px(3),last_x+px(4),last_y+px(4));SelectObject(dc,oldbrush);DeleteObject(brush);}
    SelectObject(dc,old);DeleteObject(line);
}
static HWND button(int id,const wchar_t *text,int x,int y,int width,int height) {
    HWND h=CreateWindowExW(0,L"BUTTON",text,WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_OWNERDRAW,px(x),px(y),px(width),px(height),window,(HMENU)(INT_PTR)id,NULL,NULL);
    SendMessageW(h,WM_SETFONT,(WPARAM)normal_font,TRUE);return h;
}
static void draw_button(const DRAWITEMSTRUCT *item) {
    RECT r=item->rcItem;int disabled=(item->itemState&ODS_DISABLED)!=0;
    FillRect(item->hDC,&r,bg_brush);
    COLORREF fill=item->CtlID==ID_APPLY?accent:card;
    if(item->itemState&ODS_SELECTED)fill=RGB(55,70,80);
    if(item->CtlID==ID_KEEP)fill=bg;
    HBRUSH brush=CreateSolidBrush(fill);HPEN pen=CreatePen(PS_SOLID,1,fill);
    HGDIOBJ oldbrush=SelectObject(item->hDC,brush),oldpen=SelectObject(item->hDC,pen);
    RoundRect(item->hDC,r.left,r.top,r.right,r.bottom,px(9),px(9));
    SelectObject(item->hDC,oldbrush);SelectObject(item->hDC,oldpen);DeleteObject(brush);DeleteObject(pen);
    wchar_t text[128];GetWindowTextW(item->hwndItem,text,128);SelectObject(item->hDC,normal_font);SetBkMode(item->hDC,TRANSPARENT);
    SetTextColor(item->hDC,disabled?RGB(97,111,126):(item->CtlID==ID_APPLY?bg:fg));
    if(item->CtlID==ID_KEEP) {
        RECT box={px(2),px(6),px(21),px(25)};HBRUSH mark=CreateSolidBrush(keep_checked?accent:card);FillRect(item->hDC,&box,mark);DeleteObject(mark);
        if(keep_checked){SetTextColor(item->hDC,bg);DrawTextW(item->hDC,L"✓",-1,&box,DT_CENTER|DT_VCENTER|DT_SINGLELINE);}
        SetTextColor(item->hDC,fg);r.left+=px(32);DrawTextW(item->hDC,text,-1,&r,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    }else DrawTextW(item->hDC,text,-1,&r,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    if(item->itemState&ODS_FOCUS){InflateRect(&r,-px(3),-px(3));DrawFocusRect(item->hDC,&r);}
}
static LRESULT CALLBACK license_proc(HWND w,UINT msg,WPARAM wp,LPARAM lp) {
    if(msg==WM_SIZE) {HWND edit=GetWindow(w,GW_CHILD);if(edit)MoveWindow(edit,0,0,LOWORD(lp),HIWORD(lp),TRUE);return 0;}
    return DefWindowProcW(w,msg,wp,lp);
}
static void show_license(void) {
    HWND existing=FindWindowW(L"KookEnhancerLicense",NULL);if(existing){SetForegroundWindow(existing);return;}
    WNDCLASSW c={.lpfnWndProc=license_proc,.hInstance=GetModuleHandleW(NULL),.hCursor=LoadCursorW(NULL,MAKEINTRESOURCEW(32512)),.lpszClassName=L"KookEnhancerLicense"};
    RegisterClassW(&c);
    HWND w=CreateWindowExW(0,c.lpszClassName,L"开源许可 · MinHook / HDE",WS_OVERLAPPEDWINDOW|WS_VISIBLE,CW_USEDEFAULT,CW_USEDEFAULT,px(720),px(500),window,NULL,c.hInstance,NULL);
    HRSRC r=FindResourceW(NULL,MAKEINTRESOURCEW(202),MAKEINTRESOURCEW(10));DWORD size=SizeofResource(NULL,r);const char *raw=LockResource(LoadResource(NULL,r));
    wchar_t *text=calloc(size+1,sizeof(wchar_t));if(text&&raw)MultiByteToWideChar(CP_UTF8,0,raw,(int)size,text,(int)size);
    RECT rect;GetClientRect(w,&rect);
    HWND edit=CreateWindowExW(0,L"EDIT",text?text:L"",WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,0,0,rect.right,rect.bottom,w,NULL,c.hInstance,NULL);
    SendMessageW(edit,WM_SETFONT,(WPARAM)small_font,TRUE);free(text);
}
static LRESULT CALLBACK window_proc(HWND w,UINT msg,WPARAM wp,LPARAM lp) {
    switch(msg) {
    case WM_CREATE:
        window=w;
        mono=button(ID_MONO,L"单声道 · 300",26,353,245,39);
        stereo=button(ID_STEREO,L"双声道 · 320",289,353,245,39);
        target_edit=CreateWindowExW(0,L"EDIT",L"300",WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_NUMBER|ES_CENTER|WS_BORDER,px(130),px(414),px(90),px(33),w,(HMENU)(INT_PTR)ID_TARGET,NULL,NULL);
        SendMessageW(target_edit,WM_SETFONT,(WPARAM)title_font,TRUE);SendMessageW(target_edit,EM_SETLIMITTEXT,3,0);
        keep_button=button(ID_KEEP,L"应用后保持目标（仅当前语音连接）",26,463,508,32);
        apply=button(ID_APPLY,L"应用码率",26,511,150,40);
        restore=button(ID_RESTORE,L"恢复本次原值",192,511,169,40);
        read_button=button(ID_READ,L"读取当前",377,511,157,40);
        find_button=button(ID_FIND,L"自动查找",26,669,150,35);
        choose_button=button(ID_CHOOSE,L"选择 KOOK",192,669,169,35);
        start_button=button(ID_START,L"启动 KOOK",377,669,157,35);
        AppendMenuW(GetSystemMenu(w,FALSE),MF_SEPARATOR,0,NULL);AppendMenuW(GetSystemMenu(w,FALSE),MF_STRING,ID_LICENSE,L"开源许可");
        SetTimer(w,1,400,NULL);SetTimer(w,2,1000,NULL);begin_connect();find_location();refresh();return 0;
    case WM_CONNECTED: {
        connecting=0;KHost *result=(void *)lp;
        if(result){host=*result;HeapFree(GetProcessHeap(),0,result);}else host.error=ERROR_NOT_ENOUGH_MEMORY;
        if(closing){begin_close();return 0;}
        if(!host.shared){swprintf_s(status_text,256,L"%ls\n错误码：%lu",connection_error(host.error),host.error);DWORD delay=k_retry_delay(host.error);retry_at=delay?GetTickCount64()+delay:0;}
        else {retry_at=0;host.error=0;}
        refresh();return 0;
    }
    case WM_CLOSED:DestroyWindow(w);return 0;
    case WM_LOCATED: {
        locating=0;KLocation *result=(void *)lp;
        if(result&&result->code==K_PATH_FOUND)show_location(result->path);
        else wcscpy_s(location_text,K_PATH_CAP+32,result&&result->code==K_PATH_MULTIPLE?L"KOOK：找到多个位置，请手动选择":L"KOOK：自动查找未找到唯一位置，请手动选择");
        if(result)HeapFree(GetProcessHeap(),0,result);if(closing){begin_close();return 0;}refresh();return 0;
    }
    case WM_TIMER:if(wp==2)chart_tick();else refresh();return 0;
    case WM_SYSCOMMAND:if(wp==ID_LICENSE){show_license();return 0;}break;
    case WM_COMMAND:
        if(HIWORD(wp)!=BN_CLICKED)return 0;
        switch(LOWORD(wp)) {
        case ID_MONO:send_command(K_CMD_PROFILE,1);break;
        case ID_STEREO:send_command(K_CMD_PROFILE,2);break;
        case ID_APPLY: {
            wchar_t text[16];GetWindowTextW(target_edit,text,16);int value=_wtoi(text);
            if(value<6||value>320){set_status(L"请输入 6–320 之间的码率。");return 0;}
            send_command(K_CMD_APPLY,value);break;
        }
        case ID_RESTORE:send_command(K_CMD_RESTORE,0);break;
        case ID_FIND:find_location();break;
        case ID_CHOOSE:choose_location();break;
        case ID_START: {
            DWORD error=0;int result=kl_start(kook_path,&error);
            if(result)set_status(result==2?L"KOOK 已经打开，将自动尝试连接。":L"已启动 KOOK，正在等待语音引擎，将自动连接。");
            else if(error==740)set_status(L"KOOK 需要管理员权限，请手动启动 KOOK。");
            else set_status(L"启动 KOOK 失败，请重新选择程序位置。");
            if(result&&!host.shared){host.error=0;begin_connect();}break;
        }
        case ID_KEEP:
            keep_checked=!keep_checked;InvalidateRect(keep_button,NULL,FALSE);
            if(!keep_checked&&host.shared&&host.shared->holding)send_command(K_CMD_RELEASE,0);
            break;
        case ID_READ:
            if(!host.shared)begin_connect();
            else if(host.shared->pending_channels)send_command(K_CMD_RELEASE,0);
            else {last_sequence=0;refresh();}
            break;
        }
        return 0;
    case WM_DRAWITEM:draw_button((const DRAWITEMSTRUCT *)lp);return TRUE;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:SetTextColor((HDC)wp,fg);SetBkColor((HDC)wp,card);return (LRESULT)card_brush;
    case WM_ERASEBKGND:return 1;
    case WM_PAINT: {
        PAINTSTRUCT paint;HDC screen=BeginPaint(w,&paint);RECT client;GetClientRect(w,&client);
        HDC dc=CreateCompatibleDC(screen);HBITMAP bitmap=CreateCompatibleBitmap(screen,client.right,client.bottom);HGDIOBJ old=SelectObject(dc,bitmap);FillRect(dc,&client,bg_brush);
        label(dc,L"KOOK 语音增强",26,15,508,37,title_font,fg,DT_LEFT|DT_SINGLELINE);
        label(dc,L"实时音频码率",26,57,508,22,normal_font,muted,DT_LEFT|DT_SINGLELINE);
        label(dc,value_text,24,80,510,55,value_font,accent,DT_LEFT|DT_SINGLELINE);
        label(dc,detail_text,26,139,508,25,normal_font,fg,DT_LEFT|DT_SINGLELINE);
        label(dc,L"最近 30 秒 · 音频编码输出",26,163,270,20,small_font,muted,DT_LEFT|DT_SINGLELINE);
        wchar_t extrema[96];int any=0;for(int i=0;i<K_CHART_POINTS;i++)any|=chart.valid[i];
        if(any)swprintf_s(extrema,96,L"谷值 %.2f  ·  峰值 %.2f",chart.low,chart.high);else wcscpy_s(extrema,96,L"谷值 —  ·  峰值 —");
        label(dc,extrema,290,163,244,20,small_font,muted,DT_RIGHT|DT_SINGLELINE);paint_chart(dc);
        label(dc,L"30 秒前",26,318,200,22,small_font,muted,DT_LEFT|DT_SINGLELINE);
        label(dc,L"现在",334,318,200,22,small_font,muted,DT_RIGHT|DT_SINGLELINE);
        label(dc,L"请求码率",26,420,100,30,normal_font,fg,DT_LEFT|DT_SINGLELINE);
        label(dc,L"kbps  ·  6–320",235,420,290,30,normal_font,muted,DT_LEFT|DT_SINGLELINE);
        label(dc,status_text,26,571,508,57,normal_font,accent,DT_LEFT|DT_WORDBREAK);
        label(dc,location_text,26,638,508,25,small_font,muted,DT_LEFT|DT_SINGLELINE|DT_PATH_ELLIPSIS|DT_NOPREFIX);
        label(dc,L"曲线仅保留 30 秒，不含网络开销；关闭工具后停止保持。",26,718,508,22,small_font,muted,DT_LEFT|DT_SINGLELINE);
        BitBlt(screen,0,0,client.right,client.bottom,dc,0,0,SRCCOPY);SelectObject(dc,old);DeleteObject(bitmap);DeleteDC(dc);EndPaint(w,&paint);return 0;
    }
    case WM_CLOSE:if(!closing)begin_close();return 0;
    case WM_DESTROY:KillTimer(w,1);KillTimer(w,2);PostQuitMessage(0);return 0;
    }
    return DefWindowProcW(w,msg,wp,lp);
}
static HFONT make_font(int size,int weight,const wchar_t *face){return CreateFontW(-px(size),0,0,0,weight,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,face);}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE previous,LPWSTR command,int show) {
    (void)previous;(void)command;HANDLE mutex=CreateMutexW(NULL,FALSE,L"Local\\KookVoiceEnhancerNative");
    if(!mutex)return 1;
    if(GetLastError()==ERROR_ALREADY_EXISTS) {HWND other=FindWindowW(window_class,NULL);if(other){ShowWindow(other,SW_RESTORE);SetForegroundWindow(other);}CloseHandle(mutex);return 0;}
    SetProcessDPIAware();HDC dc=GetDC(NULL);dpi=GetDeviceCaps(dc,LOGPIXELSX);ReleaseDC(NULL,dc);
    normal_font=make_font(14,FW_NORMAL,L"Microsoft YaHei UI");small_font=make_font(12,FW_NORMAL,L"Microsoft YaHei UI");
    title_font=make_font(24,FW_SEMIBOLD,L"Microsoft YaHei UI");value_font=make_font(42,FW_SEMIBOLD,L"Segoe UI");
    bg_brush=CreateSolidBrush(bg);card_brush=CreateSolidBrush(card);
    WNDCLASSW c={.lpfnWndProc=window_proc,.hInstance=instance,.hIcon=LoadIconW(instance,MAKEINTRESOURCEW(1)),.hCursor=LoadCursorW(NULL,MAKEINTRESOURCEW(32512)),.hbrBackground=bg_brush,.lpszClassName=window_class};
    RegisterClassW(&c);DWORD style=WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX;RECT r={0,0,px(560),px(746)};AdjustWindowRect(&r,style,FALSE);
    HWND w=CreateWindowExW(0,window_class,L"克克咪 KOOK语音增强",style,CW_USEDEFAULT,CW_USEDEFAULT,r.right-r.left,r.bottom-r.top,NULL,NULL,instance,NULL);
    if(!w){CloseHandle(mutex);return 1;}ShowWindow(w,show);UpdateWindow(w);
    MSG msg;while(GetMessageW(&msg,NULL,0,0)>0){if(!IsDialogMessageW(w,&msg)){TranslateMessage(&msg);DispatchMessageW(&msg);}}
    DeleteObject(normal_font);DeleteObject(small_font);DeleteObject(title_font);DeleteObject(value_font);DeleteObject(bg_brush);DeleteObject(card_brush);CloseHandle(mutex);return 0;
}
