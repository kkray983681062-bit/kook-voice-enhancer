#define WIN32_LEAN_AND_MEAN
#include "features.h"
#include <stdlib.h>
#include <string.h>
#include "vendor/minhook/src/hde/hde64.h"

static int span(size_t size, size_t at, size_t count) {
    return at <= size && count <= size - at;
}
static int has32(const unsigned char *p, size_t n, uint32_t value) {
    for (size_t i=0; i+4<=n; ++i) {
        uint32_t found; memcpy(&found,p+i,4); if(found==value) return 1;
    }
    return 0;
}
static const IMAGE_NT_HEADERS64 *headers(const unsigned char *p, size_t n) {
    if(!span(n,0,sizeof(IMAGE_DOS_HEADER)))return NULL;
    const IMAGE_DOS_HEADER *dos=(const void *)p;
    if(dos->e_magic!=IMAGE_DOS_SIGNATURE || dos->e_lfanew<0 ||
       !span(n,(size_t)dos->e_lfanew,sizeof(IMAGE_NT_HEADERS64)))return NULL;
    const IMAGE_NT_HEADERS64 *nt=(const void *)(p+dos->e_lfanew);
    if(nt->Signature!=IMAGE_NT_SIGNATURE || nt->FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64 ||
       nt->OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
       nt->OptionalHeader.NumberOfRvaAndSizes<=IMAGE_DIRECTORY_ENTRY_EXCEPTION)return NULL;
    return nt;
}
static DWORD export_rva(const unsigned char *p,size_t n,const IMAGE_NT_HEADERS64 *nt,const char *wanted) {
    IMAGE_DATA_DIRECTORY dd=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if(!span(n,dd.VirtualAddress,sizeof(IMAGE_EXPORT_DIRECTORY)))return 0;
    const IMAGE_EXPORT_DIRECTORY *e=(const void *)(p+dd.VirtualAddress);
    if(!e->NumberOfNames || e->NumberOfNames>100000 || e->NumberOfFunctions>100000 ||
       !span(n,e->AddressOfNames,e->NumberOfNames*4ull) ||
       !span(n,e->AddressOfNameOrdinals,e->NumberOfNames*2ull) ||
       !span(n,e->AddressOfFunctions,e->NumberOfFunctions*4ull))return 0;
    const DWORD *names=(const void *)(p+e->AddressOfNames),*functions=(const void *)(p+e->AddressOfFunctions);
    const WORD *ordinals=(const void *)(p+e->AddressOfNameOrdinals);
    size_t len=strlen(wanted)+1;
    for(DWORD i=0;i<e->NumberOfNames;++i) {
        if(span(n,names[i],len) && !memcmp(p+names[i],wanted,len) && ordinals[i]<e->NumberOfFunctions) {
            DWORD r=functions[ordinals[i]];
            if(span(n,r,32) && !(r>=dd.VirtualAddress && r<dd.VirtualAddress+dd.Size))return r;
        }
    }
    return 0;
}
static int displacement(const hde64s *h) {
    if(h->flags&F_SIB || (h->modrm_mod!=1 && h->modrm_mod!=2))return -1;
    return h->modrm_mod==1?(int)(int8_t)h->disp.disp8:(int)h->disp.disp32;
}
static unsigned decode(const unsigned char *p,size_t available,hde64s *h) {
    /* The bundled HDE predates UD2 recognition; this two-byte trap has no operands. */
    if(available>=2 && p[0]==0x0f && p[1]==0x0b) {
        memset(h,0,sizeof(*h));h->len=2;h->opcode=0x0f;h->opcode2=0x0b;return 2;
    }
    return hde64_disasm(p,h);
}
static int has_call(const unsigned char *p,DWORD start,DWORD end,DWORD target) {
    /* Decode from a function boundary: an E8 byte inside an immediate is not a call. */
    for(DWORD at=start;at<end;) {
        hde64s h;unsigned step=decode(p+at,end-at,&h);
        if(!step || h.flags&F_ERROR || step>end-at)return 0;
        if(h.opcode==0xe8 && (int64_t)at+step+(int32_t)h.imm.imm32==target)return 1;
        at+=step;
    }
    return 0;
}
static DWORD caller(const unsigned char *p,size_t n,const RUNTIME_FUNCTION *ranges,size_t count,
                    DWORD target,unsigned maximum,uint32_t required) {
    DWORD found=0;unsigned matches=0;
    for(size_t f=0;f<count;++f) {
        DWORD a=ranges[f].BeginAddress,z=ranges[f].EndAddress;
        if(z<=a || z-a>maximum || !span(n,a,z-a) || (required&&!has32(p+a,z-a,required)))continue;
        /* Cheap direct-call prefilter before decoding thousands of unrelated functions. */
        int possible=0;
        for(DWORD at=a;at+5<=z;++at)if(p[at]==0xe8) {
            int32_t rel;memcpy(&rel,p+at+1,4);
            if((int64_t)at+5+rel==target){possible=1;break;}
        }
        if(possible && has_call(p,a,z,target)){found=a;matches++;}
    }
    return matches==1?found:0;
}
static int find_upstream(const unsigned char *p,size_t n,const RUNTIME_FUNCTION *ranges,size_t count,KFeatures *out) {
    DWORD encoder_wrapper=caller(p,n,ranges,count,out->encode_rva,1024,0);
    DWORD rate_wrapper=caller(p,n,ranges,count,out->control_rva,192,4002);
    if(!encoder_wrapper || !rate_wrapper)return 0;
    out->upstream_encode_rva=caller(p,n,ranges,count,encoder_wrapper,8192,32767);
    if(!out->upstream_encode_rva)return 0;
    unsigned matches=0;
    for(size_t f=0;f<count;++f) {
        DWORD a=ranges[f].BeginAddress,z=ranges[f].EndAddress;
        if(z<=a || z-a>2048 || !span(n,a,z-a) || !has32(p+a,z-a,510000) ||
           !has32(p+a,z-a,6000) || !has32(p+a,z-a,6001) || !has_call(p,a,z,rate_wrapper))continue;
        unsigned rate_offset=0,encoder_offset=0,last_rcx=0,loads=0,stores=0,calls=0;int valid=1;
        for(DWORD at=a;at<z;) {
            hde64s h;unsigned step=decode(p+at,z-at,&h);int d=displacement(&h);
            if(!step || h.flags&F_ERROR || step>z-at){valid=0;break;}
            unsigned reg=h.modrm_reg+(h.rex_r?8:0),base=h.modrm_rm+(h.rex_b?8:0);
            if(h.opcode==0x8b && !h.rex_w && base==1 && d>0 && d<2048) {
                if(!rate_offset){rate_offset=(unsigned)d;loads++;}
                else if(rate_offset!=(unsigned)d)valid=0;
            }
            if(h.opcode==0x89 && !h.rex_w && rate_offset && d==(int)rate_offset)stores++;
            if(h.opcode==0x8b && h.rex_w && reg==1 && d>0 && d<4096)last_rcx=(unsigned)d;
            if(h.opcode==0xe8) {
                if((int64_t)at+step+(int32_t)h.imm.imm32==rate_wrapper) {
                    if(!last_rcx || (encoder_offset&&encoder_offset!=last_rcx))valid=0;
                    encoder_offset=last_rcx;calls++;
                }
                last_rcx=0;
            }
            at+=step;
        }
        if(valid && loads==1 && stores && calls && encoder_offset && !(rate_offset%4) && !(encoder_offset%8)) {
            matches++;out->upstream_rate_rva=a;out->upstream_encoder_offset=encoder_offset;out->upstream_bitrate_offset=rate_offset;
        }
    }
    return matches==1;
}
int k_find_features(const unsigned char *p,size_t n,KFeatures *out) {
    memset(out,0,sizeof(*out));
    const IMAGE_NT_HEADERS64 *nt=headers(p,n);if(!nt)return 0;
    out->start_rva=export_rva(p,n,nt,"KL_StartPushAudioStream");
    if(!out->start_rva || !export_rva(p,n,nt,"KL_SetPushAudioBitratebps"))return 0;
    IMAGE_DATA_DIRECTORY dd=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if(!dd.Size || dd.Size%sizeof(RUNTIME_FUNCTION) || !span(n,dd.VirtualAddress,dd.Size))return 0;
    const RUNTIME_FUNCTION *ranges=(const void *)(p+dd.VirtualAddress);
    size_t count=dd.Size/sizeof(*ranges);
    for(size_t f=0;f<count;++f) {
        DWORD start=ranges[f].BeginAddress,end=ranges[f].EndAddress;
        if(end<=start || end-start<100 || end-start>20000 || !span(n,start,end-start))continue;
        const unsigned char *body=p+start;size_t length=end-start;
        int ctl=has32(body,length,300000) && has32(body,length,0xfffffc18u) &&
                has32(body,length,500) && (has32(body,length,0xfffff060u)||has32(body,length,4000));
        int enc=length>=200 && length<=4096 && has32(body,length,5000) && has32(body,length,5005);
        if(!ctl&&!enc)continue;
        unsigned clamps=0,offset=0;int pcm16=0;
        for(size_t at=0;at<length;) {
            hde64s h;unsigned step=hde64_disasm(body+at,&h);
            if(!step || h.flags&F_ERROR || !span(length,at,step))break;
            if(ctl && h.opcode==0x69 && h.modrm_mod!=3 && h.imm.imm32==300000 &&
               !(h.flags&F_SIB) && (h.modrm_mod==1||h.modrm_mod==2)) {
                int displacement=h.modrm_mod==1?(int)(int8_t)h.disp.disp8:(int)h.disp.disp32;
                if(displacement>0 && displacement<2048 && !(displacement%4)) { clamps++;offset=(unsigned)displacement; }
            }
            if(enc && h.opcode==0x0f && h.opcode2==0xbf && h.modrm_mod!=3)pcm16=1;
            at+=step;
        }
        if(ctl&&clamps==1) {out->control_matches++;out->control_rva=start;out->channels_offset=offset;}
        if(enc&&pcm16) {out->encode_matches++;out->encode_rva=start;}
    }
    return out->control_matches==1 && out->encode_matches==1 && out->control_rva!=out->encode_rva &&
           find_upstream(p,n,ranges,count,out);
}

int k_entry_matches_file(HMODULE module,DWORD rva) {
    wchar_t path[32768];if(!GetModuleFileNameW(module,path,32768))return 0;
    HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);
    if(file==INVALID_HANDLE_VALUE)return 0;
    HANDLE mapping=CreateFileMappingW(file,NULL,PAGE_READONLY,0,0,NULL);
    const unsigned char *p=mapping?MapViewOfFile(mapping,FILE_MAP_READ,0,0,0):NULL;
    LARGE_INTEGER length;int ok=0;
    if(p && GetFileSizeEx(file,&length)) {
        const IMAGE_NT_HEADERS64 *nt=headers(p,(size_t)length.QuadPart);
        if(nt) {
            const IMAGE_SECTION_HEADER *s=IMAGE_FIRST_SECTION(nt);
            for(WORD i=0;i<nt->FileHeader.NumberOfSections;++i) {
                if(rva>=s[i].VirtualAddress && rva-s[i].VirtualAddress+16<=s[i].SizeOfRawData) {
                    size_t at=s[i].PointerToRawData+(rva-s[i].VirtualAddress);
                    if(span((size_t)length.QuadPart,at,16))ok=!memcmp(p+at,(const unsigned char *)module+rva,16);
                    break;
                }
            }
        }
    }
    if(p)UnmapViewOfFile(p);if(mapping)CloseHandle(mapping);CloseHandle(file);return ok;
}
