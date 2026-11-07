#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "features.h"
int wmain(int argc,wchar_t **argv) {
    if(argc<2)return 2;
    FILE *file=_wfopen(argv[1],L"rb");if(!file)return 3;
    fseek(file,0,SEEK_END);long length=ftell(file);fseek(file,0,SEEK_SET);
    unsigned char *raw=malloc((size_t)length);if(!raw){fclose(file);return 4;}
    if(fread(raw,1,(size_t)length,file)!=(size_t)length){fclose(file);free(raw);return 5;}fclose(file);
    IMAGE_DOS_HEADER *dos=(void *)raw;IMAGE_NT_HEADERS64 *nt=(void *)(raw+dos->e_lfanew);
    size_t size=nt->OptionalHeader.SizeOfImage;unsigned char *image=calloc(1,size);if(!image)return 6;
    memcpy(image,raw,nt->OptionalHeader.SizeOfHeaders);IMAGE_SECTION_HEADER *s=IMAGE_FIRST_SECTION(nt);
    for(WORD i=0;i<nt->FileHeader.NumberOfSections;i++) {
        if((size_t)s[i].VirtualAddress+s[i].SizeOfRawData>size || (size_t)s[i].PointerToRawData+s[i].SizeOfRawData>(size_t)length)return 7;
        memcpy(image+s[i].VirtualAddress,raw+s[i].PointerToRawData,s[i].SizeOfRawData);
    }
    KFeatures f;int ok=k_find_features(image,size,&f);
    printf("{\"matched\":%s,\"control\":%lu,\"encode\":%lu,\"start\":%lu,\"channels_offset\":%lu,\"control_matches\":%u,\"encode_matches\":%u}\n",
           ok?"true":"false",f.control_rva,f.encode_rva,f.start_rva,f.channels_offset,f.control_matches,f.encode_matches);
    printf("{\"upstream_encode\":%lu,\"upstream_rate\":%lu,\"encoder_offset\":%lu,\"bitrate_offset\":%lu}\n",
           f.upstream_encode_rva,f.upstream_rate_rva,f.upstream_encoder_offset,f.upstream_bitrate_offset);
    if(ok && argc>2) {
        const IMAGE_NT_HEADERS64 *loaded=(const void *)(image+dos->e_lfanew);
        IMAGE_DATA_DIRECTORY dd=loaded->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        RUNTIME_FUNCTION *ranges=(void *)(image+dd.VirtualAddress);size_t count=dd.Size/sizeof(*ranges);
        RUNTIME_FUNCTION ctl_range={0};size_t replace=0;
        for(size_t i=0;i<count;i++)if(ranges[i].BeginAddress==f.control_rva)ctl_range=ranges[i];
        while(replace<count&&(ranges[replace].BeginAddress==f.control_rva||ranges[replace].BeginAddress==f.encode_rva))replace++;
        if(replace==count)return 8;
        RUNTIME_FUNCTION saved=ranges[replace];ranges[replace]=ctl_range;KFeatures duplicate;
        int ambiguity_rejected=!k_find_features(image,size,&duplicate);ranges[replace]=saved;
        printf("{\"ambiguous_match_rejected\":%s}\n",ambiguity_rejected?"true":"false");if(!ambiguity_rejected)ok=0;
        const DWORD upstream[]={f.upstream_encode_rva,f.upstream_rate_rva};
        for(unsigned u=0;u<2;++u) {
            RUNTIME_FUNCTION selected={0};
            for(size_t i=0;i<count;++i)if(ranges[i].BeginAddress==upstream[u])selected=ranges[i];
            ranges[replace]=selected;KFeatures duplicate_upstream;
            int rejected=!k_find_features(image,size,&duplicate_upstream);ranges[replace]=saved;
            printf("{\"upstream_%s_ambiguity_rejected\":%s}\n",u?"rate":"encode",rejected?"true":"false");
            if(!rejected)ok=0;
        }
        for(size_t i=f.upstream_rate_rva;i+4<size && i<f.upstream_rate_rva+2048;++i) {
            uint32_t v;memcpy(&v,image+i,4);if(v==510000) {
                uint32_t changed=509999;memcpy(image+i,&changed,4);KFeatures negative_upstream;
                int rejected=!k_find_features(image,size,&negative_upstream);memcpy(image+i,&v,4);
                printf("{\"upstream_semantic_mismatch_rejected\":%s}\n",rejected?"true":"false");
                if(!rejected)ok=0;break;
            }
        }
        /* A semantic mismatch must be rejected; no fixed-address fallback. */
        for(size_t i=f.control_rva;i+4<size && i<f.control_rva+20000;++i) {
            uint32_t v;memcpy(&v,image+i,4);if(v==300000){v=299999;memcpy(image+i,&v,4);break;}
        }
        KFeatures negative;int rejected=!k_find_features(image,size,&negative);
        printf("{\"semantic_mismatch_rejected\":%s}\n",rejected?"true":"false");
        if(!rejected)ok=0;
    }
    free(image);free(raw);return ok?0:1;
}
