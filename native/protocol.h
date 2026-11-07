#ifndef KOOK_PROTOCOL_H
#define KOOK_PROTOCOL_H
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#define K_MAGIC 0x4b564532u
enum { K_INIT, K_READY, K_NO_AUDIO, K_AMBIGUOUS, K_UNSUPPORTED, K_WAIT_REJOIN, K_STOPPED, K_FAILURE };
enum { K_CMD_NONE, K_CMD_APPLY, K_CMD_RESTORE, K_CMD_PROFILE, K_CMD_RELEASE, K_CMD_STOP };
typedef struct {
    DWORD magic,version;
    volatile LONG status,command,sequence,acknowledged,applied;
    volatile LONG argument,keep,desired,holding,pending_channels;
    volatile LONG channels,sample_rate,bitrate,generation,original_bitrate,original_generation;
    volatile LONG error,feature_control,feature_encode,feature_channels_offset;
    volatile LONG upstream_bitrate,output_capacity,last_packet_bytes,packet_samples,original_upstream_bitrate;
    volatile LONG celt_bitrate;
    volatile LONG64 frames,encoding_errors,payload_bytes,last_frame;
} KShared;
typedef struct { DWORD magic;HANDLE mapping,parent; } KInit;
typedef DWORD (WINAPI *KInitFn)(KInit *);
#endif
