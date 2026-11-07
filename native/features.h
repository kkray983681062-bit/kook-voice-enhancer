#ifndef KOOK_FEATURES_H
#define KOOK_FEATURES_H
#include <windows.h>
#include <stdint.h>
typedef struct {
    DWORD control_rva, encode_rva, start_rva, channels_offset;
    unsigned control_matches, encode_matches;
    DWORD upstream_encode_rva, upstream_rate_rva, upstream_encoder_offset, upstream_bitrate_offset;
} KFeatures;
int k_find_features(const unsigned char *image, size_t size, KFeatures *out);
int k_entry_matches_file(HMODULE module, DWORD rva);
#endif
