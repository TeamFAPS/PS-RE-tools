#ifndef TOOLS_H__
#define TOOLS_H__ 1
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

#include "types.h"
#include "aes.h"

void print_hash(u8 *ptr, u32 len);
void memcpy_to_file(const char *fname, u8 *ptr, u64 size);
void fail(const char *fmt, ...) __attribute__((noreturn));

void aes256cbc(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out);
void aes256cbc_enc(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out);
void aes128ctr(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out);
void aes128cbc(u8 *key, u8 *iv_in, u8 *in, u64 len, u8 *out);
void aes128cbc_enc(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out);
void aes128(u8 *key, const u8 *in, u8 *out);
void aes128_enc(u8 *key, const u8 *in, u8 *out);

#endif