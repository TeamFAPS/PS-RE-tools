#include "tools.h"


void print_hash(u8 *ptr, u32 len) {
	while (len--)
		printf(" %02x", *ptr++);
}

void memcpy_to_file(const char *fname, u8 *ptr, u64 size) {
	FILE *fp = fopen(fname, "wb");
	fwrite(ptr, size, 1, fp);
	fclose(fp);
}

void fail(const char *a, ...) {
	char msg[1024];
	va_list va;
	va_start(va, a);
	vsnprintf(msg, sizeof msg, a, va);
	fprintf(stderr, "%s\n", msg);
	perror("perror");
	exit(1);
}

void aes256cbc(u8 *key, u8 *iv_in, u8 *in, u64 len, u8 *out) {
	aes_context ctx;
	assert(!aes_setkey_dec(&ctx, key, 256));
	aes_crypt_cbc(&ctx, AES_DECRYPT, len, iv_in, in, out);
}

void aes256cbc_enc(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out) {
	aes_context ctx;
	assert(!aes_setkey_enc(&ctx, key, 256));
	aes_crypt_cbc(&ctx, AES_ENCRYPT, len, iv, in, out);
}

void aes128cbc(u8 *key, u8 *iv_in, u8 *in, u64 len, u8 *out) {
	aes_context ctx;
	assert(!aes_setkey_dec(&ctx, key, 128));
	aes_crypt_cbc(&ctx, AES_DECRYPT, len, iv_in, in, out);
}

void aes128cbc_enc(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out) {
	aes_context ctx;
	assert(!aes_setkey_enc(&ctx, key, 128));
	aes_crypt_cbc(&ctx, AES_ENCRYPT, len, iv, in, out);
}

void aes128ctr(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out) {
	aes_context ctx;
	assert(!aes_setkey_enc(&ctx, key, 128));
	u8 ctr[16];
	memset(ctr, 0, 16);
	aes_crypt_ctr(&ctx, len, 0, ctr, iv, in, out);
}

void aes128(u8 *key, const u8 *in, u8 *out) {
	aes_context ctx;
	assert(!aes_setkey_dec(&ctx, key, 128));
	aes_crypt_ecb(&ctx, AES_DECRYPT, in, out);
}

void aes128_enc(u8 *key, const u8 *in, u8 *out) {
	aes_context ctx;
	assert(!aes_setkey_enc(&ctx, key, 128));
	aes_crypt_ecb(&ctx, AES_ENCRYPT, in, out);
}