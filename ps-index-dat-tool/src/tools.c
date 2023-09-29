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

void aes256cbc_dec(u8 *key, u8 *iv_in, u8 *in, u64 len, u8 *out) {
	void *tmp = malloc(len);
	memcpy(tmp, in, len);
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv_in, 256);
	AES_CBC_decrypt_buffer(&ctx, tmp, len);
	memcpy(out, tmp, len);
}

void aes256cbc_enc(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out) {
	void *tmp = malloc(len);
	memcpy(tmp, in, len);
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv, 256);
	AES_CBC_encrypt_buffer(&ctx, tmp, len);
	memcpy(out, tmp, len);
}

void aes128cbc_dec(u8 *key, u8 *iv_in, u8 *in, u64 len, u8 *out) {
	void *tmp = malloc(len);
	memcpy(tmp, in, len);
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv_in, 128);
	AES_CBC_decrypt_buffer(&ctx, tmp, len);
	memcpy(out, tmp, len);
}

void aes128cbc_enc(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out) {
	void *tmp = malloc(len);
	memcpy(tmp, in, len);
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv, 128);
	AES_CBC_encrypt_buffer(&ctx, tmp, len);
	memcpy(out, tmp, len);
}

void aes128ctr(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out) {
	void *tmp = malloc(len);
	memcpy(tmp, in, len);
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv, 128);
	AES_CTR_xcrypt_buffer(&ctx, tmp, len);
	memcpy(out, tmp, len);
}

void aes128_dec(u8 *key, const u8 *in, u8 *out) {
	void *tmp = malloc(16);
	memcpy(tmp, in, 16);
	struct AES_ctx ctx;
	AES_init_ctx(&ctx, key, 128);
	AES_ECB_decrypt(&ctx, tmp);
	memcpy(out, tmp, 16);
}

void aes128_enc(u8 *key, const u8 *in, u8 *out) {
	void *tmp = malloc(16);
	memcpy(tmp, in, 16);
	struct AES_ctx ctx;
	AES_init_ctx(&ctx, key, 128);
	AES_ECB_encrypt(&ctx, tmp);
	memcpy(out, tmp, 16);
}