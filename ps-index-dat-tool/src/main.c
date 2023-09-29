#include "tools.h"


unsigned char index_dat_key_ps3[0x10] = {0x2B,0x7E,0x15,0x16,0x28,0xAE,0xD2,0xA6,0xAB,0xF7,0x15,0x88,0x09,0xCF,0x4F,0x3C};
unsigned char index_dat_key_psp2_old[0x20] = {0x06,0xCC,0x2E,0x8F,0xD4,0x08,0x05,0xA7,0x36,0xF1,0x7C,0xF2,0xC1,0x3D,0x58,0xA6,0xC8,0xCF,0x10,0x7E,0x9E,0x4A,0x66,0xAE,0x25,0xD3,0x9C,0xA2,0x1C,0x25,0x31,0xCC};
unsigned char index_dat_key_psp2_new[0x20] = {0x27,0x2A,0xE4,0x37,0x8C,0xB0,0x6B,0xF3,0xF6,0x58,0xF5,0x1C,0x77,0xAC,0xA2,0x76,0x9B,0xE8,0x7F,0xB1,0x9B,0xBF,0x3D,0x4D,0x6B,0x1B,0x0E,0xD2,0x26,0xE3,0x9C,0xC6};
unsigned char index_dat_key_ps4[0x20] = {0xEE,0xD5,0xA4,0xFF,0xE8,0xA3,0xC9,0x10,0xDC,0x1B,0xFD,0x6A,0xAF,0x13,0x82,0x25,0x0B,0x38,0x0D,0xBA,0xE5,0x04,0x5D,0x23,0x05,0x69,0x47,0x3F,0x46,0xB0,0x7B,0x1F};
unsigned char index_dat_iv_ps3[0x10] = {0x30,0x32,0xAD,0xFC,0xDE,0x09,0xCF,0xBF,0xF0,0xA3,0xB3,0x52,0x5B,0x09,0x7F,0xAF};
unsigned char index_dat_iv_psp2[0x10] = {0x37,0xFA,0x4E,0xD2,0xB6,0x61,0x8B,0x59,0xB3,0x4F,0x77,0x0F,0xBB,0x92,0x94,0x7B};
unsigned char index_dat_iv_ps4[0x10] = {0x3A,0xCB,0x38,0xC1,0xEC,0x12,0x11,0x9D,0x56,0x92,0x9F,0x49,0xF7,0x04,0x15,0xFF};
unsigned char* table[4] = {(unsigned char*)&index_dat_key_ps3, (unsigned char*)&index_dat_key_psp2_old, (unsigned char*)&index_dat_key_psp2_new, (unsigned char*)&index_dat_key_ps4};

int encdec_index_dat(int generation_mode, int key_rev, char* index_dat_path, char* version_txt_path) {
	int ret = 0;
	FILE *in = NULL;
	size_t len;
	u8 *enc;
	u8 *plain;
	u8 *digest;
	if (!generation_mode) {
		printf("Running in decryption mode with key rev %i\n", key_rev);
		in = fopen(index_dat_path, "rb");
		if (in == NULL)
			fail("Unable to open %s\n", index_dat_path);
		fseek(in, 0, SEEK_END);
		len = ftell(in);
		fseek(in, 0, SEEK_SET);
		if (len < 0x20)
			fail("Invalid index.dat size : 0x%X\n", len);
		enc = malloc(len);
		size_t tmp = fread(enc, 1, len, in);
		fclose(in);
		if (tmp != len)
			fail("Unable to read index.dat file\n");
		plain = malloc(len);
		digest = malloc(0x20);
		if (key_rev == 0) {
			aes128cbc_dec(table[key_rev], index_dat_iv_ps3, enc, len, plain);
			sha1(plain + 0x20, len - 0x20, digest);
			if (memcmp(plain, digest, 0x14) != 0) {
				printf("SHA-1 mismatch\n");
				ret = 1;
				goto hmm;
			}
		} else {
			aes256cbc_dec(table[key_rev], key_rev < 3 ? index_dat_iv_psp2 : index_dat_iv_ps4, enc, len, plain);
			sha2(plain + 0x20, len - 0x20, digest, 0);
			if (memcmp(plain, digest, 0x20) != 0) {
				printf("SHA-256 mismatch\n");
				ret = 1;
				goto hmm;
			}
		}
		memcpy_to_file(version_txt_path, plain + 0x20, len - 0x20);
	} else {
		printf("Running in generation mode with key rev %i\n", key_rev);
		size_t new_len;
		in = fopen(version_txt_path, "rb");
		if (in == NULL)
			fail("Unable to open %s\n", version_txt_path);
		fseek(in, 0, SEEK_END);
		len = ftell(in);
		fseek(in, 0, SEEK_SET);
		plain = malloc(len);
		if (fread(plain, 1, len, in) != len)
			fail("Unable to read version.txt file\n");
		fclose(in);
		new_len = len + 0x20;
		if (new_len % 0x10 != 0)
			new_len += 0x10 - (new_len % 0x10);
		enc = malloc(new_len);
		memset(enc, '\n', new_len);
		memset(enc, '0', 0x20);
		memcpy(enc + 0x20, plain, len);
		if (key_rev == 0) {
			sha1(enc + 0x20, new_len - 0x20, enc);
			aes128cbc_enc(table[key_rev], index_dat_iv_ps3, enc, new_len, enc);
		} else {
			sha2(enc + 0x20, new_len - 0x20, enc, 0);
			aes256cbc_enc(table[key_rev], key_rev < 3 ? index_dat_iv_psp2 : index_dat_iv_ps4, enc, new_len, enc);
		}
		memcpy_to_file(index_dat_path, enc, new_len);
	}
hmm:
	if (plain)
		free(plain);
	if (enc)
		free(enc);
	return ret;
}

int main (int argc, char *argv[]) {
	int generation_mode = 0;
	if (argc != 3 && argc != 5)
		fail("Usage: ps-index-dat-tool [-g key_rev] index.dat version.txt\n");
	if (argc == 5 && !strcmp(argv[1], "-g"))
		generation_mode = 1;
	if (generation_mode) {
		int key_rev = strtol(argv[2], &((char*){0}), 10);
		encdec_index_dat(generation_mode, key_rev, argv[3], argv[4]);
	} else {
		for (int key_rev = 0; key_rev < sizeof(table)/sizeof(unsigned char*); ++key_rev) {
			if (!encdec_index_dat(generation_mode, key_rev, argv[1], argv[2])) {
				printf("Successfully decrypted!\n");
				break;
			}
		}
	}
	return 0;
}