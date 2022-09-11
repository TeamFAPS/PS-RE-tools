#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>


#define ARRAYSIZE(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))
#define SECTOR_SIZE 0x200
#define READ_SECTOR_SIZE 0x1000000

#if (defined(_WIN32) || defined(__WIN32__))
#define mkdir(A, B) mkdir(A)
#endif

typedef struct SceMbrV3PartEntry { // size is 0x11-bytes
	unsigned int start_lba;
	unsigned int n_sectors;
	unsigned char id;
	unsigned char type;
	unsigned char flag;
	unsigned short acl;
	unsigned int unused;
} __attribute__((packed)) SceMbrV3PartEntry;

typedef struct SceMbrV4PartEntry { // size is 0x14-bytes
	unsigned int start_lba;
	unsigned int n_sectors;
	unsigned char id;
	unsigned char flag;
	char unknown[10];
} __attribute__((packed)) SceMbrV4PartEntry;

typedef struct SceMbrV3Parts { // size is 0x110-bytes
	SceMbrV3PartEntry entries[0x10];
} __attribute__((packed)) SceMbrV3Parts;

typedef struct SceMbrV4Parts { // size is 0x110-bytes
	SceMbrV4PartEntry entries[0x10];
} __attribute__((packed)) SceMbrV4Parts;

typedef struct SceMbrHead { // size is 0x24-bytes
	char magic[0x20];
	unsigned int version;
} __attribute__((packed)) SceMbrHead;

typedef struct SceMbrV1 { // size is 0x200-bytes
	char magic[0x20];
	unsigned int version;
	unsigned int second_boot_record_0_lba; // guessed name
	unsigned int second_boot_record_1_lba; // guessed name
	unsigned int unk_1; // ex: 1
	unsigned int unk_2; // ex: 1
	unsigned int boot_record_info_lba; // ex: 8
	unsigned int unk_3; // ex: 1
	unsigned int unk_4;
	char unused[0x1C0];
} __attribute__((packed)) SceMbrV1;

typedef struct SceMbrV3 { // size is 0x200-bytes
	char magic[0x20];
	unsigned int version;
	unsigned int n_sectors;
	unsigned int second_boot_record_0_lba; // guessed name
	unsigned int second_boot_record_1_lba; // guessed name
	unsigned int loader_start;
	unsigned int loader_count;
	unsigned int current_bl_lba;
	unsigned int bl_bank0_lba;
	unsigned int bl_bank1_lba;
	unsigned int current_os_lba;
	char unused2[8];
	SceMbrV3Parts parts;
	char unused3[0x6E];
	char unused4[0x30];
	unsigned short signature;
} __attribute__((packed)) SceMbrV3;

typedef struct SceMbrV4 { // size is 0x200-bytes
	char magic[0x20];
	unsigned int version;
	unsigned int n_sectors;
	unsigned int second_boot_record_0_lba; // guessed name
	unsigned int second_boot_record_1_lba; // guessed name
	unsigned int data_lba;
	unsigned int unk_2; // ex: 1, 0x11A
	unsigned int unk_3; // ex: 8, 0
	unsigned int unk_4; // ex: 1, 0
	SceMbrV4Parts parts;
	char unused[0x80];
} __attribute__((packed)) SceMbrV4;

# define PLATFORM_PSP2 3
# define PLATFORM_PS4 4

const char *get_block_dev_by_part_id(int id, int platform) {
	static char *psp2_block_dev_list[] = {
		"empty",
		"idstor",
		"sloader",
		"os",
		"vsh",
		"vshdata",
		"vtrm",
		"user",
		"userext",
		"gamero",
		"gamerw",
		"updater",
		"sysdata",
		"mediaid",
		"pidata",
		"unused"
	};
	static char *ps4_block_dev_list[] = { // Not totally known yet
		"empty",
		"idata",
		"sam-ipl",
		"sam-secureos",
		"4",
		"5",
		"vtrm",
		"7",
		"8",
		"9",
		"10",
		"11",
		"12",
		"13",
		"14",
		"15",
		"0",
		"1",
		"2",
		"3",
		"4",
		"5",
		"6",
		"7",
		"8",
		"9",
		"10",
		"11",
		"12",
		"13",
		"14",
		"15",
		"emc",
		"eap",
		"nvs",
		"3",
		"4",
		"5",
		"wifi-fw-ps4",
		"bdhrl",
		"ffs",
		"wifi-fw",
		"10",
		"11",
		"12",
		"13",
		"14",
		"15",
	};
	if (platform == PLATFORM_PSP2)
		return psp2_block_dev_list[id];
	else if (platform == PLATFORM_PS4)
		return ps4_block_dev_list[id];
	return "default";
}

const char *get_fs_by_part_type(int type) {
	if (type == 6)
		return "FAT16";
	else if (type == 7)
		return "exFAT";
	else if (type == 0xDA)
		return "raw";
	return "unknown";
}

void unpack(char *filename, bool preserve_ram) {
	char dirname[256-sizeof("_active")];
	char outpath[256];
	FILE *in;
	if ((in = fopen(filename, "rb")) == NULL) {
		perror("open");
		return;
	}
	SceMbrHead mbr_head;
	fread(&mbr_head, 1, sizeof(mbr_head), in);
	int version = mbr_head.version;
	int slide = 0;
	if (version == 1) {
		SceMbrV1 mbr_v1;
		fseeko(in, 0, SEEK_SET);
		fread(&mbr_v1, 1, sizeof(mbr_v1), in);
		
		int platform = PLATFORM_PS4;
		SceMbrV4 mbr;
		slide = mbr_v1.second_boot_record_0_lba;
		fseeko(in, mbr_v1.second_boot_record_0_lba * SECTOR_SIZE, SEEK_SET);
		fread(&mbr, 1, sizeof(mbr), in);
		snprintf(dirname, 256, "%s_out", filename);
		mkdir(dirname, 0777);
		for (int part_idx = 0; part_idx < ARRAYSIZE(mbr.parts.entries); ++part_idx) {
			SceMbrV4PartEntry *p = &mbr.parts.entries[part_idx];
			printf("Partition idx %d, block_dev=%s, flag=%d, start_lba=0x%08x, n_sectors=0x%08x\n", part_idx, get_block_dev_by_part_id(p->id, platform), p->flag, p->start_lba, p->n_sectors);
			if (memcmp(get_block_dev_by_part_id(p->id, platform), "empty", 5) != 0){
				printf("Unpacking partition %s...\n", get_block_dev_by_part_id(p->id, platform));
				snprintf(outpath, 256, "%s/%s%s", dirname, get_block_dev_by_part_id(p->id, platform), p->flag == 0 ? "" : "_active");
				FILE *out;
				if ((out = fopen(outpath, "wb")) == NULL) {
					perror("open");
					return;
				}
				fseeko(in, (p->start_lba + slide) * SECTOR_SIZE, SEEK_SET);
				void *buffer;
				if (!preserve_ram) {
					unsigned int size = p->n_sectors * SECTOR_SIZE;
					buffer = malloc(size);
					fread(buffer, 1, size, in);
					fwrite(buffer, 1, size, out);
				} else {
					buffer = malloc(READ_SECTOR_SIZE + 0x1FF);
					void *buffer_aligned = (void *)((((uintptr_t)buffer) + 0x1FF) & ~0x1FF);
					unsigned int size = 0;
					for (unsigned int size_remain = p->n_sectors * SECTOR_SIZE; size_remain > 0; size_remain -= size) {
						size = size_remain >= READ_SECTOR_SIZE ? READ_SECTOR_SIZE : size_remain;
						fread(buffer_aligned, size, 1, in);
						fwrite(buffer_aligned, size, 1, out);
					}
				}
				fclose(out);
				free(buffer);
			}
		}
		slide = mbr_v1.second_boot_record_1_lba;
		fseeko(in, mbr_v1.second_boot_record_1_lba * SECTOR_SIZE, SEEK_SET);
		fread(&mbr, 1, sizeof(mbr), in);
		snprintf(dirname, 256, "%s_1_out", filename);
		mkdir(dirname, 0777);
		// TO REFACTOR
		for (int part_idx = 0; part_idx < ARRAYSIZE(mbr.parts.entries); ++part_idx) {
			SceMbrV4PartEntry *p = &mbr.parts.entries[part_idx];
			printf("Partition idx %d, block_dev=%s, flag=%d, start_lba=0x%08x, n_sectors=0x%08x\n", part_idx, get_block_dev_by_part_id(p->id, platform), p->flag, p->start_lba, p->n_sectors);
			if (memcmp(get_block_dev_by_part_id(p->id, platform), "empty", 5) != 0){
				printf("Unpacking partition %s...\n", get_block_dev_by_part_id(p->id, platform));
				snprintf(outpath, 256, "%s/%s%s", dirname, get_block_dev_by_part_id(p->id, platform), p->flag == 0 ? "" : "_active");
				FILE *out;
				if ((out = fopen(outpath, "wb")) == NULL) {
					perror("open");
					return;
				}
				fseeko(in, (p->start_lba + slide) * SECTOR_SIZE, SEEK_SET);
				void *buffer;
				if (!preserve_ram) {
					unsigned int size = p->n_sectors * SECTOR_SIZE;
					buffer = malloc(size);
					fread(buffer, 1, size, in);
					fwrite(buffer, 1, size, out);
				} else {
					buffer = malloc(READ_SECTOR_SIZE + 0x1FF);
					void *buffer_aligned = (void *)((((uintptr_t)buffer) + 0x1FF) & ~0x1FF);
					unsigned int size = 0;
					for (unsigned int size_remain = p->n_sectors * SECTOR_SIZE; size_remain > 0; size_remain -= size) {
						size = size_remain >= READ_SECTOR_SIZE ? READ_SECTOR_SIZE : size_remain;
						fread(buffer_aligned, size, 1, in);
						fwrite(buffer_aligned, size, 1, out);
					}
				}
				fclose(out);
				free(buffer);
			}
		}
	} else if (version == 3) {
		int platform = PLATFORM_PSP2;
		SceMbrV3 mbr;
		slide = 0;
		fseeko(in, 0, SEEK_SET);
		fread(&mbr, 1, sizeof(mbr), in);
		fseeko(in, 0, SEEK_END);
		off_t filesize = ftello(in);
		if (filesize == -1) {
			printf("Failed to ftello %s\n", filename);
			return;
		}
		if (filesize != mbr.n_sectors * SECTOR_SIZE) {
			perror("File size does not match Master Boot Record!");
			return;
		}
		snprintf(dirname, 256, "%s_out", filename);
		mkdir(dirname, 0777);
		for (int part_idx = 0; part_idx < ARRAYSIZE(mbr.parts.entries); ++part_idx) {
			SceMbrV3PartEntry *p = &mbr.parts.entries[part_idx];
			printf("Partition idx %d, block_dev=%s, fs=%s, flag=%d, start_lba=0x%08x, n_sectors=0x%08x, acl=0x%08x, unused=0x%08x\n", part_idx, get_block_dev_by_part_id(p->id, platform), get_fs_by_part_type(p->type), p->flag, p->start_lba, p->n_sectors, p->acl, p->unused);
			if (memcmp(get_block_dev_by_part_id(p->id, platform), "empty", 5) != 0){
				printf("Unpacking partition %s flag=%d start_lba 0x%08x n_sectors 0x%08x...\n", get_block_dev_by_part_id(p->id, platform), p->flag, p->start_lba, p->n_sectors);
				snprintf(outpath, 256, "%s/%s%s", dirname, get_block_dev_by_part_id(p->id, platform), p->flag == 0 ? "" : "_active");
				FILE *out;
				if ((out = fopen(outpath, "wb")) == NULL) {
					perror("open");
					return;
				}
				fseeko(in, (p->start_lba + slide) * SECTOR_SIZE, SEEK_SET);
				void *buffer;
				if (!preserve_ram) {
					unsigned int size = p->n_sectors * SECTOR_SIZE;
					buffer = malloc(size);
					fread(buffer, 1, size, in);
					fwrite(buffer, 1, size, out);
				} else {
					buffer = malloc(READ_SECTOR_SIZE + 0x1FF);
					void *buffer_aligned = (void *)((((uintptr_t)buffer) + 0x1FF) & ~0x1FF);
					unsigned int size = 0;
					for (unsigned int size_remain = p->n_sectors * SECTOR_SIZE; size_remain > 0; size_remain -= size) {
						size = size_remain >= READ_SECTOR_SIZE ? READ_SECTOR_SIZE : size_remain;
						fread(buffer_aligned, size, 1, in);
						fwrite(buffer_aligned, size, 1, out);
					}
				}
				fclose(out);
				free(buffer);
			}
		}
	}
	fclose(in);
}

int main (int argc, char *argv[]) {
	printf("Usage: ps-flash-extract [flash.bin]\n");
	if (argc > 1)
		unpack(argv[1], true);
	else
		unpack("flash.bin", true);
	return 0;
}