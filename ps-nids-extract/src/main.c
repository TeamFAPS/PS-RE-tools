// ps-nids-extract
// By @CelesteBlue123

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "elf.h"
#include "sce_module_info.h"


void getExports(Elf32_Addr ent_top, Elf32_Addr ent_btm, unsigned short modattribute, uint8_t *segment0, uint32_t vaddr, uint32_t seg0_sz) {
	Elf32_Addr i = ent_top;
	while (i < ent_btm) {
		SceLibEntryTable_20 *exp_table = (SceLibEntryTable_20 *)(segment0 + i);
		if (exp_table->nid_table - vaddr < seg0_sz && exp_table->libname - vaddr < seg0_sz) {
			char *libname = (char *)(segment0 + exp_table->libname - vaddr);
			uint32_t *nid_table = (uint32_t *)(segment0 + exp_table->nid_table - vaddr);
			if (exp_table->libname) {
				printf("      %s:\n", libname);
				printf("        kernel: %s\n", (exp_table->c.attribute & 0x4000 || !(modattribute & 0x7)) ? "false" : "true");
				printf("        nid: 0x%08X\n", exp_table->libname_nid);
				int j = 0;
				if (exp_table->c.nfunc > 0) {
					printf("        functions:\n");
					for (int k = 0; k < exp_table->c.nfunc; k++) {
						uint32_t nid = nid_table[j++];
						printf("          %s_%08X: 0x%08X\n", libname, nid, nid);
					}
				}
				if (exp_table->c.nvar > 0) {
					printf("        variables:\n");
					for (int k = 0; k < exp_table->c.nvar; k++) {
						uint32_t nid = nid_table[j++];
						printf("          %s_%08X: 0x%08X\n", libname, nid, nid);
					}
				}
				if (exp_table->c.ntls > 0) {
					printf("        tls-variables:\n");
					for (int k = 0; k < exp_table->c.ntls; k++) {
						uint32_t nid = nid_table[j++];
						printf("          %s_%08X: 0x%08X\n", libname, nid, nid);
					}
				}
			}
		}
		i += exp_table->c.size;
	 }
}

static void usage(char *argv[]) {
	printf("Usage: %s fw_ver file1.elf path/file2.elf... > db_lookup.yml\n", argv[0]);
}

int main(int argc, char **argv) {
	if (argc < 3) {
		usage(argv);
		return 1;
	}
	FILE *fin = NULL;
	printf("version: 2\n");
	printf("firmware: %s\n", argv[1]);
	printf("modules:\n");
	for (uint32_t i = 2; i < (uint32_t)argc; ++i) {
		fprintf(stderr, "Opening %s\n", argv[i]);
		fin = fopen(argv[i], "rb");
		if (!fin) {
			perror("Failed to open input file");
			goto error;
		}
		fseek(fin, 0, SEEK_END);
		size_t sz = ftell(fin);
		fseek(fin, 0, SEEK_SET);
		uint8_t *input = calloc(1, sz);	
		if (!input) {
			perror("Failed to allocate buffer for input file");
			goto error;
		}
		if (fread(input, sz, 1, fin) != 1) {
			static const char s[] = "Failed to read input file";
			if (feof(fin))
				fprintf(stderr, "%s: unexpected end of file\n", s);
			else
				perror(s);
			goto error;
		}
		fclose(fin);
		fin = NULL;
		// TODO: locate SceModuleInfo in a different way for old formats
		Elf32_Ehdr *ehdr = (Elf32_Ehdr *)(input);
		Elf32_Phdr *phdr = (Elf32_Phdr *)(input + ehdr->e_phoff);
		// TODO: add support of other SceModuleInfo versions
		SceModuleInfo_v6* module_info = (SceModuleInfo_v6 *)(input + phdr[0].p_offset + ehdr->e_entry);
		printf("  %s: # %s\n", module_info->c.modname, argv[i]);
		printf("    libraries:\n");
		getExports(module_info->ent_top, module_info->ent_btm, module_info->c.modattribute, input + phdr[0].p_offset, phdr[0].p_vaddr, phdr[0].p_memsz);
	}

error:
	if (fin)
		fclose(fin);
	exit(0);
	return 0;
}