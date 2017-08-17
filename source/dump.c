#include <nds.h>
#include <fat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>

void relocate(uint32_t addr, uint32_t len, uint32_t off, uint32_t a, uint32_t b)
{
	uint32_t *dat = (uint32_t*)addr;
	for(int j = 0; j < len/4; j++,dat++)
	{
		uint32_t v = *dat;
		if(a <= v && v < b)
			*dat = v + off;
	}
}

//---------------------------------------------------------------------------------
int main(int argc, char **argv) {
//---------------------------------------------------------------------------------
	uint32_t dldi_storage_addr = 0x02100000;
	uint32_t *dldi_storage =   (uint32_t*)dldi_storage_addr;
	// Initialise the console, required for printf
	consoleDemoInit();

	iprintf("Finding DLDI signature..");
	uint32_t *scan_start = (uint32_t*)0x02000000;
	uint32_t *scan_end =   (uint32_t*)0x02001000;

	int size = 0;

	for(uint32_t *scan = scan_start; scan < scan_end; scan++)
	{
		if(*scan == 0xBF8DA5ED)
		{
			iprintf("at %08lx\n", (uint32_t)scan);
			char *dldi_base = (char*)scan;

			iprintf("Card: %s\n", dldi_base + 16);

			int log2_size = *(dldi_base + 13);
			size = 1<<log2_size;
			iprintf("log2 size: %i (%i bytes)\n", log2_size, size);

			memcpy(dldi_storage, scan, size);

			uint32_t curr_addr = (uint32_t)dldi_base;
			uint32_t curr_end = curr_addr + size;
			uint32_t new_base = 0xBF800000;
			uint32_t reloc_off = new_base - curr_addr;

			iprintf("reloc_off: %08lx.\n", reloc_off);

			uint32_t section_starts[4];
			uint32_t section_ends[4];
			uint32_t section_sizes[4];

			uint32_t *section_table = dldi_storage + 0x10;

			for(int i = 0; i < 4; i++,section_table+=2)
			{
				section_starts[i] = (*section_table) - curr_addr + dldi_storage_addr;
				section_ends[i] = *(section_table + 1) - curr_addr + dldi_storage_addr;
				section_sizes[i] = section_ends[i] - section_starts[i];
				iprintf("Section %i %08lx=>%08lx (%08lx).\n", i, section_starts[i], section_ends[i], section_sizes[i]);
			}

			// Fix sections
			for(int i = 0; i < 8; i++)
			{
				*(dldi_storage + 0x10 + i) += reloc_off;
			}

			// Fix function pointers
			for(int i = 0; i < 6; i++)
			{
				*(dldi_storage + 0x1a + i) += reloc_off;
			}

			int sections = *(dldi_base + 14);
			iprintf("Sections %08x.\n", sections);

			if(sections & 1) // Data references.
			{
				iprintf("Relocating data %08lx=>%08lx.\n", section_starts[0], section_ends[0]);
				relocate(section_starts[0], section_sizes[0], reloc_off, curr_addr, curr_end);
			}

			if(sections & 2) // Glue references.
			{
				iprintf("Relocating glue %08lx=>%08lx\n", section_starts[1], section_ends[1]);
				relocate(section_starts[1], section_sizes[1], reloc_off, curr_addr, curr_end);
			}

			if(sections & 4) // GOT references.
			{
				iprintf("Relocating got %08lx=>%08lx\n", section_starts[2], section_ends[2]);
				relocate(section_starts[2], section_sizes[2], reloc_off, curr_addr, curr_end);
			}

			if(sections & 8) // clear BSS
			{
				memset((uint32_t*)section_starts[3], 0, section_sizes[3]);
			}

			break;
		}
	}

	if (fatInitDefault()) {
		iprintf("Writing...\n");
		FILE *f = fopen("dldi.bin", "wb");
		fwrite(dldi_storage, 1, size, f);
		fclose(f);
	} else {
		iprintf("fatInitDefault failure: terminating\n");
	}

	iprintf("Press START to exit..\n");
	while(1) {
		swiWaitForVBlank();
		scanKeys();
		if(keysDown()&KEY_START) break;
	}

	return 0;
}
