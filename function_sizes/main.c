/*
 *  _______                    __   __                _______ __              
 * |    ___|.--.--.-----.----.|  |_|__|.-----.-----. |     __|__|.-----.-----.
 * |    ___||  |  |     |  __||   _|  ||  _  |     | |__     |  ||-- __|  -__|
 * |___|    |_____|__|__|____||____|__||_____|__|__| |_______|__||_____|_____|
 *
 * v0.1
 *
 * Compute the function sizes inside a mach-o binary.
 *
 * *WARNING* values include the alignment space at the end of each function
 *
 * Copyright (c) fG!, 2011, 2012, 2013. All rights reserved. - reverser@put.as - http://reverse.put.as
 *
 * main.c
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/nlist.h>

#include <mach/machine.h>
#include <mach/ppc/thread_status.h>
#include <mach/i386/thread_status.h>

#define DEBUG 1

#define MALLOC_CHECK(variable) \
if (variable == NULL) { printf("[ERROR] Malloc failed! Exiting...\n"); exit(1); }

#define MALLOC(variable, size) \
variable = malloc(size); MALLOC_CHECK(variable);

// a few global variables we will need
uint8_t     is64bits;
uint32_t    nrFatArch;
uint32_t    nrLoadCmds;
uint32_t    sizeOfCmds;

struct symbolsinfo
{
    char *name;
    uint32_t size;
    uint32_t location;
};

int struct_cmp(const void *, const void *);

/*
 * Required steps:
 * 1) read mach-o header
 * 2) find LC_SYMTAB location
 * 3) read LC_SYMTAB information
 * 4) search and store the function info
 * 5) sort it
 * 6) calculate sizes of each
 */
int main (int argc, const char * argv[])
{
    FILE *in_file;
	
    in_file = fopen(argv[1], "r");
    if (!in_file)
    {
		printf("[ERROR] Could not open target file %s!\n", argv[1]);
        return(1);
    }
    if (fseek(in_file, 0, SEEK_END))
    {
		printf("[ERROR] Fseek failed at %s\n", argv[1]);
        return(1);
    }
    uint32_t fileSize;
    fileSize = ftell(in_file);

#if DEBUG
    printf("[DEBUG] filesize is %d\n", fileSize);
#endif
    if (fseek(in_file, 0, SEEK_SET))
    {
		printf("[ERROR] Fseek failed at %s\n", argv[1]);
        return(1);
    }
	uint8_t *targetBuffer;
    
	MALLOC(targetBuffer, fileSize);
    fread(targetBuffer, fileSize, 1, in_file);
	if (ferror(in_file))
	{
		printf("[ERROR] fread failed at %s\n", argv[1]);
		return(1);
	}
    fclose(in_file);

    uint8_t isFat = 0;
    uint32_t magic = *(uint32_t*)(targetBuffer);
    printf("Magic %x\n", magic);
	if (magic == FAT_CIGAM ||   // fat binary
        magic == MH_MAGIC  ||   // non-fat 32bits
        magic == MH_MAGIC_64)   // non-fat 64bits
	{
        if (magic == FAT_CIGAM)
        {
            isFat = 1;
        }
	}
    else
    {
        printf("[ERROR] Not a valid mach-o binary!\n");
		exit(1);
    }
    /*
     *  _______ _______ _______ 
     * |    ___|   _   |_     _|
     * |    ___|       | |   |  
     * |___|   |___|___| |___|  
     *
     */
    if (isFat)
    {        
        // end of fat
    }
    /*
     *  _______ _______ _______        _______ _______ _______ 
     * |    |  |       |    |  |______|    ___|   _   |_     _|
     * |       |   -   |       |______|    ___|       | |   |  
     * |__|____|_______|__|____|      |___|   |___|___| |___| 
     *
     */
    else
    {
        int32_t magic = *(uint32_t*)targetBuffer;
        uint8_t *address = NULL;
        uint8_t *symtabAdress = 0;
        
        if (magic == MH_MAGIC)
        {
            struct mach_header *machHeader = (struct mach_header*)(targetBuffer);
            nrLoadCmds = machHeader->ncmds;
            
            is64bits = 0;
            // first load cmd address
            address = targetBuffer + sizeof(struct mach_header);
        }
        else if (magic == MH_MAGIC_64)
        {
            struct mach_header_64 *machHeader64 = (struct mach_header_64*)(targetBuffer);
            nrLoadCmds = machHeader64->ncmds;
            
            is64bits = 1;
            // first load cmd address
            address = targetBuffer + sizeof(struct mach_header_64);
        }   
        // find the last command offset
        struct load_command *loadCommand = NULL;
        struct symtab_command *symtabCommand = NULL;
        struct segment_command *segmentCommand = NULL;
        struct section *section = NULL;
        uint32_t i = 0;
        uint32_t textMax = 0;
        for (i = 0; i < nrLoadCmds; i++)
        {
            loadCommand = (struct load_command*)address;
            if (loadCommand->cmd == LC_SEGMENT)
            {
                segmentCommand = (struct segment_command *)(loadCommand);
                // add the total sections so we can calculate the index in LC_SYMTAB
                if (strcmp(segmentCommand->segname, "__TEXT") == 0)
                {
                    printf("Found __TEXT segment!\n");

                    section = (struct section *)((char*)segmentCommand + sizeof(struct segment_command));
                    for (uint32_t x = 0; x < segmentCommand->nsects; x++)
                    {
#if DEBUG
                        printf("Section name %s Segment Name %s\n", section->sectname, section->segname);
#endif
                        if (strcmp(section->sectname, "__text") == 0)
                        {
                            textMax = section->addr + section->size;
                            break;
                        }
                        section++;
                    }
                }

            }
            else if (loadCommand->cmd == LC_SYMTAB)
            {
                symtabCommand = (struct symtab_command*)(address);
                symtabAdress = address;
#if DEBUG
                printf("[DEBUG] Found LC_SYMTAB command!\n");
                printf("Symbol offset %x Number of symbols %d\n", symtabCommand->symoff, symtabCommand->nsyms);
                printf("String offset %x String size %d\n", symtabCommand->stroff, symtabCommand->strsize);
#endif
            }
            // advance to next command
            address += loadCommand->cmdsize;
        }
        
        // read the symbol table
        uint8_t *symbolsAddress = targetBuffer + symtabCommand->symoff;
        // the symbol table is an array of nlist type (array size is nsyms field of symtab_command structure)
        printf("Searching for symbols\n");
        struct nlist *nlist = NULL;
        nlist = (struct nlist *)(symbolsAddress);
        char * symbolString = NULL;
        // count
        uint32_t nrFunctions = 0;
        for (uint32_t x = 0; x < symtabCommand->nsyms; x++)
        {
            if (nlist->n_type & N_STAB)
            {
                //printf("Type: N_STAB ");
            }
            else
            {
                switch (nlist->n_type & N_TYPE)
                {
                    case N_SECT:
                        if (nlist->n_sect == 1)
                        {
                            nrFunctions++;
                        }
                        break;
                }
            }
            nlist++;
        }
        printf("Total number of functions %d\n", nrFunctions);
        nlist = (struct nlist *)(symbolsAddress);
        uint32_t z = 0;
        struct symbolsinfo symbolsInfo[nrFunctions];
        for (uint32_t x = 0; x < symtabCommand->nsyms; x++)
        {
            if (nlist->n_type & N_STAB)
            {
                //printf("Type: N_STAB ");
            }
            else
            {
                switch (nlist->n_type & N_TYPE)
                {
                    case N_SECT:
                        symbolString = ((char*)targetBuffer + symtabCommand->stroff+nlist->n_un.n_strx);
                        if (nlist->n_sect == 1)
                        {
                            printf("Type: N_SECT Symbol: %s Value %x\n", symbolString, nlist->n_value);
                            symbolsInfo[z].location = nlist->n_value;
                            symbolsInfo[z].name = malloc(strlen(symbolString)+1);
                            strcpy(symbolsInfo[z].name, symbolString);
                            symbolsInfo[z].size = 0;
                            z++;
                        }
                        break;
                }
            }
            nlist++;
        }
        
        // sort
        size_t symbolsLength = sizeof(symbolsInfo) / sizeof(struct symbolsinfo);
        qsort(symbolsInfo, symbolsLength, sizeof(struct symbolsinfo), struct_cmp);
        
        printf("Checking my sorted tables...\n");
        // compute size
        for (uint32_t x = 0; x < nrFunctions; x++)
        {
            symbolsInfo[x].size = symbolsInfo[x+1].location - symbolsInfo[x].location;
        }
        symbolsInfo[nrFunctions-1].size = textMax - symbolsInfo[nrFunctions-1].location;
        
        for (uint32_t x = 0; x < nrFunctions; x++)
        {
            printf("%s %x %d\n", symbolsInfo[x].name, symbolsInfo[x].location, symbolsInfo[x].size);
        }

        // end of non-fat
    }
    free(targetBuffer);
    return(0);
}

int struct_cmp(const void *a, const void *b)
{
    struct symbolsinfo *ia = (struct symbolsinfo*)a;
    struct symbolsinfo *ib = (struct symbolsinfo*)b;
    return (int)(ia->location - ib->location);
}
