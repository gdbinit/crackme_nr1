/*
 *  ______                    __   
 * |      |.----.--.--.-----.|  |_ 
 * |   ---||   _|  |  |  _  ||   _|
 * |______||__| |___  |   __||____|
 *              |_____|__|         
 *  _______                    __   __                    
 * |    ___|.--.--.-----.----.|  |_|__|.-----.-----.-----.
 * |    ___||  |  |     |  __||   _|  ||  _  |     |__ --|
 * |___|    |_____|__|__|____||____|__||_____|__|__|_____|
 *
 * v0.1
 *
 * Encrypt a function (from symbol table) in a mach-o binary
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

#include "main.h"

#define VERSION "0.1"

/*
 * Required steps:
 * 1) read and calculate the size and location of our functions
 * 2) encrypt the selected function
 */

struct headerInfo headerInfo;
struct symbolsInfo *symbolsInfo = NULL;

int main (int argc, const char * argv[])
{
    printf("  ______                    __   \n");
    printf(" |      |.----.--.--.-----.|  |_ \n");
    printf(" |   ---||   _|  |  |  _  ||   _|\n");
    printf(" |______||__| |___  |   __||____|\n");
    printf("              |_____|__|         \n");
    printf("  _______                    __   __                    \n");
    printf(" |    ___|.--.--.-----.----.|  |_|__|.-----.-----.-----.\n");
    printf(" |    ___||  |  |     |  __||   _|  ||  _  |     |__ --|\n");
    printf(" |___|    |_____|__|__|____||____|__||_____|__|__|_____|\n");
    printf(" v%s\n", VERSION);
    printf(" (c) fG!, 2011. All rights reserved. - reverser@put.as\n");
    printf("--------------------------------------------------------\n");

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
    
    // verify if it's a valid mach-o binary
    verify_macho(targetBuffer);
    // 
    get_header_info(targetBuffer);
    
    //
    get_symbols_info(targetBuffer);
    
    // start encrypting
    for (uint32_t i = 0; i < headerInfo.nrFunctions; i++)
    {
        if (strcmp(symbolsInfo[i].name, argv[2]) == 0)
        {
            printf("Found target function to encrypt!\n");
            for (uint32_t x = 0; x < symbolsInfo[i].size; x++)
            {
                *(uint8_t*)(targetBuffer+symbolsInfo[i].offset+x) ^= 0x69;
            }
            printf("Original values %x %x\n", *(uint32_t*)(targetBuffer + headerInfo.tableLocation), *(uint32_t*)(targetBuffer + headerInfo.tableLocation+4));
            *(uint32_t*)(targetBuffer + headerInfo.tableLocation) = symbolsInfo[i].location;
            *(uint32_t*)(targetBuffer + headerInfo.tableLocation+4) = symbolsInfo[i].size;
            printf("Modified values %x %x\n", *(uint32_t*)(targetBuffer + headerInfo.tableLocation), *(uint32_t*)(targetBuffer + headerInfo.tableLocation+4));
        }
    }
    
    FILE *output = NULL;
    output = fopen("crap", "wb");
    fwrite(targetBuffer, fileSize, 1, output);
    fclose(output);
    free(symbolsInfo);
    free(targetBuffer);
    return 0;
}

// verify if it's a valid mach-o binary
__attribute__ ((aligned (512))) void verify_macho(uint8_t *targetBuffer)
{
    uint32_t magic = *(uint32_t*)(targetBuffer);
    printf("Magic %x\n", magic);
	if (magic == FAT_CIGAM ||   // fat binary
        magic == MH_MAGIC  ||   // non-fat 32bits
        magic == MH_MAGIC_64)   // non-fat 64bits
	{
        if (magic == FAT_CIGAM)
        {
            headerInfo.isFat = 1;
        }
	}
    else
    {
        printf("[ERROR] Not a valid mach-o binary!\n");
		exit(1);
    }
}

void get_header_info(uint8_t *targetBuffer)
{
    int32_t magic = *(uint32_t*)targetBuffer;
    uint8_t *address = NULL;
    uint8_t *symtabAdress = 0;
    uint32_t nrLoadCmds = 0;
    if (magic == MH_MAGIC)
    {
        struct mach_header *machHeader = (struct mach_header*)(targetBuffer);
        nrLoadCmds = machHeader->ncmds;
        
        headerInfo.is64bits = 0;
        // first load cmd address
        address = targetBuffer + sizeof(struct mach_header);
    }
    else if (magic == MH_MAGIC_64)
    {
        struct mach_header_64 *machHeader64 = (struct mach_header_64*)(targetBuffer);
        nrLoadCmds = machHeader64->ncmds;
        
        headerInfo.is64bits = 1;
        // first load cmd address
        address = targetBuffer + sizeof(struct mach_header_64);
    }   
    // find the last command offset
    struct load_command *loadCommand = NULL;
    struct symtab_command *symtabCommand = NULL;
    struct segment_command *segmentCommand = NULL;
    struct section *section = NULL;
    uint32_t i = 0;
    // initialize
    headerInfo.symtabCommand.cmd        = 0;
    headerInfo.symtabCommand.cmdsize    = 0;
    headerInfo.symtabCommand.nsyms      = 0;
    headerInfo.symtabCommand.stroff     = 0;
    headerInfo.symtabCommand.strsize    = 0;
    headerInfo.symtabCommand.symoff     = 0;
    headerInfo.textMax                  = 0;
    for (i = 0; i < nrLoadCmds; i++)
    {
        loadCommand = (struct load_command*)address;
        if (loadCommand->cmd == LC_SEGMENT)
        {
            segmentCommand = (struct segment_command *)(loadCommand);
            // add the total sections so we can calculate the index in LC_SYMTAB
            //                nSectIndexTemp+=segmentCommand->nsects;
            if (strcmp(segmentCommand->segname, "__TEXT") == 0)
            {
                printf("Found __TEXT segment!\n");
                headerInfo.textVMAddr = segmentCommand->vmaddr;
                section = (struct section *)((char*)segmentCommand + sizeof(struct segment_command));
                for (uint32_t x = 0; x < segmentCommand->nsects; x++)
                {
#if DEBUG
                    printf("Section name %s Segment Name %s\n", section->sectname, section->segname);
#endif
                    if (strcmp(section->sectname, "__text") == 0)
                    {
                        headerInfo.textMax = section->addr + section->size;
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
            memcpy(&headerInfo.symtabCommand, symtabCommand, sizeof(struct symtab_command));
            
        }
        // advance to next command
        address += loadCommand->cmdsize;
    }
}


void get_symbols_info(uint8_t *targetBuffer)
{
    // read the symbol table
    uint8_t *symbolsAddress = targetBuffer + headerInfo.symtabCommand.symoff;
    // the symbol table is an array of nlist type (array size is nsyms field of symtab_command structure)
    printf("Searching for symbols\n");
    struct nlist *nlist = NULL;
    nlist = (struct nlist *)(symbolsAddress);
    char * symbolString = NULL;
    // count
    uint32_t nrFunctions = 0;
    for (uint32_t x = 0; x < headerInfo.symtabCommand.nsyms; x++)
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
    headerInfo.nrFunctions = nrFunctions;
    printf("Total number of functions %d\n", nrFunctions);
    nlist = (struct nlist *)(symbolsAddress);
    uint32_t z = 0;
    symbolsInfo = malloc(sizeof(struct symbolsInfo)*nrFunctions);
    
    for (uint32_t x = 0; x < headerInfo.symtabCommand.nsyms; x++)
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
                    //                        printf("Type: N_SECT ");
                    symbolString = ((char*)targetBuffer + headerInfo.symtabCommand.stroff+nlist->n_un.n_strx);
                    // FIXME need to retrieve the indexes
                    if (nlist->n_sect == 1)
                    {
                        symbolsInfo[z].location = nlist->n_value;
                        symbolsInfo[z].name = malloc(strlen(symbolString)+1);
                        strcpy(symbolsInfo[z].name, symbolString);
                        symbolsInfo[z].size = 0;
                        symbolsInfo[z].offset = nlist->n_value - (uint32_t)headerInfo.textVMAddr;
                        z++;
                    }
                    else if (nlist->n_sect == 11)
                    {
                        
                        if (strcmp(((char*)targetBuffer + headerInfo.symtabCommand.stroff+nlist->n_un.n_strx), "_tabela") == 0)
                        {
                            headerInfo.tableLocation = nlist->n_value - (uint32_t)headerInfo.textVMAddr;
                            printf("Found table location %x!\n", headerInfo.tableLocation);
                        }
                    }
                    break;
            }
        }
        nlist++;
    }
    
    // sort
    size_t symbolsLength = (sizeof(struct symbolsInfo)*nrFunctions) / sizeof(struct symbolsInfo);
    qsort(symbolsInfo, symbolsLength, sizeof(struct symbolsInfo), struct_cmp);
    
    printf("Checking my sorted tables...\n");
    // compute size
    for (uint32_t x = 0; x < nrFunctions; x++)
    {
        symbolsInfo[x].size = symbolsInfo[x+1].location - symbolsInfo[x].location;
    }
    symbolsInfo[nrFunctions-1].size = headerInfo.textMax - symbolsInfo[nrFunctions-1].location;
    
    for (uint32_t x = 0; x < nrFunctions; x++)
    {
        printf("%s %x %x %x\n", symbolsInfo[x].name, symbolsInfo[x].location, symbolsInfo[x].size, symbolsInfo[x].offset);
    }
}


int struct_cmp(const void *a, const void *b)
{
    struct symbolsInfo *ia = (struct symbolsInfo*)a;
    struct symbolsInfo *ib = (struct symbolsInfo*)b;
    return (int)(ia->location - ib->location);
}
