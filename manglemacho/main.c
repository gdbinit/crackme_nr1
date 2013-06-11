/*
 *    _____                        .__          
 *   /     \ _____    ____    ____ |  |   ____  
 *  /  \ /  \\__  \  /    \  / ___\|  | _/ __ \ 
 * /    Y    \/ __ \|   |  \/ /_/  >  |_\  ___/ 
 * \____|__  (____  /___|  /\___  /|____/\___  >
 *         \/     \/     \//_____/           \/ 
 *    _____                .__              ________   
 *   /     \ _____    ____ |  |__           \_____  \  
 *  /  \ /  \\__  \ _/ ___\|  |  \   ______  /   |   \ 
 * /    Y    \/ __ \\  \___|   Y  \ /_____/ /    |    \
 * \____|__  (____  /\___  >___|  /         \_______  /
 *         \/     \/     \/     \/                  \/ 
 *
 * v0.3
 *
 * A small PoC that mangles Mach-O headers.
 * Support only for 32bits binaries.
 * 64 and FAT archives support is trivial to add.
 *
 * Copyright (c) fG!, 2011, 2012, 2013. All rights reserved. - reverser@put.as - http://reverse.put.as
 *
 * Please refer to:
 * http://reverse.put.as/2012/02/02/anti-disassembly-obfuscation-1-apple-doesnt-follow-their-own-mach-o-specifications/
 *
 * Compile as: gcc -arch i386 -O2 -std=c99 -o manglemacho manglemacho.c
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
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>

#define VERSION "0.3"

#define MALLOC_CHECK(variable) \
if (variable == NULL) { printf("[ERROR] Malloc failed! Exiting...\n"); exit(1); }

#define MALLOC(variable, size) \
variable = malloc(size); MALLOC_CHECK(variable);

struct sectionInfo
{
    struct section *location;
    struct section section;
    struct section_64 section_64;
};

static uint32_t read_target(uint8_t **targetBuffer, const char *target);
static uint8_t write_buffer(const uint8_t *targetBuffer, const char *originalTarget, const uint32_t fileSize);
static void verify_macho(const uint8_t *targetBuffer);
static void mangle_offsets(uint8_t *targetBuffer, uint8_t mode);
static int rand_int(int n);
static void shuffle(struct sectionInfo *array, int n);

int main (int argc, const char * argv[])
{

    printf(" __  __                _       __  __         _        ___  \n");
    printf("|  \\/  |__ _ _ _  __ _| |___  |  \\/  |__ _ __| |_ ___ / _ \\ \n");
    printf("| |\\/| / _` | ' \\/ _` | / -_) | |\\/| / _` / _| ' \\___| (_) |\n");
    printf("|_|  |_\\__,_|_||_\\__, |_\\___| |_|  |_\\__,_\\__|_||_|   \\___/ \n");
    printf("                 |___/                                      \n");
    printf("[v%s]                        (c) fG!, 2012, reverser@put.as\n", VERSION);
    printf("------------------------------------------------------------\n");
        
    uint8_t *targetBuffer = NULL;
    uint32_t fileSize = 0;
    
    // read the target into a buffer
    fileSize = read_target(&targetBuffer, argv[1]);
    // verify if it's a valid mach-o binary
    verify_macho(targetBuffer);
    
    // mangle header
    if (argv[2]) mangle_offsets(targetBuffer, 1);
    else mangle_offsets(targetBuffer, 0);
        
    // write result
    if (write_buffer(targetBuffer, argv[1], fileSize))
    {
        free(targetBuffer);
        exit(1);
    }

    printf("All done, binary headers are mangled!\n");
    free(targetBuffer);
    return(0);
}

// write modified buffer to a file
static uint8_t write_buffer(const uint8_t *targetBuffer, const char *originalTarget, const uint32_t fileSize)
{
    FILE *output = NULL;
    char extension[] = ".patched";
    uint32_t outputNameSize = strlen(originalTarget) + strlen(extension) + 1;
    char *outputName = NULL;
    MALLOC(outputName,outputNameSize);
    strncpy(outputName, originalTarget, strlen(originalTarget)+1);
    strncat(outputName, extension, sizeof(extension));
    outputName[outputNameSize-1] = '\0';
    
    output = fopen(outputName, "wb");
    if (!output)
    {
        printf("[ERROR] Could not open file to write\n");
        return(1);
    }
    
    if (fwrite(targetBuffer, fileSize, 1, output) < 1)
    {
        printf("[ERROR] Write failed!\n");
        fclose(output);
        free(outputName);
        return(1);
    }
    
    free(outputName);
    fclose(output);
    return(0);
}

// read the target file into a buffer
static uint32_t read_target(uint8_t **targetBuffer, const char *target)
{
    FILE *in_file;
	
    in_file = fopen(target, "r");
    if (!in_file)
    {
		printf("[ERROR] Could not open target file %s!\n", target);
        exit(1);
    }
    if (fseek(in_file, 0, SEEK_END))
    {
		printf("[ERROR] Fseek failed at %s\n", target);
        exit(1);
    }

    uint32_t fileSize = ftell(in_file);
    
    if (fseek(in_file, 0, SEEK_SET))
    {
		printf("[ERROR] Fseek failed at %s\n", target);
        exit(1);
    }
    
	MALLOC(*targetBuffer, fileSize);
    fread(*targetBuffer, fileSize, 1, in_file);
	if (ferror(in_file))
	{
		printf("[ERROR] fread failed at %s\n", target);
        free(*targetBuffer);
		exit(1);
	}
    fclose(in_file);  
    return(fileSize);
}

// verify if it's a valid mach-o binary
static void verify_macho(const uint8_t *targetBuffer)
{
    uint32_t magic = *(uint32_t*)(targetBuffer);

	if (magic == FAT_CIGAM ||   // fat binary
        magic == MH_MAGIC  ||   // non-fat 32bits
        magic == MH_MAGIC_64)   // non-fat 64bits
	{
        if (magic == FAT_CIGAM)
        {
            printf("[ERROR] Target is a fat archive, not supported by this version :-)\n");
            exit(1);
        }
	}
    else
    {
        printf("[ERROR] Not a valid mach-o binary!\n");
		exit(1);
    }
}


static void mangle_offsets(uint8_t *targetBuffer, uint8_t mode)
{
    int32_t magic = *(uint32_t*)targetBuffer;
    uint8_t *address = NULL;
    uint32_t nrLoadCmds = 0;
    if (magic == MH_MAGIC)
    {
        struct mach_header *machHeader = (struct mach_header*)(targetBuffer);
        nrLoadCmds = machHeader->ncmds;        
        // first load cmd address
        address = targetBuffer + sizeof(struct mach_header);
    }
    else if (magic == MH_MAGIC_64)
    {
        struct mach_header_64 *machHeader64 = (struct mach_header_64*)(targetBuffer);
        nrLoadCmds = machHeader64->ncmds;
        // first load cmd address
        address = targetBuffer + sizeof(struct mach_header_64);
    }   
    // find the last command offset
    struct load_command *loadCommand = NULL;

    for (uint32_t i = 0; i < nrLoadCmds; i++)
    {
        loadCommand = (struct load_command*)address;
        switch (loadCommand->cmd)
        {
            case LC_SEGMENT:
            {
                struct segment_command *segmentCommand = (struct segment_command *)(loadCommand);
                // mangle segment names for __TEXT and __DATA
                struct section *section = (struct section *)((uint8_t*)segmentCommand + sizeof(struct segment_command));
                // array of structures to hold the header info
                struct sectionInfo allsections[segmentCommand->nsects];
                
                // get sections information so we can shuffle them
                for (uint32_t x = 0; x < segmentCommand->nsects; x++)
                {
                    allsections[x].location = section;
                    memcpy(&allsections[x].section, section, sizeof(struct section));
                    section++;
                }
                
                // shuffle sections order
                shuffle(allsections, segmentCommand->nsects);
                
                // sections are shuffled, so write them back to the buffer in shuffled order
                section = (struct section *)((uint8_t*)segmentCommand + sizeof(struct segment_command));
                for (uint32_t x = 0; x < segmentCommand->nsects; x++)
                {
                    memcpy(section, &allsections[x].section, sizeof(struct section));
                    section++;
                }
                // mangle the reordered
                int entropy = 0;
                srandomdev();
                section = (struct section *)((char*)segmentCommand + sizeof(struct segment_command));
                for (uint32_t x = 0; x < segmentCommand->nsects; x++)
                {
                    // mess up offsets, flags, size and names
                    if (strncmp(section->segname, "__TEXT", 16) == 0 || strncmp(section->segname, "__DATA", 16) == 0)
                    {
                        // section and segment name are char[16] in length but no guarantee of being null terminated!
                        if (strncmp(section->sectname, "__mod_init_func", 16) != 0)
                        {
                            if (mode)
                            {
                                section->addr       = 0;
                                section->size       = 0;
                                section->offset     = 0;
                                section->align      = 0;
                                section->reloff     = 0;
                                section->nreloc     = 0;
                                section->flags      = 0;
                                section->reserved1  = 0;
                                section->reserved2  = 0;
                            }
                            else
                            {
                                entropy = random();
                                entropy &= 0xffff;
                                // mess up the offsets
                                section->offset = section->offset+entropy;
                                // clean the flags
                                section->flags = 0x0;
                                // mess up the size - negative sizes will give trouble to IDA
                                entropy = random();
                                entropy &= 0xffff;
                                section->size -= entropy;
                            }
                        }
                        // clear the section and segment names
                        memcpy(section->segname, "----------------", 16);
                        memcpy(section->sectname, "----------------", 16);
                    }
                    section++;
                }
                break;
            }
                // TODO :-)
            case LC_SEGMENT_64:
                break;
        }
        // advance to next command
        address += loadCommand->cmdsize;
    }
}

// Fisher-Yates shuffle
static int rand_int(int n) 
{
    int limit = RAND_MAX - RAND_MAX % n;
    int rnd;
    
    do {
        rnd = rand();
    } while (rnd >= limit);
    return rnd % n;
}

static void shuffle(struct sectionInfo *array, int n) 
{
    int i, j;
    struct sectionInfo tmp;
    
    for (i = n - 1; i > 0; i--) 
    {
        j = rand_int(i + 1);
        tmp = array[j];
        array[j] = array[i];
        array[i] = tmp;
    }
}
