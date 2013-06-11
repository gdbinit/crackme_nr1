/*
 *  ______ ______ _______ _______ _______ ______ _______ _______ ______ __
 * |   __ \   __ \       |_     _|    ___|      |_     _|       |   __ \  |
 * |    __/      <   -   | |   | |    ___|   ---| |   | |   -   |      <__|
 * |___|  |___|__|_______| |___| |_______|______| |___| |_______|___|__|__|
 *
 * Copyright (c) fG!, 2011, 2012, 2013. All rights reserved. - reverser@put.as - http://reverse.put.as
 *
 * mangleoffsets.c
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

#include "mangleoffsets.h"

extern struct headerInfo headerInfo;
extern struct symbolsInfo *symbolsInfo;

void mangle_offsets(uint8_t *targetBuffer)
{
    int32_t magic = *(uint32_t*)targetBuffer;
    uint8_t *address = NULL;
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
    uint32_t i = 0;
    for (i = 0; i < nrLoadCmds; i++)
    {
        loadCommand = (struct load_command*)address;
        switch (loadCommand->cmd)
        {
            case LC_SEGMENT:
            {
                struct segment_command *segmentCommand = (struct segment_command *)(loadCommand);
                // mangle segment names for __TEXT and __DATA
                struct section *section = (struct section *)((char*)segmentCommand + sizeof(struct segment_command));
                struct sectionInfo allsections[segmentCommand->nsects];
                // get sections information so we can shuffle them
                for (uint32_t x = 0; x < segmentCommand->nsects; x++)
                {
                    allsections[x].location = section;
                    memcpy(&allsections[x].section, section, sizeof(struct section));
                    section++;
                }
                // shuffle sections
                shuffle(allsections, segmentCommand->nsects);
                // sections are shuffled, so write them back to the buffer in shuffled order
                section = (struct section *)((char*)segmentCommand + sizeof(struct segment_command));
                for (uint32_t x = 0; x < segmentCommand->nsects; x++)
                {
                    memcpy(section, &allsections[x].section, sizeof(struct section));
                    section++;
                }
                
                section = (struct section *)((char*)segmentCommand + sizeof(struct segment_command));
                for (uint32_t x = 0; x < segmentCommand->nsects; x++)
                {
                    srandomdev();
                    int entropy = random();
                    entropy &= 0xffff;
                    // mess up the offset
                    if (strcmp(section->sectname, "__mod_init_func") != 0)
                    {
                        section->offset = section->offset+entropy;
                    }
                    if (strcmp(section->segname, "__TEXT") == 0 || strcmp(section->segname, "__DATA") == 0)
                    {
                        srandomdev();
                        entropy = random();
                        entropy &= 0xffff;
                        if (strcmp(section->sectname, "__mod_init_func") == 0)
                        {
                        }
                        else
                        {
                            // clean the flags
                            section->flags = 0x0;
                            // mess up the size - negative sizes will give trouble to IDA
                            section->size -= entropy;
                        }
                        memcpy(section->segname, "----------------", 16);
                        memcpy(section->sectname, "----------------", 16);
                    }
                    section++;
                }
                break;
            }
            case LC_SEGMENT_64:
                break;
        }
        // advance to next command
        address += loadCommand->cmdsize;
    }
}

// Fisher-Yates shuffle
// http://stackoverflow.com/questions/3343797/is-this-c-implementation-of-fisher-yates-shuffle-correct
static int rand_int(int n) {
    int limit = RAND_MAX - RAND_MAX % n;
    int rnd;
    
    do {
        rnd = rand();
    } while (rnd >= limit);
    return rnd % n;
}

void shuffle(struct sectionInfo *array, int n) {
    int i, j;
    struct sectionInfo tmp;
    
    for (i = n - 1; i > 0; i--) {
        j = rand_int(i + 1);
        tmp = array[j];
        array[j] = array[i];
        array[i] = tmp;
    }
}
