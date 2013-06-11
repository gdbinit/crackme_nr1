/*
 *  ______ ______ _______ _______ _______ ______ _______ _______ ______ __
 * |   __ \   __ \       |_     _|    ___|      |_     _|       |   __ \  |
 * |    __/      <   -   | |   | |    ___|   ---| |   | |   -   |      <__|
 * |___|  |___|__|_______| |___| |_______|______| |___| |_______|___|__|__|
 *
 * Copyright (c) fG!, 2011, 2012, 2013. All rights reserved. - reverser@put.as - http://reverse.put.as
 *
 * injectfakelib.c
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

#include "injectfakelib.h"

// a few global variables we will need
uint8_t     is64bits;
uint32_t    nrFatArch;
uint32_t    nrLoadCmds;
uint32_t    sizeOfCmds;

const char libToInject[] = "/usr/lib/libncurses.dylib";

void inject_fakelib(uint8_t *targetBuffer, uint32_t fakeLibStringLocation)
{
    printf("[INFO] Starting the injection process...\n");
    int32_t magic = *(uint32_t*)targetBuffer;
    uint8_t *address = NULL;
    
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
    
    // 
    uint32_t firstSectionAddress = 0;
    uint32_t textfirstSectionAddress = 0;
    uint32_t cryptfirstSectionAddress = 0;
    
    // find the last command offset
    struct load_command *loadCommand = NULL;
    uint32_t i = 0;
    for (i = 0; i < nrLoadCmds; i++)
    {
        loadCommand = (struct load_command*)address;
        if (loadCommand->cmd == LC_SEGMENT)
        {
            struct segment_command *segmentCommand = (struct segment_command*)address;
            if (strcmp(segmentCommand->segname, "__TEXT") == 0)
            {
                // address of the first section
                uint8_t *sectionAddress = address + sizeof(struct segment_command);
                struct section *sectionCommand = NULL; 
                // iterate thru all sections
                uint32_t i = 0;
                for (i = 0; i < segmentCommand->nsects; i++)
                {
                    sectionCommand = (struct section*)(sectionAddress);
                    if (strcmp(sectionCommand->sectname, "__text") == 0)
                    {
                        // retrieve the offset for this section
                        textfirstSectionAddress = sectionCommand->offset;
#if MYDEBUG
                        printf("[DEBUG] __text section address %x\n", textfirstSectionAddress);
#endif
                    }
                    sectionAddress += sizeof(struct section);
                }
            }
        }
        // usually this segment is before the text
        else if (loadCommand->cmd == LC_ENCRYPTION_INFO)
        {
            struct encryption_info_command *segmentCommand = (struct encryption_info_command*)address;
            cryptfirstSectionAddress = segmentCommand->cryptoff;
#if MYDEBUG
            printf("[DEBUG] Crypt offset is %x\n", cryptfirstSectionAddress);
#endif
        }
#if PRIVATE
        else if (loadCommand->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *segmentCommand64 = (struct segment_command_64*)address;
            if (strcmp(segmentCommand64->segname, "__TEXT") == 0)
            {
                // address of the first section
                uint8_t *sectionAddress = address + sizeof(struct segment_command_64);
                struct section_64 *sectionCommand64 = NULL; 
                // iterate thru all sections
                uint32_t i = 0;
                for (i = 0; i < segmentCommand64->nsects; i++)
                {
                    sectionCommand64 = (struct section_64*)(sectionAddress);
                    if (strcmp(sectionCommand64->sectname, "__text") == 0)
                    {
                        // retrieve the offset for this section
                        textfirstSectionAddress = sectionCommand64->offset;
#if MYDEBUG
                        printf("[DEBUG] __text section address %x\n", textfirstSectionAddress);
#endif
                    }
                    sectionAddress += sizeof(struct section_64);
                }
            }
        }
#endif
        // advance to next command
        address += loadCommand->cmdsize;
    }
    
    // use the lowest one
    if (cryptfirstSectionAddress == 0 || cryptfirstSectionAddress > textfirstSectionAddress)
        firstSectionAddress = textfirstSectionAddress;
    else
        firstSectionAddress = cryptfirstSectionAddress;
    
    // calculate offset to start injection
    uint8_t *injectionStartOffset = 0;
    // address is positioned after all load commands
    injectionStartOffset = address;
    
    // verify is there is enough space available
    // this is the position in our buffer of the __text code!
    // the size for the new command to be injected
    uint32_t injectionSize = sizeof(struct dylib_command) + strlen(libToInject)+1;
    // must be a multiple of uint32_t
    uint32_t remainder = injectionSize % sizeof(uint32_t);
    if (remainder != 0)
        injectionSize += sizeof(uint32_t) - remainder;
            
    // build the command to be injected
    struct dylib_command injectionCommand;
    injectionCommand.cmd = LC_LOAD_DYLIB;
    injectionCommand.cmdsize = injectionSize;
    injectionCommand.dylib.timestamp = 0;
    injectionCommand.dylib.current_version = 0;
    injectionCommand.dylib.compatibility_version = 0;
    // the location of the string, don't forget that it's it distance from the start of the dylib_command
    injectionCommand.dylib.name.offset = (targetBuffer + fakeLibStringLocation) - injectionStartOffset;
    // copy the header
    memcpy(injectionStartOffset, &injectionCommand, sizeof(struct dylib_command));
    
    // modify the mach header
    if (is64bits)
    {
        struct mach_header_64 *tempHeader64 = (struct mach_header_64*)targetBuffer;
        tempHeader64->ncmds += 1;
        tempHeader64->sizeofcmds += injectionSize;
    }
    else
    {
        struct mach_header *tempHeader = (struct mach_header*)targetBuffer;
        tempHeader->ncmds += 1;
        tempHeader->sizeofcmds += injectionSize;            
    }

}
