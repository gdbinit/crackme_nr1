/*
 * _________                   ______                       _______ ________
 * __  ____/____________ _________  /________ ________      ____/ // /__<  /
 * _  /    __  ___/  __ `/  ___/_  //_/_  __ `__ \  _ \     _ _  _  __/_  /
 * / /___  _  /   / /_/ // /__ _  ,<  _  / / / / /  __/     /_  _  __/_  /
 * \____/  /_/    \__,_/ \___/ /_/|_| /_/ /_/ /_/\___/       /_//_/   /_/
 *
 * Crackme #1
 *
 * Copyright (c) fG!, 2011, 2012, 2013. All rights reserved. - reverser@put.as - http://reverse.put.as
 *
 * findsymbols.c
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

#include "findsymbols.h"

#define PROC32 0
#define PROC64 1

/* NOTES
 task_info TASK_DYLD_INFO to get dyld address ?
 
 */
uint8_t get_version(void)
{
    int mib[2];
    size_t len = 0;
    char *kernelVersion = NULL;
    uint8_t retValue = 0;

    mib[0] = CTL_KERN;
    mib[1] = KERN_OSRELEASE;
    sysctl(mib, 2, NULL, &len, NULL, 0);
    kernelVersion = malloc(len * sizeof(char));
    sysctl(mib, 2, kernelVersion, &len, NULL, 0);
    
    // return values: 0 is Snow Leopard, 1 is Lion
    if (strncmp(kernelVersion, "10.", 3) == 0)
        retValue = 0;
    else if (strncmp(kernelVersion, "11.", 3) == 0)
        retValue = 1;
    
    free(kernelVersion);
    return retValue;
}


uint64_t get_dyldbase(void)
{
    
    uint64_t imageAddress   = 0;
    uint64_t imageSize      = 0;
    uint64_t startAddr  = 0;
    uint64_t dyldAddress    = 0;
    uint8_t kernelVersion   = 0;
    
    kernelVersion = get_version();

    mach_port_t myself = mach_task_self();
    // retrieve if process is 32 or 64bits
    // in this case we could just use the __LP64__ define
    // because code will be compiled for the correct version
    uint8_t processCpu = find_processcpu2();
    
    // the first attempt used the following article and fixed offsets
    // http://www.0xcafebabe.it/2011/10/15/on-macos-10-7-dyld-randomization/
    // the problem is that code compiled in Snow Leopard and executed on Lion fails the fixed offsets
    // our code will not be ASLR enabled while dyld is, so the computations would fail
    // the improved method is to scan memory searching for dyld
    // to accomplish this, we are "abusing" of two properties
    // 1 - dyld is the first code loaded on the specified memory regions
    // 2 - the memory regions start address are stable, which is valid both for x86 and x64 in Lion
#if DEBUG
    printf("[DEBUG] Searching dyld base address for %s, %s cpu...\n", kernelVersion == 0 ? "Snow Leopard" : "Lion",
           processCpu == PROC32 ? "32bits" : "64bits");
#endif
    // to hide strings
    // base64 encode ?
    // then xor with header ?
    if (kernelVersion == 0)
    {
        if (processCpu == PROC32)
        {
            startAddr = 0x8fe00000;
            find_image(myself, &imageAddress, &imageSize, startAddr);
            if (imageAddress == 0)
            {
#if DEBUG
                printf("[ERROR] Failed to find dyld image address!\n");
#endif
                exit(1);
            }
            dyldAddress = imageAddress;
        }
        else
        {
            startAddr = 0x00007fff5fc00000;
            find_image(myself, &imageAddress, &imageSize, startAddr);
            if (imageAddress == 0)
            {
#if DEBUG
                printf("[ERROR] Failed to find dyld image address!\n");
#endif
                exit(1);
            }
            dyldAddress = imageAddress;            
        }
    }
    else if (kernelVersion == 1)
    {
        if (processCpu == PROC32)
        {
            startAddr = 0x8fe00000;
            find_image(myself, &imageAddress, &imageSize, startAddr);
            if (imageAddress == 0)
            {
#if DEBUG
                printf("[ERROR] Failed to find dyld image address!\n");
#endif
                exit(1);
            }
            dyldAddress = imageAddress;
        }
        // dyld first 32bits starts at 0x00007fff
        else
        {
            startAddr = 0x00007fff60000000;
            find_image(myself, &imageAddress, &imageSize, startAddr);
            if (imageAddress == 0)
            {
#if DEBUG
                printf("[ERROR] Failed to find dyld image address!\n");
#endif
                exit(1);
            }
            dyldAddress = imageAddress;
        }
    }
#if DEBUG
//    printf("[DEBUG] get_dyldbase dyld address is %p\n", (void*)dyldAddress);
#endif
    return (dyldAddress);
}

/*
 find the memory address where we have a first valid mach-o, starting at startAddr
 returns on addr and size parameters
 */
uint64_t find_image(mach_port_t targettask, uint64_t *addr, uint64_t *size, uint64_t startAddr)
{
	kern_return_t kr = 0;
	mach_vm_address_t address = startAddr;
	vm_size_t lsize = 0;
	uint32_t depth = 1;
	mach_msg_type_number_t bytesRead = 0;
	vm_offset_t magicNumber = 0;
    kern_return_t (*myvm_region_recurse_64)(vm_map_t target_task,vm_address_t *address,vm_size_t *size,natural_t *nesting_depth,vm_region_recurse_info_t info,mach_msg_type_number_t *infoCnt);
    volatile uint8_t vmregionrecurse64symbol[] = {0x6f,0x74,0x46,0x6b,0x7c,0x7e,0x70,0x76,0x77,0x46,0x6b,0x7c,0x7a,0x6c,0x6b,0x6a,0x7c,0x46,0x2f,0x2d,0x19};
    DECRYPT_STRING(21, vmregionrecurse64symbol, 0x19);
    myvm_region_recurse_64 = DLSYM_GET(vmregionrecurse64symbol);

	while (1) 
	{
		struct vm_region_submap_info_64 info;
		mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
		kr = (*myvm_region_recurse_64)(targettask, &address, &lsize, &depth, (vm_region_info_64_t)&info, &count);
		if (kr == KERN_INVALID_ADDRESS)
		{
			break;
		}
		if (info.is_submap)
		{
			depth++;
		}
		else 
		{
			//do stuff
#if DEBUG
//			printf ("[DEBUG] find_image Found region: %p to %p\n", (void*)address, (void*)address+lsize);
#endif
			// try to read first 4 bytes
            kern_return_t (*mymach_vm_read)(vm_map_t target_task,mach_vm_address_t address,mach_vm_size_t size,vm_offset_t *data,mach_msg_type_number_t *dataCnt);
            volatile uint8_t machvmreadsymbol[] = {0x60,0x6c,0x6e,0x65,0x52,0x7b,0x60,0x52,0x7f,0x68,0x6c,0x69,0x0d};
            DECRYPT_STRING(13, machvmreadsymbol, 0xd);
            mymach_vm_read = DLSYM_GET(machvmreadsymbol);

			kr = (*mymach_vm_read)(targettask, (mach_vm_address_t)address, (mach_vm_size_t)4, &magicNumber, &bytesRead);
			// avoid deferencing an invalid memory location (for example PAGEZERO segment)
			if (kr == KERN_SUCCESS & bytesRead == 4)
			{
				// verify if it's a mach-o binary at that memory location
                // we can also verify the type
				if (*(uint32_t*)magicNumber == MH_MAGIC ||
					*(uint32_t*)magicNumber == MH_MAGIC_64)
				{
#if DEBUG
//					printf("[DEBUG] find_image Found a valid mach-o image @ %p!\n", (void*)address);
#endif
					*addr = address;
					*size = lsize;
					break;
				}
			}
			address += lsize;
		}
	}
	return(0);
}

uint8_t find_processcpu(void)
{

    //    int proc_pidinfo(int pid, int flavor, uint64_t arg,  void *buffer, int buffersize);
    struct proc_bsdinfo processInfo;
    // PROC_PIDTBSDINFO, PROC_PIDTBSDINFO_SIZE - check sys/proc_info.h
    int pid = getpid();
    int err;
    err = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &processInfo, PROC_PIDTBSDINFO_SIZE);
    if (err != PROC_PIDTBSDINFO_SIZE)
    {
#if DEBUG
        printf("Error in proc_pidinfo!\n");
#endif
        exit(1);
    }

    if (processInfo.pbi_flags & PROC_FLAG_LP64)
        return PROC64;
    else
        return PROC32;
       
}

uint8_t find_processcpu2(void)
{
    if (sizeof(long) == 4)
        return 0;
    else if (sizeof(long) == 8)
        return 1;
}

mach_vm_address_t find_picbase(uint64_t dyldAddress)
{
    // we need to process the symbol table to find the address of __dyld_start_static_picbase symbol (contains the address of dyld_start)
    uint8_t processCpu = find_processcpu2();
    struct mach_header *machHeader              = NULL;
    struct mach_header_64 *machHeader64         = NULL;
    struct load_command *loadCommand            = NULL;
    struct segment_command *segmentCommand      = NULL;
    struct segment_command_64 *segmentCommand64 = NULL;
    struct symtab_command *symtabCommand        = NULL;
    
    
    uint32_t nrCmds = 0, fileType = 0, sizeOfCmds = 0, flags = 0;
    uint32_t symbolTableOffset = 0, symbolTableNrSymbols = 0, stringTableOffset = 0, stringTableSize = 0;
    uint64_t linkeditVmAddr = 0, linkeditOffset = 0;
    uint64_t textVmAddr = 0;

    uint64_t retValue = 0;
    
    if (processCpu == PROC32)
    {
        machHeader  = (struct mach_header *)(dyldAddress);
        nrCmds      = machHeader->ncmds;
        fileType    = machHeader->filetype;
        sizeOfCmds  = machHeader->sizeofcmds;
        flags       = machHeader->flags;
        loadCommand = (struct load_command *)((char*)machHeader + sizeof(struct mach_header));

    }
    else if (processCpu == PROC64)
    {
        machHeader64 = (struct mach_header_64 *)(dyldAddress);
        nrCmds = machHeader64->ncmds;
        fileType = machHeader64->filetype;
        sizeOfCmds = machHeader64->sizeofcmds;
        flags = machHeader64->flags;
        loadCommand = (struct load_command *)((char*)machHeader64 + sizeof(struct mach_header_64));
        
    }
    uint32_t i = 0, x = 0;
    uint32_t command = 0, commandSize = 0;

    for (i = 0; i < nrCmds; i++)
    {
        command = loadCommand->cmd;
        commandSize = loadCommand->cmdsize;
#if DEBUG
//        printf("Cmd %s CmdSize %d\n", print_command(command), commandSize);
#endif
        if (command == LC_SEGMENT)
        {
            segmentCommand = (struct segment_command *)(loadCommand);
            if (strcmp(segmentCommand->segname, "__LINKEDIT") == 0)
            {
                linkeditVmAddr = segmentCommand->vmaddr;
                linkeditOffset = segmentCommand->fileoff;
            }
            // retrieve the virtual memory address of the __TEXT segment
            // this will be used on ASLR computations
            else if (strcmp(segmentCommand->segname, "__TEXT") == 0)
            {
                textVmAddr = segmentCommand->vmaddr;
            }
        }
        else if (command == LC_SEGMENT_64)
        {
            segmentCommand64 = (struct segment_command_64 *)(loadCommand);
            if (strcmp(segmentCommand64->segname, "__LINKEDIT") == 0)
            {
                linkeditVmAddr = segmentCommand64->vmaddr;
                linkeditOffset = segmentCommand64->fileoff;
            }            
            // retrieve the virtual memory address of the __TEXT segment
            // this will be used on ASLR computations
            else if (strcmp(segmentCommand64->segname, "__TEXT") == 0)
            {
                textVmAddr = segmentCommand64->vmaddr;
            }
        }
        else if (command == LC_SYMTAB)
        {
#if DEBUG
            printf("[DEBUG] Found LC_SYMTAB!\n");
#endif
            symtabCommand        = (struct symtab_command *)(loadCommand);
            symbolTableOffset    = symtabCommand->symoff;
            symbolTableNrSymbols = symtabCommand->nsyms;
            stringTableOffset    = symtabCommand->stroff;
            stringTableSize      = symtabCommand->strsize;
        }
        loadCommand = (struct load_command*)((char*)loadCommand + commandSize);
    }
    // do some ASLR computations
    // we need to retrieve the ASLR'ed address of LINKEDIT
    // dyldAddress contains the ASLR'ed base address
    // so we can calculate the distance between the __TEXT and __LINKEDIT segments
    // present in the header and add this to the ASLR'ed address

    linkeditVmAddr = dyldAddress + (linkeditVmAddr - textVmAddr);
#if DEBUG
//    printf("[DEBUG] find_picbase ASLR'ed linkedit address is %p\n", (void*)linkeditVmAddr);
#endif
    struct nlist *nlist = NULL;
    struct nlist_64 *nlist64 = NULL;
    
    // 32bits
    if (processCpu == PROC32)
    {
#if DEBUG
        printf("[INFO] Searching for 32bits symbols...\n");
        printf("[INFO] Total nr of symbols %d symbol offset %x string offset %x\n", symbolTableNrSymbols, symbolTableOffset, stringTableOffset);
#endif
        nlist = (struct nlist *)(linkeditVmAddr+symbolTableOffset-linkeditOffset);
        char * symbolString = NULL;

        for (x = 0; x < symbolTableNrSymbols; x++)
        {
            symbolString = ((char*)linkeditVmAddr+(stringTableOffset-linkeditOffset)+nlist->n_un.n_strx);
#if DEBUG
//            printf("[DEBUG] find_picbase Symbol: %s\n", symbolString);
#endif
            if (strcmp(symbolString, "__dyld_start_static_picbase")==0)
            {
#if DEBUG
                printf("[INFO] Found __dyld_start_static_picbase symbol...\n");
                printf("[DEBUG] Symbol found %s %p %x!\n", symbolString, (void*)nlist->n_value, nlist->n_un.n_strx);
#endif
                retValue = nlist->n_value;
            }
            nlist++;
        }
    // 64 bits
    }
    else if (processCpu == PROC64)
    {
#if DEBUG
        printf("[INFO] Searching for 64bits symbols...\n");
        printf("[INFO] Total nr of symbols %d symbol offset %x string offset %x\n", symbolTableNrSymbols, symbolTableOffset, stringTableOffset);
#endif
        nlist64 = (struct nlist_64 *)(linkeditVmAddr+symbolTableOffset-linkeditOffset);
        char * symbolString;

        for (x = 0; x < symbolTableNrSymbols; x++)
        {
            symbolString = ((char*)linkeditVmAddr+(stringTableOffset-linkeditOffset)+nlist64->n_un.n_strx);
#if DEBUG
//            printf("[DEBUG] find_picbase Symbol: %s\n", symbolString);
#endif
            if (strcmp(symbolString, "__dyld_start_static")==0)
            {
#if DEBUG
                printf("[INFO] Found __dyld_start_static symbol...\n");
//                printf("[DEBUG] Symbol found %s %p %x!\n", symbolString, (void*)nlist64->n_value, nlist64->n_un.n_strx);
#endif
                retValue = nlist64->n_value;
            }
            nlist64++;
        }
    }
    // we need to fix the return value to the real ASLR'ed address - symbol is obviously non-ASLR'ed
    retValue = dyldAddress + (retValue - textVmAddr);
    // but we still don't have the address where the symbol is used. we are here:
    // __data:8FE42CA0 3C 10 E0 8F       __dyld_start_static_picbase dd offset loc_8FE0103C
    // so we need to read that address and return the value
#if __LP64__
    return *(mach_vm_address_t*)retValue;
#else
    return *(vm_address_t*)retValue;
#endif
}

mach_vm_address_t find_retaddress(mach_vm_address_t picBase)
{
    mach_vm_address_t retValue = 0;
// 64bits
//    +20  00007fff5fc0103c  4c8b059dc60300            movq        0x0003c69d(%rip),%r8          __dyld_start_static
//    +27  00007fff5fc01043  488d0ddeffffff            leaq        0xffffffde(%rip),%rcx
//    +34  00007fff5fc0104a  4c29c1                    subq        %r8,%rcx
//    +37  00007fff5fc0104d  e861030000                callq       dyldbootstrap::start(macho_header const*, int, char const**, long)
//    +42  00007fff5fc01052  4889ec                    movq        %rbp,%rsp
//    +45  00007fff5fc01055  4883c410                  addq        $0x10,%rsp
//    +49  00007fff5fc01059  48c7c500000000            movq        $0x00000000,%rbp
//    +56  00007fff5fc01060  ffe0                      jmp         *%rax
#if __LP64__
    char buffer[16];
    int x = 0;
    for (x = 0; x < 50; x++)
    {
        memcpy(&buffer, (uint64_t*)picBase, 16);
//        printf("First byte is %x\n", *(uint64_t*)buffer);
        
        Fnv32_t computedHash = 0;
        computedHash = fnv_32_buf(&buffer, 16, FNV1_32_INIT);
        if (computedHash == 0x34f6e9b0)
        {
#if DEBUG
            printf("[DEBUG] Found valid hash @ %p\n", (void*)(picBase+14));
#endif
            retValue = (picBase+14);
            break;
        }
        picBase++;
    }
    // 32 bits
    //__text:8FE0103C 5B                                pop     ebx <- where picbase points to
    //__text:8FE0103D 8B 83 64 1C 04 00                 mov     eax, ds:(__dyld_start_static_picbase - 8FE0103Ch)[ebx]
    //__text:8FE01043 29 C3                             sub     ebx, eax
    //__text:8FE01045 53                                push    ebx
    //__text:8FE01046 8D 5D 0C                          lea     ebx, [ebp+0Ch]
    //__text:8FE01049 53                                push    ebx
    //__text:8FE0104A 8B 5D 08                          mov     ebx, [ebp+8]
    //__text:8FE0104D 53                                push    ebx
    //__text:8FE0104E 8B 5D 04                          mov     ebx, [ebp+4]
    //__text:8FE01051 53                                push    ebx
    //__text:8FE01052 E8 4F 05 00 00                    call    __ZN13dyldbootstrap5startEPK12macho_headeriPPKcl ; dyldbootstrap::start(macho_header  const*,int,char  const**,long)
    //__text:8FE01057 89 EC                             mov     esp, ebp <- match start
    //__text:8FE01059 83 C4 08                          add     esp, 8
    //__text:8FE0105C BD 00 00 00 00                    mov     ebp, 0
    //__text:8FE01061 FF E0                             jmp     eax      <- match end
#else
    char buffer[12];
    int x = 0;
    for (x = 0; x < 50; x++)
    {
        memcpy(&buffer, (uint32_t*)picBase, 12);        
        Fnv32_t computedHash = 0;
        computedHash = fnv_32_buf(&buffer, 12, FNV1_32_INIT);
        if (computedHash == 0x703a9f8b)
        {
        #if DEBUG
//            printf("[DEBUG] Found valid hash @ %p\n", (void*)(picBase+10));
        #endif
            // beware of evil 64bits extension :X
            retValue = (uint32_t)(picBase+10);
            break;
        }
        picBase++;
    }
#endif
//    printf("Retvalue is %p\n", (void*)retValue);
    return retValue;    
}
