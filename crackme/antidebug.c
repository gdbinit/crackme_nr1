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
 * antidebug.c
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

#include "antidebug.h"
//#define DEBUG 0

#define DISTANCE_TO_REAL_VERIFY_KEY 0x104E
#define SIZE_REAL_VERIFY_KEY 0x350

// this one can be used to detect gdb before we set our exception port
// if the port is different than 0, then someone is listening at the exception port
// usually this will be a debugger :-)
// another trick can also be played with masks - if masks are different , more than 1 port will exist
// one for EXC_MASK_ALL and one for our mask
// we can also try to get THREAD_STATE_NONE as flavor
void antidebug_check_mach_ports(void)
{
#if DEBUG
    printf("[DEBUG] Checking exception ports...\n");
#endif
    kern_return_t (*mytask_get_exception_ports)(task_t task,exception_mask_t exception_mask,exception_mask_array_t masks,mach_msg_type_number_t *masksCnt,
     exception_handler_array_t old_handlers,exception_behavior_array_t old_behaviors,exception_flavor_array_t old_flavors);
    volatile uint8_t taskgetexceptionportssymbol[] = {0x59,0x4c,0x5e,0x46,0x72,0x4a,0x48,0x59,0x72,0x48,0x55,0x4e,0x48,0x5d,0x59,0x44,0x42,0x43,0x72,0x5d,0x42,0x5f,0x59,0x5e,0x2d};
    DECRYPT_STRING(25,taskgetexceptionportssymbol,0x2d);
    mytask_get_exception_ports = DLSYM_GET(taskgetexceptionportssymbol);

    kern_return_t kr;
    struct macosx_exception_info
    {
        exception_mask_t masks[EXC_TYPES_COUNT];
        mach_port_t ports[EXC_TYPES_COUNT];
        exception_behavior_t behaviors[EXC_TYPES_COUNT];
        thread_state_flavor_t flavors[EXC_TYPES_COUNT];
        mach_msg_type_number_t count;
    };
    struct macosx_exception_info *info = malloc(sizeof(struct macosx_exception_info));
    kr = (*mytask_get_exception_ports)(mach_task_self(),
                                  EXC_MASK_ALL,
                                  info->masks, 
                                  &info->count, 
                                  info->ports, 
                                  info->behaviors, 
                                  info->flavors);

    for (uint32_t i = 0; i < info->count; i++)
    {
#if DEBUG
        printf("Mask: %x, Port %x\n", info->masks[i], info->ports[i]);
#endif
        if (info->ports[i] != 0 || info->flavors[i] == THREAD_STATE_NONE)
        {
#if DEBUG
            printf("[ANTI-DEBUG] Gdb detected via exception ports (null port)!\n");
#endif
            // do something nasty here
            uint32_t search;
            // decrypt next block 
            asm(".att_syntax prefix");
            asm __volatile__("call 1f\n\t" // E8 00 00 00 00
                             ".byte 0x21\n\t"
                             "1:\n\t"
                             "pop %%eax\n\t" // 58
                             "mov %%eax, %0" // 89 C3
                             : "=r" (search)
                             :
                             :"eax");
            asm(".att_syntax prefix");
            srandomdev();
            int32_t entropy = random();
            kern_return_t (*mymach_vm_protect)(vm_map_t target_task,mach_vm_address_t address,mach_vm_size_t size,boolean_t set_maximum,vm_prot_t new_protection);
            volatile uint8_t vmprotectsymbol[] = {0x2e,0x22,0x20,0x2b,0x1c,0x35,0x2e,0x1c,0x33,0x31,0x2c,0x37,0x26,0x20,0x37,0x43};
            DECRYPT_STRING(16, vmprotectsymbol, 0x43);
            mymach_vm_protect = DLSYM_GET(vmprotectsymbol);

            kern_return_t kr = (*mymach_vm_protect)(mach_task_self(), (mach_vm_address_t)search+DISTANCE_TO_REAL_VERIFY_KEY, (mach_vm_size_t)SIZE_REAL_VERIFY_KEY, FALSE,  WRITEPROTECTION);
#if DEBUG
            EXIT_ON_MACH_ERROR("antidebug", 1);
#endif
            uint32_t x = 0;
            for (; x < SIZE_REAL_VERIFY_KEY; x++)
            {
#if DEBUG
                printf("Overwrite %x\n", (search+DISTANCE_TO_REAL_VERIFY_KEY+x));
#endif
                *(uint8_t*)(search+DISTANCE_TO_REAL_VERIFY_KEY+x) ^= entropy;
            }
        }
    }
}

uint8_t	keyskipjack[10] = { 0x00,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11 };

void antidebug_check_gdb_breakpoint(uint32_t addr, uint32_t size)
{
    // we need to find _dyld_all_image_infos symbol from dyld
    // gdb insert a breakpoint here to get notified of images being added
    
    // find dyld vmaddr
    mach_port_t myself = mach_task_self();

#if __LP64__
    vm_address_t address = 0x00007fff5fc00000;
#else
    vm_address_t address = 0;
    uint8_t in[4] = { 0x7a, 0x53, 0x2a, 0xa6 };
    skip32(keyskipjack, in, 0);
    address = *(uint32_t*)in;
#endif
    kern_return_t kr = 0;


	vm_size_t lsize = 0;
	uint32_t depth = 1;
	mach_msg_type_number_t bytesRead = 0;
	vm_offset_t magicNumber = 0;
	vm_address_t dyldAddr = 0;
    
    kern_return_t (*myvm_region_recurse_64)(vm_map_t target_task,vm_address_t *address,vm_size_t *size,natural_t *nesting_depth,vm_region_recurse_info_t info,mach_msg_type_number_t *infoCnt);
    volatile uint8_t vmregionrecurse64symbol[] = {0x6f,0x74,0x46,0x6b,0x7c,0x7e,0x70,0x76,0x77,0x46,0x6b,0x7c,0x7a,0x6c,0x6b,0x6a,0x7c,0x46,0x2f,0x2d,0x19};
    DECRYPT_STRING(21, vmregionrecurse64symbol, 0x19);
    myvm_region_recurse_64 = DLSYM_GET(vmregionrecurse64symbol);

	while (1) 
	{
		struct vm_region_submap_info_64 info;
		mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
		kr = (*myvm_region_recurse_64)(myself, &address, &lsize, &depth, (vm_region_info_64_t)&info, &count);
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
			printf ("[DEBUG] check_gdb_breakpoint find_image Found region: %p to %p\n", (void*)address, (void*)address+lsize);
#endif
			// try to read first 4 bytes
            kern_return_t (*mymach_vm_read)(vm_map_t target_task,mach_vm_address_t address,mach_vm_size_t size,boolean_t set_maximum,vm_prot_t new_protection);
            volatile uint8_t machvmreadsymbol[] = {0x60,0x6c,0x6e,0x65,0x52,0x7b,0x60,0x52,0x7f,0x68,0x6c,0x69,0x0d};
            DECRYPT_STRING(13, machvmreadsymbol, 0xd);
            mymach_vm_read = DLSYM_GET(machvmreadsymbol);

			kr = (*mymach_vm_read)(myself, (mach_vm_address_t)address, (mach_vm_size_t)4, &magicNumber, &bytesRead);
			// avoid deferencing an invalid memory location (for example PAGEZERO segment)
			if (kr == KERN_SUCCESS & bytesRead == 4)
			{
				// verify if it's a mach-o binary at that memory location
				if (*(unsigned int*)magicNumber == MH_MAGIC ||
					*(unsigned int*)magicNumber == MH_MAGIC_64)
				{
#if DEBUG
					printf("[DEBUG] check_gdb_breakpoint find_image Found a valid mach-o image @ %p!\n", (void*)address);
#endif
					dyldAddr = address;
					break;
				}
			}
			address += lsize;
		}
	}
    // add the DYLD_ALL_IMAGE_INFOS_OFFSET_OFFSET to dyld's mach-header location
    vm_address_t dyldImageInfoOffset = 0;
    dyldImageInfoOffset = dyldAddr + DYLD_ALL_IMAGE_INFOS_OFFSET_OFFSET;
    // read the value at that address
    uint32_t dyldImageInfoLocation = *(uint32_t*)(dyldImageInfoOffset);
    // add the value to dyld vmaddr and the result is the address of dyld_all_image_infos
    dyldImageInfoLocation += dyldAddr;
    // now we can get a pointer to the structure and verify the notification field for breakpoints
    struct dyld_all_image_infos *dyldAllImageInfos = (struct dyld_all_image_infos*)dyldImageInfoLocation;
    
    volatile uint8_t xorKey = 0x56;
    // verify if there's a breakpoint in there...
    if ((*(uint8_t*)(dyldAllImageInfos->notification) ^ xorKey) == 0x9A) // 0xcc
    {
        // so what kind of nasty things can we do here???? :-)
        // maybe try to kill the debugger thread so program will crash?
        // or just crash it?
        // or trash the next function to be decrypted ;-)
        srandomdev();
        int32_t entropy = random();
        kern_return_t (*mymach_vm_protect)(vm_map_t target_task,mach_vm_address_t address,mach_vm_size_t size,boolean_t set_maximum,vm_prot_t new_protection);
        volatile uint8_t vmprotectsymbol[] = {0x0c,0x00,0x02,0x09,0x3e,0x17,0x0c,0x3e,0x11,0x13,0x0e,0x15,0x04,0x02,0x15,0x61};
        DECRYPT_STRING(16, vmprotectsymbol, 0x61);
        mymach_vm_protect = DLSYM_GET(vmprotectsymbol);
        
        kern_return_t kr = (*mymach_vm_protect)(mach_task_self(), (mach_vm_address_t)addr, (mach_vm_size_t)size, FALSE,  WRITEPROTECTION);
#if DEBUG
        EXIT_ON_MACH_ERROR("antidebug", 1);
#endif
        
        for (uint32_t x = 0; x < size; x++)
        {
            *(uint8_t*)(addr+x) ^= entropy;
        }

#if DEBUG
        printf("antidebug_check_gdb_breakpoint I AM DEBUGGED!\n");
#endif
    }
}

// verify the mach-header checksum
// this is for the LC_LOAD_DYLIB offset trick
// one way to overcome it is to copy the library name to the right place and fix the header
void antidebug_check_libtrick(void)
{
    // this symbol will always point to the start of the binary, ASLR included
    // ATTACK: we could redirect this symbol to a clean copy so hash will always match
    // we could try to obfuscate this symbol by retrieving it somewhere else and storing it before
    extern uint32_t _mh_execute_header;
    
    uint32_t nrCmds = 0;
    uint32_t sizeOfCmds = 0;
    
    // retrieve size and nr of commands
    if (_mh_execute_header == MH_MAGIC)
    {
        struct mach_header *machHeader = (struct mach_header*)&_mh_execute_header;
        nrCmds = machHeader->ncmds;
        sizeOfCmds = machHeader->sizeofcmds;
    }
    else if (_mh_execute_header == MH_MAGIC_64)
    {
        struct mach_header_64 *machHeader64 = (struct mach_header_64*)&_mh_execute_header;
        nrCmds = machHeader64->ncmds;
        sizeOfCmds = machHeader64->sizeofcmds;
    }
    
    // hash the header: size = sizeof(struct mach_header) + sizeOfCmds
    uint32_t totalSize = sizeof(struct mach_header) + sizeOfCmds;
    uint8_t *buffer = malloc(totalSize);
    memcpy(buffer, &_mh_execute_header, totalSize);
    uint8_t sum[32];
    memset(sum, 0, sizeof(sum));
    // retrieve the sha-512 hash of the header
    sha2(buffer, totalSize, sum, 0);

#if DEBUG
    int i;
    for( i = 0; i < 32; i++ )
        printf( "%02x", sum[i] );
    printf("\n");
#endif
    // but also check if our section isn't null
}
