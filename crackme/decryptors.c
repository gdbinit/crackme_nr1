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
 * decryptors.c
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

#include "decryptors.h"

extern void install_debugger(void);

volatile char xpto[] = "/usr/lib/libncurses.dylib";

/*
 TODO:
 - obfuscate address to decrypt
 - obfuscate dlsym strings
 - decryption algorithm
 */
void decrypt_debugger_install(void)
{
#if DEBUG
    printf("-------------------------------------------------------------------\n");
    printf("[DEBUG] start decrypt_debugger_install\n");
#endif
    kern_return_t kr;
    
    kern_return_t (*mymach_vm_protect)(vm_map_t target_task,mach_vm_address_t address,mach_vm_size_t size,boolean_t set_maximum,vm_prot_t new_protection);
    EVIL_ASM1;
    uint32_t search;
    
    // we use this to find where to start searching the tail
    // it's the same trick call $+5 that is used in objective-c binaries
    asm __volatile__(
                     "call 1f\n\t"
                     "1:\n\t"
                      "pop %%ecx\n\t"
                      "mov %%ecx, %0"
                      : "=r" (search));
#if DEBUG
    printf("Search is %x\n", search);
#endif
    // grab the necessary information to decrypt the debugger installation
    uint32_t addr = 0;
    uint32_t protectSize = 0;
    uint8_t key[32];
    uint8_t iv[8];
    // the key is generated from the mach-o header checksum
    extern uint32_t _mh_execute_header;
    sha2((uint8_t*)&_mh_execute_header, sizeof(struct mach_header) + ((struct mach_header*)&_mh_execute_header)->sizeofcmds, key, 0);
    
    // build the salt array
    uint32_t salt[4];
    x86_debug_state32_t debug;
    mach_msg_type_number_t	count;
	thread_state_flavor_t flavor;
	flavor = x86_DEBUG_STATE32;
	count = x86_DEBUG_STATE32_COUNT;
    thread_act_port_array_t thread_list;
    mach_msg_type_number_t thread_count;
    kern_return_t (*mytask_threads)(task_t target_task,thread_act_array_t *act_list,mach_msg_type_number_t *act_listCnt);
    volatile uint8_t taskthreadssymbol[] = {0x2d,0x38,0x2a,0x32,0x06,0x2d,0x31,0x2b,0x3c,0x38,0x3d,0x2a,0x59};
    DECRYPT_STRING(13,taskthreadssymbol,0x59);
    mytask_threads = DLSYM_GET(taskthreadssymbol);
    
    (*mytask_threads)(mach_task_self(), &thread_list, &thread_count);

    kern_return_t (*mythread_get_state)(thread_act_t target_act,thread_state_flavor_t flavor,thread_state_t old_state,mach_msg_type_number_t *old_stateCnt);
    volatile uint8_t threadgetstatesymbol[] = {0x17,0x0b,0x11,0x06,0x02,0x07,0x3c,0x04,0x06,0x17,0x3c,0x10,0x17,0x02,0x17,0x06,0x63};
    DECRYPT_STRING(17,threadgetstatesymbol,0x63);
    mythread_get_state = DLSYM_GET(threadgetstatesymbol);

    kr = (*mythread_get_state)(thread_list[0], flavor, (thread_state_t)&debug, &count);
    salt[0] = debug.__dr0;
    salt[1] = debug.__dr1;
    salt[2] = debug.__dr2;
    salt[3] = debug.__dr3;
    
    uint8_t *tempKey = malloc(sizeof(salt) + sizeof(key));
    memcpy(tempKey, key, sizeof(key));
    memcpy(tempKey+sizeof(key), salt, sizeof(salt));
    // compute the final salted key
    sha2((uint8_t*)tempKey, sizeof(salt) + sizeof(key), key, 0);
    free(tempKey);

    // extract information at the tail of the function
    // address to decrypt
    // size ot decrypt
    // the IV
    EVIL_ASM4;
    for (uint32_t i = search+0x250; i < search+0x250+0x500; i++)
    {
        if ((*(uint32_t*)i & 0xffffff) == 0x31337)
        {
#if DEBUG
            printf("[DEBUG] Found decrypting info at %x %x %x %x!\n", i, *(uint32_t*)(i+4), *(uint32_t*)(i+8), *(uint32_t*)(i+12));
#endif
            addr = *(uint32_t*)(i+4);
            protectSize = *(uint32_t*)(i+8);
            memcpy(iv, (uint8_t*)(i+12), 8);
        }
    }
#if DEBUG
    printf("Header SHA256 checksum is:\n");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", key[i]);
    }
    printf("\n");
#endif
    // obfuscate address to decrypt - not used
    volatile uint64_t crapaddr = 0x1234567890123456;
    // mach_vm_protect
    volatile uint8_t machvmprotectsymbol[] = {0x4c,0x40,0x42,0x49,0x7e,0x57,0x4c,0x7e,0x51,0x53,0x4e,0x55,0x44,0x42,0x55,0x21};
    DECRYPT_STRING(16,machvmprotectsymbol,0x21);
    mymach_vm_protect = DLSYM_GET(machvmprotectsymbol);

    // modify memory protection so we can decrypt and write
#if DEBUG
    printf("[DEBUG] Starting to decrypt debugger install...\n");
#endif
    kr = (*mymach_vm_protect)(mach_task_self(), (mach_vm_address_t)addr, (mach_vm_size_t)protectSize, FALSE,  WRITEPROTECTION);
#if DEBUG
    EXIT_ON_MACH_ERROR("Failurex", 1);
#endif
    
    // start decryption, the input buffer is the same as the output buffer
    SALSA_ctx x;
    SALSA_keysetup(&x, key, 256, 64);
    SALSA_ivsetup(&x, iv);
    EVIL_ASM3;
    SALSA_decrypt_bytes(&x, (uint8_t*)addr, (uint8_t*)addr, protectSize);

    // restore original memory permissions
    kr = (*mymach_vm_protect)(mach_task_self(), (mach_vm_address_t)addr, (mach_vm_size_t)protectSize, FALSE,  READPROTECTION);
#if DEBUG
    EXIT_ON_MACH_ERROR("Failure", 1);
    printf("[DEBUG] End decrypt_debugger_install\n");
#endif
    // the tail that will hold our decryption data
    asm(".intel_syntax noprefix");
    asm __volatile__ ("xor edx, edx\n\t" //31d2
                      "test edx, edx\n\t" // 85d2
                      "jz 1f\n\t" // 7416
                      ".long 0x0064a990\n\t"
                      ".long 0x00031337\n\t"
                      ".long 0x00000000\n\t" // address
                      ".long 0x00000000\n\t" // size
                      ".long 0x00000000\n\t" // iv[8]
                      ".long 0x00000000\n\t"
                      "1:\n\t");
    asm(".att_syntax prefix");
    // that's it! :-)
}
