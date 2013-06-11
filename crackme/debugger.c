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
 * debugger.c
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

#include "debugger.h"

//#define DEBUG 1

// exception handling
mach_port_t exception_port;
extern vm_offset_t originalopcode;

/*
 * install the debugger function
 * decrypts debug_loop()
 */
void install_debugger(void)
{
#if DEBUG
    printf("-------------------------------------------------------------------\n");
    printf("[DEBUG] install_debugger start\n");
#endif
	kern_return_t kr;
    mach_port_t myself = mach_task_self();
    // the header that will hold our decryption data
    asm(".intel_syntax noprefix");
    asm __volatile__ ("xor edx, edx\n\t"
                      "test edx, edx\n\t"       // 
                      "jz 1f\n\t"               //
                      ".long 0x0064a990\n\t"
                      ".long 0x00006969\n\t"
                      ".long 0x00000000\n\t"
                      ".long 0x00000000\n\t"
                      ".long 0x00000000\n\t"
                      "1:\n\t");
    asm(".att_syntax prefix");
    EVIL_ASM4;    
#if DEBUG
    printf("[DEBUG] Initializing the exception handler.\n");
#endif
    // FIXME:
    exception_mask_t mask = EXC_MASK_SOFTWARE | EXC_MASK_BREAKPOINT | EXC_MASK_ARITHMETIC;// | EXC_BAD_INSTRUCTION;
                                                                    //    exception_mask_t mask = EXC_MASK_ALL;
    // create a receive right in our task
    kern_return_t (*mymach_port_allocate)(ipc_space_t task,mach_port_right_t right,mach_port_name_t *name);
    volatile uint8_t machportallocatesymbol[] = {0x0f,0x03,0x01,0x0a,0x3d,0x12,0x0d,0x10,0x16,0x3d,0x03,0x0e,0x0e,0x0d,0x01,0x03,0x16,0x07,0x62};
    DECRYPT_STRING(19,machportallocatesymbol,0x62);
    mymach_port_allocate = DLSYM_GET(machportallocatesymbol);

    kern_return_t (*mymach_port_insert_right)(ipc_space_t task,mach_port_name_t name,mach_port_t poly,mach_msg_type_name_t polyPoly);
    volatile uint8_t machportinsertrightsymbol[] = {0x21,0x2d,0x2f,0x24,0x13,0x3c,0x23,0x3e,0x38,0x13,0x25,0x22,0x3f,0x29,0x3e,0x38,0x13,0x3e,0x25,0x2b,0x24,0x38,0x4c};
    DECRYPT_STRING(23,machportinsertrightsymbol,0x4c);
    mymach_port_insert_right = DLSYM_GET(machportinsertrightsymbol);
    JUNK_CODE2;
    kern_return_t (*mytask_set_exception_ports)(task_t task,exception_mask_t exception_mask,mach_port_t new_port,exception_behavior_t behavior,thread_state_flavor_t new_flavor);
    volatile uint8_t tasksetexceptionportssymbol[] = {0x59,0x4c,0x5e,0x46,0x72,0x5e,0x48,0x59,0x72,0x48,0x55,0x4e,0x48,0x5d,0x59,0x44,0x42,0x43,0x72,0x5d,0x42,0x5f,0x59,0x5e,0x2d};
    DECRYPT_STRING(25,tasksetexceptionportssymbol,0x2d);
    mytask_set_exception_ports = DLSYM_GET(tasksetexceptionportssymbol);
    
    EVIL_ASM2;
    kr = (*mymach_port_allocate)(myself, MACH_PORT_RIGHT_RECEIVE, &exception_port);
#if DEBUG
    EXIT_ON_MACH_ERROR("Failure", 1);
    printf("[DEBUG] Allocated exception port is %x\n", exception_port);
#endif
    // insert a send right: we will now have combined receive/send rights
    kr = (*mymach_port_insert_right)(myself, exception_port, exception_port, MACH_MSG_TYPE_MAKE_SEND);
#if DEBUG
    EXIT_ON_MACH_ERROR("Failure", 1);
#endif
	// add an exception port in our target
    kr = (*mytask_set_exception_ports)(myself, mask, exception_port, EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, i386_THREAD_STATE);
#if DEBUG
    EXIT_ON_MACH_ERROR("Failure", 1);    
    printf("[DEBUG] Creating exception handler thread.\n");
#endif
    // decrypt the debug_loop
    // find the decryption info
    // we use this to find where to start searching the tail
    // it's the same trick call $+5 that is used in objective-c binaries
    uint32_t search;
    asm(".att_syntax prefix");
    asm __volatile__(
                     "call 1f\n\t"
                     "1:\n\t"
                     "pop %%eax\n\t"
                     "mov %%eax, %0"
                     : "=r" (search)
                     :
                     :"eax");
    asm(".att_syntax prefix");

    uint8_t iv[8] = "fastcars";
    EVIL_ASM5;
    // extract information at the tail of the function
    // address to decrypt
    // size ot decrypt
    // function size
    mach_vm_address_t addr = 0;
    uint32_t protectSize = 0;
    uint32_t functionSize = 0;
    uint32_t functionBegin = 0;
    for (uint32_t i = search; i > 0x1000; i--)
    {
        if ((*(uint16_t*)i) == 0x6969)
        {
            addr = *(uint32_t*)(i+4);
            protectSize = *(uint32_t*)(i+8);
            functionSize = *(uint32_t*)(i+12);
#if DEBUG
            printf("[DEBUG] Found debug_loop decrypting info at %x . Address:%x Size:%x Function Size:%x!\n", i, *(uint32_t*)(i+4), *(uint16_t*)(i+8),*(uint16_t*)(i+10));
#endif
        }
        if ((*(uint16_t*)i) == 0xe589)
        {
            functionBegin = i - 1;
#if DEBUG
            printf("[DEBUG] Found install_debugger() beginning at %x\n", functionBegin);
#endif
            break;
        }
    }
    // build the key
    uint8_t key[32];

    sha2((uint8_t*)functionBegin, functionSize, key, 0);
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
    volatile uint8_t taskthreadssymbol[] = {0x20,0x35,0x27,0x3f,0x0b,0x20,0x3c,0x26,0x31,0x35,0x30,0x27,0x54};
    DECRYPT_STRING(13,taskthreadssymbol,0x54);
    mytask_threads = DLSYM_GET(taskthreadssymbol);
    (*mytask_threads)(mach_task_self(), &thread_list, &thread_count);
    EVIL_ASM1;
    kern_return_t (*mythread_get_state)(thread_act_t target_act,thread_state_flavor_t flavor,thread_state_t old_state,mach_msg_type_number_t *old_stateCnt);
    volatile uint8_t threadgetstatesymbol[] = {0x66,0x7a,0x60,0x77,0x73,0x76,0x4d,0x75,0x77,0x66,0x4d,0x61,0x66,0x73,0x66,0x77,0x12};
    DECRYPT_STRING(17,threadgetstatesymbol,0x12);
    mythread_get_state = DLSYM_GET(threadgetstatesymbol);

    kr = (*mythread_get_state)(thread_list[0], flavor, (thread_state_t)&debug, &count);
    salt[0] = debug.__dr0;
    salt[1] = debug.__dr1;
    salt[2] = debug.__dr2;
    salt[3] = debug.__dr3;
    JUNK_CODE1;
    uint8_t *tempKey = malloc(sizeof(salt) + sizeof(key));
    memcpy(tempKey, key, sizeof(key));
    memcpy(tempKey+sizeof(key), salt, sizeof(salt));
    // compute the final salted key
    sha2((uint8_t*)tempKey, sizeof(salt) + sizeof(key), key, 0);
    free(tempKey);
    // dump the sha hash
#if DEBUG
    printf("[DEBUG] Sha256 header checksum:\n");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", key[i]);
    }
    printf("\n");
#endif
    // and now we can finally decrypt
    // modify memory protection so we can decrypt and write
#if DEBUG
    printf("[DEBUG] Starting to decrypt debug_loop...\n");
#endif
    kern_return_t (*mymach_vm_protect)(vm_map_t target_task,mach_vm_address_t address,mach_vm_size_t size,boolean_t set_maximum,vm_prot_t new_protection);
    volatile uint8_t machvmprotectsymbol[] = {0x2c,0x20,0x22,0x29,0x1e,0x37,0x2c,0x1e,0x31,0x33,0x2e,0x35,0x24,0x22,0x35,0x41};
    DECRYPT_STRING(16,machvmprotectsymbol,0x41);
    mymach_vm_protect = DLSYM_GET(machvmprotectsymbol);

    int (*mypthread_create)(pthread_t * __restrict,const pthread_attr_t * __restrict,void *(*)(void *),void * __restrict);
    volatile uint8_t pthreadcreatesymbol[] = {0x67,0x63,0x7f,0x65,0x72,0x76,0x73,0x48,0x74,0x65,0x72,0x76,0x63,0x72,0x17};
    DECRYPT_STRING(15,pthreadcreatesymbol,0x17);
    mypthread_create = DLSYM_GET(pthreadcreatesymbol);

    int (*mypthread_detach)(pthread_t );
    volatile uint8_t pthreaddetachsymbol[] = {0x37,0x33,0x2f,0x35,0x22,0x26,0x23,0x18,0x23,0x22,0x33,0x26,0x24,0x2f,0x47};
    DECRYPT_STRING(15,pthreaddetachsymbol,0x47);
    mypthread_detach = DLSYM_GET(pthreaddetachsymbol);
    EVIL_ASM4;
    
    kr = (*mymach_vm_protect)(mach_task_self(), (mach_vm_address_t)addr, (mach_vm_size_t)protectSize, FALSE,  WRITEPROTECTION);
#if DEBUG
    EXIT_ON_MACH_ERROR("Failurex", 1);
#endif
    
    // start decryption, the input buffer is the same as the output buffer
    SALSA_ctx ctx;
    SALSA_keysetup(&ctx, key, 256, 64);
    SALSA_ivsetup(&ctx, iv);
    SALSA_decrypt_bytes(&ctx, (uint8_t*)addr, (uint8_t*)addr, protectSize);
    
    // restore original memory permissions
    kr = (*mymach_vm_protect)(mach_task_self(), (mach_vm_address_t)addr, (mach_vm_size_t)protectSize, FALSE,  READPROTECTION);
#if DEBUG
    EXIT_ON_MACH_ERROR("Failure", 1);
    printf("[DEBUG] End debug_loop decrypt\n");
    printf("[DEBUG] Starting debugger thread\n");     
#endif
    // start the debugger loop
    pthread_t exception_thread = NULL;
    if (((*mypthread_create)(&exception_thread, (pthread_attr_t *)0,(void *(*)(void *))debug_loop, (void *)0))) 
    {
#if DEBUG
        perror("pthread_create");
#endif
    }
    (*mypthread_detach)(exception_thread);

}

/*
 * the debug loop, we decrypt and encrypt the exception handler and the
 * function that deals with the exceptions
 */
void
debug_loop(void)
{
#if DEBUG
    printf("***************************\n");
    printf("[DEBUG] Started debug loop!\n");
    printf("***************************\n");
#endif
    JUNK_CODE1;
    uint32_t search;
    asm(".att_syntax prefix");
    asm __volatile__("nop\n\t"
                     "call 1f\n\t" // E8 00 00 00 00
                     "1:\n\t"
                     "pop %%eax\n\t" // 58
                     "mov %%eax, %0" // 89 C3
                     : "=r" (search)
                     :
                     :"eax");
    asm(".att_syntax prefix");
#if DEBUG
    printf("Search is %x %x\n", search, *(uint32_t*)(search+5));
#endif
    EVIL_ASM5;
    uint8_t iv[8] = "hackersz";
    mach_vm_address_t addr = 0;
    uint32_t protectSize = 0;
    uint32_t functionSize = 0;
    uint32_t functionBegin = 0;
    volatile uint16_t xorKey = 0x4569;
    for (uint32_t i = search; i < search + 0x2000; i++)
    {    
        if ((*(uint16_t*)i ^xorKey) == 0x745D) // 0x3134
        {
            addr = *(uint32_t*)(i+4);
            protectSize = *(uint32_t*)(i+8);
            functionSize = *(uint32_t*)(i+12);
#if DEBUG
            printf("[DEBUG] Found exception_handler decrypting info at %x . Address:%x Size:%x Function Size:%x!\n", i, *(uint32_t*)(i+4), *(uint32_t*)(i+8),*(uint32_t*)(i+12));
#endif
            break;
        }
    }
    xorKey = 0x1233;
    for (uint32_t i = search; i > 0x1000; i--)
    {
        if ((*(uint16_t*)i ^ xorKey) == 0xF7BA) // 0xe589
        {
            functionBegin = i - 1;
#if DEBUG
            printf("[DEBUG] Found debug_loop() beginning at %x\n", functionBegin);
#endif
            break;
        }
    }
    
    kern_return_t (*mymach_vm_protect)(vm_map_t target_task,mach_vm_address_t address,mach_vm_size_t size,boolean_t set_maximum,vm_prot_t new_protection);
    volatile uint8_t vmprotectsymbol[] = {0x2e,0x22,0x20,0x2b,0x1c,0x35,0x2e,0x1c,0x33,0x31,0x2c,0x37,0x26,0x20,0x37,0x43};
    DECRYPT_STRING(16, vmprotectsymbol, 0x43);
    mymach_vm_protect = DLSYM_GET(vmprotectsymbol);

    while (1)
	{
        // decrypt exception handler
        // build the key
        uint8_t key[32];
        EVIL_ASM3;
        sha2((uint8_t*)functionBegin, functionSize, key, 0);
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
        volatile uint8_t taskthreadssymbol[] = {0x20,0x35,0x27,0x3f,0x0b,0x20,0x3c,0x26,0x31,0x35,0x30,0x27,0x54};
        DECRYPT_STRING(13,taskthreadssymbol,0x54);
        mytask_threads = DLSYM_GET(taskthreadssymbol);
        (*mytask_threads)(mach_task_self(), &thread_list, &thread_count);
        
        kern_return_t (*mythread_get_state)(thread_act_t target_act,thread_state_flavor_t flavor,thread_state_t old_state,mach_msg_type_number_t *old_stateCnt);
        volatile uint8_t threadgetstatesymbol[] = {0x37,0x2b,0x31,0x26,0x22,0x27,0x1c,0x24,0x26,0x37,0x1c,0x30,0x37,0x22,0x37,0x26,0x43};
        DECRYPT_STRING(17,threadgetstatesymbol,0x43);
        mythread_get_state = DLSYM_GET(threadgetstatesymbol);

        (*mythread_get_state)(thread_list[0], flavor, (thread_state_t)&debug, &count);
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
        EVIL_ASM5;
#if DEBUG
        printf("[DEBUG] Sha256 header checksum:\n");
        for (int i = 0; i < 32; i++)
        {
            printf("%02x", key[i]);
        }
        printf("\n");
#endif
        // and now we can finally decrypt
        // modify memory protection so we can decrypt and write
        kern_return_t kr;
#if DEBUG
        printf("[DEBUG] Starting to decrypt exception_handler...\n");
#endif
        kr = (*mymach_vm_protect)(mach_task_self(), (mach_vm_address_t)addr, (mach_vm_size_t)protectSize, FALSE,  WRITEPROTECTION);
#if DEBUG
        EXIT_ON_MACH_ERROR("Failurex", 1);
#endif
        
        // start decryption, the input buffer is the same as the output buffer
        SALSA_ctx ctx;
        SALSA_keysetup(&ctx, key, 256, 64);
        SALSA_ivsetup(&ctx, iv);
        SALSA_decrypt_bytes(&ctx, (uint8_t*)addr, (uint8_t*)addr, protectSize);
        EVIL_ASM1;
        // restore original memory permissions
        kr = (*mymach_vm_protect)(mach_task_self(), (mach_vm_address_t)addr, (mach_vm_size_t)protectSize, FALSE,  READPROTECTION);
#if DEBUG
        EXIT_ON_MACH_ERROR("Failure", 1);
        printf("[DEBUG] End exception_handler decrypt\n");
        printf("[DEBUG] Calling exception handler...\n");
#endif
		exception_handler();
        // crypt exception handler?
#if DEBUG
        printf("[DEBUG] Starting to encrypt exception_handler...\n");
#endif
        kr = (*mymach_vm_protect)(mach_task_self(), (mach_vm_address_t)addr, (mach_vm_size_t)protectSize, FALSE,  WRITEPROTECTION);
#if DEBUG
        EXIT_ON_MACH_ERROR("Failurex", 1);
#endif

        SALSA_keysetup(&ctx, key, 256, 64);
        SALSA_ivsetup(&ctx, iv);
        EVIL_ASM2;
        SALSA_encrypt_bytes(&ctx, (uint8_t*)addr, (uint8_t*)addr, protectSize);
        
        // restore original memory permissions
        kr = (*mymach_vm_protect)(mach_task_self(), (mach_vm_address_t)addr, (mach_vm_size_t)protectSize, FALSE,  READPROTECTION);
#if DEBUG
        EXIT_ON_MACH_ERROR("Failure", 1);
        printf("[DEBUG] End exception_handler encrypt\n");
        printf("[DEBUG] Return from exception handler...\n");
#endif
        // the tail that will hold our decryption data
        asm(".intel_syntax noprefix");
        asm __volatile__ ("xor edx, edx\n\t" //31d2
                          "test edx, edx\n\t" // 85d2
                          "jz 1f\n\t" // 7416
                          //                                            "jmp 1f\n\t"
                          ".byte 0x00\n\t"
                          ".long 0x0064a990\n\t"
                          ".long 0x00003134\n\t" 
                          ".long 0x00000000\n\t" // address
                          ".long 0x00000000\n\t" // size
                          ".long 0x00000000\n\t" // function size
                          "1:\n\t");
        asm(".att_syntax prefix");
	}
}

// this will be responsible for receiving and delivering exception messages
// mach_exc_server does the magic
__attribute ((noinline)) void
exception_handler()
{
#if DEBUG
    printf("[DEBUG] exception_handler() start\n");
#endif
    kern_return_t kr;
    exc_msg_t     msg_recv;
    reply_msg_t   msg_resp;
	
    msg_recv.Head.msgh_local_port = exception_port;
    msg_recv.Head.msgh_size = sizeof(msg_recv);
    
    mach_msg_return_t (*mymach_msg)(
                                 mach_msg_header_t *msg,
                                 mach_msg_option_t option,
                                 mach_msg_size_t send_size,
                                 mach_msg_size_t rcv_size,
                                 mach_port_name_t rcv_name,
                                 mach_msg_timeout_t timeout,
                                 mach_port_name_t notify);
    volatile uint8_t machmsgsymbol[] = {0x60,0x6c,0x6e,0x65,0x52,0x60,0x7e,0x6a,0x0d};
    DECRYPT_STRING(9,machmsgsymbol,0xd);
    mymach_msg = DLSYM_GET(machmsgsymbol);
    EVIL_ASM4;
	// when the handler is started, it stays here waiting for a message
    kr = (*mymach_msg)(&(msg_recv.Head),				// message
                  MACH_RCV_MSG|MACH_RCV_LARGE,	// options
                  0,							// send size (irrelevant here)
                  sizeof(msg_recv),				// receive limit
                  exception_port,				// port for receiving
                  100,							// no timeout
                  MACH_PORT_NULL);				// notify port (irrelevant here)
                                                //EXIT_ON_MACH_ERROR("myloader.c - mach_msg_receive", kr);
#if DEBUG
    printf("[DEBUG] exception_handler Received message!\n");
#endif
    // a message was received so we can process it now
    // decrypt catch_mach_exception*
    uint32_t search;
    asm(".att_syntax prefix");
    asm __volatile__("nop\n\t"
                     "call 1f\n\t" // E8 00 00 00 00
                     "1:\n\t"
                     "pop %%eax\n\t" // 58
                     "mov %%eax, %0" // 89 C3
                     : "=r" (search)
                     :
                     :"eax");
    asm(".att_syntax prefix");
#if DEBUG
    printf("Search is %x %x\n", search, *(uint32_t*)(search+5));
#endif
    JUNK_CODE2;
    mach_vm_address_t addr = 0;
    uint32_t protectSize = 0;
    uint32_t functionSize = 0;
    uint32_t functionBegin = 0;
    volatile uint16_t xorKey = 0x9813;
    for (uint32_t i = search; i < search + 0x3000; i++)
    {    
        if ((*(uint16_t*)i ^xorKey) == 0xDF06) // 0x4715
        {
            addr = *(uint32_t*)(i+4);
            protectSize = *(uint32_t*)(i+8);
            functionSize = *(uint32_t*)(i+12);
#if DEBUG
            printf("[DEBUG] Found catch_mach_exception decrypting info at %x . Address:%x Size:%x Function Size:%x!\n", i, *(uint32_t*)(i+4), *(uint32_t*)(i+8),*(uint32_t*)(i+12));
#endif
            break;
        }
    }
    xorKey = 0x7865;
    for (uint32_t i = search; i > 0x1000; i--)
    {
        if ((*(uint16_t*)i ^ xorKey) == 0x9DEC) // 0xe589
        { 
            functionBegin = i - 1;
#if DEBUG
            printf("[DEBUG] Found exception_handler() beginning at %x\n", functionBegin);
#endif
            break;
        }
    }
    EVIL_ASM2;
    // build the key
    uint8_t key[32];
    uint8_t iv[8] = "mercedes";
    
    sha2((uint8_t*)functionBegin, functionSize, key, 0);
    // build the salt array
    uint32_t salt[4];
    x86_debug_state32_t debug;
    mach_msg_type_number_t	count;
    thread_state_flavor_t flavor;
    flavor = x86_DEBUG_STATE32;
    count = x86_DEBUG_STATE32_COUNT;
    thread_act_port_array_t thread_list;
    mach_msg_type_number_t thread_count;
    
    kern_return_t (*mythread_get_state)(thread_act_t target_act,thread_state_flavor_t flavor,thread_state_t old_state,mach_msg_type_number_t *old_stateCnt);
    volatile uint8_t threadgetstatesymbol[] = {0x37,0x2b,0x31,0x26,0x22,0x27,0x1c,0x24,0x26,0x37,0x1c,0x30,0x37,0x22,0x37,0x26,0x43};
    DECRYPT_STRING(17,threadgetstatesymbol,0x43);
    mythread_get_state = DLSYM_GET(threadgetstatesymbol);
    EVIL_ASM1;
    kern_return_t (*mytask_threads)(task_t target_task,thread_act_array_t *act_list,mach_msg_type_number_t *act_listCnt);
    volatile uint8_t taskthreadssymbol[] = {0x20,0x35,0x27,0x3f,0x0b,0x20,0x3c,0x26,0x31,0x35,0x30,0x27,0x54};
    DECRYPT_STRING(13,taskthreadssymbol,0x54);
    mytask_threads = DLSYM_GET(taskthreadssymbol);
    (*mytask_threads)(mach_task_self(), &thread_list, &thread_count);
    
    kern_return_t (*mymach_vm_protect)(vm_map_t target_task,mach_vm_address_t address,mach_vm_size_t size,boolean_t set_maximum,vm_prot_t new_protection);
    volatile uint8_t vmprotectsymbol[] = {0x2e,0x22,0x20,0x2b,0x1c,0x35,0x2e,0x1c,0x33,0x31,0x2c,0x37,0x26,0x20,0x37,0x43};
    DECRYPT_STRING(16, vmprotectsymbol, 0x43);
    mymach_vm_protect = DLSYM_GET(vmprotectsymbol);

    (*mythread_get_state)(thread_list[0], flavor, (thread_state_t)&debug, &count);
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
#if DEBUG
    printf("[DEBUG] Sha256 exception_handler checksum:\n");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", key[i]);
    }
    printf("\n");
#endif
    // and now we can finally decrypt
    // modify memory protection so we can decrypt and write
#if DEBUG
    printf("[DEBUG] Starting to decrypt catch_mach_exception...\n");
#endif
    kr = (*mymach_vm_protect)(mach_task_self(), (mach_vm_address_t)addr, (mach_vm_size_t)protectSize, FALSE,  WRITEPROTECTION);
#if DEBUG
    EXIT_ON_MACH_ERROR("Failurex", 1);
#endif
    
    // start decryption, the input buffer is the same as the output buffer
    SALSA_ctx ctx;
    SALSA_keysetup(&ctx, key, 256, 64);
    SALSA_ivsetup(&ctx, iv);
    EVIL_ASM1;
    antidebug_check_gdb_breakpoint((uint32_t)addr, protectSize);
    EVIL_ASM5;
    JUNK_CODE3;
    SALSA_decrypt_bytes(&ctx, (uint8_t*)addr, (uint8_t*)addr, protectSize);
    
    // restore original memory permissions
    kr = (*mymach_vm_protect)(mach_task_self(), (mach_vm_address_t)addr, (mach_vm_size_t)protectSize, FALSE,  READPROTECTION);
#if DEBUG
    EXIT_ON_MACH_ERROR("Failure", 1);
    printf("[DEBUG] End catch_mach_exception decrypt\n");
#endif
	// dispatch the message
    mach_exc_server(&msg_recv.Head, &msg_resp.Head);
    // now msg_resp.RetCode contains return value of catch_exception_raise()
    // encrypt exceptions
#if DEBUG
    printf("[DEBUG] Starting to encrypt catch_mach_exception...\n");
#endif
    kr = (*mymach_vm_protect)(mach_task_self(), (mach_vm_address_t)addr, (mach_vm_size_t)protectSize, FALSE,  WRITEPROTECTION);
#if DEBUG
    EXIT_ON_MACH_ERROR("Failurex", 1);
#endif
    
    // start encryption, the input buffer is the same as the output buffer
    SALSA_keysetup(&ctx, key, 256, 64);
    EVIL_ASM4;
    SALSA_ivsetup(&ctx, iv);
    JUNK_CODE1;
    SALSA_encrypt_bytes(&ctx, (uint8_t*)addr, (uint8_t*)addr, protectSize);
    
    // restore original memory permissions
    kr = (*mymach_vm_protect)(mach_task_self(), (mach_vm_address_t)addr, (mach_vm_size_t)protectSize, FALSE,  READPROTECTION);
    
#if DEBUG
    EXIT_ON_MACH_ERROR("Failure", 1);
    printf("[DEBUG] End catch_mach_exception encrypt\n");
    printf("[DEBUG] exception_handler Sending reply\n");
#endif
    
    kr = (*mymach_msg)(&(msg_resp.Head),			// message
                  MACH_SEND_MSG,			// options
                  msg_resp.Head.msgh_size,	// send size
                  0,						// receive limit (irrelevant here)
                  MACH_PORT_NULL,			// port for receiving (none)
                  100,						// no timeout
                  MACH_PORT_NULL);			// notify port (we don't want one)
                                            // the tail that will hold our decryption data
    asm(".intel_syntax noprefix");
    asm __volatile__ ("xor edx, edx\n\t" //31d2
                      "test edx, edx\n\t" // 85d2
                      "jz 1f\n\t" // 7416
                      //                                            "jmp 1f\n\t"
                      ".byte 0x00\n\t"
                      ".long 0x0064a990\n\t"
                      ".long 0x00004715\n\t" 
                      ".long 0x00000000\n\t" // address
                      ".long 0x00000000\n\t" // size
                      ".long 0x00000000\n\t" // function size
                      "1:\n\t");
    asm(".att_syntax prefix");
}

// where the magic happens!
// the code to be executed whenever an exception occurs
// the logic of dealing with different exceptions stays here
kern_return_t
catch_mach_exception_raise(mach_port_t            port,
						   mach_port_t            threadid,
						   mach_port_t            task,
						   exception_type_t       exception,
						   exception_data_t       code,
						   mach_msg_type_number_t code_count)
{
#if DEBUG
    printf("[DEBUG] Handling exception start\n");
#endif
    // the header that will hold our decryption data
    asm(".intel_syntax noprefix");
    asm __volatile__ ("xor edx, edx\n\t"
                      "test edx, edx\n\t"       // 
                      "jz 1f\n\t"               //
                      ".long 0x0064a990\n\t"
                      ".long 0x00001810\n\t"
                      ".long 0x00000000\n\t"
                      ".long 0x00000000\n\t"
                      ".long 0x00000000\n\t"
                      ".long 0x00000000\n\t"
                      "1:\n\t");
    asm(".att_syntax prefix");

    kern_return_t (*mymach_vm_protect)(vm_map_t target_task,mach_vm_address_t address,mach_vm_size_t size,boolean_t set_maximum,vm_prot_t new_protection);
    volatile uint8_t vmprotectsymbol[] = {0x2e,0x22,0x20,0x2b,0x1c,0x35,0x2e,0x1c,0x33,0x31,0x2c,0x37,0x26,0x20,0x37,0x43};
    DECRYPT_STRING(16, vmprotectsymbol, 0x43);
    mymach_vm_protect = DLSYM_GET(vmprotectsymbol);
    EVIL_ASM3;
    JUNK_CODE2;
    // try to do something here with port ? so it will crash if we jumped directly to here ?
    // gdb uses a EXC_MASK_ALL and removes EXC_MASK_BAD_ACCESS (if configured!)
    // the default mask is 0x3fe but port will be empty
    // if gdb is there, then a port is set
    // the gdb mask can be modified with the handle command
    // we have different ports if the mask is different
    // if we use the EXC_MASK_ALL, only one exception port exists
    mach_port_t myself = mach_task_self();
#if DEBUG
    printf("thread id is %d\n", threadid);
#endif
    kern_return_t kr;
#if __LP64__
	x86_thread_state64_t state;
    //    x86_debug_state64_t debug;
#else
	i386_thread_state_t state;
    //    x86_debug_state32_t debug;
#endif
    mach_msg_type_number_t	count;
	thread_state_flavor_t flavor;
#if __LP64__
	flavor = x86_THREAD_STATE64;
	count = x86_THREAD_STATE64_COUNT;
#else
	flavor = i386_THREAD_STATE;
	count = i386_THREAD_STATE_COUNT;
#endif
    kern_return_t (*mythread_get_state)(thread_act_t target_act,thread_state_flavor_t flavor,thread_state_t old_state,mach_msg_type_number_t *old_stateCnt);
    volatile uint8_t threadgetstatesymbol[] = {0x37,0x2b,0x31,0x26,0x22,0x27,0x1c,0x24,0x26,0x37,0x1c,0x30,0x37,0x22,0x37,0x26,0x43};
    DECRYPT_STRING(17,threadgetstatesymbol,0x43);
    mythread_get_state = DLSYM_GET(threadgetstatesymbol);
    EVIL_ASM5;
	kr = (*mythread_get_state)(threadid, flavor, (thread_state_t)&state, &count);
    
#if __LP64__
    uint64_t eip = state.__rip;
#else
    uint64_t eip = state.__eip;
#endif

	/*
	 here we have the logic to deal with the exceptions types
	 we call different functions to treat the exceptions based on address
	 */
#if DEBUG
    printf("Exception is %x\n", exception);
#endif
	switch (exception) {
            // ********************
            // SOFTWARE BREAKPOINTS
            // ********************
		case EXC_BREAKPOINT:
		{
			// **********************************************************************************************
			// REMEMBER THAT SOFTWARE BREAKPOINT HIT ADDRESS IS ALWAYS +1 BYTE THAN THE ADDRESS WE CONFIGURED
			// **********************************************************************************************
			// so let's do it right and decrease EIP so it matches our configured breakpoints
			// easier than making mistakes with adding +1 and fixing it all the time ;-)
            mach_vm_address_t bpAddress = 0;
            uint32_t search;
            asm(".att_syntax prefix");
            asm __volatile__("nop\n\t"
                             "call 1f\n\t" // E8 00 00 00 00
                             "1:\n\t"
                             "pop %%eax\n\t" // 58
                             "mov %%eax, %0" // 89 C3
                             : "=r" (search)
                             :
                             :"eax");
            asm(".att_syntax prefix");
#if DEBUG
            printf("Search is %x %x\n", search, *(uint32_t*)(search+5));
#endif
            uint32_t oep = 0;
            // find encryption info
            volatile uint16_t xorKey = 0x5476;
            for (uint32_t i = search; i > 0x1000; i--)
            {    
                if ((*(uint16_t*)i ^ xorKey) == 0x4C66) // 0x1810
                {
                    oep = *(uint32_t*)(i+16);
                    break;
                }
            }

#if __LP64__
            state.__rip--;
            state.__rax = oep;
            bpAddress = state.__rip;
#else
			state.__eip--;
            state.__eax = oep;
            bpAddress = state.__eip;
#endif
            // restore original byte
            mach_msg_type_number_t len = 1;
            vm_offset_t bytetorestore = 0;
            mach_msg_type_number_t bytesread;
            bytetorestore = *(unsigned char*)originalopcode;
            kr = (*mymach_vm_protect)(mach_task_self(), (mach_vm_address_t)bpAddress, (mach_vm_size_t)1, FALSE,  WRITEPROTECTION);
#if DEBUG
            EXIT_ON_MACH_ERROR("mach_vm_protect at exception handler failed", 1);
#endif
            // 0x8fe01061
            kern_return_t (*mymach_vm_write)(vm_map_t target_task,mach_vm_address_t address,vm_offset_t data,mach_msg_type_number_t dataCnt);
            volatile uint8_t machvmwritesymbol[] = {0x3c,0x30,0x32,0x39,0x0e,0x27,0x3c,0x0e,0x26,0x23,0x38,0x25,0x34,0x51};
            DECRYPT_STRING(14, machvmwritesymbol, 0x51);
            mymach_vm_write = DLSYM_GET(machvmwritesymbol);
            EVIL_ASM1;
            kr = (*mymach_vm_write)(myself, (mach_vm_address_t)bpAddress, (vm_offset_t)&bytetorestore, len);
#if DEBUG
            EXIT_ON_MACH_ERROR("mach_vm_write at exception handler failed", 1);
#endif
            kr = (*mymach_vm_protect)(mach_task_self(), (mach_vm_address_t)bpAddress, (mach_vm_size_t)1, FALSE,  READPROTECTION);
#if DEBUG
            EXIT_ON_MACH_ERROR("mach_vm_protect at exception handler failed", 1);
#endif
            kern_return_t (*mythread_set_state)(thread_act_t target_act,thread_state_flavor_t flavor,thread_state_t new_state,mach_msg_type_number_t new_stateCnt);
            volatile uint8_t threadsetstatesymbol[] = {0x75,0x69,0x73,0x64,0x60,0x65,0x5e,0x72,0x64,0x75,0x5e,0x72,0x75,0x60,0x75,0x64,0x01};
            DECRYPT_STRING(17,threadsetstatesymbol,0x01);
            mythread_set_state = DLSYM_GET(threadsetstatesymbol);

            kr = (*mythread_set_state)(threadid, flavor, (thread_state_t)&state,count);
#if DEBUG
            kr = mach_vm_read(myself, (mach_vm_address_t)bpAddress, len, &originalopcode, &bytesread);
            printf("new %x\n", *(unsigned char*)originalopcode);
#endif
			// software exception not handled by anything so treat it as an error
			//printf("[INFO] Nothing found for dealing with this software breakpoint at 0x%llx!\n", eip);
			//exit(-1);
#if DEBUG
            printf("Exception handled!\n");
#endif
            EVIL_ASM4;
            return KERN_SUCCESS;
			break;
		}
        case EXC_ARITHMETIC:
        {
#if DEBUG
            printf("[DEBUG] Arithmetic exception!\n");
#endif
            JUNK_CODE3;
            uint8_t iv[8] = "devilRus";
            // decrypt the code
            // decrypt real_verify_key*
            uint32_t search;
            asm(".att_syntax prefix");
            asm __volatile__("nop\n\t"
                             "call 1f\n\t" // E8 00 00 00 00
                             "1:\n\t"
                             "pop %%eax\n\t" // 58
                             "mov %%eax, %0" // 89 C3
                             : "=r" (search)
                             :
                             :"eax");
            asm(".att_syntax prefix");
#if DEBUG
            printf("Search is %x %x\n", search, *(uint32_t*)(search+5));
#endif
            EVIL_ASM4;
            mach_vm_address_t addr = 0;
            uint32_t protectSize = 0;
            uint32_t functionSize = 0;
            uint32_t functionBegin = 0;
            // find encryption info
            volatile uint16_t xorKey = 0x7654;
            for (uint32_t i = search; i > 0x1000; i--)
            {    
                if ((*(uint16_t*)i ^ xorKey) == 0x6E44) // 0x1810
                {
                    addr = *(uint32_t*)(i+4);
                    protectSize = *(uint32_t*)(i+8);
                    functionSize = *(uint32_t*)(i+12);
#if DEBUG
                    printf("[DEBUG] Found real_verify_key decrypting info at %x . Address:%x Size:%x Function Size:%x!\n", i, *(uint32_t*)(i+4), *(uint32_t*)(i+8),*(uint32_t*)(i+12));
#endif
                    break;
                }
            }
            xorKey = 0x6512;
            // find start of the function
            for (uint32_t i = search; i > 0x1000; i--)
            {
                if ((*(uint16_t*)i ^ xorKey) == 0x809B) // 0xe589
                {
                    functionBegin = i - 1;
#if DEBUG
                    printf("[DEBUG] Found catch_mach_exception() beginning at %x\n", functionBegin);
#endif
                    break;
                }
            }
            
            // build the key
            uint8_t key[32];
            EVIL_ASM3;
            sha2((uint8_t*)functionBegin, functionSize, key, 0);
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
            volatile uint8_t taskthreadssymbol[] = {0x20,0x35,0x27,0x3f,0x0b,0x20,0x3c,0x26,0x31,0x35,0x30,0x27,0x54};
            DECRYPT_STRING(13,taskthreadssymbol,0x54);
            mytask_threads = DLSYM_GET(taskthreadssymbol);
            (*mytask_threads)(mach_task_self(), &thread_list, &thread_count);
            
            (*mythread_get_state)(thread_list[0], flavor, (thread_state_t)&debug, &count);
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
#if DEBUG
            printf("[DEBUG] Sha256 catch_mach_exception() checksum:\n");
            for (int i = 0; i < 32; i++)
            {
                printf("%02x", key[i]);
            }
            printf("\n");
#endif
            // and now we can finally decrypt
            // modify memory protection so we can decrypt and write
            EVIL_ASM4;
#if DEBUG
            printf("[DEBUG] Starting to decrypt real_verify_key...\n");
#endif
            kr = (*mymach_vm_protect)(mach_task_self(), (mach_vm_address_t)addr, (mach_vm_size_t)protectSize, FALSE,  WRITEPROTECTION);
#if DEBUG
            EXIT_ON_MACH_ERROR("Failurex", 1);
#endif
            
            // start decryption, the input buffer is the same as the output buffer
            SALSA_ctx ctx;
            SALSA_keysetup(&ctx, key, 256, 64);
            SALSA_ivsetup(&ctx, iv);
            SALSA_decrypt_bytes(&ctx, (uint8_t*)addr, (uint8_t*)addr, protectSize);
            // call it - it will destroy itself
            uint16_t nameLength = strlen((char*)(*(uint32_t*)(state.__esp+4)));
            uint16_t serialLength = strlen((char*)(*(uint32_t*)(state.__esp)));
            EVIL_ASM5;
            JUNK_CODE1;
#if DEBUG
            printf("Name %s serial %s\n",(char*)(*(uint32_t*)(state.__esp+4)),  (char*)(*(uint32_t*)(state.__esp)));
            printf("Name len from stack is %d Serial is %d\n", nameLength, serialLength);
#endif
            char *name = malloc(nameLength+1);
            name[nameLength] = '\00';
            JUNK_CODE2;
            char *serial = malloc(serialLength+1);
            serial[serialLength] = '\00';
            memcpy(name, (char*)(*(uint32_t*)(state.__esp+4)), nameLength);
            EVIL_ASM1;
            memcpy(serial, (char*)(*(uint32_t*)(state.__esp)), serialLength);
            real_verify_key(name, serial);
            //
            exit(0);
            break;
        }
            // default case - just exit
		default:
		{
#if DEBUG
			printf("[ERROR] not a breakpoint exception %d @ 0x%llx [%d]\n", exception, eip, threadid);
#endif
			exit(1);
		}
	}
	return(0);
}

// this is where the real verification of the serial number is done
// it's encrypted at the catch_mach_exception
__attribute ((noinline)) void real_verify_key(char *name, char *serial)
{
    // verify if key format is correct
    if (serial[6] != '-' || serial[12] != '-' || serial[21] != '-')
    {
#if DEBUG
        printf("[DEBUG] Wrong serial format!\n");
#endif
        exit(0);
    }
    EVIL_ASM5;
    JUNK_CODE3;
    // find our current position, to find beginning and end of the function
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
    uint32_t functionBegin = 0;
    uint32_t functionEnd = 0;
    volatile uint16_t xorKey1 = 0x6754;
    volatile uint16_t xorKey2 = 0x3133;
    EVIL_ASM1;
    for (uint32_t i = search; i > 0x1000; i--)
    {
        if ((*(uint16_t*)i ^ xorKey1) == 0x82DD)
        {
            functionBegin = i - 1;
            break;
        }
    }
    for (uint32_t i = search; i < search + 0x2000; i++)
    {
        if ((*(uint16_t*)i ^ xorKey2) == 0xD4BA)
        {
            functionEnd = i -1;
            break;
        }
    }
    uint32_t functionSize = functionEnd - functionBegin;
    // build the key
    uint8_t key[32];
    
    kern_return_t (*mythread_get_state)(thread_act_t target_act,thread_state_flavor_t flavor,thread_state_t old_state,mach_msg_type_number_t *old_stateCnt);
    volatile uint8_t threadgetstatesymbol[] = {0x37,0x2b,0x31,0x26,0x22,0x27,0x1c,0x24,0x26,0x37,0x1c,0x30,0x37,0x22,0x37,0x26,0x43};
    DECRYPT_STRING(17,threadgetstatesymbol,0x43);
    mythread_get_state = DLSYM_GET(threadgetstatesymbol);

    sha2((uint8_t*)functionBegin, functionSize, key, 0);
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
    volatile uint8_t taskthreadssymbol[] = {0x20,0x35,0x27,0x3f,0x0b,0x20,0x3c,0x26,0x31,0x35,0x30,0x27,0x54};
    DECRYPT_STRING(13,taskthreadssymbol,0x54);
    mytask_threads = DLSYM_GET(taskthreadssymbol);
    (*mytask_threads)(mach_task_self(), &thread_list, &thread_count);
    EVIL_ASM3;
    (*mythread_get_state)(thread_list[0], flavor, (thread_state_t)&debug, &count);
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
#if DEBUG
    printf("[DEBUG] Sha256 real_verify_key() checksum:\n");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", key[i]);
    }
    printf("\n");
#endif
    // compare with the stored value at LC_UUID
    extern uint32_t _mh_execute_header;
    uint8_t headerKey[7];
    struct mach_header *machHeader = (struct mach_header*)&_mh_execute_header;
    struct segment_command *segmentCmd = NULL;
    uint8_t *tempAddress = ((uint8_t*)&_mh_execute_header + sizeof(struct mach_header));
    for (uint32_t i = 0; i < machHeader->ncmds; i++)
    {
        segmentCmd = (struct segment_command*)tempAddress;
        if (segmentCmd->cmd == LC_UUID)
        {
            struct uuid_command *uuidCmd = (struct uuid_command*)segmentCmd;
            memcpy(headerKey, &uuidCmd->uuid[2], 7);
        }
        tempAddress += segmentCmd->cmdsize;
    }
    EVIL_ASM3;
    // compare both
    char temp[9];
    memcpy(temp, &serial[13], 8);
    temp[8] = '\00';
    // verify checksums
    if (memcmp(key, headerKey, 7) != 0)
    {
#if DEBUG
        printf("[DEBUG] mismatch between checksums!\n");
#endif
        exit(0);
    }
    unsigned long (*mystrtoul)(const char *, char **, int);
    volatile uint8_t strtoulsymbol[] = {0x7a,0x7d,0x7b,0x7d,0x66,0x7c,0x65,0x09};
    DECRYPT_STRING(8,strtoulsymbol,0x09);
    mystrtoul = DLSYM_GET(strtoulsymbol);

    // verify 3rd field
    if ((*mystrtoul)(temp, NULL, 16) != *(uint32_t*)headerKey)
    {
#if DEBUG
        printf("[DEBUG] 3rd field failed! Should be %08x\n", *(uint32_t*)headerKey);
#endif
        exit(0);
    }
    EVIL_ASM2;
    // generate sha256 of input name
    uint8_t nameKey[32];
    sha2((uint8_t*)name, strlen(name), nameKey, 0);
    JUNK_CODE1;
#if DEBUG
    printf("[DEBUG] Sha256 name checksum:\n");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", nameKey[i]);
    }
    printf("\n");
#endif

    // verify fields
    // 1st field = first 6 chars
    char *temp2;
    temp2 = malloc(7);
    temp2[6] = '\00';
    memcpy(temp2, &serial[0], 6);
    JUNK_CODE2;
    if ((*mystrtoul)(temp2, NULL, 16) != ( *(uint32_t*)nameKey & 0xffffff))
    {
#if DEBUG
        printf("[DEBUG] 1st field failed! Should be %06x\n", *(uint32_t*)nameKey & 0xffffff);
#endif
        exit(2);
    }
    free(temp2);
    EVIL_ASM4;
    // 2nd field = 15 to 20
    temp2 = malloc(6);
    temp2[5] = '\00';
    memcpy(temp2, &serial[7], 5);
    if ((*mystrtoul)(temp2, NULL, 16) != ( *(uint32_t*)(nameKey+15) & 0xfffff))
    {
#if DEBUG
        printf("[DEBUG] 2nd field failed! Should be %05x\n", *(uint32_t*)(nameKey+15) & 0xfffff);
#endif
        exit(2);
    }
    free(temp2);
    // last field = last 8 chars
    temp2 = malloc(9);
    temp2[8] = '\00';
    memcpy(temp2, &serial[22], 8);
    if ((*mystrtoul)(temp2, NULL, 16) != (*(uint32_t*)(nameKey+23)))
    {
#if DEBUG
        printf("[DEBUG] 4th field failed! Should be %08x\n", *(uint32_t*)(nameKey+23));
#endif
        exit(2);
    }
    EVIL_ASM5;
    // decryption in stages for each part of the serial
    printf(" ___                      _ \n");
    printf("/ __|_  _ __ __ ___ _____| |\n");
    printf("\\__ \\ || / _/ _/ -_|_-<_-<_|\n");
    printf("|___/\\_,_\\__\\__\\___/__/__(_)\n");
    printf("-----------------------------------------------\n");
    printf("Congratulations! You found the magic key!\n");
    printf("I hope you had some fun with this challenge :-)\n\n");
    printf("fG! - reverser@put.as\n\n");
    printf("-[http://reverse.put.as]-----------------------\n");
    exit(0);
}

// this is just here because compiler complaints...
kern_return_t
catch_mach_exception_raise_state (mach_port_t            port,
								  mach_port_t            thread,
								  mach_port_t            task,
								  exception_type_t       exception,
								  exception_data_t       code,
								  mach_msg_type_number_t code_count)
{
	
	return(KERN_INVALID_ADDRESS);
}

// this is just here because compiler complaints...
kern_return_t
catch_mach_exception_raise_state_identity (
										   mach_port_t             exception_port,
										   mach_port_t             thread,
										   mach_port_t             task,
										   exception_type_t        exception,
										   exception_data_t        code,
										   mach_msg_type_number_t  codeCnt,
										   int *                   flavor,
										   thread_state_t          old_state,
										   mach_msg_type_number_t  old_stateCnt,
										   thread_state_t          new_state,
										   mach_msg_type_number_t *new_stateCnt
										   )
{
	return(KERN_INVALID_ADDRESS);
}
