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
 * v1.0
 *
 * TODO:
 * - ASLR support
 * - 64bits support
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

#define VERSION "1.0"

const uint32_t ep = 0x1234;
// new section 
vm_offset_t originalopcode;

/*
 * first stage decryption: the whole binary is encrypted except this function, sha2 and rabbit encryption
 * the key is the sha224 checksum of init2 function
 * the iv is "funtimes"
 * to decrypt we need the following info
 * - size of init2 (located at UUID)
 * - address & size of functions to decrypt (located at addresses after the fake lib command)
 */
void 
init2(void)
{
    // function pointers
    kern_return_t (*mymach_vm_protect)(vm_map_t target_task, mach_vm_address_t address,mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
    void* (*mymemcpy)(void *restrict s1, const void *restrict s2, size_t n);
    kern_return_t (*mytask_threads)(task_t target_task,thread_act_array_t *act_list,mach_msg_type_number_t *act_listCnt);
    JUNK_CODE3;
#if DEBUG
    printf("-------------------------------------------------------------------\n");
    printf("[DEBUG] I am init2()\n");
#endif
    EVIL_ASM3;
    // load the hardware registers with salt value
    kern_return_t kr = 0;
    x86_debug_state32_t debug;
    mach_msg_type_number_t	count;
	thread_state_flavor_t flavor;
	flavor = x86_DEBUG_STATE32;
	count = x86_DEBUG_STATE32_COUNT;
    thread_act_port_array_t thread_list;
    mach_msg_type_number_t thread_count;
    volatile uint8_t taskthreadssymbol[] = {0x2d,0x38,0x2a,0x32,0x06,0x2d,0x31,0x2b,0x3c,0x38,0x3d,0x2a,0x59};
    DECRYPT_STRING(13,taskthreadssymbol,0x59);
    mytask_threads = DLSYM_GET(taskthreadssymbol);

    (*mytask_threads)(mach_task_self(), &thread_list, &thread_count);
#if DEBUG
    if (thread_count > 1)
    {
        printf("[ERROR] More than one main thread?\n");
        exit(1);
    }
#endif
    kern_return_t (*mythread_get_state)(thread_act_t target_act,thread_state_flavor_t flavor,thread_state_t old_state,mach_msg_type_number_t *old_stateCnt);
    volatile uint8_t threadgetstatesymbol[] = {0x43,0x5f,0x45,0x52,0x56,0x53,0x68,0x50,0x52,0x43,0x68,0x44,0x43,0x56,0x43,0x52,0x37};
    DECRYPT_STRING(17,threadgetstatesymbol,0x37);
    mythread_get_state = DLSYM_GET(threadgetstatesymbol);
    EVIL_ASM4;
    kern_return_t (*mythread_set_state)(thread_act_t target_act,thread_state_flavor_t flavor,thread_state_t new_state,mach_msg_type_number_t new_stateCnt);
    volatile uint8_t threadsetstatesymbol[] = {0x75,0x69,0x73,0x64,0x60,0x65,0x5e,0x72,0x64,0x75,0x5e,0x72,0x75,0x60,0x75,0x64,0x01};
    DECRYPT_STRING(17,threadsetstatesymbol,0x01);
    mythread_set_state = DLSYM_GET(threadsetstatesymbol);

    kern_return_t (*mytask_set_state)(task_t task,thread_state_flavor_t flavor,thread_state_t new_state,mach_msg_type_number_t new_stateCnt);
    volatile uint8_t tasksetstatesymbol[] = {0x7d,0x68,0x7a,0x62,0x56,0x7a,0x6c,0x7d,0x56,0x7a,0x7d,0x68,0x7d,0x6c,0x09};
    DECRYPT_STRING(15,tasksetstatesymbol,0x09);
    mytask_set_state = DLSYM_GET(tasksetstatesymbol);

	kr = (*mythread_get_state)(thread_list[0], flavor, (thread_state_t)&debug, &count);
    // the salt values
    debug.__dr0 = 0x75750963;
    debug.__dr1 = 0x539d516b;
    debug.__dr2 = 0xfc0a2498;
    debug.__dr3 = 0xb57c81c4;
    // this will affect new threads
    kr = (*mytask_set_state)(mach_task_self(), flavor, (thread_state_t)&debug, count);
    // this will set current thread
    kr = (*mythread_set_state)(thread_list[0], flavor, (thread_state_t)&debug, count);
#if DEBUG
    kr = (*mythread_get_state)(thread_list[0], flavor, (thread_state_t)&debug, &count);
    printf("dr0 %x dr1 %x dr2 %x dr3 %x\n", debug.__dr0, debug.__dr1, debug.__dr2, debug.__dr3);    
#endif
    // retrieve the current position in init2() so we can search backwards the start of the function
    uint32_t search = 0;
    asm(".att_syntax prefix");
    asm __volatile__(
                     "call 1f\n\t"
                     "1:\n\t"
                     "pop %%ecx\n\t"
                     "mov %%ecx, %0"
                     : "=r" (search));
    asm(".att_syntax prefix");
    // search for the beginning of this function
    while (1)
    {
        if (*(uint16_t*)search == 0xe589)
        {
#if DEBUG
            printf("[DEBUG] Found init2() beginning at %x\n", search);
#endif
            break;
        }
        search = search - 1;
    }
    // adjust address by push ebp
    search = search - 1;
    uint8_t key[28];
    uint8_t iv[8];
    // initialize the IV
    volatile uint8_t memcpysymbol[] = {0x4c,0x44,0x4c,0x42,0x51,0x58,0x21};
    for (int i = 0; i < 7; i++)
    {
        memcpysymbol[i] ^= 0x21;
    }
    mymemcpy = dlsym(RTLD_DEFAULT, (char*)memcpysymbol);

    (*mymemcpy)(iv,"funtimes",8);
    EVIL_ASM5;
    extern uint32_t _mh_execute_header;
    
    // store the size at LC_UUID field :-)
#if DEBUG
    printf("[DEBUG] Searching for LC_UUID to retrieve size\n");
#endif
    struct mach_header *machHeader = (struct mach_header*)&_mh_execute_header;
    struct segment_command *segmentCmd = NULL;
    uint8_t *address = (uint8_t*)(&_mh_execute_header) + sizeof(struct mach_header);
    uint16_t uuidSize = 0;
    for (uint32_t i = 0; i < machHeader->ncmds; i++)
    {
        segmentCmd = (struct segment_command*)address;
        if (segmentCmd->cmd == LC_UUID)
        {
#if DEBUG
            printf("[DEBUG] Found LC_UUID!\n");
#endif
            struct uuid_command *uuidCmd = (struct uuid_command*)segmentCmd;
            // we just need 16 bits to store the size
            uuidSize = *(uint16_t*)uuidCmd->uuid;
#if DEBUG
            printf("[DEBUG] stored size at LC_UUID is %x\n", uuidSize);
#endif
        }
        address += segmentCmd->cmdsize;
    }
    // the sha224 checksum of the init(2) is the decryption key
#if DEBUG
    printf("[DEBUG] Creating init2() hash...\n");
#endif
    sha2((uint8_t*)search, uuidSize, key, 1);
    // build the salt array
    uint32_t salt[4];
    kr = (*mythread_get_state)(thread_list[0], flavor, (thread_state_t)&debug, &count);
    EVIL_ASM1;
    salt[0] = debug.__dr0;
    salt[1] = debug.__dr1;
    salt[2] = debug.__dr2;
    salt[3] = debug.__dr3;

    uint8_t *tempKey = malloc(sizeof(salt) + sizeof(key));
    memcpy(tempKey, key, 28);
    memcpy(tempKey+28, salt, sizeof(salt));
    // compute the final salted key
    sha2((uint8_t*)tempKey, 44, key, 1);
    free(tempKey);

#if DEBUG
    printf("[DEBUG] init2() sha224 hash:\n");
    for (int i = 0; i < 28; i++)
    {
        printf("%02x", key[i]);
    }
    printf("\n");
#endif
    JUNK_CODE1;
    // get ready to decrypt the first layer
    RABBIT_ctx ctx;
    RABBIT_keysetup(&ctx, key, 128, 64);
    RABBIT_ivsetup(&ctx, iv);
    // mach_vm_protect
    volatile uint8_t vmprotectsymbol[] = {0x5e,0x52,0x50,0x5b,0x6c,0x45,0x5e,0x6c,0x43,0x41,0x5c,0x47,0x56,0x50,0x47,0x33};
    for (int i = 0; i < 16; i++)
    {
        vmprotectsymbol[i] ^= 0x33;
    }
    mymach_vm_protect = dlsym(RTLD_DEFAULT, (char*)vmprotectsymbol);
    
    // we have 3 blocks to decrypt
    // 1st - start(), main(), init()
    // 2nd - between init2() and sha2
    // 3rd - the rest after rabbit()
    // FIXME: fakeLib to be removed when protect injects the fake library
    uint32_t fakeLib = 28;
    uint32_t index = 0;
    uint32_t decryptAddress = 0;
    uint32_t decryptSize = 0;
    vm_prot_t writeProtection = VM_PROT_EXECUTE | VM_PROT_WRITE | VM_PROT_READ;
    vm_prot_t readProtection = VM_PROT_EXECUTE | VM_PROT_READ;
#define NR_BLOCKS_TO_DECRYPT 3
    // decrypt the 3 blocks
    for (uint8_t x = 0; x < NR_BLOCKS_TO_DECRYPT; x++)
    {
        EVIL_ASM5;
        decryptAddress = *(uint32_t*)(fakeLib+index+(uint32_t)&_mh_execute_header+(uint32_t)((struct mach_header*)&_mh_execute_header)->sizeofcmds);
        decryptSize = *(uint32_t*)(fakeLib+index+4+(uint32_t)&_mh_execute_header+(uint32_t)((struct mach_header*)&_mh_execute_header)->sizeofcmds);
        index += 8;
#if DEBUG
        printf("[DEBUG] address to decrypt is %x size %x contents %x\n", decryptAddress, decryptSize, *(uint32_t*)decryptAddress);
#endif
        // allow writes
        kr = (*mymach_vm_protect)(mach_task_self(), (mach_vm_address_t)decryptAddress, (mach_vm_size_t)decryptSize, FALSE,  writeProtection);
        // decrypt
        RABBIT_decrypt_bytes(&ctx, (uint8_t*)decryptAddress, (uint8_t*)decryptAddress, decryptSize);
        // restore memory protections
        (*mymach_vm_protect)(mach_task_self(), (mach_vm_address_t)decryptAddress, (mach_vm_size_t)decryptSize, FALSE,  readProtection);
#if DEBUG
        printf("[DEBUG] Decrypted block %d %x\n", x, *(uint32_t*)decryptAddress);
#endif
    }

#if DEBUG
    printf("[DEBUG] End of init2()\n");
#endif
    volatile const char libToInject[] = "/usr/lib/libncurses.dylib";
}

void init(void)
{
    // function pointers
    kern_return_t (*mymach_vm_read)(vm_map_t target_task,mach_vm_address_t address,mach_vm_size_t size,vm_offset_t *data,mach_msg_type_number_t *dataCnt);    
    kern_return_t (*mymach_vm_protect)(vm_map_t target_task,mach_vm_address_t address,mach_vm_size_t size,boolean_t set_maximum,vm_prot_t new_protection);
    kern_return_t (*mymach_vm_write)(vm_map_t target_task,mach_vm_address_t address,vm_offset_t data,mach_msg_type_number_t dataCnt);

#if DEBUG
    printf("[DEBUG] I am init1()\n");
#endif
	kern_return_t kr;
    mach_port_t myself = mach_task_self();

    asm(".intel_syntax noprefix");
    asm __volatile__ ("jmp 1f\n\t"
                      ".word 0xeb34\n\t"
                      "1:\n\t");
    asm(".att_syntax prefix");

    // check if debugger is present
    EVIL_ASM5;
    JUNK_CODE1;
    antidebug_check_mach_ports();
    // if yes, destroy keys
    // decrypt the debugger installation
#if DEBUG
    printf("[DEBUG] Decrypting debugger_install\n");
#endif
    decrypt_debugger_install();
    EVIL_ASM1;
    // install it
#if DEBUG
    printf("[DEBUG] Installing debugger...\n");
#endif
    install_debugger();
    // we need to wait for the debugger thread !
    sleep(1);
    
    // find the dyld address
#if DEBUG
    printf("[DEBUG] Searching for the breakpoint address.\n");
#endif
    // read original byte
    mach_msg_type_number_t len = 1;
    mach_msg_type_number_t bytesread;
    uint64_t dyldAddress = get_dyldbase();
    uint64_t picAddress = find_picbase(dyldAddress);
    bpAddress = find_retaddress(picAddress);
    
    // install the breakpoint on dyld so we can hijack the entrypoint
#if DEBUG
    printf("[DEBUG] Inserting breakpoint at %x.\n", bpAddress);
#endif
    volatile uint8_t vmreadsymbol[] = {0x40,0x4c,0x4e,0x45,0x72,0x5b,0x40,0x72,0x5f,0x48,0x4c,0x49,0x2d};
    DECRYPT_STRING(13,vmreadsymbol,0x2d);
    mymach_vm_read = DLSYM_GET(vmreadsymbol);
    // FIXME: do we really need bpAddress to be global ?
    kr = (*mymach_vm_read)(myself, bpAddress, len, &originalopcode, &bytesread);
#if DEBUG
    EXIT_ON_MACH_ERROR("vm_read failure!", 1);
#endif
    // modify protection
    vm_prot_t writeProtection = VM_PROT_EXECUTE | VM_PROT_WRITE | VM_PROT_READ;
    vm_prot_t readProtection = VM_PROT_EXECUTE | VM_PROT_READ;
    JUNK_CODE3;
    volatile uint8_t vmprotectsymbol[] = {0x2e,0x22,0x20,0x2b,0x1c,0x35,0x2e,0x1c,0x33,0x31,0x2c,0x37,0x26,0x20,0x37,0x43};
    DECRYPT_STRING(16, vmprotectsymbol, 0x43);
    mymach_vm_protect = DLSYM_GET(vmprotectsymbol);
    
    kr = (*mymach_vm_protect)(myself, (mach_vm_address_t)bpAddress, (mach_vm_size_t)1, FALSE,  writeProtection);
#if DEBUG
    EXIT_ON_MACH_ERROR("vm_protect failure!", 1);
#endif
    EVIL_ASM3;
    // write the int3
	uint8_t opcode = 0xCC;
    volatile uint8_t vmwritesymbol[] = {0x61,0x6d,0x6f,0x64,0x53,0x7a,0x61,0x53,0x7b,0x7e,0x65,0x78,0x69,0x0c};
    DECRYPT_STRING(14, vmwritesymbol, 0xc);
    mymach_vm_write = DLSYM_GET(vmwritesymbol);
    kr = (*mymach_vm_write)(myself, bpAddress, (vm_offset_t)&opcode, len);
#if DEBUG
    EXIT_ON_MACH_ERROR("vm_write failure!", 1);
#endif

    // restore protection
    kr = (*mymach_vm_protect)(myself, (mach_vm_address_t)bpAddress, (mach_vm_size_t)1, FALSE, readProtection);
#if DEBUG
    EXIT_ON_MACH_ERROR("vm_protect failure!", 1);
#endif
    
    // after this we have a breakpoint triggered on jump to OEP
    // the debugger code will still be crypted
    // and only decrypted when debug loop is called
}



int main(int argc, const char * argv[])
{
    // the crackme code is at crackme.c
    // basically we ask for info here and compute the results there
    // that code will be crypted and protected by the exception handler
    // for example generate a div by 0 error
    printf(" ______                   __     _______            _____   ____   \n");
    printf("|      |.----.---.-.----.|  |--.|   |   |.-----.  _|  |  |_|_   |  \n");
    printf("|   ---||   _|  _  |  __||    < |       ||  -__| |_       _|_|  |_ \n");
    printf("|______||__| |___._|____||__|__||__|_|__||_____| |_       _|______|\n");
    printf("                                                   |__|__|         \n");
    printf("v%s                                                  (c) 2012, fG!\n", VERSION);
    printf("-------------------------------------------------------------------\n");
    
    if (argc > 1 && strcmp(argv[1], "-h") == 0)
    {
        printf("Help:\n");
        printf("---------------------------------------------------------------------------\n");
        printf("Welcome to my first Mac OS X crackme. I hope you enjoy it!\n");
        printf("This is an advanced crackme that is also a PoC for some fun tricks I found.\n");
        printf("Your objective is to retrieve a valid key for your name/handle/whatever.\n");
        printf("It's your choice on how to attack this. I have a few ideas on how to do it\n");
        printf("but I am curious to see yours.\n");
        printf("Please submit your solution(s) to reverser@put.as.\n");
        printf("I can keep them private if you wish so, else I will publish them\n\n");
        printf("To make it easier, this crackme accepts name and key as arguments.\n");
        printf("Syntax is:crackme name key\n");
        printf("Have fun!\nfG!\n");
        exit(0);
    }

    if (argc > 3 || argc == 2)
    {
        printf("[ERROR] Number of arguments is 2 (name and key)!\n");
        exit(1);
    }
    
    char nameString[257], *ptr_nameString = NULL;
    char keyString[32], *ptr_keyString = NULL;
    if (argc == 3)
    {
        strncpy(nameString, argv[1], 256);
        nameString[256] = '\00';
        strncpy(keyString, argv[2], 31);
        keyString[31] = '\00';
    }
    else
    {
        printf("Hello, what's your name?\n");
        // Get input data
        fflush(stdout);
        fgets(nameString, 256, stdin);
        if ((ptr_nameString = strchr(nameString, '\n')) != NULL)
        {
            *ptr_nameString = '\0';
        }
        
        fflush(stdout);
        printf("And the magic key is?\n");
        fgets(keyString, 31, stdin);
        if ((ptr_keyString = strchr(keyString, '\n')) != NULL)
        {
            *ptr_keyString = '\0';
        }
    }
    if (strlen(nameString) < 4)
    {
        printf("[ERROR] Name must be at least 4 chars long...\n");
        exit(1);
    }
    
    if (strlen(keyString) != 30)
    {
        printf("[ERROR] Key should be 30 chars long!\n");
        exit(1);
    }
    
    // check serial
    verify_key(&nameString[0], &keyString[0]);    
    exit(0);
}	
