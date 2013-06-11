/*
 *  ______ ______ _______ _______ _______ ______ _______ _______ ______ __ 
 * |   __ \   __ \       |_     _|    ___|      |_     _|       |   __ \  |
 * |    __/      <   -   | |   | |    ___|   ---| |   | |   -   |      <__|
 * |___|  |___|__|_______| |___| |_______|______| |___| |_______|___|__|__|
 *
 * v0.1
 *
 * Modify mach-o binaries to install our protection
 * - modify entrypoint
 * - modify segments offsets
 * - encrypt functions
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
#define DEBUG 1
#define MANGLE_OFFSETS 1
#define INJECT_FAKELIB 1

/*
 * Required steps:
 * 1) read and calculate the size and location of our functions
 * 2) encrypt the selected function
 */

struct headerInfo headerInfo;
struct symbolsInfo *symbolsInfo = NULL;
uint8_t myRandom[8];
uint32_t fakeLibStringLocation = 0;
uint32_t salt0 = 0x75750963;
uint32_t salt1 = 0x539d516b;
uint32_t salt2 = 0xfc0a2498;
uint32_t salt3 = 0xb57c81c4;

uint32_t oep = 0;

int main (int argc, const char * argv[])
{
    printf("  ______ ______ _______ _______ _______ ______ _______ _______ ______ __ \n");
    printf(" |   __ \\   __ \\       |_     _|    ___|      |_     _|       |   __ \\  |\n");
    printf(" |    __/      <   -   | |   | |    ___|   ---| |   | |   -   |      <__|\n");
    printf(" |___|  |___|__|_______| |___| |_______|______| |___| |_______|___|__|__|\n");
    printf(" v%s - (c) fG!, 2011. All rights reserved. - reverser@put.as\n", VERSION);
    printf("-------------------------------------------------------------------------\n");
    
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
    // generate a random number to modify the entrypoint
    // we truncate later for 32bits
    havege_state hs;
    uint8_t iv[8];
    havege_init(&hs);
    if(havege_random(&hs, iv, sizeof(myRandom)) != 0)
    {
        printf("[ERROR] random generator failed!\n");
        exit(1);
    }
    for (int x = 0; x < 2; x++)
    {
        havege_random(&hs, iv, sizeof(myRandom));
        printf("0x%08x 0x%08x\n", *(uint32_t*)iv, *(uint32_t*)(iv+4));
    }
    // we also search the fakelibstring inside here
    get_header_info(targetBuffer);
    //
    get_symbols_info(targetBuffer);
    
    // START ALL MODIFICATIONS TO HEADER, BECAUSE ITS CHECKSUM WILL BE A DECRYPTION KEY
    // mangle names, offsets and sizes
#if MANGLE_OFFSETS
    mangle_offsets(targetBuffer);
#endif
    
    // inject the fake dylib
#if INJECT_FAKELIB
    inject_fakelib(targetBuffer, fakeLibStringLocation);
#endif
    
    // build the salt array
    uint32_t salt[4];
    salt[0] = salt0;
    salt[1] = salt1;
    salt[2] = salt2;
    salt[3] = salt3;
    // encrypt all functions - this is the last stage of encryption and the first of decryption
    // this will be done in two stages, first we generate and collect the info
    // and encrypt at the end, because of the info storage at the mach-header
    
    // first 3 functions - start, main, init
    printf("[INFO] Generating encryption key from init2\n");
    uint8_t lastKey[28];
    memset(lastKey, 0, sizeof(lastKey));

    printf("[DEBUG] hashing init2 with size %x\n",symbolsInfo[3].size); 
    // sha224 hash of init2()
    sha2((uint8_t*)(targetBuffer+symbolsInfo[3].offset), symbolsInfo[3].size, lastKey, 1);
    // add the salt
    uint8_t *tempKey = malloc(sizeof(salt) + sizeof(lastKey));
    memcpy(tempKey, lastKey, 28);
    memcpy(tempKey+28, salt, sizeof(salt));
    // compute the final salted key
    sha2((uint8_t*)tempKey, 44, lastKey, 1);
    free(tempKey);
    
#if DEBUG
    printsha(&lastKey[0], 1);
#endif
        
    // store the init2 size at LC_UUID field :-)
    printf("Searching for LC_UUID to inject size\n");
    struct mach_header *machHeader = (struct mach_header*)targetBuffer;
    struct segment_command *segmentCmd = NULL;
    uint8_t *tempAddress = (targetBuffer + sizeof(struct mach_header));
    for (uint32_t i = 0; i < machHeader->ncmds; i++)
    {
        segmentCmd = (struct segment_command*)tempAddress;
        if (segmentCmd->cmd == LC_UUID)
        {
            printf("[DEBUG] Found LC_UUID! Size to inject will be %x\n", symbolsInfo[3].size);
            struct uuid_command *uuidCmd = (struct uuid_command*)segmentCmd;
            // we just need 16 bits to store the size
            *(uint16_t*)uuidCmd->uuid = (uint16_t)symbolsInfo[3].size;
            // create sha256 of real_verify_key()
            uint8_t key[32];
            // generate sha for the function that holds the encryption info - it's already salted by hardware registers
            generate_sha256key(targetBuffer, get_index(_real_verify_key), &key[0]);
            memcpy(&uuidCmd->uuid[2], key, 7);
        }
        // because we want init2() to be the first one to be executed
        // swap the mod_init_func order
        if (segmentCmd->cmd == LC_SEGMENT)
        {
            struct section *sectionCmd = (struct section*)((uint8_t*)segmentCmd + sizeof(struct segment_command));
            for (uint32_t x = 0; x < segmentCmd->nsects; x++)
            {
                if (sectionCmd->flags == 0x9)
                {
                    uint8_t *modInitFuncOffset = targetBuffer+sectionCmd->offset;
                    uint32_t init1 = *(uint32_t*)modInitFuncOffset;
                    uint32_t init2 = *(uint32_t*)(modInitFuncOffset+4);
                    *(uint32_t*)modInitFuncOffset = init2;
                    *(uint32_t*)(modInitFuncOffset+4) = init1;
                }
                sectionCmd++;
            }
        }
        tempAddress += segmentCmd->cmdsize;
    }
    // retrieve and store the necessary info for the outter encryption
#define NR_BLOCKS_TO_DECRYPT 3
    // each block requires address + size info, each is 32 bits long
    struct outterInfo
    {
        uint32_t offset;
        uint32_t size;
    };
    struct outterInfo outterInfo[NR_BLOCKS_TO_DECRYPT];
    
    printf("Encrypting first 3 functions...\n");
    // FIRST OUTTER BLOCK TO ENCRYPT
    uint32_t sizeToEncrypt = (uint32_t)symbolsInfo[3].offset - (uint32_t)symbolsInfo[0].offset;
    // store this info in the array so we can encrypt later
    outterInfo[0].size = sizeToEncrypt;
    outterInfo[0].offset = symbolsInfo[0].offset;
    printf("First block to encrypt %x and address %x\n", sizeToEncrypt, symbolsInfo[0].location);
    // store the info to decrypt at the header
    uint32_t encryptAddress = (uint32_t)targetBuffer + sizeof(struct mach_header) + (uint32_t)((struct mach_header*)targetBuffer)->sizeofcmds;
    printf("Encrypt address %x\n", encryptAddress);
    *(uint32_t*)encryptAddress = symbolsInfo[0].location;
    *(uint32_t*)(encryptAddress+4) = sizeToEncrypt;
    // advance to next place to store information
    encryptAddress += 8;
    
    // SECOND OUTTER BLOCK TO ENCRYPT
    // everything else, except that sha2 and rabbit functions!
    // find where sha2 starts and rabbit ends
    uint16_t shaStartIndex = 0;
    uint16_t rabbitStartIndex = 0;
    for (uint32_t i = 0; i < headerInfo.nrFunctions; i++)
    {
        if (strcmp(symbolsInfo[i].name, _sha2_process) == 0)
            shaStartIndex = i;
        if (strcmp(symbolsInfo[i].name, _RABBIT_process_bytes) == 0)
            rabbitStartIndex = i;
    }
    
    // first block to encrypt, from init2 till start of sha functions
    sizeToEncrypt = (uint32_t)symbolsInfo[shaStartIndex].offset - (uint32_t)symbolsInfo[4].offset;
    outterInfo[1].size = sizeToEncrypt;
    outterInfo[1].offset = symbolsInfo[4].offset;
    printf("Second block to encrypt size %x\n", sizeToEncrypt);
    // store information to decrypt
    *(uint32_t*)encryptAddress = symbolsInfo[4].location;
    *(uint32_t*)(encryptAddress+4) = sizeToEncrypt;
    // advance to next place to store information
    encryptAddress += 8;
    // THIRD OUTTER BLOCK TO ENCRYPT
    // the rest to encrypt is from rabbitStartIndex.offset + size till the end of the functions
    sizeToEncrypt = (uint32_t)symbolsInfo[headerInfo.nrFunctions-1].offset+(uint32_t)symbolsInfo[headerInfo.nrFunctions-1].size - ((uint32_t)symbolsInfo[rabbitStartIndex].offset + symbolsInfo[rabbitStartIndex].size);
    outterInfo[2].size = sizeToEncrypt;
    outterInfo[2].offset = symbolsInfo[rabbitStartIndex+1].offset;
    printf("Third block to encrypt size %x\n", sizeToEncrypt);
    // store information to decrypt
    *(uint32_t*)encryptAddress = symbolsInfo[rabbitStartIndex+1].location;
    *(uint32_t*)(encryptAddress+4) = sizeToEncrypt;

    uint16_t encryptedSize      = 0;
    uint32_t encryptedAddress   = 0;
    uint32_t addressToEncrypt   = 0;
    uint8_t led = 0;
    SALSA_ctx sctx;
    // find all addresses we are going to need below
    // we need addresses of install_debugger and debug_loop
    int32_t installDebuggerIndex    = get_index(_install_debugger);
    int32_t debugLoopIndex          = get_index(_debug_loop);
    int32_t exceptionHandlerIndex   = get_index(_exception_handler);
    int32_t catchMachExceptionIndex = get_index(_catch_mach_exception_raise);
    int32_t realVerifyKeyIndex      = get_index(_real_verify_key);
    
    printf("%d Indexes %d %d %d %d %d\n", headerInfo.nrFunctions, installDebuggerIndex, debugLoopIndex, exceptionHandlerIndex, catchMachExceptionIndex, realVerifyKeyIndex);
    /* 
     * encrypt real_verify_key
     * store info at catch_mach_exception_raise()
     */
    printf("[INFO] Starting to encrypt real_verify_key() (%d)\n", realVerifyKeyIndex);    
    // decryption info to store - index is of the function to be encrypted!
    encryptedSize = symbolsInfo[realVerifyKeyIndex].size;
    encryptedAddress = symbolsInfo[realVerifyKeyIndex].location;
    PRINT_ENCRYPTINFO(encryptedAddress, encryptedSize);
    // store info at catch_mach_exception_raise()
    store_cryptinfo(targetBuffer, catchMachExceptionIndex, 0x1810, 0, encryptedAddress, encryptedSize);
    uint8_t realVerifyKeyKey[32];
    // generate sha for the function that holds the encryption info - it's already salted by hardware registers
    generate_sha256key(targetBuffer, catchMachExceptionIndex, &realVerifyKeyKey[0]);
    // start encryption
    addressToEncrypt = (uint32_t)targetBuffer + symbolsInfo[realVerifyKeyIndex].offset;
    SALSA_keysetup(&sctx,realVerifyKeyKey,256,64);
    memcpy(iv, "devilRus", 8);
    SALSA_ivsetup(&sctx,iv);
    SALSA_encrypt_bytes(&sctx,(uint8_t*)addressToEncrypt, (uint8_t*)addressToEncrypt, symbolsInfo[realVerifyKeyIndex].size);
    printf("[INFO] End to encrypt real_verify_key()\n");
    
    /*
     * encrypt catch_mach_exception
     * store info at exception_handler()
     */
    printf("[INFO] Starting to encrypt catch_mach_exception() (%d)\n", catchMachExceptionIndex);    
    // decryption info to store - index is of the function to be encrypted!
    encryptedSize = symbolsInfo[catchMachExceptionIndex].size;
    encryptedAddress = symbolsInfo[catchMachExceptionIndex].location;
    PRINT_ENCRYPTINFO(encryptedAddress, encryptedSize);
    // store info at exception_handler()
    store_cryptinfo(targetBuffer, exceptionHandlerIndex, 0x4715, 1, encryptedAddress, encryptedSize);
    uint8_t cathMachExceptionKey[32];
    // generate sha for the function that holds the encryption info - it's already salted by hardware registers
    generate_sha256key(targetBuffer, exceptionHandlerIndex, &cathMachExceptionKey[0]);
    // start encryption
    addressToEncrypt = (uint32_t)targetBuffer + symbolsInfo[catchMachExceptionIndex].offset;
    SALSA_keysetup(&sctx,cathMachExceptionKey,256,64);
    memcpy(iv, "mercedes", 8);
    SALSA_ivsetup(&sctx,iv);
    SALSA_encrypt_bytes(&sctx,(uint8_t*)addressToEncrypt, (uint8_t*)addressToEncrypt, symbolsInfo[catchMachExceptionIndex].size);
    printf("[INFO] End to encrypt catch_mach_exception()\n");
    
    /*
     * encrypt exception_handler()
     * store info at debug_loop()
     */
    printf("[INFO] Starting to encrypt exception_handler() (%d)\n", exceptionHandlerIndex);
    // decryption info to store
    encryptedSize = symbolsInfo[exceptionHandlerIndex].size;
    encryptedAddress = symbolsInfo[exceptionHandlerIndex].location;
    PRINT_ENCRYPTINFO(encryptedAddress, encryptedSize);
    // store info at debug_loop()
    store_cryptinfo(targetBuffer, debugLoopIndex, 0x3134, 1, encryptedAddress, encryptedSize);
    uint8_t exceptionHandlerKey[32];
    generate_sha256key(targetBuffer, debugLoopIndex, &exceptionHandlerKey[0]);
    // start encryption
    addressToEncrypt = (uint32_t)targetBuffer + symbolsInfo[exceptionHandlerIndex].offset;
    SALSA_keysetup(&sctx,exceptionHandlerKey,256,64);
    memcpy(iv, "hackersz", 8);
    SALSA_ivsetup(&sctx,iv);
    SALSA_encrypt_bytes(&sctx,(uint8_t*)addressToEncrypt, (uint8_t*)addressToEncrypt, symbolsInfo[exceptionHandlerIndex].size);
    printf("[INFO] End to encrypt exception_handler()\n");
    
    /*
     encrypt debug_loop
     */
    printf("[INFO] Starting to encrypt debug_loop() (%d)\n", debugLoopIndex);
    
    // decryption info to store
    encryptedSize = symbolsInfo[debugLoopIndex].size;
    encryptedAddress = symbolsInfo[debugLoopIndex].location;
    // store the info at install_debugger
    store_cryptinfo(targetBuffer, installDebuggerIndex, 0x6969, 0, encryptedAddress, encryptedSize);
    // generate checksum for install_debugger
    uint8_t installDebuggerKey[32];
    generate_sha256key(targetBuffer, installDebuggerIndex, &installDebuggerKey[0]);
    // start encryption
    addressToEncrypt = (uint32_t)targetBuffer + symbolsInfo[debugLoopIndex].offset;
    SALSA_keysetup(&sctx,installDebuggerKey,256,64);
    memcpy(iv, "fastcars", 8);
    SALSA_ivsetup(&sctx,iv);
    SALSA_encrypt_bytes(&sctx,(uint8_t*)addressToEncrypt, (uint8_t*)addressToEncrypt, symbolsInfo[debugLoopIndex].size);
    printf("[INFO] End of encrypt debug_loop()\n");
    /*
     *  encrypt the debugger install
     */
    printf("[INFO] Starting to encrypt install_debugger()\n");
    // checksum the header to get the second key
    // allocate a temp buffer
    size_t headerBufferSize = sizeof(struct mach_header) + ((struct mach_header*)targetBuffer)->sizeofcmds;
    uint8_t *headerBuffer = malloc(headerBufferSize);
    memcpy(headerBuffer, targetBuffer, headerBufferSize);
    uint8_t debuggerKey[32];
    memset(debuggerKey, 0, sizeof(debuggerKey));
    
    sha2(headerBuffer, headerBufferSize, debuggerKey, 0);
    // add the salt
    tempKey = malloc(sizeof(salt) + sizeof(debuggerKey));
    memcpy(tempKey, debuggerKey, sizeof(debuggerKey));
    memcpy(tempKey+sizeof(debuggerKey), salt, sizeof(salt));
    // compute the final salted key
    sha2((uint8_t*)tempKey, sizeof(salt) + sizeof(debuggerKey), debuggerKey, 0);
    free(tempKey);

    printsha(&debuggerKey[0], 0);
    
    // and generate some random IV
    if(havege_random(&hs, iv, sizeof(myRandom)) != 0)
    {
        printf("[ERROR] random generator failed!\n");
        exit(1);
    }

    // start encrypting
    for (uint32_t i = 0; i < headerInfo.nrFunctions; i++)
    {
        if (strcmp(symbolsInfo[i].name, _install_debugger) == 0)
        {
            printf("Found target function to encrypt size is %x!\n", symbolsInfo[i].size);
            // 
            addressToEncrypt = (uint32_t)targetBuffer + symbolsInfo[i].offset;
            // start encryption
            SALSA_ctx ctx;
            SALSA_keysetup(&ctx,debuggerKey,256,64);
            SALSA_ivsetup(&ctx,iv);
            SALSA_encrypt_bytes(&ctx,(uint8_t*)addressToEncrypt, (uint8_t*)addressToEncrypt, symbolsInfo[i].size);
            // decryption info to store
            encryptedSize = symbolsInfo[i].size;
            encryptedAddress = symbolsInfo[i].location;
        }
    }
    led = 0;
    for (uint32_t i = 0; i < headerInfo.nrFunctions; i++)
    {
        if (strcmp(symbolsInfo[i].name, _decrypt_debugger_install) == 0)
        {
            for (uint32_t x = (uint32_t)targetBuffer+symbolsInfo[i].offset;
                 x < (uint32_t)targetBuffer+symbolsInfo[i].offset+symbolsInfo[i].size;
                 x++)
            {
                if ((*(uint32_t*)x & 0xffffff) == 0x31337)
                {
                        if (led)
                        {
                            *(uint32_t*)(x+4) = encryptedAddress;
                            *(uint32_t*)(x+8) = encryptedSize;
                            memcpy((uint8_t*)(x+12), iv, 8);
                            printf("Found at %x %x!\n", x, *(uint32_t*)(x+4));
                        }
                    led++;
                }
                
            }
        }
    }
    printf("[INFO] End to encrypt install_debugger()\n");
    /*
     * encrypt the outter layer
     * the info was computed at the beginning
     */
    RABBIT_ctx ctx;
    memcpy(iv,"funtimes",8);
    RABBIT_keysetup(&ctx, lastKey, 128, 64);
    RABBIT_ivsetup(&ctx, iv);
    for (uint16_t y = 0; y < NR_BLOCKS_TO_DECRYPT; y++)
    {
        uint8_t *toEncrypt = (uint8_t*)(targetBuffer+outterInfo[y].offset);
        RABBIT_encrypt_bytes(&ctx, toEncrypt, toEncrypt, outterInfo[y].size); 
    }
    // search where to store the info
    FILE *output = NULL;
    output = fopen("crap", "wb");
    fwrite(targetBuffer, fileSize, 1, output);
    fclose(output);
    free(symbolsInfo);
    free(targetBuffer);
    return 0;
}


// verify if it's a valid mach-o binary
void verify_macho(uint8_t *targetBuffer)
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
    
    havege_state hs;
    havege_init(&hs);
    if(havege_random(&hs, myRandom, sizeof(myRandom)) != 0)
    {
        printf("[ERROR] random generator failed!\n");
        exit(1);
    }

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
    thread_commandhead_t *threadCommand = NULL;
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
        // 32bits segments
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
                    }
                    // find where our fake lib string is located at
                    if (strcmp(section->sectname, "__cstring") == 0)
                    {
                        printf("[DEBUG] Found __cstring!\n");
                        uint32_t seekAddress = (uint32_t)(targetBuffer + section->offset);
                        uint32_t seekSize = (uint32_t)(targetBuffer + section->offset + section->size);
                        for ( ; seekAddress < seekSize; seekAddress += 1)
                        {
                            if ( *(uint32_t*)seekAddress == 0x7273752f)
                            {
                                fakeLibStringLocation = (uint32_t)((uint32_t)seekAddress - (uint32_t)targetBuffer);
                                printf("[DEBUG] Found string %s at %x\n", (char*)seekAddress, fakeLibStringLocation);
                                break;
                            }
                        }
                    }
                    section++;
                }
            }
            
        }
        // 64bits segments
        else if (loadCommand->cmd == LC_SEGMENT_64)
        {
            
        }
        // symtab
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
        // unix thread
        else if (loadCommand->cmd == LC_UNIXTHREAD)
        {
            threadCommand = (thread_commandhead_t*)(address);
            // find which type is it
            switch (threadCommand->flavor)
            {
                case x86_THREAD_STATE32:
                {
                    x86_thread_state32_t *threadState = (x86_thread_state32_t*)(address + sizeof(thread_commandhead_t));
                    oep = threadState->__eip;
                    printf("EiP is %x %x\n", threadState->__eip, *(uint32_t*)myRandom);
                    threadState->__eip = *(uint32_t*)myRandom;
                    break;
                }
            }            
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
    //    struct symbolsInfo symbolsInfo[nrFunctions];
    // allocate space for all the symbols
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
        printf("[%d] [Name]: %s [MemAddress]: %x [Size]: %x [Offset]: %x\n", x, symbolsInfo[x].name, symbolsInfo[x].location, symbolsInfo[x].size, symbolsInfo[x].offset);
    }
}


int struct_cmp(const void *a, const void *b)
{
    struct symbolsInfo *ia = (struct symbolsInfo*)a;
    struct symbolsInfo *ib = (struct symbolsInfo*)b;
    return (int)(ia->location - ib->location);
}
