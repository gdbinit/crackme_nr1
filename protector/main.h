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
 * Encrypt a (symbol table) function from a target mach-o binary
 * 
 * Copyright (c) fG!, 2011, 2012, 2013. All rights reserved. - reverser@put.as - http://reverse.put.as
 *
 * main.h
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
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/nlist.h>

#include <mach/machine.h>
//#include <mach/ppc/thread_status.h>
#include <mach/i386/thread_status.h>

#include "polarssl/config.h"
#include "polarssl/havege.h"
#include "polarssl/sha2.h"

#include "ecrypt-sync.h"

#include "rename_functions.h"

#define MALLOC_CHECK(variable) \
if (variable == NULL) { printf("[ERROR] Malloc failed! Exiting...\n"); exit(1); }

#define MALLOC(variable, size) \
variable = malloc(size); MALLOC_CHECK(variable);

#define PRINT_ENCRYPTINFO(address,size) \
printf("[DEBUG] Address to encrypt %x Size %x\n", address, size);

struct symbolsInfo
{
    char *name;
    uint32_t size;
    uint32_t location;
    uint32_t offset;
};

struct headerInfo
{
    uint8_t isFat;
    uint8_t is64bits;
    // FIXME to 64bits
    uint32_t textMax;
    uint32_t textVMAddr;
    uint32_t nrFunctions;
    struct symtab_command symtabCommand;
    uint32_t tableLocation;
};

typedef struct thread_commandhead
{
	uint32_t cmd;
	uint32_t cmdsize;
	uint32_t flavor;
	uint32_t count;
} thread_commandhead_t;

//prototypes
int struct_cmp(const void *, const void *);
void verify_macho(uint8_t *);
void get_header_info(uint8_t *);
void get_symbols_info(uint8_t *);


extern int32_t get_index(char *);
extern void printsha(uint8_t *, uint8_t);
extern void store_cryptinfo(uint8_t *targetBuffer, int32_t index, uint16_t identifier, uint8_t orientation, uint32_t encryptedAddress, uint16_t encryptedSize);
extern void generate_sha256key(uint8_t *targetBuffer, uint32_t index, uint8_t *key);
extern void mangle_offsets(uint8_t *);
extern void inject_fakelib(uint8_t *, uint32_t);
