/*
 *  ______ ______ _______ _______ _______ ______ _______ _______ ______ __
 * |   __ \   __ \       |_     _|    ___|      |_     _|       |   __ \  |
 * |    __/      <   -   | |   | |    ___|   ---| |   | |   -   |      <__|
 * |___|  |___|__|_______| |___| |_______|______| |___| |_______|___|__|__|
 *
 * Copyright (c) fG!, 2011, 2012, 2013. All rights reserved. - reverser@put.as - http://reverse.put.as
 *
 * helpers.h
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

#define PRINT_ENCRYPTINFO(address,end) \
printf("[DEBUG] Address to encrypt %x End %x\n", address, end);

extern struct symbolsInfo
{
    char *name;
    uint32_t size;
    uint32_t location;
    uint32_t offset;
};

extern struct headerInfo
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


void get_symbols_info(uint8_t *);
int32_t get_index(char *);
void printsha(uint8_t *, uint8_t);
void store_cryptinfo(uint8_t *targetBuffer, int32_t index, uint16_t identifier, uint8_t orientation, uint32_t encryptedAddress, uint16_t encryptedSize);
void generate_sha256key(uint8_t *targetBuffer, uint32_t index, uint8_t *key);
