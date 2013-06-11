/*
 *  ______ ______ _______ _______ _______ ______ _______ _______ ______ __
 * |   __ \   __ \       |_     _|    ___|      |_     _|       |   __ \  |
 * |    __/      <   -   | |   | |    ___|   ---| |   | |   -   |      <__|
 * |___|  |___|__|_______| |___| |_______|______| |___| |_______|___|__|__|
 *
 * Copyright (c) fG!, 2011, 2012, 2013. All rights reserved. - reverser@put.as - http://reverse.put.as
 *
 * helpers.c
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

#include "helpers.h"
extern uint32_t salt0;
extern uint32_t salt1;
extern uint32_t salt2;
extern uint32_t salt3;
extern struct symbolsInfo *symbolsInfo;
extern struct headerInfo headerInfo;
extern uint32_t oep;

void generate_sha256key(uint8_t *targetBuffer, uint32_t index, uint8_t *key)
{
    // build the salt array
    uint32_t salt[4];
    salt[0] = salt0;
    salt[1] = salt1;
    salt[2] = salt2;
    salt[3] = salt3;
    
    sha2((uint8_t*)((uint32_t)targetBuffer+symbolsInfo[index].offset), symbolsInfo[index].size, key, 0);
    // add the salt
    uint8_t *tempKey = malloc(sizeof(salt) + 32);
    memcpy(tempKey, key, 32);
    memcpy(tempKey+32, salt, sizeof(salt));
    // compute the final salted key
    sha2((uint8_t*)tempKey, sizeof(salt) + 32, key, 0);
    free(tempKey);
    printsha(&key[0], 0);
    
}

// orientation: 0 if info is stored on top, 1 if bottom
// index of the function where to store the info
// this will store info at the function that will decrypt next in the following format
// encrypted function address, encrypted function size, and function that decrypts size
void store_cryptinfo(uint8_t *targetBuffer, int32_t index, uint16_t identifier, uint8_t orientation, uint32_t encryptedAddress, uint16_t encryptedSize)
{
    uint8_t led = 0;
    uint32_t searchStart = (uint32_t)targetBuffer + symbolsInfo[index].offset;
    uint32_t searchEnd = (uint32_t)targetBuffer + symbolsInfo[index].offset + symbolsInfo[index].size;
    uint32_t foundAddress = 0;
    PRINT_ENCRYPTINFO(searchStart, searchEnd);
    for (uint32_t x = searchStart; x < searchEnd; x++)
    {
        if ((*(uint16_t*)x) == identifier)
        {
            if (orientation == 0)
            {
                if (led==0)
                {
                    foundAddress = x;
                    printf("Found top place to store crypt info at %x!\n", x);
                    break;
                }
                led++;
            }
            else
            {
                foundAddress = x;
                printf("Found bottom place to store crypt info at %x!\n", x);
            }
        }
    }
    *(uint32_t*)(foundAddress+4) = encryptedAddress;
    *(uint32_t*)(foundAddress+8) = encryptedSize;
    *(uint32_t*)(foundAddress+12) = symbolsInfo[index].size;
    // store the OEP
    if (identifier == 0x1810)
    {
        *(uint32_t*)(foundAddress+16) = oep;
    }
    printf("[DEBUG] Address to write encryption info to %x\n", (uint32_t)(foundAddress - (uint32_t)targetBuffer));
    
}

// dump the sha hash
void printsha(uint8_t *key, uint8_t type)
{
    // 1 is sha224
    if (type)
    {
        printf("[DEBUG] Sha224 header checksum:\n");
        for (int i = 0; i < 28; i++)
        {
            printf("%02x", key[i]);
        }
        
    }
    else
    {
        printf("[DEBUG] Sha256 header checksum:\n");
        for (int i = 0; i < 32; i++)
        {
            printf("%02x", key[i]);
        }
    }
    printf("\n");
}

// retrieve index from headerInfo structure array
int32_t get_index(char *lookupName)
{
    for (uint32_t i = 0; i < headerInfo.nrFunctions; i++)
    {
        if (strcmp(symbolsInfo[i].name, lookupName) == 0)
        {
            printf("[DEBUG] Found index for %s\n", lookupName);
            return i;
        }
    }
    return -1;
}
