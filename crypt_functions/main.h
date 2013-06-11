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
 * (c) fG!, 2011. All rights reserved. - reverser@put.as
 *
 * main.h
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
#include <mach/ppc/thread_status.h>
#include <mach/i386/thread_status.h>

#define MALLOC_CHECK(variable) \
if (variable == NULL) { printf("[ERROR] Malloc failed! Exiting...\n"); exit(1); }

#define MALLOC(variable, size) \
variable = malloc(size); MALLOC_CHECK(variable);

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
    uint64_t textMax;
    uint64_t textVMAddr;
    uint32_t nrFunctions;
    struct symtab_command symtabCommand;
    uint32_t tableLocation;
};

//prototypes
int struct_cmp(const void *, const void *);
void verify_macho(uint8_t *);
void get_header_info(uint8_t *);
void get_symbols_info(uint8_t *);
