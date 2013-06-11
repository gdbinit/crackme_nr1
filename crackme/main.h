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
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_types.h> 
#include <mach/i386/thread_status.h> 
#include <mach/mach_vm.h>
#include <mach-o/loader.h>
#include <stdint.h>
#include <stdlib.h>
#include <mach/machine.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <getopt.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <signal.h>
// the required include for dealing with dyld_all_image_infos
#include <mach-o/dyld_images.h>
// for posix spawn stuff
#include <spawn.h>
#include <sys/wait.h>
#include "polarssl/config.h"
#include "polarssl/havege.h"
#include "polarssl/sha2.h"
#include "ciphers/ecrypt-sync.h"
#include "macros.h"
#include "rename_functions.h"

struct my_thread_command
{
	uint32_t cmd;
	uint32_t cmdsize;
	uint32_t flavor;
	uint32_t count;
	union 
	{
		x86_thread_state32_t	x86_thread_state;
		x86_thread_state64_t	x64_thread_state;
	} state;
};

extern uint64_t get_dyldbase(void);
extern mach_vm_address_t find_picbase(uint64_t);
extern mach_vm_address_t find_retaddress(mach_vm_address_t);

extern int _dyld_func_lookup(const char* dyld_func_name, void** address);
void init(void) __attribute__ ((constructor));
void init2(void) __attribute__ ((constructor));

extern void test_skipjack(void);
mach_vm_address_t bpAddress;
void merdax(void);
void list_exceptionports(void);

extern void antidebug_check_gdb_breakpoint(void);
extern void antidebug_check_mach_ports(void);
extern void install_debugger(void);
extern void decrypt_debugger_install(void);
void antidebug_check_libtrick(void);
extern void verify_key(char *nameString, char *keyString);
