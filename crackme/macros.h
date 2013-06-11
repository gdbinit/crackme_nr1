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
 * macros.h
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

#define DEBUG 0

#define CHECKVMREAD \
if (bytesRead == 0) { printf("[ERROR] mach_vm_read!\n"); exit(1); }

#define EXIT_ON_MACH_ERROR(msg, retval) \
if (kr != KERN_SUCCESS) { mach_error(msg ":" , kr); exit((retval)); }

#define FORCE_INLINE __attribute__((always_inline))

#define DECRYPT_STRING(x,y,z) \
for (int i = 0; i < x; i++) \
{ \
y[i] ^= z; \
}

#define DLSYM_GET(symbol) \
dlsym(RTLD_DEFAULT, (char*)symbol);

#define WRITEPROTECTION VM_PROT_EXECUTE | VM_PROT_WRITE | VM_PROT_READ
#define READPROTECTION VM_PROT_EXECUTE | VM_PROT_READ

#define EVIL_ASM1 \
asm(".intel_syntax noprefix"); \
asm __volatile__ ("call $+5\n\t" \
                  "pop edx\n\t" \
                  "add edx,7\n\t" \
                  ".byte 0xeb\n\t" \
                  "call edx\n\t" \
                  "pop edx\n\t" \
                  "xor edx,edx\n\t"); \
asm(".att_syntax prefix");

#define EVIL_ASM2 \
uint32_t evilvar; \
asm(".att_syntax prefix"); \
asm __volatile__("call 1f\n\t"  \
                 ".word 0x21eb\n\t" \
                 "1:\n\t" \
                 "pop %%eax\n\t" \
                 "mov %%eax, %0" \
                 : "=r" (evilvar) \
                 : \
                 :"eax"); \
asm(".att_syntax prefix");

#define EVIL_ASM3 \
asm(".intel_syntax noprefix"); \
asm __volatile__ ("call $+5\n\t" \
                  "pop edx\n\t" \
                  "add edx,7\n\t" \
                  ".byte 0xeb\n\t" \
                  "call edx\n\t" \
                  "pop edx\n\t" \
                  "xor edx,edx\n\t"); \
asm(".att_syntax prefix");

#define EVIL_ASM4 \
asm(".intel_syntax noprefix"); \
asm __volatile__ ("call $+7\n\t" \
                  ".word 0xc7eb\n\t" \
                  "pop eax\n\t" \
                  ); \
asm(".att_syntax prefix");

#define EVIL_ASM5 \
asm(".intel_syntax noprefix"); \
asm __volatile__ ("call $+5\n\t" \
                  "pop edx\n\t" \
                  "add edx,7\n\t" \
                  ".byte 0xeb\n\t" \
                  "jmp edx\n\t"); \
asm(".att_syntax prefix");

#define JUNK_CODE1 \
asm(".intel_syntax noprefix"); \
asm __volatile__ ("push eax\n\t" \
                  "push edx\n\t" \
                  "xor edx,0x90\n\t" \
                  "push edx\n\t" \
                  "sub edx, 0x80\n\t" \
                  "pop eax\n\t" \
                  "add eax, edx\n\t" \
                  "pop edx\n\t" \
                  "pop eax\n\t"); \
asm(".att_syntax prefix");                      

#define JUNK_CODE2 \
asm(".intel_syntax noprefix"); \
asm __volatile__ ("push eax\n\t" \
                  "xor eax,eax\n\t" \
                  "setpo al\n\t" \
                  "push edx\n\t" \
                  "xor edx, eax\n\t" \
                  "sal edx, 2\n\t" \
                  "xchg eax, edx\n\t" \
                  "or eax, ecx\n\t" \
                  "pop edx\n\t" \
                  "pop eax\n\t"); \
asm(".att_syntax prefix");

#define JUNK_CODE3 \
asm(".intel_syntax noprefix"); \
asm __volatile__ ("push eax\n\t" \
                  "mov eax, 0x5\n\t" \
                  "push edx\n\t" \
                  "xor edx, edx\n\t" \
                  "jz $+4\n\t" \
                  "int 0x80\n\t" \
                  "pop edx\n\t" \
                  "pop eax\n\t"); \
asm(".att_syntax prefix");

