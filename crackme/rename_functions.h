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
 * rename_functions.h
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

#define OBFUSCATE 1

#if OBFUSCATE

#define init2                           llIllIIIlIlIIllIIIll
#define init                            IIlIIllllIllIllIIIll
#define sha2                            lllIIlIIllIIIllIIlIl
#define sha2_starts                     lIIlIlllIIlIIIIIlIlI
#define sha2_process                    llIlIllIIIIIIIIIllll
#define sha2_update						IIIIlIlllIllIlIIlIIl
#define sha2_finish                     llIlIIllllIIIlIlIlIl
#define decrypt_debugger_install		lIIlIlllllIIIlllIIII
#define install_debugger                IIIIllIlIIllIIIIllII
#define debug_loop                      IIIIllIIIIllIIIIllII
#define exception_handler				IIIIllIIIIllIIIIllIl
#define catch_mach_exception_raise		IlIIllIIIIllIIIIllIl
#define catch_mach_exception_raise_state    llIIllIIIlIIIIIIlllI
#define catch_mach_exception_raise_state_identity    IIllIIIllllIlIlIllIl
#define g                               IIIlIIIllIllllIIlIll
#define skip32                          lllIllIIIIIlIllIlIll
#define antidebug_check_mach_ports		llIlIIIIllllIIIIlIIl
#define antidebug_check_gdb_breakpoint	IIIIIIlIllIIIlllIlIl
#define antidebug_check_libtrick		lllIllIlllIIllIlIlIl
#define get_version                     lllIlIlIlIlIIIlIlIll
#define get_dyldbase                    IIIllIIIIllllIIIlllI
#define find_image                      llllllIIIllIllllIIll
#define find_processcpu                 IIlllIlllIIllllIIlll
#define find_processcpu2				IIIIllIIIIIIIIlIIllI
#define find_picbase                    IIIllllIIllIIllIIlII
#define find_retaddress                 IIIIIllIIIllIIIIIlIl
#define real_verify_key                 llIIlIllllIIlllIllIl
#define verify_key                      lIlllIIIlIIIIlIIlIIl

#define SALSA_keysetup                  IIllIllIllIllIIllllI
#define SALSA_ivsetup                   lIIIllIlllIIllllIlll
#define SALSA_encrypt_bytes				IllIlllIIllIIllIIIll
#define SALSA_decrypt_bytes             IllIlllIIllIIllIIIlI
#define SALSA_keystream_bytes			IllIlllIIllIIlllIIlI
#define salsa20_wordtobyte              llIIIIIlIlIIlIlIIlIl

#define _Xmach_exception_raise			IllIIllIIIlIIIlIlIII
#define _Xmach_exception_raise_state 	lIlllllIIllIllIlllll
#define _Xmach_exception_raise_state_identity				IIIIIlIlIlIIIlIlIIll

#define mach_exc_server                 llIlIIIIlIlllIllIlll
#define mach_exc_server_routine   		lllllIIllIlllllIIIlI

#define fnv_32_buf                      llIllIlIIlIlllIIlIll

#define RABBIT_keysetup                 IlllllllIlllllllIIlI
#define RABBIT_ivsetup                  lIIlIIllllllIllIIlII
#define RABBIT_process_bytes			IlllIlIIIIlIllllllII
#define RABBIT_keystream_bytes			IIllllIIllIIlIlIlIlI
#define RABBIT_process_blocks			lIIlIlIIllIlIIIlIIll
#define RABBIT_next_state               IIIIIlllIIIlIllIlIII
// variables & constants
#define originalopcode                  llIIllIlIlllIIllllIl
#define sha2_padding					IIlIlIIIIIlIIllIlIll
#define sigma                           IlIlIIlllIIIIllIlIII
#define tau                             lIlIIlIlIllllIIllIll
#define bpAddress                       llIlIlIIlIIIlllIlllI
#define keyskipjack                     IIlIllIlIIIllllIIlII
#define catch_mach_exc_subsystem		IIlIllIlIIIllIllIlII
#define exception_port					IIlIllIllIIllIllIlII
#define ftable                          IIlIllIllIIIIIllIlII
#define constants                       IlllIlllIlIlIllIlIII

#endif
