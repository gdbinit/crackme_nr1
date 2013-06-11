/*
 *  ______ ______ _______ _______ _______ ______ _______ _______ ______ __
 * |   __ \   __ \       |_     _|    ___|      |_     _|       |   __ \  |
 * |    __/      <   -   | |   | |    ___|   ---| |   | |   -   |      <__|
 * |___|  |___|__|_______| |___| |_______|______| |___| |_______|___|__|__|
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

#define _init2                              "_llIllIIIlIlIIllIIIll"
#define _init                               "_IIlIIllllIllIllIIIll"
#define _sha2                               "_lllIIlIIllIIIllIIlIl"
#define _sha2_starts                        "_lIIlIlllIIlIIIIIlIlI"
#define _sha2_process                       "_llIlIllIIIIIIIIIllll"
#define _sha2_update                        "_IIIIlIlllIllIlIIlIIl"
#define _sha2_finish                        "_llIlIIllllIIIlIlIlIl"
#define _decrypt_debugger_install           "_lIIlIlllllIIIlllIIII"
#define _install_debugger                   "_IIIIllIlIIllIIIIllII"
#define _debug_loop                         "_IIIIllIIIIllIIIIllII"
#define _exception_handler                  "_IIIIllIIIIllIIIIllIl"
#define _catch_mach_exception_raise         "_IlIIllIIIIllIIIIllIl"
#define _catch_mach_exception_raise_state    "_llIIllIIIlIIIIIIlllI"
#define _catch_mach_exception_raise_state_identity    "_IIllIIIllllIlIlIllIl"
#define _g                                  "_IIIlIIIllIllllIIlIll"
#define _skip32                             "_lllIllIIIIIlIllIlIll"
#define _antidebug_check_mach_ports         "_llIlIIIIllllIIIIlIIl"
#define _antidebug_check_gdb_breakpoint     "_IIIIIIlIllIIIlllIlIl"
#define _antidebug_check_libtrick           "_lllIllIlllIIllIlIlIl"
#define _get_version                        "_lllIlIlIlIlIIIlIlIll"
#define _get_dyldbase                       "_IIIllIIIIllllIIIlllI"
#define _find_image                         "_llllllIIIllIllllIIll"
#define _find_processcpu                    "_IIlllIlllIIllllIIlll"
#define _find_processcpu2                   "_IIIIllIIIIIIIIlIIllI"
#define _find_picbase                       "_IIIllllIIllIIllIIlII"
#define _find_retaddress                    "_IIIIIllIIIllIIIIIlIl"
#define _real_verify_key                    "_llIIlIllllIIlllIllIl"
#define _verify_key                         "_lIlllIIIlIIIIlIIlIIl"

#define _RABBIT_keysetup                    "_lllllllIlllllllIIlI"
#define _RABBIT_ivsetup                     "_lIIlIIllllllIllIIlII"
#define _RABBIT_process_bytes               "_IlllIlIIIIlIllllllII"
#define _RABBIT_keystream_bytes             "_IIllllIIllIIlIlIlIlI"
#define _RABBIT_process_blocks              "_lIIlIlIIllIlIIIlIIll"

// variables
#define originalopcode                  llIIllIlIlllIIllllIl

#endif
