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
 * encryption.h
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

#include <stdint.h>
#include <stdio.h>
#include "rename_functions.h"

typedef uint8_t	BYTE; /* 8 bits */
typedef uint16_t	WORD; /* 16 bits */

WORD g(BYTE *, int , WORD );
void skip32(BYTE key[10], BYTE buf[4], int);
void test_skipjack(void);
