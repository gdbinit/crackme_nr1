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
 * dlsymprototypes.h
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

kern_return_t (*mymach_vm_read)(vm_map_t target_task,mach_vm_address_t address,mach_vm_size_t size,vm_offset_t *data,mach_msg_type_number_t *dataCnt);    
kern_return_t (*mymach_vm_protect)(vm_map_t target_task,mach_vm_address_t address,mach_vm_size_t size,boolean_t set_maximum,vm_prot_t new_protection);
kern_return_t (*mymach_vm_write)(vm_map_t target_task,mach_vm_address_t address,vm_offset_t data,mach_msg_type_number_t dataCnt);

kern_return_t (*mythread_get_state)(thread_act_t target_act,thread_state_flavor_t flavor,thread_state_t old_state,mach_msg_type_number_t *old_stateCnt);
kern_return_t (*mythread_set_state)(thread_act_t target_act,thread_state_flavor_t flavor,thread_state_t new_state,mach_msg_type_number_t new_stateCnt);
kern_return_t (*mytask_set_state)(task_t task,thread_state_flavor_t flavor,thread_state_t new_state,mach_msg_type_number_t new_stateCnt);
kern_return_t (*mytask_threads)(task_t target_task,thread_act_array_t *act_list,mach_msg_type_number_t *act_listCnt);
kern_return_t (*myvm_region_recurse_64)(vm_map_t target_task,vm_address_t *address,vm_size_t *size,natural_t *nesting_depth,vm_region_recurse_info_t info,mach_msg_type_number_t *infoCnt);

void* (*mymemcpy)(void *restrict s1, const void *restrict s2, size_t n);
