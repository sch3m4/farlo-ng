/*********************************************************************************
 * Copyright (c) 2009, Chema Garcia                                              *
 * All rights reserved.                                                          *
 *                                                                               *
 * Redistribution and use in source and binary forms, with or                    *
 * without modification, are permitted provided that the following               *
 * conditions are met:                                                           *
 *                                                                               *
 *    * Redistributions of source code must retain the above                     *
 *      copyright notice, this list of conditions and the following              *
 *      disclaimer.                                                              *
 *                                                                               *
 *    * Redistributions in binary form must reproduce the above                  *
 *      copyright notice, this list of conditions and the following              *
 *      disclaimer in the documentation and/or other materials provided          *
 *      with the distribution.                                                   *
 *                                                                               *
 *    * Neither the name of the SafetyBits nor the names of its contributors may *
 *      be used to endorse or promote products derived from this software        *
 *      without specific prior written permission.                               *
 *                                                                               *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"   *
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE     *
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE    *
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE     *
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR           *
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF          *
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS      *
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN       *
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)       *
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE    *
 * POSSIBILITY OF SUCH DAMAGE.                                                   *
 *********************************************************************************/

#ifndef __FARLO_NG_CBUFFER_H__
# define __FARLO_NG_CBUFFER_H__

struct lock_access
{
    pthread_mutex_t mutex;
    pthread_cond_t  pcond;
    int             cond;
    unsigned short  init;
};

/* estructura del buffer circular */
typedef struct cyclic_buffer CBuffer, *PCBuffer;

#define CBUFFER_NOFORCE_WAIT   0
#define CBUFFER_FORCE_WAIT     1

void threads_init_lock ( struct lock_access *access );
void threads_free_lock ( struct lock_access *access );
void threads_lock ( struct lock_access *access );
void threads_unlock ( struct lock_access *access );

int cbuffer_count ( PCBuffer data );
void cbuffer_write ( PCBuffer data, void *item );
void *cbuffer_read ( PCBuffer data, unsigned int force_wait , struct timespec *tv );
size_t cbuffer_size ( PCBuffer buffer );
void cbuffer_free ( PCBuffer buffer );
PCBuffer cbuffer_new ( size_t buffer_length , size_t entry_size );


#endif /* __FARLO_NG_CBUFFER_H__ */

