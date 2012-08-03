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

#ifndef __FARLO_NG_HTABLE_H__
# define __FARLO_NG_HTABLE_H__

#include "main.h"

/* linked list */
typedef struct _hash_node_
{
    struct _hash_node_	*next;
    void				*val;
    unsigned long		key;
} htnode_t , *phtnode_t;

/* hash table definition */
typedef struct
{
    size_t	table_size;
    phtnode_t *table;
} htable_t , *phtable_t;

/******************************************************************/
/** Hash Table implementation (collision resolution by chaining) **/
/******************************************************************/
unsigned long htable_sdbm_hash ( unsigned char *str );
phtable_t htable_map ( size_t size );
int htable_insert ( phtable_t ht  , unsigned long key , void *val );
void *htable_find ( phtable_t ht , unsigned long key );
void *htable_remove ( phtable_t ht , unsigned long key );
unsigned int htable_count ( phtable_t ht );
unsigned int htable_first ( phtable_t ht );
void htable_destroy ( phtable_t *ht );


void lock_access ( plock_t lock );
void unlock_access ( plock_t lock );
void free_lockaccess ( plock_t lock );

#endif /* __FARLO_NG_HTABLE_H__ */
