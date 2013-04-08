/*********************************************************************************
 * Copyright (c) 2012, Chema Garcia                                              *
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>

#include "includes/cbuffer.h"

void threads_init_lock ( struct lock_access *access )
{
    if ( !access )
        return;

    pthread_mutex_init ( & ( access->mutex ), 0 );
    pthread_cond_init ( & ( access->pcond ), 0 );
    access->init = 1;

    return;
}

void threads_free_lock ( struct lock_access *access )
{
    if ( !access || !access->init )
        return;

    pthread_mutex_destroy ( & ( access->mutex ) );
    pthread_cond_destroy ( & ( access->pcond ) );
    access->init = 0;

    return;
}

void threads_lock ( struct lock_access *access )
{
    if ( !access || !access->init )
        return;

    pthread_mutex_lock ( & ( access->mutex ) );
    while ( access->cond )
        pthread_cond_wait ( & ( access->pcond ) , & ( access->mutex ) );
    access->cond = 1;
    pthread_mutex_unlock ( & ( access->mutex ) );

    return;
}

void threads_unlock ( struct lock_access *access )
{
    if ( !access || !access->init )
        return;

    pthread_mutex_lock ( & ( access->mutex ) );
    access->cond = 0;
    pthread_cond_signal ( & ( access->pcond ) );
    pthread_mutex_unlock ( & ( access->mutex ) );

    return;
}

PCBuffer cbuffer_new ( size_t buffer_length , size_t entry_size )
{
    PCBuffer            ret;

    if ( !buffer_length || !entry_size )
        return 0;

    ret = (PCBuffer) calloc ( 1 , sizeof ( CBuffer ) );
    ret->size_buffer = buffer_length;
    ret->read = 0;
    ret->write = 0;

    ret->buffer = (void**) calloc ( ret->size_buffer + 1 , entry_size );

    threads_init_lock ( & ret->lock );

    sem_init ( & ( ret->s_data ), 0, 0 );
    sem_init ( & ( ret->s_space ), 0, ret->size_buffer );

    return ret;
}

void cbuffer_free ( PCBuffer buffer )
{
    if ( buffer == NULL )
        return;

    threads_lock ( & buffer->lock );

    sem_destroy ( & ( buffer->s_data ) );
    sem_destroy ( & ( buffer->s_space ) );

    threads_unlock ( & buffer->lock );
    threads_free_lock ( & buffer->lock );

    free ( buffer->buffer );
    free ( buffer );

    return;
}

size_t cbuffer_size ( PCBuffer buffer )
{
    int ret = 0;

    threads_lock(&buffer->lock);

    ret = buffer->size_buffer;

    threads_unlock(&buffer->lock);

    return ret;
}

void *cbuffer_read ( PCBuffer data, unsigned int force_wait , struct timespec *tv )
{
    void    *ret = 0;
    int     i = 0;

    if ( !data )
        return ret;

    if ( force_wait > 0 )
    {
        if ( ! tv )
            i = sem_wait ( & ( data->s_data ) );
        else
            i = sem_timedwait ( & ( data->s_data ) , tv );
    }
    else
        i = sem_trywait ( & ( data->s_data ) );

    if ( i == 0 )
    {
        threads_lock ( & data->lock );

        /* read buffer data */
        ret = data->buffer[data->read];

        /* set read pointer */
        if ( ++(data->read) >= data->size_buffer )
            data->read = 0;

        /* notify more space available */
        sem_post ( & ( data->s_space ) );

        threads_unlock ( & data->lock );
    }

    return ret;
}

void cbuffer_write ( PCBuffer data, void *item )
{
    if ( !data )
        return;

    sem_wait ( & ( data->s_space ) );
    threads_lock ( & data->lock );

    /* write the new item */
    data->buffer[data->write] = item;

    /* set write pointer */
    if ( ++(data->write) >= data->size_buffer )
        data->write = 0;

    sem_post ( & ( data->s_data ) );

    threads_unlock ( & data->lock );

    return;
}

int cbuffer_count ( PCBuffer data )
{
    int ret = 0;

    if ( !data )
        return ret;

    sem_getvalue( &(data->s_data) , &ret );

    return ret;
}
