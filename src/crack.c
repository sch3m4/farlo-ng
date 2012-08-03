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

#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <semaphore.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "includes/main.h"
#include "includes/patterns.h"
#include "includes/crack.h"
#include "includes/cbuffer.h"
#include "includes/ciphers.h"

typedef struct _cqueue_
{
    struct _cqueue_ *next;
    struct wnetwork *net;
} cqueue_t , *pcqueue_t;

typedef struct
{
    pcqueue_t           first;
    pcqueue_t           last;
    struct lock_access  lock;
    sem_t               got;
    pthread_t           cracktid;
} crackqueue_t , *pcrackqueue_t;

crackqueue_t cqueue;

static char *read_line ( int fd , unsigned short *finish )
{
    char            c = 0;
    int             rd = 0;
    int             bytes = 0;
    size_t          tam = 255;
    char            *buffer,*aux;

    SAFE_CALLOC ( buffer , tam , sizeof ( char ) );
    *finish = 0;

    while ( ( rd = read(fd,&c,sizeof(c)) ) > 0 )
    {
        if ( c == '\r' ) /* supports CRLF */
            continue;
        if ( c == '\n' )
            break;

        if ( bytes >= tam -1 )
        {
            aux = buffer;
            tam = tam + tam / 2;
            SAFE_CALLOC ( buffer , tam , sizeof ( char ) );
            memcpy ( buffer , aux , bytes );
            SAFE_FREE ( aux );
        }

        buffer[bytes++] = c;
    }

    if ( ! bytes )
        SAFE_FREE(buffer);

    return buffer;
}

static void *crack_passwd ( void *p )
{
    struct crackdata    *crack = (struct crackdata*)p;
    unsigned  char      *item;
    unsigned short      locked = 0 , finish = 0;
    int                 fd = 0;
    char                nl='\n';

    while ( ( !locked || cbuffer_count(crack->buffer) > 0 ) && !finish )
    {
        if ( !locked && !pthread_mutex_trylock ( &crack->done ) )
            locked++;

        if ( !(item = cbuffer_read( crack->buffer , CBUFFER_NOFORCE_WAIT , 0 ) ) )
            continue;

        switch ( crack->net->encrypt )
        {
        case ENCRYPT_WEP:
            if ( ! verify_wep_key(crack->net,item) )
            {
                SAFE_FREE ( item );
                continue;
            }

            crack->net->pwd.passwd = item;
            crack->net->pwd.checked = 1;
            finish++;
            break;

            /* not supported yet */
        case ENCRYPT_WPA:
        case ENCRYPT_WPA2:
            /* save the passwords to file */
            if ( !crack->net->pwd.path[0])
                snprintf ( (char*)crack->net->pwd.path , sizeof ( crack->net->pwd ) , "dic_%s_%s" , crack->net->essid , crack->net->bssid );

            if ( !fd && (fd = open ( (char*)crack->net->pwd.path , O_CREAT | O_WRONLY | O_APPEND | O_NONBLOCK , S_IRUSR | S_IWUSR ) ) < 0 )
            {
                fprintf ( stderr , "\n[e] Cannot create \"%s\": %s" , crack->net->pwd.path , strerror(errno));
                finish++;
            }
            else
            {
                write(fd,item,strlen((char*)item));
                write(fd,&nl,sizeof(nl));
            }
            break;
        }
    }

    if ( fd )
        close(fd);

    pthread_exit(0);
    return 0;
}

static void crack_network ( struct wnetwork *net )
{
    struct crackdata    *crack;
    char                *tmp;
    unsigned short      finish;
    long int            elapsed,min,sec,msec;

    SAFE_CALLOC ( crack , 1 , sizeof ( struct crackdata ) );
    crack->buffer = cbuffer_new(DEFAULT_BUFFER_SIZE, sizeof ( unsigned char* ) );
    pthread_mutex_init ( &crack->done , 0 );
    pthread_mutex_lock ( &crack->done );

    crack->net = net;
    clock_gettime(CLOCK_REALTIME,&crack->tinit);

    pthread_create ( &crack->prodtid,0,gen_password, (void*) crack );
    pthread_create ( &crack->constid,0,crack_passwd,(void*) crack );

    pthread_join ( crack->constid , 0 );
    if ( pthread_tryjoin_np(crack->prodtid,0) != 0)
    {
        pthread_cancel(crack->prodtid);
        pthread_join ( crack->prodtid , 0 );
    }

    /* if the password was not found and we got a dictionary, try to crack the network by using the dictionary */
    if ( !net->pwd.found && settings.dicfd != 0 )
    {
        fprintf ( stderr , "\n[i] Trying dictionary attack against network %s (%s)\n" , net->essid , net->bssid );

        lseek ( settings.dicfd , 0 , SEEK_SET );

        /* make sure the mutex is locked (gen_password thread may not be clean, fix it) */
        pthread_mutex_trylock ( &crack->done );
        /* start the thread again */
        pthread_create ( &crack->constid,0,crack_passwd,(void*) crack );

        finish = 0;
        while ( !finish && !net->pwd.checked )
        {
            if ( ! (tmp = read_line ( settings.dicfd , &finish ) ) )
                continue;

            cbuffer_write( crack->buffer , (void*) tmp );
        }

        pthread_mutex_unlock(&crack->done);
        pthread_join ( crack->constid , 0 );
    }

    net->pwd.checked = 1;
    clock_gettime(CLOCK_REALTIME,&crack->tfinish);
    elapsed = crack->tfinish.tv_sec - crack->tinit.tv_sec;
    min = elapsed / 60;
    sec = elapsed - (min * 60 );
    msec = (crack->tfinish.tv_nsec - crack->tinit.tv_nsec) / 1000 / 1000 ;

    while ( ( tmp = (char*) cbuffer_read(crack->buffer,CBUFFER_NOFORCE_WAIT,0) ) )
        SAFE_FREE ( tmp );

    cbuffer_free(crack->buffer);
    pthread_mutex_destroy ( &crack->done );
    SAFE_FREE ( crack );
    net->pwd.inprogress = 0;

    if ( net->pwd.path[0] != 0 )
        fprintf ( stderr , "\n[C] Passwords dictionary created for network %s (%s)\n\t- Path: %s\n" , net->essid , net->bssid , net->pwd.path );
    else if ( net->pwd.found )
    {
        get_netinfo ( net->pwd.decrypted , net->pwd.declen , net );
        fprintf ( stderr , "\n[F] Network %s (%s) cracked!\n\t- Password: %s\n\t- IP:       %s\n\t- Network:  %s/%d\n\t- Elapsed time: %li min %li sec %li msec\n" , net->essid , net->bssid , net->pwd.passwd , net->ip , net->network , net->cidr , min , sec , msec);
    }
    else
        fprintf ( stderr , "\n[F] Network %s (%s) password not found! :-(\n" , net->essid , net->bssid );

    return;
}

void *crack_thread ( void *p )
{
    pcqueue_t       item;
    struct wnetwork *net;

    pthread_setcancelstate ( PTHREAD_CANCEL_ENABLE, NULL );
    pthread_setcanceltype ( PTHREAD_CANCEL_DEFERRED, NULL );

    while (1)
    {
        sem_wait ( &cqueue.got );
        threads_lock(&cqueue.lock);
        item = cqueue.first;
        cqueue.first = item->next;
        threads_unlock(&cqueue.lock);

        net = item->net;
        SAFE_FREE ( item );

        fprintf ( stderr , "\n[i] Cracking %s network %s (%s)\n" , GET_ENCRYPT_STRING(net->encrypt) , net->essid , net->bssid );

        crack_network(net);

        pthread_testcancel();
    }

    return 0;
}

void add_network_tocrack ( struct wnetwork *net )
{
    pcqueue_t item;

    SAFE_CALLOC ( item , 1 , sizeof ( cqueue_t) );

    item->net = net;

    threads_lock( &cqueue.lock );

    if ( ! cqueue.first )
        cqueue.first = cqueue.last = item;
    else
    {
        cqueue.last->next = item;
        cqueue.last = item;
    }

    threads_unlock( &cqueue.lock );
    sem_post ( &cqueue.got );

    return;
}

void init_crackqueue()
{
    memset ( &cqueue , 0 , sizeof ( crackqueue_t ) );
    threads_init_lock(&cqueue.lock);
    sem_init ( &cqueue.got , 0 , 0 );
    pthread_create( &cqueue.cracktid , 0 , crack_thread, 0 );
}

void finish_crackqueue()
{
    pcqueue_t item;

    pthread_cancel(cqueue.cracktid);
    pthread_join(cqueue.cracktid,0);

    while ( (item = cqueue.first) != 0 )
    {
        cqueue.first = item->next;
        SAFE_FREE ( item );
    }

    threads_free_lock(&cqueue.lock);
}
