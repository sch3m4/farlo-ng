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

#ifndef __FARLO_NG_MAIN_H__
#define __FARLO_NG_MAIN_H__

#include <pcap.h>
#include <assert.h>
#include <pthread.h>

#include "includes/wireless.h"

#define SAFE_CALLOC(a,n,t)  assert((a=(void*)calloc(n,t))!=0)
#define SAFE_FREE(a)        if(a!=0){free(a);a=0;}

#ifndef CHANNEL_HOPPING_DELAY
# define CHANNEL_HOPPING_DELAY  30  // miliseconds
#endif

// wireless channels
#define MAX_CHANNELS    13

typedef struct
{
	char			bssid[BSSID_LEN];
	unsigned short	encryption;
}filter_t,*pfilter_t;

typedef struct
{
	filter_t		filter;
    char            *source;
    unsigned short  live;
    pcap_t          *handle;
    int             dlt;
    size_t          table_size;
    char            *configpath;
    unsigned short  supported;
    int             dicfd;
    /* channel hopping */
    unsigned short	hopping;
    unsigned short  channels[MAX_CHANNELS]; //channels list
    unsigned long   delay;
    pthread_t       hoptid;

} settings_t,*psettings_t;

typedef struct
{
    pthread_mutex_t	mutex;
    pthread_cond_t	pcond;
    int				use;
} lock_t , *plock_t;

settings_t  settings;

#endif /* __FARLO_NG_MAIN_H__ */
