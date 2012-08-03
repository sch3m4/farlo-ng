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

#ifndef __FARLO_NG_NETWORK_PATTERNS_H__
# define __FARLO_NG_NETWORK_PATTERNS_H__

#include <sys/types.h>
#include <regex.h>

#include "wireless.h"
#include "algorithms.h"

typedef struct _pattern_
{
    struct _pattern_ *next;

    regex_t bssid;
    unsigned short  filter_bssid;

    regex_t essid;
    unsigned short  filter_essid;

    int     encryption;
    char    *name;

    palgorithm_t algorithm;
} pattern_t , *ppattern_t;

ppattern_t patterns;

static const char patterns_error[3][21] =
{
    "Document syntax error",
    "Empty document",
    "Root node error"
};
#define GET_PATTERNS_ERRSTR(val) (val<1||val>3)?NULL:patterns_error[val-1]

unsigned short load_network_patterns ();
void free_patterns ();
unsigned short net_allowed ( struct wnetwork *net );
void* gen_password ( void *p );

#endif /* __FARLO_NG_NETWORK_PATTERNS_H__ */
