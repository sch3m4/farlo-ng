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
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <regex.h>

#include "includes/main.h"
#include "includes/ciphers.h"
#include "includes/algorithms.h"

#include "algorithms/thomson.h"

//@todo: brute-force 4/6 essid digits
static void thomson_algorithm ( const char *suffix , const unsigned int lpwd , const unsigned int lssid , struct crackdata *crack )
{
    char                    plain[13],pwd[65];
    const char              hexstr[]="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    size_t                  lenhex = strlen(hexstr);
    register unsigned int   j = 0 , k = 0,l = 0,m = 0;
    unsigned char           *tmp;

    for ( j = THOMSON_MIN_YEAR * 100 ; j < (THOMSON_MAX_YEAR + 1) * 100 && !crack->net->pwd.checked; j++ )
        for ( k = 0 ; k < lenhex && !crack->net->pwd.checked; k++ )
            for ( l = 0 ; l < lenhex && !crack->net->pwd.checked; l++ )
                for ( m = 0 ; m < lenhex && !crack->net->pwd.checked; m++ )
                {
                    snprintf ( plain , sizeof(plain) , "CP%04i%02X%02X%02X" , j , hexstr[k] , hexstr[l] , hexstr[m] );
                    get_sha1sum(plain,strlen(plain),pwd,sizeof(pwd));

                    if ( ! strcasecmp ( (char*)&pwd[strlen(pwd)-lssid] , suffix ) )
                    {
                        pwd[lpwd] = 0;
                        tmp = (unsigned char*) strdup ( (char*) pwd );
                        cbuffer_write(crack->buffer,(void*)tmp);
                    }
                }
    return;
}

void thomson_pwd ( struct crackdata *crack , unsigned int pattern )
{
    size_t lensuffix = 0;

    if ( pattern != THOMSON_MODEL_58X )
        return;

    switch ( toupper(crack->net->essid[0]) )
    {
    case 'S':
        lensuffix = 6;
        break;

    case 'B':
        lensuffix = 4;
        break;
    }

    thomson_algorithm(&crack->net->essid[10],10,lensuffix,crack);

    return;
}


