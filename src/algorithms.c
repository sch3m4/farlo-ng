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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>

#include "includes/htable.h"
#include "includes/algorithms.h"
#include "includes/patterns.h"
#include "includes/crack.h"
#include "includes/ciphers.h"

#include "algorithms/zyxel.h"
#include "algorithms/wlanlike.h"
#include "algorithms/dlink.h"
#include "algorithms/huawei.h"
#include "algorithms/smc.h"
#include "algorithms/xavi.h"
#include "algorithms/thomson.h"
#include "algorithms/comtrendwpa.h"

phtable_t algorithms = 0;

algorithm_t initial[] =
{
    { GET_ZYXEL_KEY(ZYXEL_MODEL_P660HWB1A)      , ZYXEL_MODEL_P660HWB1A         , &zyxel_pwd },

    { GET_WLAN_KEY (ZYXEL_MODEL_P660HWD1)       , ZYXEL_MODEL_P660HWD1          , &wlan_like },
    { GET_WLAN_KEY(ZYXEL_MODEL_P6X0HW)          , ZYXEL_MODEL_P6X0HW            , &wlan_like },
    { GET_WLAN_KEY(ZYXEL_MODEL_P660HW_FTTH)     , ZYXEL_MODEL_P660HW_FTTH       , &wlan_like },
    { GET_WLAN_KEY(ZYXEL_MODEL_P660HW_D1)       , ZYXEL_MODEL_P660HW_D1         , &wlan_like },
    { GET_WLAN_KEY(COMTREND_MODEL_CT535)        , COMTREND_MODEL_CT535          , &wlan_like },
    { GET_WLAN_KEY(COMTREND_MODEL_AR5381U)      , COMTREND_MODEL_AR5381U        , &wlan_like },
    { GET_WLAN_KEY(COMTREND_MODEL_CT536T)       , COMTREND_MODEL_CT536T         , &wlan_like },
    { GET_WLAN_KEY(ZCOM_MODEL_GENERIC)          , ZCOM_MODEL_GENERIC            , &wlan_like },
    { GET_WLAN_KEY(HUAWEI_MODEL_HG520V_FTTH)    , HUAWEI_MODEL_HG520V_FTTH      , &wlan_like },
    { GET_WLAN_KEY(THOMSON_MODEL_GENERIC)       , THOMSON_MODEL_GENERIC         , &wlan_like },
    { GET_WLAN_KEY(XAVI_MODEL_7768R)            , XAVI_MODEL_7768R              , &wlan_like },
    { GET_WLAN_KEY(XAVI_MODEL_7968_SOLOS_461X)  , XAVI_MODEL_7968_SOLOS_461X    , &wlan_like },
    { GET_WLAN_KEY(ZYGATE_MODEL_GENERIC)        , ZYGATE_MODEL_GENERIC          , &wlan_like },

    { GET_DLINK_KEY(DLINK_MODEL_GENERIC)        , DLINK_MODEL_GENERIC           , &dlink_pwd },

    { GET_HUAWEI_KEY(HUAWEI_MODEL_HG5XX)        , HUAWEI_MODEL_HG5XX            , &huawei_pwd },

    { GET_SMC_KEY(SMC_MODEL_GENERIC)            , SMC_MODEL_GENERIC             , &smc_pwd },

    { GET_XAVI_KEY(XAVI_MODEL_ONO_7768R)        , XAVI_MODEL_ONO_7768R          , &xavi_pwd },

    { GET_THOMSON_MODEL(THOMSON_MODEL_58X)      , THOMSON_MODEL_58X             , &thomson_pwd },

    { GET_COMTREND_KEY(COMTREND_MODEL_WPAMAC)   , COMTREND_MODEL_WPAMAC         , &comtrend_pwd },
    { GET_COMTREND_KEY(COMTREND_MODEL_WPASSID)  , COMTREND_MODEL_WPASSID        , &comtrend_pwd },

};

void init_algorithms()
{
    unsigned int    i;
    unsigned long   key;
    size_t          nalg = sizeof(initial) / sizeof(*initial);

    /* definir los nombres de los algoritmos como numeros y acceder al array? */

    algorithms = htable_map(nalg);
    for ( i = 0 ; i < nalg ; i++ )
    {
        key = htable_sdbm_hash((unsigned char*)initial[i].name);
        htable_insert(algorithms,key,(void*)&(initial[i]));
    }
}

void free_algorithms()
{
    unsigned long   key;

    // free the stored networks
    if ( algorithms != 0 )
    {
        while ( ( key = htable_first(algorithms) ) != 0 )
            htable_remove(algorithms,key);

        // and the hash table
        htable_destroy(&algorithms);
    }
}

palgorithm_t get_algorithm ( const char *name )
{
    unsigned long key = htable_sdbm_hash((unsigned char*)name );

    return htable_find(algorithms,key);
}
