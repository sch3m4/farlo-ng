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

#ifndef __WLAN_LIKE_H__
#define __WLAN_LIKE_H__

#include "includes/wireless.h"
#include "includes/crack.h"

#define COMTREND_MODEL_AR5381U      1   /* OK */
#define COMTREND_MODEL_CT536T       2   /* OK */
#define COMTREND_MODEL_CT535        3   /* OK */

#define ZCOM_MODEL_GENERIC          4

#define ZYXEL_MODEL_P660HWD1        5
#define ZYXEL_MODEL_P6X0HW          6
#define ZYXEL_MODEL_P660HW_FTTH     7
#define ZYXEL_MODEL_P660HW_D1       8

#define HUAWEI_MODEL_HG520V_FTTH    9

#define THOMSON_MODEL_GENERIC       10

#define XAVI_MODEL_7768R            11
#define XAVI_MODEL_7968_SOLOS_461X  12

#define ZYGATE_MODEL_GENERIC        13

static const char wlan_algorithm_keys[][21] =
{
    "COMTREND_AR_5381U\0",  /* SI */
    "COMTREND_CT_536T\0",   /* SI */
    "COMTREND_CT_535\0",    /* SI */
    "ZCOM_GENERIC\0",       /* SI */
    "ZYXEL_P660HWD1\0",     /* SI */
    "ZYXEL_P6X0HW\0",       /* SI */
    "ZYXEL_P660HWFTTH\0",   /* SI */
    "ZYXEL_P660HW_D1\0",    /* SI */
    "HG520V_FTTH\0",        /* SI */
    "TH_GENROUTER\0",       /* SI */
    "XAVI_7768R\0",         /* SI */
    "XAVI_7968RD461X\0",    /* SI */
    "ZYGATE_GENERIC\0",     /* SI */

};
#define GET_WLAN_KEY(val)   (val<1||val>13)?0:wlan_algorithm_keys[val-1]

void wlan_like ( struct crackdata *crack , unsigned int pattern );

#endif /* __WLAN_LIKE_H__ */
