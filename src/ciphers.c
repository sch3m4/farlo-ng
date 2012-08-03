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
#include <unistd.h>

#include "includes/wireless.h"
#include "includes/ciphers.h"

static unsigned long calc_crc( unsigned char * buf, int len)
{
    register unsigned long crc = 0xFFFFFFFF;

    for( ; len > 0; len--, buf++ )
        crc = crc_tbl[(crc ^ *buf) & 0xFF] ^ ( crc >> 8 );

    return( ~crc );
}

static unsigned short check_crc_buf( unsigned char *buf, int len )
{
    register unsigned long crc;

    crc = calc_crc(buf, len);
    buf+=len;
    return( ( ( crc       ) & 0xFF ) == buf[0] &&
            ( ( crc >>  8 ) & 0xFF ) == buf[1] &&
            ( ( crc >> 16 ) & 0xFF ) == buf[2] &&
            ( ( crc >> 24 ) & 0xFF ) == buf[3] );
}

unsigned short decrypt_wep( struct wnetwork *net , unsigned char *key, int keylen )
{
    RC4_KEY         S;
    unsigned short  ret = 0;

    memcpy ( net->pwd.datatmp , net->pwd.data , net->pwd.datalen );

    RC4_set_key( &S, keylen, key );
    RC4( &S, net->pwd.datalen, net->pwd.datatmp, net->pwd.datatmp );

    ret = check_crc_buf( net->pwd.datatmp, net->pwd.datalen - 4 );

    if ( ret && net->pwd.datalen > 10 )
    {
        net->pwd.decrypted = (unsigned char*)net->pwd.datatmp + 6;
        net->pwd.declen = net->pwd.datalen - 10;
    }

    return ret;
}

unsigned short verify_wep_key ( struct wnetwork *net , unsigned char *passwd )
{
    size_t          pwd_len = 0;
    unsigned char   K[PASSWD_LEN];

    pwd_len = strlen((const char*)passwd);

    memset ( K , 0 , sizeof ( K ));
    memcpy( K, &net->pwd.hdr , IV_LEN );
    memcpy( K + IV_LEN , passwd, pwd_len );

    net->pwd.found = decrypt_wep( net , K , IV_LEN + pwd_len );

    return net->pwd.found;
}

void get_md5sum ( char *string , size_t len , char *output , size_t out_len )
{
    EVP_MD_CTX      ctx;
    unsigned char   value[MD5_DIGEST_LENGTH];
    unsigned int    cph_len;
    register int    i;

    memset ( value, 0, sizeof ( value ) );
    memset ( output , 0 , out_len );

    EVP_DigestInit ( &ctx, EVP_md5 () );
    EVP_DigestUpdate ( &ctx, string, len );
    EVP_DigestFinal_ex ( &ctx, value, &cph_len );
    EVP_MD_CTX_cleanup ( &ctx );

    for ( i = 0; i < sizeof ( value ) && i*2 < out_len ; i++ )
        sprintf ( output + ( i * 2 ), "%02hx", value[i] );

    return;
}

void get_sha1sum ( char *string , size_t len , char *output , size_t out_len )
{
    EVP_MD_CTX      ctx;
    unsigned char   value[SHA_DIGEST_LENGTH];
    unsigned int    cph_len;
    register int    i;

    memset ( value, 0, sizeof ( value ) );
    memset ( output , 0 , out_len );

    EVP_DigestInit ( &ctx, EVP_sha1() );
    EVP_DigestUpdate ( &ctx, string, len );
    EVP_DigestFinal_ex ( &ctx, value, &cph_len );
    EVP_MD_CTX_cleanup ( &ctx );

    for ( i = 0; i < sizeof ( value ) && i*2 < out_len ; i++ )
        sprintf ( output + ( i * 2 ), "%02hx", value[i] );

    return;
}
