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

#ifndef __FARLO_NG_WIRELESS_H__
# define __FARLO_NG_WIRELESS_H__

#include <pcap.h>

#ifndef DEFAULT_TABLE_SIZE
# define DEFAULT_TABLE_SIZE 255
#endif

#ifndef ESSID_LEN
# define ESSID_LEN   256
#endif

#ifndef BSSID_LEN
# define BSSID_LEN   18
#endif

#ifndef PASSWD_LEN
# define PASSWD_LEN  64
#endif

#define IS_BEACON(val,len)  ( len > 38 && ((unsigned int)((val)->protocol+(val)->type+(val)->subtype) == 0x08 ) )
#define IS_DATA(val)        ((val->type + val->subtype) == 2)
#define IS_FROM_AP(val)     ((val)->cap_info[0] & 0x01)
#define IS_ENCRYPTED(val)   ((val)->cap_info[0] & 0x0F)

/********************/
/** 802.11 Headers **/
/********************/
typedef struct
{
    unsigned char   version;
    unsigned short  len;
    unsigned int    present;
} radiotaphdr_t , *pradiotaphdr_t ;
typedef struct
{
    unsigned char fc[2];
    unsigned char id[2];
    unsigned char add1[6];
    unsigned char add2[6];
    unsigned char add3[6];
    unsigned char sc[2];
} wirelesshdr_t , *pwirelesshdr_t ;
typedef struct
{
    unsigned char protocol: 2;
    unsigned char type: 2;
    unsigned char subtype: 4;
    unsigned char to_ds: 1;
    unsigned char from_ds: 1;
    unsigned char more_frag: 1;
    unsigned char retry: 1;
    unsigned char pwr_mgt: 1;
    unsigned char more_data: 1;
    unsigned char prot: 1;
    unsigned char order: 1;
} framectrl_t , *pframectrl_t ;
typedef struct
{
    unsigned char timestamp[8];
    unsigned char beacon_interval[2];
    unsigned char cap_info[2];
} beaconhdr_t , *pbeaconhdr_t ;
#define IV_LEN 3
struct wep_header
{
    unsigned char    init_vector[IV_LEN];
    unsigned char    key;
};

/* tags */
#define TAG_VENDOR              0xDD
#define TAG_RSN_INFO            0x30
#define TAG_RATES               0x32
#define TAG_CHANNEL             0x03
#define TAG_SSID                0x00
/* encryption */
#define ENCRYPT_WEP             1
#define ENCRYPT_WPA             2
#define ENCRYPT_WPA2            3
#define ALL_ENCRYPTS            (ENCRYPT_WEP | ENCRYPT_WPA | ENCRYPT_WPA2)
static const char encrypts[3][5]=
{
    "WEP\0",
    "WPA\0",
    "WPA2\0"
};
#define GET_ENCRYPT_STRING(val) (val<1||val>3)?NULL:encrypts[val-1]

/* sure, not all of them are ciphers, but we will distinguish them as ciphers... */
#define CIPHER_RC4              1
#define CIPHER_TKIP             2
#define CIPHER_WRAP             3
#define CIPHER_CCMP             4
#define CIPHER_WEP104           5
static const char ciphers[5][7]=
{
    "RC4\0",
    "TKIP\0",
    "WRAP\0",
    "CCMP\0",
    "WEP104\0"
};
#define GET_CIPHER_STRING(val) (val<1||val>5)?NULL:ciphers[val-1]

/* autentication */
#define AUTH_OPEN   1
#define AUTH_MGT    2
#define AUTH_PSK    3
static const char auth_strings[3][5]=
{
    "Open\0",
    "MGT\0",
    "PSK\0"
};
#define GET_AUTH_STRING(val) (val<1||val>3)?NULL:auth_strings[val-1]

struct wpasswd
{
    unsigned char       checked;
    unsigned char       found;
    unsigned char       inprogress;
    unsigned char       *passwd;
    unsigned char       path[FILENAME_MAX];

    struct wep_header   hdr;
    unsigned char       *data;
    unsigned char       *datatmp;
    size_t              datalen;

    unsigned char       *decrypted;
    size_t              declen;
};

struct wnetwork
{
    unsigned char   allowed;

    char            bssid[BSSID_LEN];
    char            essid[ESSID_LEN];

    int             ssi;
    unsigned int    rate;
    unsigned int    channel;
    unsigned int    encrypt;
    unsigned int    cipher;
    unsigned int    auth;

    struct wpasswd  pwd;

    unsigned short  ip_class;
    char            ip[16];
    char            network[16];
    unsigned int    cidr;
};

void *channel_hopping ( void *param );
void get_netinfo ( unsigned char *pkt , size_t len , struct wnetwork *net );
void procPacket ( u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet );
void init_wireless ();
void finish_wireless();

#endif /* __FARLO_NG_WIRELESS_H__ */
