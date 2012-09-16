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
#include <stdlib.h>
#include <ctype.h>
#include <pthread.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <linux/wireless.h>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <pcap.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <sqlite3.h>
#include <regex.h>
#include <linux/wireless.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

#include <sys/ioctl.h>
#include <unistd.h>

#include "includes/main.h"
#include "includes/wireless.h"
#include "includes/htable.h"
#include "includes/patterns.h"
#include "includes/crack.h"

#define IP_CLASS_A  1
#define IP_CLASS_B  2
#define IP_CLASS_C  3

phtable_t networks = 0;

struct ip
{
    u_int8_t ip_vhl;
    u_int8_t ip_tos;			/* type of service */
    u_short ip_len;			/* total length */
    u_short ip_id;			/* identification */
    u_short ip_off;			/* fragment offset field */
    u_int8_t ip_ttl;			/* time to live */
    u_int8_t ip_p;			/* protocol */
    u_short ip_sum;			/* checksum */
    u_int32_t ip_src, ip_dst;	/* source and dest address */
};

void init_wireless ()
{
    // map the hash table
    networks = htable_map( settings.table_size );
}

void finish_wireless()
{
    struct wnetwork *net;
    unsigned long   key;

    // free the stored networks
    if ( networks != 0 )
    {
        while ( ( key = htable_first(networks) ) != 0 )
        {
            net = htable_remove(networks,key);

            SAFE_FREE ( net->pwd.data );
            SAFE_FREE ( net->pwd.datatmp );
            SAFE_FREE ( net );
        }

        // and the hash table
        htable_destroy(&networks);
    }
}

void *channel_hopping ( void *param )
{
    int i, fd;
    struct iwreq wrq;

    fd = pcap_fileno ( settings.handle );

    pthread_setcancelstate ( PTHREAD_CANCEL_ENABLE, NULL );
    pthread_setcanceltype ( PTHREAD_CANCEL_DEFERRED, NULL );

    while ( 1 )
        for ( i = 0; i < MAX_CHANNELS; i++ )
        {
            if ( ! settings.channels[i] )
                continue;

            memset ( &wrq, 0, sizeof ( struct iwreq ) );
            strncpy ( wrq.ifr_name , settings.source , IFNAMSIZ );
            wrq.u.freq.m = ( double ) i + 1;
            wrq.u.freq.e = ( double ) 0;

            if ( ioctl ( fd, SIOCSIWFREQ, &wrq ) < 0 )
                fprintf ( stderr , "\n[e] Error (%d) setting interface channel %d: %s" , errno , i + 1 , strerror ( errno ) );

            usleep ( settings.delay * 1000 );

            pthread_testcancel();
        }

    return 0;
}

void get_netinfo ( unsigned char *pkt , size_t len , struct wnetwork *net )
{
    struct ip   *ip = 0;
    unsigned short found = 0 , count = 0;
    unsigned int ip1 = 0,ip2 = 0;
    unsigned int addr = 0 , mask = 0;

    switch ( ntohs(*(unsigned short*)pkt ) )
    {
    case ETHERTYPE_IP:
        ip = (struct ip*)((unsigned char*)pkt + sizeof(unsigned short));

        if ( 4*(ip->ip_vhl & 0x0F) < sizeof(struct ip) )
            break;

        if ( len - ((void*)ip - (void*)pkt) < sizeof ( struct ip) )
            break;

        ip1 = ip->ip_dst;
        ip2 = ip->ip_src;
        break;

    case ETHERTYPE_ARP:
        if ( len < sizeof(unsigned short) + 0x2A )
            return;

        ip1 = *(unsigned int*)((unsigned char*)pkt + sizeof(unsigned short)+0x26);
        ip2 = *(unsigned int*)((unsigned char*)pkt + sizeof(unsigned short)+0x1D);
        break;

    case ETHERTYPE_IPV6:
        fprintf ( stderr , "\n[W] get_netinfo(): IPv6 not implemented");
        break;

    default:
        fprintf ( stderr , "\n[W] get_netinfo(): Don't know what is %02X" , ntohs(*(unsigned short*)pkt ) );
        break;
    }

    if ( ! ip1 || ! ip2 )
        return;

    while ( !found && count < 2 )
    {
        if ( count == 0 )
            addr = ip1;
        else
            addr = ip2;

        switch ( ntohl(addr) >> 24 )
        {
        case 10:
            net->ip_class = IP_CLASS_A;
            mask = addr & 0xFF;
            net->cidr = 8;
            found++;
            break;

        case 172:
            net->ip_class = IP_CLASS_B;
            mask = addr & 0xFFFF;
            net->cidr = 16;
            found++;
            break;

        case 192:
            net->ip_class = IP_CLASS_C;
            mask = addr & 0xFFFFFF;
            net->cidr = 24;
            found++;
            break;
        }

        count++;
    }

    if ( found )
    {
        snprintf ( net->ip , sizeof(net->ip ) , "%s" , inet_ntoa ( *(struct in_addr*)&addr ) );
        snprintf ( net->network , sizeof(net->ip ) , "%s" , inet_ntoa ( *(struct in_addr*)&mask ));
    }
    else
        snprintf ( net->ip , sizeof (net->ip) , "N/A");

    return;
}

/* based on airodump-ng */
static void get_beacon_info ( unsigned char *tagged , unsigned char *aux , struct wnetwork *net )
{
    int type = 0 , len = 0 , i = 0;
    int align = 0;
    unsigned int numuni , numauth;
    unsigned char *orig;

    net->encrypt = ENCRYPT_WEP;
    net->auth = AUTH_OPEN;
    net->cipher = CIPHER_RC4;

    while ( tagged < aux )
    {
        type = tagged[0];
        len = tagged[1];

        if ( (void*)tagged + 2 + len > (void*)aux )
            break;

        if ( len == 0 )
        {
            tagged += 2;
            continue;
        }

        if ( type == TAG_RSN_INFO || ( type == TAG_VENDOR && len > 8 && memcmp ( tagged+2 , "\x00\x50\xF2\x01\x01\x00", 6) == 0) )
        {
            orig = tagged;
            align = 0;

            if ( type == TAG_VENDOR )
            {
                net->encrypt = ENCRYPT_WPA;
                align = 4;
            }

            if ( type == TAG_RSN_INFO )
            {
                net->encrypt = ENCRYPT_WPA2;
                align = 0;
            }

            if ( len < 18 + align )
            {
                tagged += 2+len;
                continue;
            }

            if( tagged+9+align > aux )
                break;

            numuni  = tagged[8+align] + (tagged[9+align]<<8);

            if( tagged+ (11+align) + 4*numuni > aux)
                break;

            numauth = tagged[(10+align) + 4*numuni] + (tagged[(11+align) + 4*numuni]<<8);

            tagged += (10+align);

            if( type == TAG_VENDOR )
            {
                if( tagged + (4*numuni) + (2+4*numauth) > aux)
                    break;
            }
            else
            {
                if( tagged + (4*numuni) + (2+4*numauth) + 2 > aux)
                    break;
            }

            for(i=0; i<numuni; i++)
            {
                switch(tagged[i*4+3])
                {
                case 0x01:
                    net->encrypt  = ENCRYPT_WEP;
                    net->cipher = CIPHER_RC4;
                    break;

                case 0x02:
                    net->cipher = CIPHER_TKIP;
                    break;

                case 0x03:
                    net->cipher = CIPHER_WRAP;
                    break;

                case 0x04:
                    net->cipher = CIPHER_CCMP;
                    break;

                case 0x05:
                    net->cipher = CIPHER_WEP104;
                    break;

                default:
                    break;
                }
            }

            tagged += 2+4*numuni;

            for(i=0; i<numauth; i++)
            {
                switch(tagged[i*4+3])
                {
                case 0x01:
                    net->auth = AUTH_MGT;
                    break;

                case 0x02:
                    net->auth = AUTH_PSK;
                    break;

                default:
                    net->auth = AUTH_OPEN;
                    break;
                }
            }

            tagged += 2+4*numauth;

            if( type == TAG_RSN_INFO )
                tagged += 2;

            tagged = orig + len + 2;

        }
        else if ( type == TAG_RATES )
        {
            int k=0;
            unsigned int rate = 0;

            for ( k = 0 ; k < len ; k++)
            {
                rate = ((unsigned int) *(tagged+k+2)) >> 1;
                if ( net->rate < rate )
                    net->rate = rate;
            }
        }
        else if ( type == TAG_CHANNEL && len == 1 )
            net->channel = (unsigned int) *(tagged + 2);

        else if ( type == TAG_SSID )
        {
            if ( len > sizeof ( net->essid) )
            {
#ifndef NOT_WARN_BAD_SSID
                fprintf ( stderr , "\n[!] Too long SSID for %s (%d)" , net->bssid , len );
#endif
                continue;
            }
            else
                memcpy ( net->essid , tagged + 2 , len );
        }

        tagged += len+2;
    }

    return;
}

static void show_network ( struct wnetwork *net )
{
    fprintf ( stderr , "\n[i] %s (%s)" , net->essid , net->bssid );
    fprintf ( stderr , "\n\t- Channel: %d" , net->channel );

    if ( ! net->rate )
        fprintf ( stderr , "\n\t- Rate: N/A");
    else
        fprintf ( stderr , "\n\t- Rate: %d Mbps" , net->rate );

    fprintf ( stderr , "\n\t- Encryption: %s" , GET_ENCRYPT_STRING ( net->encrypt ) );
    fprintf ( stderr , "\n\t- Cipher: %s" , GET_CIPHER_STRING ( net->cipher ) );
    fprintf ( stderr , "\n\t- Auth: %s" , GET_AUTH_STRING ( net->auth ) );
    fprintf ( stderr , "\n\t- Supported: %s\n" , net->allowed?"Yes":"No");
}

void procPacket ( unsigned char *arg, const struct pcap_pkthdr *pkthdr, const unsigned char *packet )
{
    unsigned int        offset = 0, i, delta = 0;
    pradiotaphdr_t      radio = 0;
    pwirelesshdr_t      wheader = 0;
    pframectrl_t        control = 0;
    pbeaconhdr_t        beacon = 0;
    unsigned short      isbeacon = 0;
    char                essid[ESSID_LEN], bssid[BSSID_LEN];
    struct wnetwork     *net;
    unsigned char       *aux,*data;
    struct wep_header   *wep_header;
    unsigned long       hash = 0;

    // wireless header offset calculation
    if ( settings.dlt == DLT_IEEE802_11_RADIO )
    {
    	radio = (pradiotaphdr_t)packet;
        offset = radio->len;
        delta = 4; // frame sequence verification is added at the end of packet data
    }

    wheader = ( pwirelesshdr_t )(packet + offset);
    control = ( pframectrl_t ) wheader->fc;

    /* we only want beacons and data */
    if( !(isbeacon = IS_BEACON(control , pkthdr->caplen - offset)) && ! IS_DATA ( control ) )
        return;

    /* store bssid and essid */
    memset ( essid, 0, ESSID_LEN );
    memset ( bssid, 0, BSSID_LEN );

    // get bssid in string format
    snprintf ( bssid, sizeof ( bssid ) , "%02hx:%02hx:%02hx:%02hx:%02hx:%02hx", wheader->add2[0], wheader->add2[1], wheader->add2[2], wheader->add2[3], wheader->add2[4], wheader->add2[5] );
    for ( i = 0; i < strlen ( bssid ); i++ )
        bssid[i] = toupper ( bssid[i] );

    // get the hash for the given bssid
    if ( !( hash = htable_sdbm_hash( (unsigned char*) bssid) ) )
    	return;

    /* if it is a beacon frame, check if the wireless is encrypted and store it */
    if ( isbeacon )
    {
        beacon = (pbeaconhdr_t) ((unsigned char*)wheader + sizeof ( wirelesshdr_t ) );
        /* we only want encrypted networks */
        if ( ! IS_ENCRYPTED( beacon ) || !IS_FROM_AP(beacon) )
            return;

        if ( htable_find(networks,hash) != 0 )
            return;

        /* new network to store */
        SAFE_CALLOC ( net , 1 , sizeof ( struct wnetwork ) );
        data = (unsigned char*)beacon + sizeof ( beaconhdr_t );
        aux = ( (unsigned char*)packet + pkthdr->caplen );
        strncpy ( net->bssid , bssid , sizeof(net->bssid));
        get_beacon_info ( data , aux , net );

        // insert it into the hash table
        htable_insert(networks,hash,(void*) net);

        if ( net_allowed(net) )
            net->allowed++;

        /* if we are filtering, show only the allowed networks */
        if ( settings.filter.bssid[0] != 0 || settings.filter.encryption > 0 )
        {
        	if ( net->allowed )
        		show_network( net );
        }else if ( net->allowed || !settings.supported )
        	show_network( net );

    }
    else
    {
        /* data frame, now check if we have stored the AP */
        if ( ! ( net = htable_find(networks,hash) ) || ! net->allowed )
            return;

        /* already checked or cracking in progress */
        if ( net->pwd.checked || net->pwd.inprogress )
            return;

        net->pwd.inprogress++;

        wep_header = ( struct wep_header * ) ( (unsigned char*)wheader + sizeof ( wirelesshdr_t )  );
        data = (unsigned char*)wep_header + sizeof ( struct wep_header );
        net->pwd.datalen = pkthdr->caplen - ( data - packet ) - delta;

        SAFE_CALLOC ( net->pwd.data , net->pwd.datalen , sizeof ( unsigned char) );
        SAFE_CALLOC ( net->pwd.datatmp , net->pwd.datalen , sizeof ( unsigned char) );

        memcpy ( net->pwd.data , data , net->pwd.datalen );
        memcpy ( (void*)&net->pwd.hdr , wep_header , sizeof ( struct wep_header ) );

        fprintf ( stderr , "\n[i] Adding network %s (%s) to crack queue\n" , net->essid , net->bssid );

        add_network_tocrack ( net );
    }

    return;
}
