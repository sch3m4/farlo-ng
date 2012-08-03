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

/*
 * Author: Chema Garcia
 * Project URL: http://sch3m4.github.com/farlo-ng
 * Contact:
 *   + http://safetybits.net
 *   + chema@safetybits.net
 *   + @sch3m4
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "includes/main.h"
#include "includes/wireless.h"
#include "includes/patterns.h"
#include "includes/algorithms.h"

#define VERSION "0.5.8b"

void usage ( char *name )
{
    fprintf ( stderr, "\nUsage: %s [options]\n", name );
    fprintf ( stderr , "\n[+] Options:" );

    fprintf ( stderr, "\n\t-i | --iface <name> --------> Interface name" );
    fprintf ( stderr, "\n\t-f | --file <path> ---------> Path to file" );
    fprintf ( stderr, "\n\t-p | --patterns <path> -----> Networks patterns file");
    fprintf ( stderr, "\n\t-s | --supported -----------> Show only supported networks");
    fprintf ( stderr, "\n\t-d | --dictionary <path> ---> Auxiliary dictionary");
    fprintf ( stderr, "\n\t-c | --channel <channels> --> Channels list (comma separated)");
    fprintf ( stderr, "\n\t-D | --delay <usec> --------> Delay between channels");

    return;
}

/* signal handler */
void shandler ( int sign )
{
    SAFE_FREE ( settings.source );
    SAFE_FREE ( settings.configpath );

    if ( settings.live && settings.delay )
    {
        pthread_cancel(settings.hoptid);
        pthread_join(settings.hoptid,0);
    }

    if ( settings.handle != 0 )
        pcap_close ( settings.handle );

    finish_wireless();
    finish_crackqueue();
    free_patterns();
    free_algorithms();

    fprintf ( stderr , "\n\n" );

    exit ( sign );
}

int main( int argc , char *argv[] )
{
    char                    *p,*q,tmp=0;
    char                    errbuf[PCAP_ERRBUF_SIZE] = {0};
    unsigned short          ret = 0;
    char                    o = 0;
    const char              schema[] = "i:f:p:sd:c:D:";
    int                     i = 0 , j = 0;
    unsigned short          channel = 0;
    static struct option    opc[] =
    {
        {"iface", 1, 0, 'i'},
        {"file" , 1 , 0 , 'f'},
        {"patterns", 1 , 0 , 'p'},
        {"supported", 0 , 0 , 's'},
        {"dictionary",1,0,'d'},
        {"channels",1,0,'c'},
        {"delay",1,0,'D'},
        {0, 0, 0, 0}
    };

    fprintf ( stderr , "      ______ _______ _______  ______         _____  ______" );
    fprintf ( stderr , "\n     /\\      |______ |_____| |_____/ |      |     |      /\\" );
    fprintf ( stderr , "\n..~.~\\/_____ |       |     | |    \\_ |_____ |_____| _____\\/~.~..\n" );

    fprintf ( stderr, "\n\t      Wireless AP Password Revealer %s\n" , VERSION );
    fprintf ( stderr, "\n\t   +============[ Written by ]=============+" );
    fprintf ( stderr, "\n\t   |      Chema Garcia (a.k.a. sch3m4)     |" );
    fprintf ( stderr, "\n\t   |---------------------------------------|" );
    fprintf ( stderr, "\n\t   |         http://SafetyBits.Net         |" );
    fprintf ( stderr, "\n\t   |          chema@safetybits.net         |" );
    fprintf ( stderr, "\n\t   +=======================================+\n" );

    memset ( &settings , 0 , sizeof ( settings_t ) );
    // set default parameters
    settings.table_size = DEFAULT_TABLE_SIZE;

    // parse the parameters
    while ( !ret && ( o = getopt_long ( argc, argv, schema , opc, &i ) ) > 0 )
    {
        switch ( o )
        {
        case 'i':
            settings.source = strdup ( optarg );
            settings.live = 1;
            break;

        case 'f':
            settings.source = strdup ( optarg );
            settings.live = 0;
            break;

        case 'p':
            settings.configpath = strdup ( optarg );
            break;

        case 's':
            settings.supported = 1;
            break;

        case 'd':
#ifdef O_LARGEFILE
            settings.dicfd = open ( optarg , O_RDONLY | O_LARGEFILE );
#else
            settings.dicfd = open ( optarg , O_RDONLY );
#endif
            if ( settings.dicfd < 0 )
            {
                fprintf ( stderr , "\n[e] Cannot open \"%s\": %s" , optarg , strerror(errno));
                shandler(0);
            }
            break;

        case 'D':
            if ( !(settings.delay = atol(optarg)) )
            {
                fprintf ( stderr , "\n[w] Cannot set the specified delay, setting the default value\n");
                settings.delay = CHANNEL_HOPPING_DELAY;
            }
            break;

        case 'c':
            if ( !settings.delay )
                settings.delay = CHANNEL_HOPPING_DELAY;
            /* parse channels */
            j = 0;
            while ( optarg[j] != 0 )
            {
                p = &optarg[j];
                if ( !isdigit(optarg[j] ) )
                    goto cherror;

                q = 0;
                if ( ! optarg[j+1] || optarg[j+1] == ',' )
                    q = &optarg[j+1];
                else if ( (! optarg[j+2] || optarg[j+2] == ',') && isdigit(optarg[j+1]) )
                    q = &optarg[j+2];

                if ( !q )
                    goto cherror;

                tmp = *q;
                *q = 0;

                sscanf ( p , "%hu" , &channel );
                *q = tmp;

                if ( channel < 1 || channel > MAX_CHANNELS )
                    goto cherror;

                //enables this channel
                settings.channels[channel - 1] = 1;

                j += (q - p);

                if ( optarg[j] == ',' )
                    j++;
            }
            break;

cherror:
            ret++;
            fprintf ( stderr , "\n[e] Error parsing channels list");
            break;

        default:
            ret++;
            break;
        }
    }

    // cannot run
    if ( ret || !settings.source || !settings.configpath )
    {
        usage ( argv[0] );
        shandler(0);
    }

    // set the signal handler
    signal ( SIGINT, shandler );
    signal ( SIGTERM, shandler );

    errbuf[0] = 0;
    // open the capture source
    if ( settings.live )
    {
        if ( ( settings.handle = pcap_open_live ( settings.source, BUFSIZ, 1, 0, errbuf ) ) == NULL )
        {
            fprintf ( stderr, "\n[!] %s", errbuf );
            shandler(1);
        }

        if ( settings.delay )
            pthread_create(&settings.hoptid,0,channel_hopping,0);
    }
    else
    {
        if ( ( settings.handle = pcap_open_offline ( settings.source, errbuf ) ) == NULL )
        {
            fprintf ( stderr, "\n[!] %s", errbuf );
            shandler(2);
        }
    }

    // resources initialization
    init_wireless();
    init_crackqueue();
    init_algorithms();
    if ( ( i = load_network_patterns() ) < 0 )
    {
        fprintf ( stderr , "\n[!] Error loading network patterns: %s" , GET_PATTERNS_ERRSTR(i) );
        shandler(3);
    }
    settings.dlt = pcap_datalink(settings.handle);

    fprintf ( stderr , "\n[+] Capturing from: %s" , settings.source );
    fprintf ( stderr , "\n[+] Datalink: %s" , pcap_datalink_val_to_name( settings.dlt ) );
    fprintf ( stderr , "\n[+] Network patterns: %s" , settings.configpath );
    if ( settings.delay && settings.live )
    {
        j = 0;
        fprintf ( stderr , "\n[+] Using channel(s): ");
        for ( i = 0 ; i < MAX_CHANNELS ; i++ )
            if ( settings.channels[i] )
            {
                if ( j )
                    fprintf ( stderr , ",%hu" , i + 1 );
                else
                {
                    fprintf ( stderr , "%hu" , i + 1 );
                    j++;
                }
            }

        fprintf ( stderr , "\n[+] Channel hopping delay: %lu usec." , settings.delay );
    }
    fprintf ( stderr , "\n" );

    // packet capture starts
    if ( ( i = pcap_loop ( settings.handle, -1, procPacket, NULL ) ) < 0 )
    {
        fprintf ( stderr, "\n[!] %s\n\n", pcap_geterr ( settings.handle ) );
        shandler(3);
    }

    shandler(0);
    return 0;
}