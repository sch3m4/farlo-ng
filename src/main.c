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

    fprintf ( stderr, "\n\t-i | --iface <name> ---------------> Interface name" );
    fprintf ( stderr, "\n\t-f | --file <path> ----------------> Path to file" );
    fprintf ( stderr, "\n\t-b | --bssid <bssid> --------------> Capture only from this bssid");
    fprintf ( stderr, "\n\t-e | --encryption <wep/wpa/wpa2> --> Encryption filter");
    fprintf ( stderr, "\n\t-p | --patterns <path> ------------> Networks patterns file");
    fprintf ( stderr, "\n\t-s | --supported ------------------> Show only supported networks");
    fprintf ( stderr, "\n\t-d | --dictionary <path> ----------> Auxiliary dictionary");
    fprintf ( stderr, "\n\t-c | --channel <channels> ---------> Channels list (comma separated)");
    fprintf ( stderr, "\n\t-D | --delay <msec> ---------------> Delay between channels");
    fprintf ( stderr, "\n\t-n | --no-hop ---------------------> Do not do channel hopping");

    return;
}

/* signal handler */
void shandler ( int sign )
{
	static unsigned short retries = 0;

	signal ( sign, shandler );

	retries++;

    if ( settings.hopping )
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

    SAFE_FREE ( settings.source );
    SAFE_FREE ( settings.configpath );

    fprintf ( stderr , "\n\n" );

    exit ( sign );
}

int main( int argc , char *argv[] )
{
    char                    *p,*q,tmp=0;
    char                    errbuf[PCAP_ERRBUF_SIZE] = {0};
    unsigned short          ret = 0;
    char                    o = 0;
    const char              schema[] = "i:f:p:sd:c:D:b:e:n";
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
        {"bssid",1,0,'b'},
        {"encryption",1,0,'e'},
        {"no-hop",0,0,'n'},
        {0, 0, 0, 0}
    };


    fprintf ( stderr , "      _____  _______ _______  ______         _____      __   _  ______  _____      \n");
    fprintf ( stderr , "     /\\      |______ |_____| |_____/ |      |     | ___ | \\  | |  ____      /\\     \n");
    fprintf ( stderr , "..~.~\\/____  |       |     | |    \\_ |_____ |_____|     |  \\_| |_____|  ____\\/~.~..\n");


    fprintf ( stderr, "\n\t\t      Wireless AP Password Revealer %s\n" , VERSION );
    fprintf ( stderr, "\n\t\t   +============[ Written by ]=============+" );
    fprintf ( stderr, "\n\t\t   |      Chema Garcia (a.k.a. sch3m4)     |" );
    fprintf ( stderr, "\n\t\t   |---------------------------------------|" );
    fprintf ( stderr, "\n\t\t   |         http://SafetyBits.Net         |" );
    fprintf ( stderr, "\n\t\t   |          chema@safetybits.net         |" );
    fprintf ( stderr, "\n\t\t   +=======================================+\n" );

    memset ( &settings , 0 , sizeof ( settings_t ) );
    // set default parameters
    settings.table_size = DEFAULT_TABLE_SIZE;
    settings.delay = CHANNEL_HOPPING_DELAY;
    settings.hopping = 1;
    memset ( &settings.channels , 1 , sizeof ( settings.channels) );

    // parse the parameters
    while ( !ret && ( o = getopt_long ( argc, argv, schema , opc, &i ) ) > 0 )
    {
        switch ( o )
        {
        case 'i':
            settings.source = strdup ( optarg );
            settings.live = 1;
            break;

        case 'n':
        	settings.hopping = 0;
        	break;

        case 'f':
            settings.source = strdup ( optarg );
            settings.live = 0;
            break;

        case 'b':
        	strncpy(settings.filter.bssid,optarg,sizeof(settings.filter.bssid));
        	break;

        case 'p':
            settings.configpath = strdup ( optarg );
            break;

        case 'e':
        	j = strlen(optarg);
        	if ( !j || j > strlen(GET_ENCRYPT_STRING(ENCRYPT_WPA)) )
        		goto invalid_fe;

        	// convert the filter to upper-case
        	for ( j = 0 ; j < strlen(optarg) ; j++ )
        		optarg[j] = toupper(optarg[j]);

        	for ( j = 0 ; j < ENCRYPT_WPA2 ; j++ )
        		if ( !strcmp ( GET_ENCRYPT_STRING(j + 1) , optarg ) )
        			settings.filter.encryption = j + 1;

        	if ( settings.filter.encryption != 0 )
        		break;

invalid_fe:
			fprintf ( stderr , "\n[e] Invalid encryption filter");
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
        	memset ( &settings.channels , 0, sizeof ( settings.channels) );
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
    if ( ret != 0 || !settings.source || !settings.configpath )
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
    }
    else
    {
        if ( ( settings.handle = pcap_open_offline ( settings.source, errbuf ) ) == NULL )
        {
            fprintf ( stderr, "\n[!] %s", errbuf );
            shandler(3);
        }
    }

    // resources initialization
    init_wireless();
    init_crackqueue();
    init_algorithms();
    if ( ( i = load_network_patterns() ) < 0 )
    {
        fprintf ( stderr , "\n[!] Error loading network patterns: %s" , GET_PATTERNS_ERRSTR(i) );
        shandler(4);
    }

    settings.dlt = pcap_datalink(settings.handle);

    switch ( settings.dlt )
    {
    	case DLT_IEEE802_11:
    		break;

    	case DLT_IEEE802_11_RADIO:
    		break;

    	default:
    		fprintf ( stderr , "\n[e] Network datalink not supported: %s" , pcap_datalink_val_to_name( settings.dlt ) );
    		shandler(5);
    		break; // avoid IDE warning...

    }

    if ( settings.live && settings.hopping )
    {
    	/* check enabled channels */
    	j = 0;
    	for ( i = 0 ; i < MAX_CHANNELS && !j; i++ )
    		if ( settings.channels[i] != 0 )
    			j++;

    	if ( !j )
    	{
    		fprintf ( stderr , "\n[w] You have no selected channels, enabling them all...");
    		for ( i = 0 ; i < MAX_CHANNELS && !j; i++ )
    			settings.channels[i] = 1;
    	}

    	if ( ! settings.delay )
    	{
    		fprintf ( stderr , "\n[w] You have no selected channel hopping delay, using the default value...");
    		settings.delay = CHANNEL_HOPPING_DELAY;
    	}

        pthread_create(&settings.hoptid,0,channel_hopping,0);
    }

    fprintf ( stderr , "\n[+] Capturing from: %s" , settings.source );
    fprintf ( stderr , "\n[+] Datalink: %s" , pcap_datalink_val_to_name( settings.dlt ) );
    if ( settings.filter.bssid[0] != 0 )
    	fprintf ( stderr , "\n[+] BSSID filter: %s" , settings.filter.bssid );
    if ( settings.filter.encryption != 0 )
    	fprintf ( stderr , "\n[+] Encryption filter: %s" , GET_ENCRYPT_STRING(settings.filter.encryption) );
    fprintf ( stderr , "\n[+] Network patterns: %s" , settings.configpath );
    if ( settings.live )
    {
    	if ( settings.hopping )
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

			fprintf ( stderr , "\n[+] Channel hopping delay: %lu msec." , settings.delay );
    	}else
    		fprintf ( stderr , "\n[+] Don't doing channel hopping");
    }
    fprintf ( stderr , "\n" );

    // packet capture starts
    if ( ( i = pcap_loop ( settings.handle, -1, procPacket, NULL ) ) < 0 )
    {
        fprintf ( stderr, "\n[!] %s\n\n", pcap_geterr ( settings.handle ) );
        shandler(6);
    }

	while(1)
		sleep(5);
    shandler(0);
    return 0;
}
