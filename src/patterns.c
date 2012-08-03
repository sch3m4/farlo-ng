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
#include <pthread.h>
#include <libxml/xmlreader.h>

#include "includes/main.h"
#include "includes/patterns.h"
#include "includes/htable.h"
#include "includes/wireless.h"
#include "includes/crack.h"

#ifndef REGEX_FLAGS
# define REGEX_FLAGS    (REG_EXTENDED|REG_ICASE|REG_NOSUB)
#endif

void free_patterns ()
{
    ppattern_t aux;

    while ( (aux = patterns) != 0 )
    {
        patterns = aux->next;

        regfree ( &aux->bssid );
        SAFE_FREE ( aux->name );
        SAFE_FREE ( aux );
    }

    return;
}

static void add_pattern ( ppattern_t node )
{
    node->next = patterns;
    patterns = node;
}

static void parse_nodes (xmlDocPtr doc, xmlNodePtr cur)
{
    ppattern_t      node = 0;
    palgorithm_t    alg = 0;
    regex_t         regex_encrypt;
    xmlChar         *bssid,*algorithm,*encryption,*essid;
    unsigned short  enc = 0;
    int             valret = 0;
    char            error[255];

    cur = cur->xmlChildrenNode;
    while (cur != NULL)
    {
        if ( (!xmlStrcmp(cur->name, (const xmlChar *)"network") ) )
        {
            bssid = xmlGetProp(cur,(const xmlChar*) "bssid");
            essid = xmlGetProp(cur,(const xmlChar*) "essid");
            encryption = xmlGetProp(cur,(const xmlChar*) "encryption" );
            algorithm = xmlGetProp(cur,(const xmlChar*) "algorithm");

            if ( ( ( !essid || strlen((const char*)essid) == 0 ) && (!bssid || strlen((const char*)bssid) == 0 ) ) || !algorithm || !encryption )
                goto tofree;

            if ( !(alg = get_algorithm( (const char*) algorithm) ) )
                fprintf ( stderr , "\n[W] Algorithm \"%s\" not found!" , algorithm );
            else
            {
                enc = 0;
                if ( ( valret = regcomp ( &regex_encrypt , (const char*) encryption , REGEX_FLAGS ) ) != 0 )
                {
                    regerror( valret , &regex_encrypt , error , sizeof(error) );
                    fprintf ( stderr , "\n[W] Cannot compile expression: %s (%s)" , encryption , error );
                    goto tofree;
                }

                if ( regexec (&regex_encrypt , "WEP" , 0 , 0 , 0 ) != REG_NOMATCH )
                    enc |= ENCRYPT_WEP;
                if ( regexec (&regex_encrypt , "WPA" , 0 , 0 , 0 ) != REG_NOMATCH )
                    enc |= ENCRYPT_WPA;
                if ( regexec (&regex_encrypt , "WPA2" , 0 , 0 , 0 ) != REG_NOMATCH )
                    enc |= ENCRYPT_WPA2;
                regfree ( &regex_encrypt );

                if ( !enc )
                    fprintf ( stderr , "\n[W] Encryption \"%s\" not supported!" , encryption );
                else
                {
                    node = (ppattern_t) calloc ( 1 , sizeof ( pattern_t ) );
                    if ( bssid != 0 && strlen((const char*)bssid) > 0 )
                    {
                        regcomp ( &node->bssid , (const char*) bssid , REGEX_FLAGS );
                        node->filter_bssid = 1;
                    }

                    if ( essid != 0 && strlen((const char*)essid) > 0 )
                    {
                        regcomp ( &node->essid , (const char*) essid , REGEX_FLAGS );
                        node->filter_essid = 1;
                    }

                    node->name = strdup ( (char*) algorithm );
                    node->encryption = enc;
                    node->algorithm = alg;

                    add_pattern( node );
                }
            }

tofree:
            xmlFree(bssid);
            xmlFree(encryption);
            xmlFree(algorithm);
        }
        cur = cur->next;
    }
    return;
}

unsigned short load_network_patterns ()
{
    int ret = 0;
    xmlDocPtr doc;
    xmlNodePtr cur;

    LIBXML_TEST_VERSION

    if ( (doc = xmlParseFile(settings.configpath)) == NULL )
        return 1;


    if ( (cur = xmlDocGetRootElement(doc)) == NULL)
    {
        ret = 2;
        goto badret;
    }

    if ( xmlStrcmp(cur->name, (const xmlChar *) "farlo-ng" ) )
    {
        ret = 3;
        goto badret;
    }

    parse_nodes (doc, cur);

badret:
    xmlFreeDoc(doc);

    xmlCleanupParser();

    return ret;
}

unsigned short net_allowed ( struct wnetwork *net )
{
    unsigned short  ret = 0;
    ppattern_t      pattern;

    for ( pattern = patterns ; pattern != 0 && !ret ; pattern = pattern->next )
    {
        if ( pattern->filter_bssid && regexec( &pattern->bssid , net->bssid , 0 , 0 , 0 ) == REG_NOMATCH )
            continue;

        if ( pattern->filter_essid && regexec( &pattern->essid , net->essid , 0 , 0 , 0 ) == REG_NOMATCH )
            continue;

        if ( !(pattern->encryption & net->encrypt) )
            continue;

        ret = 1;
    }

    return ret;
}

void unlock ( void *p )
{
    struct crackdata    *crack = (struct crackdata*)p;

    pthread_mutex_unlock ( &crack->done );
}

void* gen_password ( void *p )
{
    struct crackdata    *crack = (struct crackdata*)p;
    ppattern_t          pattern;

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    pthread_cleanup_push(unlock, p );

    for ( pattern = patterns ; pattern != 0 && !crack->net->pwd.checked ; pattern = pattern->next )
    {
        if ( pattern->filter_bssid && regexec( &pattern->bssid , crack->net->bssid , 0 , 0 , 0 ) == REG_NOMATCH )
            continue;

        if ( pattern->filter_essid && regexec( &pattern->essid , crack->net->essid , 0 , 0 , 0 ) == REG_NOMATCH )
            continue;

        if ( !(pattern->encryption & crack->net->encrypt) )
            continue;

        pattern->algorithm->genpwd(crack,pattern->algorithm->pattern);

        pthread_testcancel();
    }

    unlock(p);

    pthread_cleanup_pop(0);
    return 0;
}
