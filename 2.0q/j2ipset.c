
/*
 * 06Aug2026, Maiko (VE4KLM)
 *
 * Time to give JNOS the ability to check any of the ipset block lists
 * that I maintain, for specific IP addresses, since JNOS gets hammered
 * with file scans, skimmers, DDOS, udp probes, you name it. Even if I
 * use the ipset block lists mostly for my web server, you can see the
 * crap also attacking my JNOS, so this takes them out as soon as the
 * source IP is extracted from the incoming IP packet header.
 *
 * This code is based on examples I found using AI Overview. It is too
 * bad there were no credits for it, could have been something that was
 * simply taken from a specific ipset libs manpage ? No idea, but I got
 * tired of looking for a good example - the rare time I do this ...
 *
 * This is just a prototype, not sure how resource or system sensitive
 * the ipset code is, but it's pretty cool. More to come later on :]
 *
 * Note : ipset name is hardcoded to "badipv4", on linux side I use this :
 *
 *  ipset create badipv4 hash:net
 *
 *  iptables -I INPUT 1 -m set --match-set badipv4 src -j DROP
 *
 *  ipset add badipv4 <subnet/mask>    as many times as you want
 *
 */

#include <stdio.h>

#include <libipset/ipset.h>
#include <libipset/session.h>
#include <libipset/data.h>
#include <libipset/types.h>

#include "global.h"	/* for j2strdup function */

static char *glob_setname;

void j2ipset_init (const char *set_name)
{
	static int alreadyset = 0;

	if (alreadyset) return;

	glob_setname = j2strdup (set_name);

	ipset_load_types();

	alreadyset = 1;
}

int j2ipset_test (const char *ip_address)
{
	struct ipset_session *session;

	const struct ipset_type *type;

	int ret = -1;

    if (!(session = ipset_session_init(NULL, NULL)))
    {
        printf ("Failed to initialize ipset session\n");
		return ret;
    }

    // set the target set name

    if (ipset_parse_setname(session, IPSET_SETNAME, glob_setname) < 0)
    {
        printf ("Failed to set target set name\n");
		return ret;
    }

    // grab the set type from the kernel

    if (!(type = ipset_type_get(session, IPSET_CMD_TEST)))
    {
        printf ("Failed to grab type of set from the kernel\n");
		return ret;
    }

    // parse the IP address string into session element data

    if (ipset_parse_elem(session, type->last_elem_optional, ip_address) < 0)
    {
        printf ("Failed to parse ip address into session element data\n");
		return ret;
    }

    // execute the actual TEST command against the kernel

    ret = ipset_cmd(session, IPSET_CMD_TEST, 0);

    ipset_session_fini(session);	// you MUST do this each time

	return ret;
}

#ifdef	TEST_PROGRAM

int main() {

   j2ipset_init ("badipv4");

    // Note: This binary must be run with root privileges (CAP_NET_ADMIN)
    int result = j2ipset_test ("171.67.71.223");
    if (result == 0) {
        printf("Element is IN the set.\n");
    } else {
        printf("Element is NOT in the set (or error occurred).\n");
    }

    return 0;
}

#endif

