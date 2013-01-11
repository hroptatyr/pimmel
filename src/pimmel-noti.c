/*** pimmel-noti.c -- pimmel publisher
 *
 * Copyright (C) 2013 Sebastian Freundt
 *
 * Author:  Sebastian Freundt <freundt@ga-group.nl>
 *
 * This file is part of pimmel.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of any contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 ***/
#if defined HAVE_CONFIG_H
# include "config.h"
#endif	/* HAVE_CONFIG_H */
#include <stdio.h>
#if defined HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if defined HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#if defined HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#if defined HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#if defined HAVE_EV_H
# include <ev.h>
# undef EV_P
# define EV_P  struct ev_loop *loop __attribute__((unused))
#endif	/* HAVE_EV_H */

#include "nifty.h"
#include "ud-sock.h"

#define MAYBE_UNUSED	UNUSED

#define DEFAULT_TIMEOUT		60
#define UDP_MULTICAST_TTL	64

#if !defined IPPROTO_IPV6
# error "system not fit for ipv6 transport"
#endif	/* IPPROTO_IPV6 */

#define PMML_NETWORK_SERVICE	7665/*PMML on the phone*/
/* http://www.iana.org/assignments/ipv6-multicast-addresses/ lists us 
 * as ff0x:0:0:0:0:0:0:134 */
/* node-local */
#define PMML_MCAST6_NODE_LOCAL	"ff01::134"
/* link-local */
#define PMML_MCAST6_LINK_LOCAL	"ff02::134"
/* site-local */
#define PMML_MCAST6_SITE_LOCAL	"ff05::134"


/* networking layer, will disappear */
static void
fiddle_with_mtu(int MAYBE_UNUSED(s))
{
#if defined IPV6_PATHMTU
	struct ip6_mtuinfo mtui;
	socklen_t mtuilen = sizeof(mtui);
#endif	/* IPV6_PATHMTU */

#if defined IPV6_USE_MIN_MTU
	/* use minimal mtu */
	opt = 1;
	setsockopt(s, IPPROTO_IPV6, IPV6_USE_MIN_MTU, &opt, sizeof(opt));
#endif	/* IPV6_USE_MIN_MTU */
#if defined IPV6_DONTFRAG
	/* rather drop a packet than to fragment it */
	opt = 1;
	setsockopt(s, IPPROTO_IPV6, IPV6_DONTFRAG, &opt, sizeof(opt));
#endif	/* IPV6_DONTFRAG */
#if defined IPV6_RECVPATHMTU
	/* obtain path mtu to send maximum non-fragmented packet */
	opt = 1;
	setsockopt(s, IPPROTO_IPV6, IPV6_RECVPATHMTU, &opt, sizeof(opt));
#endif	/* IPV6_RECVPATHMTU */
#if defined IPV6_PATHMTU
	/* obtain current pmtu */
	if (getsockopt(s, IPPROTO_IPV6, IPV6_PATHMTU, &mtui, &mtuilen) < 0) {
		perror("could not obtain pmtu");
	}
#endif	/* IPV6_PATHMTU */
	return;
}

static int
mc6_socket(void)
{
	volatile int s;

	/* try v6 first */
	if ((s = socket(PF_INET6, SOCK_DGRAM, IPPROTO_IP)) < 0) {
		return -1;
	}

#if defined IPV6_V6ONLY
	{
		int yes = 1;
		setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes));
	}
#endif	/* IPV6_V6ONLY */
	/* be less blocking */
	setsock_nonblock(s);
	/* and we do care about the mtu */
	fiddle_with_mtu(s);
	return s;
}


static void
sigall_cb(EV_P_ ev_signal *UNUSED(w), int UNUSED(revents))
{
	ev_unloop(EV_A_ EVUNLOOP_ALL);
	return;
}


#if defined __INTEL_COMPILER
# pragma warning (disable:593)
# pragma warning (disable:181)
#elif defined __GNUC__
# pragma GCC diagnostic ignored "-Wswitch"
# pragma GCC diagnostic ignored "-Wswitch-enum"
#endif /* __INTEL_COMPILER */
#include "pimmel-wait-clo.h"
#include "pimmel-wait-clo.c"
#if defined __INTEL_COMPILER
# pragma warning (default:593)
# pragma warning (default:181)
#elif defined __GNUC__
# pragma GCC diagnostic warning "-Wswitch"
# pragma GCC diagnostic warning "-Wswitch-enum"
#endif	/* __INTEL_COMPILER */

int
main(int argc, char *argv[])
{
	/* args */
	struct pimmel_args_info argi[1];
	/* use the default event loop unless you have special needs */
	struct ev_loop *loop;
	ev_signal sigint_watcher[1];
	ev_signal sigterm_watcher[1];
	/* the destination */
	union ud_sockaddr_u dst = {0};
	/* business logic */
	int res = 0;
	int s;

	/* parse the command line */
	if (pimmel_parser(argc, argv, argi)) {
		res = 1;
		goto out;
	} else if (argi->inputs_num < 2U) {
		pimmel_parser_print_help();
		res = 1;
		goto out;
	}

	if ((s = mc6_socket()) < 0) {
		perror("cannot initialise mc socket");
		res = 1;
		goto out;
	} else if (({
			union ud_sockaddr_u sa = {
				.sa6.sin6_family = AF_INET6,
				.sa6.sin6_addr = IN6ADDR_ANY_INIT,
				.sa6.sin6_port = 0,
			};

			/* as a courtesy to tools bind the channel */
			bind(s, &sa.sa, sizeof(sa)) < 0;})) {
		perror("cannot connect to pimmel network");
		res = 1;
		goto out;
	} else {
		/* set destination address */
		dst.sa6.sin6_family = AF_INET6;
		/* we pick link-local here for simplicity */
		inet_pton(AF_INET6, PMML_MCAST6_LINK_LOCAL, &dst.sa6.sin6_addr);
		/* port as well innit */
		dst.sa6.sin6_port = htons(PMML_NETWORK_SERVICE);
		/* set the flowinfo */
		dst.sa6.sin6_flowinfo = 0;
	}

	/* initialise the main loop */
	loop = ev_default_loop(EVFLAG_AUTO);

	/* initialise a sig C-c handler */
	ev_signal_init(sigint_watcher, sigall_cb, SIGINT);
	ev_signal_start(EV_A_ sigint_watcher);
	ev_signal_init(sigterm_watcher, sigall_cb, SIGTERM);
	ev_signal_start(EV_A_ sigterm_watcher);


	/* publish this one event */
	{
		char buf[1280] = "\xff" "8\x00\x7f" /*rev*/"\x01"
			/*socktyp pub*/"\x01"
			/*final short*/"\x00"
			/*identity*/"\x00"
			/*body, here as: more short*/"\x01";
		const char *b = argi->inputs[0];
		size_t z = strlen(b);
		const char *msg = argi->inputs[1];
		size_t msz = strlen(msg);

		buf[9] = (uint8_t)z;
		memcpy(buf + 9 + 1, b, (uint8_t)z);

		buf[10 + z] = /*final short*/'\0';
		buf[10 + z + 1] = (uint8_t)msz;

		memcpy(buf + 10 + z + 2, msg, (uint8_t)msz);
		z = 10 + z + 2 + msz;

		if (sendto(s, buf, z, 0, &dst.sa, sizeof(dst)) < 0) {
			perror("cannot publish");
			res = 1;
		}
	}

	/* and off */
	close(s);

	/* destroy the default evloop */
	ev_default_destroy();

out:
	pimmel_parser_free(argi);
	return res;
}

/* pimmel-noti.c ends here */
