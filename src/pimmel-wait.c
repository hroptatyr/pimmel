/*** pimmel-wait.c -- pimmel subscriber
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
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
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

#if defined DEBUG_FLAG && !defined BENCHMARK
# include <assert.h>
# define PMML_DEBUG(args...)	fprintf(stderr, args)
# define MAYBE_NOINLINE		__attribute__((noinline))
#else  /* !DEBUG_FLAG */
# define PMML_DEBUG(args...)
# define assert(x)
# define MAYBE_NOINLINE
#endif	/* DEBUG_FLAG */

/* node local, site local and link local */
static struct ipv6_mreq ALGN16(mreq6_nolo);
static struct ipv6_mreq ALGN16(mreq6_silo);
static struct ipv6_mreq ALGN16(mreq6_lilo);


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

static int
mcast6_loop(int s, int on)
{
#if defined IPV6_MULTICAST_LOOP
	/* don't loop */
	setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on, sizeof(on));
#else  /* !IPV6_MULTICAST_LOOP */
# warning multicast looping cannot be turned on or off
#endif	/* IPV6_MULTICAST_LOOP */
	return on;
}

static int
mcast6_join_group(int s, const char *addr, struct ipv6_mreq *r)
{
	/* set up the multicast group and join it */
	inet_pton(AF_INET6, addr, &r->ipv6mr_multiaddr.s6_addr);
	r->ipv6mr_interface = 0;

	/* now truly join */
	return setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP, r, sizeof(*r));
}

static void
mcast6_leave_group(int s, struct ipv6_mreq *mreq)
{
	/* drop mcast6 group membership */
	setsockopt(s, IPPROTO_IPV6, IPV6_LEAVE_GROUP, mreq, sizeof(*mreq));
	return;
}

static int
mcast6_join(int s, short unsigned int UNUSED(port))
{
	struct {
		const char *a;
		struct ipv6_mreq *r;
	} g[] = {
		{PMML_MCAST6_NODE_LOCAL, &mreq6_nolo},
		{PMML_MCAST6_LINK_LOCAL, &mreq6_lilo},
		{PMML_MCAST6_SITE_LOCAL, &mreq6_silo},
	};

	for (size_t i = 0; i < countof(g); i++) {
		if (UNLIKELY(mcast6_join_group(s, g[i].a, g[i].r) < 0)) {
			perror("cannot join group");
		}
	}
	return 0;
}

static int
mcast6_listener_init(int s, short unsigned int port)
{
	int retval;
	int opt;
	union ud_sockaddr_u sa = {
		.sa6.sin6_family = AF_INET6,
		.sa6.sin6_addr = IN6ADDR_ANY_INIT,
		.sa6.sin6_port = htons(port),
	};

	/* allow many many many servers on that port */
	setsock_reuseaddr(s);
	setsock_reuseport(s);

	/* turn multicast looping on */
	mcast6_loop(s, 1);
#if defined IPV6_V6ONLY
	opt = 1;
	setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &retval, sizeof(retval));
#endif	/* IPV6_V6ONLY */
#if defined IPV6_USE_MIN_MTU
	/* use minimal mtu */
	opt = 1;
	setsockopt(s, IPPROTO_IPV6, IPV6_USE_MIN_MTU, &opt, sizeof(opt));
#endif
#if defined IPV6_DONTFRAG
	/* rather drop a packet than to fragment it */
	opt = 1;
	setsockopt(s, IPPROTO_IPV6, IPV6_DONTFRAG, &opt, sizeof(opt));
#endif
#if defined IPV6_RECVPATHMTU
	/* obtain path mtu to send maximum non-fragmented packet */
	opt = 1;
	setsockopt(s, IPPROTO_IPV6, IPV6_RECVPATHMTU, &opt, sizeof(opt));
#endif
#if defined IPV6_MULTICAST_HOPS
	opt = UDP_MULTICAST_TTL;
	/* turn into a mcast sock and set a TTL */
	setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &opt, sizeof(opt));
#endif	/* IPV6_MULTICAST_HOPS */

	/* we used to retry upon failure, but who cares */
	if (bind(s, &sa.sa, sizeof(sa)) < 0) {
		return -1;
	}

	/* join the mcast group(s) */
	mcast6_join(s, port);

	/* return the socket we've got */
	/* succeeded if > 0 */
	return 0;
}

static void
mcast6_listener_deinit(int sock)
{
	/* drop multicast group membership */
	mcast6_leave_group(sock, &mreq6_silo);
	mcast6_leave_group(sock, &mreq6_lilo);
	mcast6_leave_group(sock, &mreq6_nolo);
	/* linger the sink sock */
	setsock_linger(sock, 1);
	return;
}


static void
ev_io_shut(EV_P_ ev_io w[static 1])
{
	ev_io_stop(EV_A_ w);
	close(w->fd);
	w->fd = -1;
	return;
}


static const char *sub_flt;
static size_t sub_flz;

static void
init_sub_flt(const char *fltstr)
{
	sub_flt = fltstr;
	sub_flz = strlen(sub_flt);

	if (LIKELY(sub_flz)) {
		if (sub_flt[sub_flz - 1] == '/') {
			sub_flz--;
		}
		if (sub_flt[0] != '/') {
			sub_flz = 0UL;
		}
	}
	return;
}

static void
free_sub_flt(void)
{
	return;
}

static bool
matchesp(const char *chn, size_t chz)
{
/* check if the channel we monitor is a superdirectory of CHN */
	if (chz < sub_flz) {
		/* can't be */
		return false;
	} else if (memcmp(chn, sub_flt, sub_flz)) {
		/* nope */
		return false;
	}
	return true;
}

static void
sub_cb(EV_P_ ev_io *w, int UNUSED(revents))
{
	static const char hdr[] = "\xff" "8\x00\x7f" /*rev*/"\x01"
		/*socktyp pub*/"\x01"
		/*final short (implicit \nul) */;
	char buf[1280];
	ssize_t nrd;
	/* for channel inspection */
	size_t chz;
	const char *chn;
	size_t msz;
	const char *msg;

	/* read it off the wire for inspection */
	if ((nrd = recv(w->fd, buf, sizeof(buf), 0)) <= (ssize_t)sizeof(hdr) ||
	    /* and see if they speak zmtp */
	    memcmp(hdr, buf, sizeof(hdr))) {
		/* nope */
		return;
	}
	{
		const char *ep = buf + nrd;;
		const char *p = buf + sizeof(hdr);
		size_t idz;

		/* *p should point to the length of the identity */
		idz = *p++;
		if (UNLIKELY((p += idz) >= ep)) {
			return;
		}

		/* we now expect a more frame in *p */
		if (*p++ != '\x01') {
			return;
		}

		/* yay, we found the channel */
		if ((chz = *p++) == 0U) {
			/* don't want no, naught byte channels */
			return;
		}
		/* keep a note about the channel */
		chn = p;
		/* skip to the body */
		if (UNLIKELY((p += chz) >= ep)) {
			return;
		}
		/* check if channel ends in / */
		if (chn[chz - 1] == '/') {
			--chz;
		}

		/* final short there? */
		if (*p++ != '\x00') {
			return;
		}
		/* yay, we found the message */
		msz = *p++;
		msg = p;
		/* skip to message ending */
		if (UNLIKELY((p += msz) > ep)) {
			return;
		}

		/* finalise channel with \t and message with \n */
		buf[chn - buf + chz] = '\t';
		buf[msg - buf + msz] = '\n';
	}

	if (!matchesp(chn, chz)) {
		/* no match */
		PMML_DEBUG("chan no matchee\n");
		return;
	}

	/* FANTASTIC, print the message and unloop */
	write(STDOUT_FILENO, chn, chz + 1);
	write(STDOUT_FILENO, msg, msz + 1);
	ev_unloop(EV_A_ EVUNLOOP_ALL);
	return;
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
	ev_io sub[1];
	/* business logic */
	int res = 0;
	int s;

	/* parse the command line */
	if (pimmel_parser(argc, argv, argi)) {
		res = 1;
		goto out;
	} else if (argi->inputs_num < 1U) {
		pimmel_parser_print_help();
		res = 1;
		goto out;
	}

	if ((s = mc6_socket()) < 0) {
		perror("cannot initialise mc socket");
		res = 1;
		goto out;
	} else if (mcast6_listener_init(s, PMML_NETWORK_SERVICE)) {
		perror("cannot join mc groups");
		close(s);
		res = 1;
		goto out;
	}

	/* initialise the main loop */
	loop = ev_default_loop(EVFLAG_AUTO);

	/* initialise a sig C-c handler */
	ev_signal_init(sigint_watcher, sigall_cb, SIGINT);
	ev_signal_start(EV_A_ sigint_watcher);
	ev_signal_init(sigterm_watcher, sigall_cb, SIGTERM);
	ev_signal_start(EV_A_ sigterm_watcher);

	ev_io_init(sub, sub_cb, s, EV_READ);
	ev_io_start(EV_A_ sub);

	init_sub_flt(argi->inputs[0]);


	/* now wait for events to arrive */
	ev_loop(EV_A_ 0);


	/* free sub filter */
	free_sub_flt();

	mcast6_listener_deinit(sub->fd);
	ev_io_shut(EV_A_ sub);

	/* destroy the default evloop */
	ev_default_destroy();

out:
	pimmel_parser_free(argi);
	return res;
}

/* pimmel-wait.c ends here */
