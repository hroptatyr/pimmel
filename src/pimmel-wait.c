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
#include <pimmel.h>
#include "nifty.h"
#include "ud-sock.h"

#define MAYBE_UNUSED	UNUSED

#if defined DEBUG_FLAG && !defined BENCHMARK
# include <assert.h>
# define PMML_DEBUG(args...)	fprintf(stderr, args)
# define MAYBE_NOINLINE		__attribute__((noinline))
#else  /* !DEBUG_FLAG */
# define PMML_DEBUG(args...)
# define assert(x)
# define MAYBE_NOINLINE
#endif	/* DEBUG_FLAG */


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
	struct pmml_chnmsg_s msg[1];
	char buf[1280];
	ssize_t nrd;

	/* read it off the wire for inspection */
	if ((nrd = recv(w->fd, buf, sizeof(buf), 0)) <= 0) {
		/* don't even bother */
		return;
	} else if (UNLIKELY((msg->flags = 0U, pmml_chck(msg, buf, nrd)) < 0)) {
		/* nope */
		PMML_DEBUG("chck() came back unsuccessful\n");
		return;
	}

	if (!matchesp(msg->chan, msg->chnz)) {
		/* no match */
		PMML_DEBUG("chan no matchee\n");
		return;
	}

	/* otherwise finalise channel with \t and message with \n */
	buf[msg->chan - buf + msg->chnz] = '\t';
	buf[msg->msg - buf + msg->msz] = '\n';

	/* FANTASTIC, print the message and unloop */
	write(STDOUT_FILENO, msg->chan, msg->chnz + 1);
	write(STDOUT_FILENO, msg->msg, msg->msz + 1);
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

	if ((s = pmml_socket(PMML_FL_SUB)) < 0) {
		perror("cannot initialise pimmel socket");
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

	ev_io_stop(EV_A_ sub);
	pmml_close(s);

	/* destroy the default evloop */
	ev_default_destroy();

out:
	pimmel_parser_free(argi);
	return res;
}

/* pimmel-wait.c ends here */
