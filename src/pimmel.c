/*** pimmel.c -- public pimmel API
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
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#if defined HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif	/* HAVE_SYS_SOCKET_H */
#if defined HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif	/* HAVE_ARPA_INET_H */
#if defined HAVE_OPENSSL_EVP_H && defined HAVE_OPENSSL_PEM_H
# include <openssl/evp.h>
# include <openssl/pem.h>
# define HAVE_OPENSSL	1
#endif	/* HAVE_OPENSSL_EVP_H && HAVE_OPENSSL_PEM_H */
#include "pimmel.h"
#include "ud-sock.h"
#include "nifty.h"

#if !defined IPPROTO_IPV6
# error system not fit for ipv6 transport
#endif	/* IPPROTO_IPV6 */

#define DEFAULT_TIMEOUT		60
#define UDP_MULTICAST_TTL	64

#if defined DEBUG_FLAG && !defined BENCHMARK
# include <assert.h>
# include <stdio.h>
# define PMML_DEBUG(args...)	fprintf(stderr, args)
# define MAYBE_NOINLINE		__attribute__((noinline))
# define MAYBE_UNUSED		UNUSED
#else  /* !DEBUG_FLAG */
# define assert(...)
# define PMML_DEBUG(args...)
# define MAYBE_UNUSED		UNUSED
# define MAYBE_NOINLINE
#endif	/* DEBUG_FLAG */

/* node local, site local and link local */
static struct ipv6_mreq ALGN16(mreq6_nolo);
static struct ipv6_mreq ALGN16(mreq6_silo);
static struct ipv6_mreq ALGN16(mreq6_lilo);
static union ud_sockaddr_u dst = {0};

/* stuff we want to associate with sockets */
union __chn_u {
	struct {
		uint8_t len;
		char str[0];
	};
	char c[0];
};

struct sockasso_s {
	int s;
	unsigned int fl;
	/* alloc size of sub */
	size_t sub_nex;
	union __chn_u *sub;
};

static size_t nsockasso;
static size_t ref_sockasso;
static struct sockasso_s *sockasso;


/* subscriptions */
#if defined HAVE_OPENSSL
# define SUB_INC	(1U + sizeof(void*))
#else  /* !HAVE_OPENSSL */
# define SUB_INC	(1U)
#endif	/* HAVE_OPENSSL */

static union __chn_u*
find_sub(const struct sockasso_s sa[static 1], const char *chn, size_t chz)
{
/* like matchesp() but return a ptr and be strict about the matches */
	union __chn_u *p;
	const union __chn_u *ep;

	for (p = sa->sub, ep = (const void*)(sa->sub->c + sa->sub_nex);
	     p < ep; p = (void*)(p->c + p->len + SUB_INC)) {
		if (p->len == chz && memcmp(p->str, chn, chz) == 0) {
			/* found him */
			return p;
		}
	}
	return NULL;
}

static bool
matchesp(const struct sockasso_s sa[static 1], const char *chn, size_t chz)
{
/* check if the channel we monitor is a superdirectory of CHN */
	union __chn_u *p;
	const union __chn_u *ep;

	for (p = sa->sub, ep = (const void*)(sa->sub->c + sa->sub_nex);
	     p < ep; p = (void*)(p->c + p->len + SUB_INC)) {
		if (p->len <= chz &&
		    memcmp(p->str, chn, p->len) == 0 &&
		    (p->len == chz || chn[p->len] == '/')) {
			/* found him */
			return true;
		}
	}
	return false;
}

#if defined HAVE_OPENSSL
static EVP_PKEY*
sub_get_pkey(const union __chn_u x[static 1])
{
	EVP_PKEY *pk;

	memcpy(&pk, x->str + x->len + 1U, sizeof(pk));
	return pk;
}

static void
sub_set_pkey(union __chn_u *restrict x, const EVP_PKEY *pk)
{
	memcpy(x->str + x->len + 1U, &pk, sizeof(pk));
	return;
}
#endif	/* HAVE_OPENSSL */

static void
free_subs(struct sockasso_s sa[static 1])
{
	if (sa->sub != NULL) {
#if defined HAVE_OPENSSL
		union __chn_u *p;
		const union __chn_u *ep;

		for (p = sa->sub, ep = (const void*)(sa->sub->c + sa->sub_nex);
		     p < ep; p = (void*)(p->c + p->len + SUB_INC)) {
			EVP_PKEY *pk;

			if ((pk = sub_get_pkey(p)) != NULL) {
				EVP_PKEY_free(pk);
			}
		}
#endif	/* HAVE_OPENSSL */
		sa->sub_nex = 0UL;
		free(sa->sub);
		sa->sub = NULL;
	}
	return;
}


/* sockasso */
static struct sockasso_s*
find_sockasso(int s)
{
	if (UNLIKELY(sockasso == NULL)) {
		return NULL;
	}
	for (size_t i = 0; i < nsockasso; i++) {
		if (sockasso[i].s == s) {
			return sockasso + i;
		}
	}
	return NULL;
}

static struct sockasso_s*
make_sockasso(int s)
{
	/* try and find the socket first */
	struct sockasso_s *sa;

	if ((sa = find_sockasso(s)) != NULL) {
		return sa;
	}
	/* otherwise try and find a free slot */
	for (size_t i = 0; i < nsockasso; i++) {
		if (sockasso[i].s == 0U) {
			sa = sockasso + i;
			goto out;
		}
	}
	/* otherwise the array might not be large enough */
	{
		size_t ol = nsockasso;
		size_t nu = nsockasso += 4;
		sockasso = realloc(sockasso, nu * sizeof(*sockasso));
		memset(sockasso + ol, 0, (nu - ol) * sizeof(*sockasso));
		sockasso[ol].s = s;
		sa = sockasso + ol;
	}
out:
	ref_sockasso++;
	return sa;
}

static void
free_sockasso(struct sockasso_s sa[static 1])
{
	free_subs(sa);
	sa->s = 0;
	return;
}


/* just some more socket helpers */
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
mc6_loop(int s, int on)
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
mc6_join_group(int s, const char *addr, struct ipv6_mreq *r)
{
	/* set up the multicast group and join it */
	inet_pton(AF_INET6, addr, &r->ipv6mr_multiaddr.s6_addr);
	r->ipv6mr_interface = 0;

	/* now truly join */
	return setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP, r, sizeof(*r));
}

static void
mc6_leave_group(int s, struct ipv6_mreq *mreq)
{
	/* drop mcast6 group membership */
	setsockopt(s, IPPROTO_IPV6, IPV6_LEAVE_GROUP, mreq, sizeof(*mreq));
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
mc6_set_dest(int UNUSED(s), const char *addr, short unsigned int port)
{
	/* set destination address */
	dst.sa6.sin6_family = AF_INET6;
	/* we pick link-local here for simplicity */
	inet_pton(AF_INET6, addr, &dst.sa6.sin6_addr);
	/* port as well innit */
	dst.sa6.sin6_port = htons(port);
	/* set the flowinfo */
	dst.sa6.sin6_flowinfo = 0;
	return;
}

static int
mc6_join(int s)
{
	mc6_join_group(s, PMML_MCAST6_NODE_LOCAL, &mreq6_nolo);
	mc6_join_group(s, PMML_MCAST6_LINK_LOCAL, &mreq6_lilo);
	mc6_join_group(s, PMML_MCAST6_SITE_LOCAL, &mreq6_silo);
	return 0;
}

static int
mc6_leave(int s)
{
	/* drop multicast group membership */
	mc6_leave_group(s, &mreq6_silo);
	mc6_leave_group(s, &mreq6_lilo);
	mc6_leave_group(s, &mreq6_nolo);
	/* linger the sink sock */
	setsock_linger(s, 1);
	return 0;
}

static int
mc6_set_pub(int s)
{
	union ud_sockaddr_u sa = {
		.sa6.sin6_family = AF_INET6,
		.sa6.sin6_addr = IN6ADDR_ANY_INIT,
		.sa6.sin6_port = 0,
	};

	/* as a courtesy to tools bind the channel */
	return bind(s, &sa.sa, sizeof(sa));
}

static int
mc6_set_sub(int s)
{
	const short unsigned int port = PMML_NETWORK_SERVICE;
	union ud_sockaddr_u sa = {
		.sa6.sin6_family = AF_INET6,
		.sa6.sin6_addr = IN6ADDR_ANY_INIT,
		.sa6.sin6_port = htons(port),
	};
	int opt;

	/* allow many many many subscribers on that port */
	setsock_reuseaddr(s);
	setsock_reuseport(s);

	/* turn multicast looping on */
	mc6_loop(s, 1);
#if defined IPV6_V6ONLY
	opt = 0;
	setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
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
	mc6_join(s);
	return 0;
}

static int
mc6_unset_pub(int UNUSED(s))
{
	/* do fuckall */
	return 0;
}

static int
mc6_unset_sub(int s)
{
	/* just leave the group */
	mc6_leave(s);
	return 0;
}


/* public funs */
int
pmml_socket(int fl)
{
	int s;

#define FL_SUBP(fl)	(fl & PMML_SUB)
#define FL_PUBP(fl)	(fl & PMML_PUB)

	if ((s = mc6_socket()) < 0) {
		goto out;
	}
	if (FL_SUBP(fl) && mc6_set_sub(s) < 0) {
		goto clos_out;
	}
	if (FL_PUBP(fl) && mc6_set_pub(s) < 0) {
		goto clos_out;
	}

	/* always reply to the global service? */
	mc6_set_dest(s, PMML_MCAST6_SITE_LOCAL, PMML_NETWORK_SERVICE);

out:
	return s;

clos_out:
	close(s);
	return -1;
}

int
pmml_close(int s)
{
	mc6_unset_pub(s);
	mc6_unset_sub(s);

	/* see if we've got a map entry */
	{
		struct sockasso_s *sa;

		if ((sa = find_sockasso(s)) != NULL) {
			/* free asso data */
			free_sockasso(sa);
			ref_sockasso--;
		}

		if (ref_sockasso == 0UL && sockasso != NULL) {
			/* last socket close */
			free(sockasso);
			sockasso = NULL;
		}
	}
	return close(s);
}

ssize_t
pmml_send(int s, const void *b, size_t z, int flags)
{
	return sendto(s, b, z, flags, &dst.sa, sizeof(dst));
}


/* packing */
static const char hdr[] =
	/* magic */"\xff" "8\x00\x7f"
	/* rev */"\x01"
	/* socktyp: pub */"\x01"
	/* final-short is implicit */;

struct zmtp_str_s {
	size_t z;
	const char *s;
};

#define ZMTP_STR(a, b)					\
	{						\
		.z = a ? a : (b ? strlen(b) : 0UL),	\
		.s = b,					\
	}

static size_t
shove_string(char *restrict tgt, size_t tsz, struct zmtp_str_s s)
{
	if (LIKELY((uint8_t)s.z + 1UL < tsz)) {
		if (LIKELY((*tgt++ = (uint8_t)s.z))) {
			memcpy(tgt, s.s, (uint8_t)s.z);
		}
		return 1UL + (uint8_t)s.z;
	}
	return 0UL;
}

ssize_t
pmml_pack(char *restrict tgt, size_t tsz, const struct pmml_chnmsg_s *msg)
{
	char *restrict p = tgt;

	/* go ahead with the header bit first */
	memcpy(p, hdr, sizeof(hdr));
	/* let p point to the end of the header */
	p += sizeof(hdr);

	/* bang the identity */
	{
		struct zmtp_str_s s = {
			.z = 0,
			.s = NULL,
		};

		if (UNLIKELY(msg->flags & PMML_CHNMSG_HAS_IDN)) {
			const struct pmml_chnmsg_idn_s *idn = (const void*)msg;

			s = (struct zmtp_str_s){.z = idn->idz, .s = idn->idn};
		}

		/* copy length and beef of idn */
		p += shove_string(p, tsz - (p - tgt), s);
	}

	/* chuck a more-short now */
	*p++ = '\x01';
	{
		struct zmtp_str_s s = ZMTP_STR(msg->chnz, msg->chan);

		p += shove_string(p, tsz - (p - tgt), s);
	}

	/* final-short now, we just assume it's a short message anyway */
	*p++ = '\x00';
	{
		struct zmtp_str_s s = ZMTP_STR(msg->msz, msg->msg);

		p += shove_string(p, tsz - (p - tgt), s);
	}

	/* return number of bytes on the wire */
	return p - tgt;
}

/* unpacking */
static struct zmtp_str_s
snarf_string(const char **p)
{
	size_t z = *(*p)++;
	const char *s = *p;

	/* copy channel info */
	*p += z;
	return (struct zmtp_str_s){.z = z, .s = s};
}

ssize_t
pmml_chck(struct pmml_chnmsg_s *restrict tgt, const char *buf, size_t bsz)
{
	const char *p = buf;
	const char *ep = buf + bsz;

	/* see if the buffer is zmtp */
	if (UNLIKELY(bsz < sizeof(hdr))) {
		return -1;
	} else if (UNLIKELY(memcmp(hdr, buf, sizeof(hdr)))) {
		/* nope */
		return -1;
	}

	/* have p pointing to the identity */
	if (UNLIKELY((p += sizeof(hdr)) >= ep)) {
		return -1;
	}

	/* check identity */
	{
		struct zmtp_str_s s = snarf_string(&p);

		/* copy identity */
		if (UNLIKELY(tgt->flags & PMML_CHNMSG_HAS_IDN)) {
			struct pmml_chnmsg_idn_s *restrict idn = (void*)tgt;

			idn->idz = s.z;
			idn->idn = s.s;
		}

		/* ffw p */
		if (UNLIKELY(p >= ep)) {
			return -1;
		}
	}

	/* we now expect a more frame in *p */
	if (UNLIKELY(*p++ != '\x01')) {
		return -1;
	}

	/* snarf off the channel info */
	{
		struct zmtp_str_s s = snarf_string(&p);

		/* copy channel info */
		tgt->chnz = s.z;
		tgt->chan = s.s;

		/* ffw p */
		if (UNLIKELY(p >= ep)) {
			return -1;
		}
	}

	/* final short next? */
	if (UNLIKELY(*p++ != '\x00')) {
		return -1;
	}

	/* must be the actual message next */
	{
		struct zmtp_str_s s = snarf_string(&p);

		/* copy message info */
		tgt->msz = s.z;
		tgt->msg = s.s;

		/* ffw p */
		if (UNLIKELY(p > ep)) {
			return -1;
		}
	}
	return p - buf;
}


/* subscription handling, this should be specific to S. */
static inline __attribute__((pure)) size_t
__nex64(size_t x)
{
	return ((x + 63U) / 64U) * 64U;
}

int
pmml_sub(int s, const char *chan, ...)
{
/* we really should use tries, innit? */
	struct sockasso_s *sa = make_sockasso(s);
	size_t chnz = strlen(chan);

	if (UNLIKELY(chnz < 1U || chan[0] != '/')) {
		/* don't go for channels with no initial / */
		return -1;
	} else if (chan[chnz - 1] == '/') {
		/* normalise chan, remove trailing / */
		chnz--;
	}

	/* go through sub before we add CHAN */
	if (UNLIKELY(find_sub(sa, chan, chnz) != NULL)) {
		/* already subscribed */
		return 0;
	}

	/* check if p is large enough */
	{
		union __chn_u *p = (void*)(sa->sub->c + sa->sub_nex);
		size_t ol = __nex64(sa->sub_nex);
		size_t nu = __nex64(sa->sub_nex + chnz + 1U);

		if (UNLIKELY(ol < nu)) {
			sa->sub = realloc(sa->sub, nu);

			/* recompute p in terms of new base ptr sa->sub */
			p = (void*)(sa->sub->c + sa->sub_nex);
		}

		/* copy the subscription */
		p->len = (uint8_t)chnz;
		memcpy(p->str, chan, chnz);
		/* up the index pointer */
		sa->sub_nex += chnz + SUB_INC;
	}
	return 0;
}

int
pmml_uns(int s, ...)
{
	struct sockasso_s *sa;
	size_t i = 0;
	va_list vap;

	if ((sa = find_sockasso(s)) == NULL) {
		/* do fuckall if there's no subs */
		return -1;
	}

	va_start(vap, s);
	for (const char *chn; (chn = va_arg(vap, const char*)); i++) {
		size_t chz = strlen(chn);
		union __chn_u *p = find_sub(sa, chn, chz);
		union __chn_u *nex = (void*)(p->str + p->len + SUB_INC);
		size_t rest = sa->sub_nex - (nex->c - sa->sub->c);
		size_t ol = __nex64(sa->sub_nex);
		size_t nu;

#if defined HAVE_OPENSSL
		EVP_PKEY *pk;

		if ((pk = sub_get_pkey(p)) != NULL) {
			EVP_PKEY_free(pk);
		}
#endif	/* HAVE_OPENSSL */

		memmove(p, nex, rest);
		sa->sub_nex -= (char*)nex - (char*)p;
		nu = __nex64(sa->sub_nex);

		if (ol > nu) {
			/* also shrink the string buffer */
			sa->sub = realloc(sa->sub, nu);
		}
	}
	va_end(vap);

	/* unsubscribe all channels then */
	if (i == 0) {
		free_subs(sa);
	}
	return 0;
}


int
pmml_vrfy_key(int s, const char *chan, const char *keyfile)
{
	int res = -1;

#if defined HAVE_OPENSSL
	struct sockasso_s *sa;
	size_t chnz;
	union __chn_u *sub;
	FILE *fp;
	EVP_PKEY *pk;

	if ((sa = find_sockasso(s)) == NULL) {
		/* do fuckall if there's no subs */
		return -1;
	} else if (UNLIKELY((chnz = strlen(chan),
			     sub = find_sub(sa, chan, chnz)) == NULL)) {
		/* not subscribed */
		return -1;
	} else if ((pk = sub_get_pkey(sub)) != NULL) {
		EVP_PKEY_free(pk);
	}

	/* start over */
	pk = NULL;
	if ((fp = fopen(keyfile, "r")) == NULL) {
		goto set;
	} else if ((pk = PEM_read_PUBKEY(fp, NULL, NULL, NULL)) == NULL) {
		goto clos;
	}

	/* success */
	res = 0;
clos:
	fclose(fp);
set:
	sub_set_pkey(sub, pk);
#endif	/* HAVE_OPENSSL */
	return res;
}

int
pmml_sign_key(int s, const char *chan, const char *keyfile)
{
	int res = -1;

#if defined HAVE_OPENSSL
	struct sockasso_s *sa;
	size_t chnz;
	union __chn_u *sub;
	FILE *fp;
	EVP_PKEY *pk;

	if (pmml_sub(s, chan) < 0) {
		/* subscribe to it just to have the asso */
		return -1;
	} else if ((sa = find_sockasso(s)) == NULL) {
		/* do fuckall if there's no subs */
		return -1;
	} else if (UNLIKELY((chnz = strlen(chan),
			     sub = find_sub(sa, chan, chnz)) == NULL)) {
		/* not subscribed */
		return -1;
	} else if ((pk = sub_get_pkey(sub)) != NULL) {
		EVP_PKEY_free(pk);
	}

	/* start over */
	pk = NULL;
	if ((fp = fopen(keyfile, "r")) == NULL) {
		goto set;
	} else if ((pk = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL) {
		goto clos;
	}

	/* success */
	res = 0;
clos:
	fclose(fp);
set:
	sub_set_pkey(sub, pk);
#endif	/* HAVE_OPENSSL */
	return res;
}


/* high level */
int
pmml_noti(int s, const struct pmml_chnmsg_s *msg)
{
	char buf[1280];
	ssize_t z;
	ssize_t nwr;

	if ((z = pmml_pack(buf, sizeof(buf), msg)) < 0) {
		return -1;
	} else if ((nwr = pmml_send(s, buf, (size_t)z, 0)) < 0) {
		return -1;
	}
	return 0;
}

int
pmml_wait(int s, struct pmml_chnmsg_s *restrict msg)
{
	static char buf[1280];
	struct pmml_chnmsg_idn_s __msg[1];
	struct sockasso_s *sa;
	ssize_t nrd;
	const char *bp;

	if ((bp = buf, nrd = recv(s, buf, sizeof(buf), 0)) <= 0) {
		/* don't even bother */
		return -1;
	} else if (UNLIKELY((sa = find_sockasso(s)) == NULL)) {
		/* no subs */
		return -1;
	}

	/* let pmml_chck() know that we are up for identity retrieval */
	__msg->chnmsg.flags = PMML_CHNMSG_HAS_IDN;
	/* process them all */
	for (ssize_t nch;
	     LIKELY(nrd > 0 && (nch = pmml_chck((void*)__msg, bp, nrd)) > 0);
	     bp += nch, nrd -= nch) {
		if (matchesp(sa, __msg->chnmsg.chan, __msg->chnmsg.chnz)) {
			goto match;
		}
	}
	/* whatever went wrong */
	return -1;

match:
	/* we're lucky */
	if (LIKELY(!(msg->flags & PMML_CHNMSG_HAS_IDN))) {
		*msg = __msg->chnmsg;
	} else {
		*(struct pmml_chnmsg_idn_s*)msg = *__msg;
	}
	return 0;
}

/* pimmel.c ends here */
