/*** sub.c -- private pimmel API, subscription handling
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
#include <string.h>
#if defined HAVE_OPENSSL_EVP_H && defined HAVE_OPENSSL_PEM_H
# include <openssl/evp.h>
# include <openssl/pem.h>
# define HAVE_OPENSSL	1
#endif	/* HAVE_OPENSSL_EVP_H && HAVE_OPENSSL_PEM_H */
#include "sub.h"
#include "nifty.h"

#if defined HAVE_OPENSSL
# define SUB_INC	(1U + sizeof(void*))
#else  /* !HAVE_OPENSSL */
# define SUB_INC	(1U)
#endif	/* HAVE_OPENSSL */

union __chn_u {
	struct {
		uint8_t len;
		char str[0];
	};
	char c[0];
};

static inline __attribute__((pure)) size_t
__nex64(size_t x)
{
	return ((x + 63U) / 64U) * 64U;
}


sub_t
find_sub(const struct sublist_s sa[static 1], const char *chn, size_t chz)
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

sub_t
add_sub(struct sublist_s sl[static restrict 1], const char *chan, size_t chnz)
{
	sub_t s;

	/* check sl before we add CHAN */
	if (UNLIKELY((s = find_sub(sl, chan, chnz)) != NULL)) {
		/* already subscribed */
		return s;
	}

	/* check if p is large enough */
	{
		union __chn_u *p = (void*)(sl->sub->c + sl->sub_nex);
		size_t ol = __nex64(sl->sub_nex);
		size_t nu = __nex64(sl->sub_nex + chnz + 1U);

		if (UNLIKELY(ol < nu)) {
			sl->sub = realloc(sl->sub, nu);

			/* recompute p in terms of new base ptr sa->sub */
			p = (void*)(sl->sub->c + sl->sub_nex);
		}

		/* copy the subscription */
		p->len = (uint8_t)chnz;
		memcpy(p->str, chan, chnz);
		/* up the index pointer */
		sl->sub_nex += chnz + SUB_INC;

		s = p;
	}
	return s;
}

void
rem_sub(struct sublist_s sl[static restrict 1], const char *chn, size_t chz)
{
	union __chn_u *p = find_sub(sl, chn, chz);
	union __chn_u *nex = (void*)(p->str + p->len + SUB_INC);
	size_t rest = sl->sub_nex - (nex->c - sl->sub->c);
	size_t ol = __nex64(sl->sub_nex);
	size_t nu;

#if defined HAVE_OPENSSL
	EVP_PKEY *pk;

	if ((pk = sub_get_pkey(p)) != NULL) {
		EVP_PKEY_free(pk);
	}
#endif	/* HAVE_OPENSSL */

	memmove(p, nex, rest);
	sl->sub_nex -= (char*)nex - (char*)p;
	nu = __nex64(sl->sub_nex);

	if (ol > nu) {
		/* also shrink the string buffer */
		sl->sub = realloc(sl->sub, nu);
	}
	return;
}

const_sub_t
sub_matches_p(const struct sublist_s sl[static 1], const char *chn, size_t chz)
{
/* check if the channel we monitor is a superdirectory of CHN */
	union __chn_u *p;
	const union __chn_u *ep;
	const union __chn_u *best = NULL;

	for (p = sl->sub, ep = (const void*)(sl->sub->c + sl->sub_nex);
	     p < ep; p = (void*)(p->c + p->len + SUB_INC)) {
		if (p->len <= chz &&
		    memcmp(p->str, chn, p->len) == 0 &&
		    (p->len == chz || chn[p->len] == '/')) {
			/* found him */
			if (best == NULL || p->len > best->len) {
				best = p;
			}
		}
	}
	return best;
}

void*
sub_get_pkey(const_sub_t sub)
{
#if defined HAVE_OPENSSL
	EVP_PKEY *pk;
	const union __chn_u *x = sub;

	memcpy(&pk, x->str + x->len + 1U, sizeof(pk));
	return pk;
#else  /* !HAVE_OPENSSL */
	return NULL;
#endif	/* HAVE_OPENSSL */
}

void
sub_set_pkey(sub_t sub, const void *pk)
{
#if defined HAVE_OPENSSL
	union __chn_u *x = sub;

	memcpy(x->str + x->len + 1U, &pk, sizeof(pk));
#endif	/* HAVE_OPENSSL */
	return;
}

void
free_subs(struct sublist_s sl[static 1])
{
	if (sl->sub != NULL) {
#if defined HAVE_OPENSSL
		union __chn_u *p;
		const union __chn_u *ep;

		for (p = sl->sub, ep = (const void*)(sl->sub->c + sl->sub_nex);
		     p < ep; p = (void*)(p->c + p->len + SUB_INC)) {
			EVP_PKEY *pk;

			if ((pk = sub_get_pkey(p)) != NULL) {
				EVP_PKEY_free(pk);
			}
		}
#endif	/* HAVE_OPENSSL */
		sl->sub_nex = 0UL;
		free(sl->sub);
		sl->sub = NULL;
	}
	return;
}

/* sub.c ends here */
