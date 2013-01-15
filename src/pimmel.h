/*** pimmel.h -- public pimmel API
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
#if !defined INCLUDED_pimmel_h_
#define INCLUDED_pimmel_h_

#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>

#if defined __cplusplus
extern "C" {
# if defined __GNUC__
#  define restrict	__restrict__
# else
#  define restrict
# endif
#endif /* __cplusplus */

#define PMML_NETWORK_SERVICE	7665/*PMML on the phone*/
/* http://www.iana.org/assignments/ipv6-multicast-addresses/ lists us
 * as ff0x:0:0:0:0:0:0:134 */
/* node-local */
#define PMML_MCAST6_NODE_LOCAL	"ff01::134"
/* link-local */
#define PMML_MCAST6_LINK_LOCAL	"ff02::134"
/* site-local */
#define PMML_MCAST6_SITE_LOCAL	"ff05::134"

/**
 * Socket flags, can be |'d. */
enum {
	PMML_NONE = 0U,
	PMML_PUB = 1U,
	PMML_SUB = 2U,
};

enum {
	PMML_CHNMSG_HAS_IDN = 4U,
};

struct pmml_chnmsg_s {
	/** bitset of flags */
	uint32_t flags;
	/** number of bytes the channel string occupies */
	size_t chnz;
	/** channel to send to, \nul terminated */
	const char *chan;
	/** message size in bytes */
	size_t msz;
	/** message */
	const char *msg;
};

/** like pmml_chnmsg_s but with identity info attached */
struct pmml_chnmsg_idn_s {
	struct pmml_chnmsg_s chnmsg;
	/** length of identity IDN in bytes */
	size_t idz;
	/** identity string */
	const char *idn;
};


/* first up socket creation and deletion */
/**
 * Return a socket set up for PUB'ing or SUB'ing, according to FLAGS. */
extern int pmml_socket(int flags);

/**
 * Close a socket and free associated resources. */
extern int pmml_close(int sock);

/* next up packing/unpacking messages */
/**
 * Produce wire-representation of MSG in provided buffer TGT of size TSZ.
 * If successful return the number of bytes on the wire, or -1 otherwise.
 * This routine will operate regardless what has been subscribed to. */
extern ssize_t
pmml_pack(char *restrict tgt, size_t tsz, const struct pmml_chnmsg_s *msg);

/**
 * Check BUF (of size BSZ bytes) for channel notifications.
 * Put a copy of the message in *TGT and return the number of bytes
 * consumed from BUF.
 * This routine will operate regardless what has been subscribed to. */
extern ssize_t
pmml_chck(struct pmml_chnmsg_s *restrict tgt, const char *buf, size_t bsz);

/* finally sending and receiving */
/**
 * Like `send()' for pimmel sockets. */
extern ssize_t pmml_send(int s, const void *buf, size_t bsz, int flags);

/* higher level, packing+sending receiving+unpacking in one go */
/**
 * Notify S with message in MSG. */
extern int pmml_noti(int s, const struct pmml_chnmsg_s *msg);

/**
 * Wait for messages on socket S according to subscriptions put via
 * `pmml_sub()', if successful fill in MSG. */
extern int pmml_wait(int s, struct pmml_chnmsg_s *restrict msg);

/**
 * Subscribe to messages to channel CHAN on S. */
extern int pmml_sub(int s, const char *chan, ...);

/**
 * Unsubscribe from all messages on S, or if const char *CHAN argument
 * is given unsubscribe from messages to channel CHAN only. */
extern int pmml_uns(int s, /* const char *chan */...);

#if defined __cplusplus
}
#endif	/* __cplusplus */

#endif	/* INCLUDED_pimmel_h_ */
