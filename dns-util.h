/*	$Id$	*/

/*
 * Copyright (c) 2005 Jakob Schlyter & Hakan Olsson.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef DNS_UTIL_H
#define DNS_UTIL_H

#define MAX_LINE		4096
#define MAX_TIMESTAMP		16

#define DNS_KEYOWNER_ZONE	0x0100
#define DNS_KEYOWNER_ZONE	0x0100
#define DNS_KEYFLAG_KSK		0x0001
#define DNS_KEYPROTO_DNSSEC	3
#define DNS_KEYALG_DSA		3
#define DNS_KEYALG_RSASHA1	5

#define DNS_TYPE_DNSKEY		48
#define DNS_TYPE_ANY		255	/* A request for all records */

#define DNS_CLASS_IN		1	/* Internet */
#define DNS_CLASS_CH		3	/* Chaos */
#define DNS_CLASS_HS		3	/* Hesiod */
#define DNS_CLASS_NONE		254	/* None */
#define DNS_CLASS_ANY		255	/* Internet */


typedef struct dns_type_dnskey {
	u_int16_t	flags;
	u_int8_t	protocol;
	u_int8_t	algorithm;
	u_int16_t	keylen;
	u_char		*keydata;
} dns_type_dnskey_t;
	
typedef struct dns_type_rrsig {
	u_int16_t	type;
	u_int8_t	algorithm;
	u_int8_t	labels;
	u_int32_t	origttl;
	u_int32_t	expiration;
	u_int32_t	inception;
	u_int16_t	keytag;
	u_char		*signer;
	u_int16_t	siglen;
	u_char		*sigdata;
} dns_type_rrsig_t;

typedef struct dns_rdata {
	u_int16_t	length;
	unsigned char	*data;
	struct dns_rdata	*next;
} dns_rdata_t;

typedef struct dns_rrset {
	char		*name;
	u_int16_t	type;		/* dns_type */
	u_int16_t	class;		/* dns_class */
	u_int32_t	ttl;
	dns_rdata_t	*rdata;
} dns_rrset_t;

dns_type_dnskey_t *RSA_to_DNSKEY(const RSA *rsa, const char *owner);
dns_type_dnskey_t *DSA_to_DNSKEY(const DSA *dsa, const char *owner);

int write_RSA_DNSKEY(FILE *f, const RSA *rsa, const char *owner);
int write_DSA_DNSKEY(FILE *f, const DSA *dsa, const char *owner);

int write_DNSKEY(FILE *f, const dns_type_dnskey_t *dnskey, const char *owner);
int write_RRSIG(FILE *f, const dns_type_rrsig_t *rrsig, const char *owner);

size_t rdata_from_RRSIG(const dns_type_rrsig_t *rrsig,
    unsigned char **rdata);
size_t rdata_from_DNSKEY(const dns_type_dnskey_t *dnskey,
    unsigned char **rdata);

u_int16_t keytag_from_DNSKEY(const dns_type_dnskey_t *dnskey);

int load_RRSET_from_file(const char *, dns_rrset_t *, int);
int gen_RRSET_HASH(const dns_rrset_t *, dns_type_rrsig_t *, char *, size_t);

const char *rrtype2string(u_int16_t type);

size_t name_from_string(const char *, u_int8_t **);
time_t string2time(const char *s);
u_int8_t nlabels(const char *s);
void hexdump(const unsigned char *buf, int buflen);


#endif /* DNS_UTIL_H */
