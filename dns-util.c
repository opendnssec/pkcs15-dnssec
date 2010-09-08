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

#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define __USE_XOPEN
#include <time.h>

#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include "base64.h"
#include "dns-util.h"

dns_type_dnskey_t *
RSA_to_DNSKEY(const RSA *rsa, const char *owner)
{
	dns_type_dnskey_t *dnskey;
	int e_bytes, mod_bytes, dlen = 0;
	char data[MAX_LINE];

	dnskey = malloc(sizeof(dns_type_dnskey_t));

	e_bytes   = BN_num_bytes (rsa->e);
	mod_bytes = BN_num_bytes (rsa->n);

	if (e_bytes <= 0xFF) {
		data[dlen++] = (char)e_bytes;
	} else {
		data[dlen++] = (char)0;
		data[dlen++] = (char)(e_bytes >> 8);
		data[dlen++] = (char)(e_bytes & 0xFF);
	}
	dlen += BN_bn2bin (rsa->e, data + dlen);
	dlen += BN_bn2bin (rsa->n, data + dlen);

	if (dnskey) {
		dnskey->flags = DNS_KEYOWNER_ZONE | DNS_KEYFLAG_KSK;
		dnskey->protocol = DNS_KEYPROTO_DNSSEC;
		dnskey->algorithm = DNS_KEYALG_RSASHA1;
		dnskey->keylen = dlen;
		dnskey->keydata = malloc(dlen);
		if (dnskey->keydata) {
			memcpy(dnskey->keydata, data, dlen);
		} else {
			free(dnskey);
			dnskey = NULL;
		}
	}

	return dnskey;
}

dns_type_dnskey_t *
DSA_to_DNSKEY(const DSA *dsa, const char *owner)
{
	dns_type_dnskey_t *dnskey;
	int p_bytes, dlen = 0, p;
	char data[MAX_LINE];

	dnskey = malloc(sizeof(dns_type_dnskey_t));

	p_bytes = BN_num_bytes (dsa->p);
	if (((p_bytes - 64) / 8) > 8) {
		return NULL;
	}

	*(data + dlen++) = (p_bytes - 64) / 8;

	/* Fields in DSA public key are zero-padded (left) */
#define PAD_ADD(var,len) \
	for (p = 0; p < (len - BN_num_bytes (var)); p++) \
	  *(data + dlen++) = (char)0;			 \
	BN_bn2bin (var, data + dlen);			 \
	dlen += BN_num_bytes (var)

	PAD_ADD (dsa->q, SHA_DIGEST_LENGTH);
	PAD_ADD (dsa->p, p_bytes);
	PAD_ADD (dsa->g, p_bytes);
	PAD_ADD (dsa->pub_key, p_bytes);
#undef PAD_ADD

	if (dnskey) {
		dnskey->flags = DNS_KEYOWNER_ZONE | DNS_KEYFLAG_KSK;
		dnskey->protocol = DNS_KEYPROTO_DNSSEC;
		dnskey->algorithm = DNS_KEYALG_DSA;
		dnskey->keylen = dlen;
		dnskey->keydata = malloc(dlen);
		if (dnskey->keydata) {
			memcpy(dnskey->keydata, data, dlen);
		} else {
			free(dnskey);
			dnskey = NULL;
		}
	}

	return dnskey;
}

int
write_RSA_DNSKEY(FILE *f, const RSA *rsa, const char *owner)
{
	dns_type_dnskey_t *dnskey;
	int c;

	dnskey = RSA_to_DNSKEY(rsa, owner);
	write_DNSKEY(f, dnskey, owner);
	free(dnskey);

	return c;
}

int
write_DSA_DNSKEY(FILE *f, const DSA *dsa, const char *owner)
{
	dns_type_dnskey_t *dnskey;
	int c;

	dnskey = DSA_to_DNSKEY(dsa, owner);
	write_DNSKEY(f, dnskey, owner);
	free(dnskey);

	return c;
}

int
write_DNSKEY(FILE *f, const dns_type_dnskey_t *dnskey,
	     const char *owner)
{
	int c, b64len;
	char b64buf[MAX_LINE];

	b64len = b64_ntop (dnskey->keydata, dnskey->keylen, b64buf, MAX_LINE);
	b64buf[b64len] = (char) 0;

	c = fprintf(f, "%s IN DNSKEY %d %d %d %s\n", owner,
		    dnskey->flags, dnskey->protocol, dnskey->algorithm, 
		    b64buf);

	return (c);
}

int
write_RRSIG(FILE *f, const dns_type_rrsig_t *rrsig,
	    const char *owner)
{
	int c, b64len;
	char b64buf[MAX_LINE];
	char expiration[MAX_TIMESTAMP], inception[MAX_TIMESTAMP];
	time_t t;

	const char *tformat = "%Y%m%d%H%M%S";

	t = rrsig->expiration;
	strftime(expiration, sizeof(expiration), tformat,
		 gmtime((time_t *) &t));

	t = rrsig->inception;
	strftime(inception,  sizeof(inception), tformat,
		 gmtime((time_t *) &t));

	b64len = b64_ntop (rrsig->sigdata, rrsig->siglen, b64buf, MAX_LINE);
	b64buf[b64len] = (char) 0;

	c = fprintf(f, "%s RRSIG %s %d %d %d %s %s %d %s %s\n",
		    owner,
		    rrtype2string(rrsig->type), rrsig->algorithm,
		    rrsig->labels, rrsig->origttl,
		    expiration, inception, rrsig->keytag,
		    rrsig->signer, b64buf);

	return (c);
}

size_t
name_from_string(const char *str, unsigned char **name)
{
	size_t len;
	u_int8_t *buf;
	int p, s;

	len = strlen(str) + 2;
	*name = buf = (u_int8_t *) calloc(1, len);

	if (buf) {
		buf[0] = '.';
		memcpy(buf + 1, str, len - 1);
		for (p = len - 2, s = p; p >= 0; p--)
			if (buf[p] == '.') {
				buf[p] = (u_int8_t)(s - p);
				s = p - 1;
			}
	} else
		len = 0;

	return (len - 1);
}

size_t
rdata_from_RRSIG(const dns_type_rrsig_t *rrsig, unsigned char **rdata)
{
	size_t len;
	u_int8_t *buf;
	const int offset = 18;

	u_int8_t *name;
	size_t namelen;

	len = offset + strlen(rrsig->signer) + 1;
	*rdata = buf = (u_int8_t *) malloc(len);

	if (buf) {
		buf[0] = (rrsig->type & 0xFF00) >> 8;
		buf[1] = (rrsig->type & 0x00FF);
		buf += 2;

		buf[0] = rrsig->algorithm;
		buf[1] = rrsig->labels;
		buf += 2;

		buf[0] = (rrsig->origttl & 0xFF000000) >> 24;
		buf[1] = (rrsig->origttl & 0x00FF0000) >> 16;
		buf[2] = (rrsig->origttl & 0x0000FF00) >> 8;
		buf[3] = (rrsig->origttl & 0x000000FF);
		buf += 4;

		buf[0] = (rrsig->expiration & 0xFF000000) >> 24;
		buf[1] = (rrsig->expiration & 0x00FF0000) >> 16;
		buf[2] = (rrsig->expiration & 0x0000FF00) >> 8;
		buf[3] = (rrsig->expiration & 0x000000FF);
		buf += 4;

		buf[0] = (rrsig->inception & 0xFF000000) >> 24;
		buf[1] = (rrsig->inception & 0x00FF0000) >> 16;
		buf[2] = (rrsig->inception & 0x0000FF00) >> 8;
		buf[3] = (rrsig->inception & 0x000000FF);
		buf += 4;

		buf[0] = (rrsig->keytag & 0xFF00) >> 8;
		buf[1] = (rrsig->keytag & 0x00FF);
		buf += 2;

		namelen = name_from_string(rrsig->signer, &name);
		memcpy(buf, name, namelen);
		free(name);
	} else {
		len = 0;
	}

	return len;
}

size_t
rdata_from_DNSKEY(const dns_type_dnskey_t *dnskey, unsigned char **rdata)
{
	size_t len;
	u_int8_t *buf;
	const int offset = 4;

	len = offset + dnskey->keylen;
	*rdata = buf = (u_int8_t *) malloc(len);

	if (buf) {
		buf[0] = (dnskey->flags & 0xFF00) >> 8;
		buf[1] = (dnskey->flags & 0x00FF);
		buf += 2;

		buf[0] = dnskey->protocol;
		buf[1] = dnskey->algorithm;
		buf += 2;

		memcpy(buf, dnskey->keydata, dnskey->keylen);
	} else {
		len = 0;
	}

	return len;
}

size_t
blob_from_rrset(const dns_rrset_t *rrset, unsigned char **blob)
{
	size_t len, dlen;
	u_int8_t *buf;

	dns_rdata_t *rd;
	u_int8_t *name;
	size_t namelen;

	u_int8_t *tmp;

	namelen = name_from_string(rrset->name, &name);

	len = 0;
	dlen = namelen + sizeof rrset->type + sizeof rrset->class +
	    sizeof rrset->ttl;
	for (rd = rrset->rdata; rd; rd = rd->next) {
		len += dlen + sizeof(rd->length) + rd->length;
	}

	*blob = buf = (u_int8_t *) malloc(len);

	if (buf) {
		for (rd = rrset->rdata; rd; rd = rd->next) {
			tmp = buf;

			memcpy(buf, name, namelen);
			buf += namelen;

			buf[0] = (rrset->type & 0xFF00) >> 8;
			buf[1] = (rrset->type & 0x00FF);
			buf += 2;

			buf[0] = (rrset->class & 0xFF00) >> 8;
			buf[1] = (rrset->class & 0x00FF);
			buf += 2;

			buf[0] = (rrset->ttl & 0xFF000000) >> 24;
			buf[1] = (rrset->ttl & 0x00FF0000) >> 16;
			buf[2] = (rrset->ttl & 0x0000FF00) >> 8;
			buf[3] = (rrset->ttl & 0x000000FF);
			buf += 4;

			buf[0] = (rd->length & 0xFF00) >> 8;
			buf[1] = (rd->length & 0x00FF);
			buf += 2;

			memcpy(buf, rd->data, rd->length);
			buf += rd->length;
		}
	} else {
		len = 0;
	}

	free(name);

	return len;
}

static u_int16_t
keytag_from_rdata(const unsigned char *rdata, size_t rdatalen)
{
	unsigned int i;
	u_int32_t ac;

	for ( ac = 0, i = 0; i < rdatalen; ++i )
		ac += (i & 1) ? rdata[i] : rdata[i] << 8;
	ac += (ac>>16) & 0xFFFF;
	return ac & 0xFFFF;
}

u_int16_t
keytag_from_DNSKEY(const dns_type_dnskey_t *dnskey)
{
	unsigned char *rdata;
	size_t rdatalen;
	u_int16_t keytag = 0;

	rdatalen = rdata_from_DNSKEY(dnskey, &rdata);

	if(rdatalen) {
		keytag = keytag_from_rdata(rdata, rdatalen);
		free(rdata);
	}

	return keytag;
}

static int
rrset_add_rdata(dns_rrset_t *rrset, dns_rdata_t *rdata, int canonical)
{
	dns_rdata_t *rd, *new, *prev;
	int	r;
	size_t	min;

	/* Allocate new object and copy data to it. */
	new = (dns_rdata_t *)calloc(1, sizeof (dns_rdata_t));
	if (!new)
		goto memfail;
	new->length = rdata->length;
	new->data = (u_int8_t *)malloc(new->length);
	if (!new->data) {
		free(new);
		goto memfail;
	}
	memcpy(new->data, rdata->data, new->length);

	/* If there is no previsous rdata in the set, addition is simple. */
	if (!rrset->rdata) {
		rrset->rdata = new;
		return 0;
	}

	if (canonical == 0) {
		/* Also, simple. We just add this RR last in the set. */
		for (rd = rrset->rdata; rd->next; rd = rd->next)
			;
		rd->next = new;
		return 0;
	}
	
	/* Canonical, meaning we add it sorted, sec 6.3 */
	prev = NULL;
	for (rd = rrset->rdata; rd; rd = rd->next) {
		min = rd->length > new->length ? new->length : rd->length;
		r = memcmp(new->data, rd->data, min);
		if (r < 0)
			goto add_or_insert;
		else if (r == 0) {
			if (new->length < rd->length)
				goto add_or_insert;
			else if (new->length == rd->length) {
				fprintf(stderr,
				    "Bad data, identical RRs in set\n");
				free(new->data);
				free(new);
				return -1;
			}
		}
		prev = rd;
	}

	/*
	 * If we've reached this point, our new RR did not fit before any
	 * of the previous, so we add it after the last RR.
	 */
  add_or_insert:
	new->next = rd;
	if (prev)
		prev->next = new;
	else
		rrset->rdata = new;
	return 0;

  memfail:
	fprintf(stderr, "rrset_add_rdata: failed to allocate memory\n");
	return -1;
}

#define MAXLINE		1024
#define DEFAULT_TTL	68400

/* Parse contents of the text string 'line' and try to fill in 'rr' */
static int
parse_line(dns_rrset_t *rr, char *line, int *cont)
{
	static dns_type_dnskey_t dnskey;
	char name[MAXLINE], key[MAXLINE];
	int  ttl, flags, proto, alg;
	size_t len = strlen(line);
	char *s, *p;
	u_int8_t *dbuf;
	int dlen;

	/*
	 * If this is a continuation from the previous line, we only expect
	 * more key data here.  
	 */
	if (*cont == 1) {
		if (sscanf(line, "%s", key) != 1)
			return -1;

		/* Look for end marker. */
		for (s = line; *cont && s < line + len; s++)
			if (*s == ')')
				*cont = 0;
		/* XXX Theoretically, this permit last line to be " ) foo " */
			
		/* Add key to dnskey.keydata */
		dbuf = realloc(dnskey.keydata,
		    dnskey.keylen + strlen(key) + 1);
		if (!dbuf) {
			fprintf(stderr, "realloc()\n");
			goto cleanup;
		}
		memcpy(dbuf + dnskey.keylen, key, strlen(key));
		dnskey.keydata = dbuf;
		dnskey.keylen += strlen(key);
		dnskey.keydata[dnskey.keylen] = (char)0;

		if (*cont)
			return 0;
		else
			goto decode_key;
	}

	/* New line - start by locating 'DNSKEY' */
	for (p = 0, s = line;
	     *s != ';' && *s != '#' && *s != '\n' && !p && s < line + len;
	     s++)
		if (*s == 'D' && strncmp(s, "DNSKEY", 6) == 0)
			p = s + sizeof("DNSKEY");

	if (!p)
		return -1;
	*(--s) = (char)0;

	/*
	 * Now line contains the parts prior to "DNSKEY", while 's' contains
	 * the rdata.
	 */

	ttl = 0;
	if (sscanf(line, "%s %d IN ", name, &ttl) == 2 ||
	    sscanf(line, "%s IN", name) == 1) {
		if (!ttl)
			ttl = DEFAULT_TTL; /* XXX ? */
	} else
		return -1;

	if (sscanf(p, "%d %d %d ( %s", &flags, &proto, &alg, key) == 4) {
		*cont = 1;
	} else if (sscanf(p, "%d %d %d %[^)]", &flags, &proto, &alg, key) == 4 &&
	    strcmp(key, "(") != 0) {
		*cont = 0;
	} else
		return -1;

	/* Build RR and DNSKEY rdata */
	memset(rr, 0, sizeof *rr);
	memset(&dnskey, 0, sizeof dnskey);

	rr->name = strdup(name);
	if (!rr->name) {
		fprintf(stderr, "strdup()\n");
		return -1;
	}
	rr->ttl = ttl;
	rr->class = DNS_CLASS_IN;
	rr->type = DNS_TYPE_DNSKEY;

	dnskey.flags = flags;
	dnskey.protocol = proto;
	dnskey.algorithm = alg;

	dnskey.keydata = strdup(key);
	if (!dnskey.keydata) {
		free(rr->name);
		fprintf(stderr, "strdup()\n");
		return -1;
	}
	dnskey.keylen = strlen(key);

	/* If more key data is coming, return for another line of input. */
	if (*cont)
		return 0;
	
  decode_key:
	/* First, decode base64. */
	dlen = dnskey.keylen * 3 / 4 + 4;
	dbuf = (u_int8_t *)malloc(dlen);
	if (!dbuf) {
		fprintf(stderr, "malloc\n");
		goto cleanup;
	}

	dlen = b64_pton(dnskey.keydata, dbuf, dlen);
	if (dlen == -1) {
		fprintf(stderr, "b64_pton\n");
		free(dbuf);
		goto cleanup;
	}

	/* Switch buffers. */
	free(dnskey.keydata);
	dnskey.keydata = dbuf;
	dnskey.keylen = dlen;

	rr->rdata = (dns_rdata_t *)calloc(1, sizeof(dns_rdata_t));
	if (!rr->rdata) {
		fprintf(stderr, "calloc\n");
		goto cleanup;
	}

	/* Convert to RRset rdata (wire format) */
	rr->rdata->length = (unsigned int)rdata_from_DNSKEY(&dnskey,
	    &rr->rdata->data);
	if (rr->rdata->length == 0) {
		fprintf(stderr, "malloc\n");
		goto cleanup;
	}
	free(dnskey.keydata);

	/* Done. */
	return 0;

  cleanup:
	if (dnskey.keydata)
		free(dnskey.keydata);
	if (rr->name)
		free(rr->name);
	if (rr->rdata) {
		if (rr->rdata->data)
			free(rr->rdata->data);
		free(rr->rdata);
	}
	return -1;
}


int
load_RRSET_from_file(const char *file, dns_rrset_t *rrset, int canonical)
{
	dns_rrset_t	rrtmp;
	FILE		*fp;
	char		line[MAXLINE], lineno = 0;
	int		cont = 0, first = 1;

	if ((fp = fopen(file, "r")) == NULL) {
		fprintf(stderr, "Could not open file \"%s\"!\n", file);
		return -1;
	}

	while (fgets(line, sizeof line, fp) != NULL) {
		lineno++;
		if (parse_line(&rrtmp, line, &cont)) {
			fprintf(stderr, "bad input line %d\n", lineno);
			continue;
		}
		if (cont)
			continue;
		if (first) {
			/* First line sets the RRset "name" */
			rrset->name = strdup(rrtmp.name);
			rrset->class =
			    rrtmp.class ? rrtmp.class : DNS_CLASS_IN;
			rrset->type = rrtmp.type;
			rrset->ttl = rrtmp.ttl; /* XXX ? */
			if (rrset_add_rdata(rrset, rrtmp.rdata, canonical))
				return -1;
			first = 0;
			continue;
		}
		if (strcmp(rrtmp.name, rrset->name) != 0 ||
		    rrtmp.type != rrset->type ||
		    rrtmp.class != rrset->class ||
		    (rrtmp.ttl != rrset->ttl && rrtmp.ttl != 0)) {
			fprintf(stderr, "line %d does not belong to "
			    "rrset %s/%d/%d/%d\n", lineno, rrset->name,
			    rrset->type, rrset->class, rrset->ttl);
		} else
			if (rrset_add_rdata(rrset, rrtmp.rdata, canonical))
				return -1;
	}

	if (ferror(fp)) {
		fclose(fp);
		return -1;
	}

	return 0;
}

/*
 * As per draft-ietf-dnsext-dnssec-records-11.txt, section 3.1.8.1 et al,
 * generate the hash that when signed will be the SIG RDATA.
 */
int
gen_RRSET_HASH(const dns_rrset_t *rrset, dns_type_rrsig_t *rrsig,
    char *digest, size_t d_max)
{
	SHA_CTX ctx;
	u_int8_t *buf;
	size_t buflen;
	
	if (!rrset || !rrsig || !digest || d_max < SHA_DIGEST_LENGTH)
		return -1;

	SHA1_Init(&ctx);

	/* RRSIG RDATA */
	buflen = rdata_from_RRSIG(rrsig, &buf);
	SHA1_Update(&ctx, buf, buflen);
	free(buf);

	/* RR(i) = owner | type | class | TTL | RDATA length | RDATA */
	buflen = blob_from_rrset(rrset, &buf);
	SHA1_Update(&ctx, buf, buflen);
	free(buf);

	SHA1_Final(digest, &ctx);

	return SHA_DIGEST_LENGTH;
}

const char *
rrtype2string(u_int16_t type)
{
	static char mnemonic[32];

	if (type == DNS_TYPE_DNSKEY)
		return "DNSKEY";

	snprintf(mnemonic, sizeof(mnemonic), "TYPE%d", type);

	return mnemonic;
}

time_t
string2time(const char *s)
{
	struct tm tm;
	char buf[1024];

	if (strptime(s, "%Y%m%d%H%M%S", &tm) == NULL)
		return 0;

	strftime(buf, sizeof buf, "%F %T", &tm);

	return mktime(&tm);
}

u_int8_t
nlabels(const char *s)
{
	int i;
	u_int8_t n = 0;

	for (i = 0; i < strlen(s); i++)
		if (s[i] == '.')
			n++;

	if (s[i-1] != '.')
			n++;

	return n;
}

void
hexdump(const unsigned char *buf, int buflen)
{
	int i;
	
	for (i = 0; i < buflen; i++) {
		printf("%02x", buf[i]);
	}
	printf("\n");
}
