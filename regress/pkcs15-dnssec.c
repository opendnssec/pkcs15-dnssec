/*	$Id$	*/

/*
 * pkcs15-crypt.c: Tool for DNSSEC cryptography operations with SmartCards
 *
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2005  Jakob Schlyter <jakob@rfc.se>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#define HAVE_OPENSSL 1

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>

#include <opensc/opensc.h>
#include <opensc/pkcs15.h>

#include "pkcs15-util.h"
#include "dns-util.h"

const char *app_name = "pkcs15-dnssec";

int opt_reader = -1, verbose = 0, opt_wait = 0;
char * opt_pincode = NULL, * opt_key_id = NULL;
char * opt_input = NULL, * opt_output = NULL;
int opt_crypt_flags = SC_ALGORITHM_RSA_HASH_SHA1 | SC_ALGORITHM_RSA_PAD_PKCS1;
time_t opt_inception = 0, opt_expiration = 0;

char * opt_keyname = NULL;

unsigned int opt_usage = SC_PKCS15_PRKEY_USAGE_SIGN |
			 SC_PKCS15_PRKEY_USAGE_SIGNRECOVER |
			 SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;

const struct option options[] = {
	{ "sign",		0, 0,		's' },
	{ "export",		0, 0,		'e' },
	{ "key",		1, 0,		'k' },
	{ "reader",		1, 0,		'r' },
	{ "input",		1, 0,		'i' },
	{ "output",		1, 0,		'o' },
	{ "pin",		1, 0,		'p' },
	{ "wait",		0, 0,		'w' },
	{ "verbose",		0, 0,		'v' },
	{ "name",		1, 0,		'n' },
	{ "inception",		1, 0,		'c' },
	{ "expiration",		1, 0,		'x' },
	{ 0, 0, 0, 0 }
};

const char *option_help[] = {
	"Performs digital signature operation",
	"Export public key",
	"Selects the private key ID to use",
	"Uses reader number <arg>",
	"Selects the input file to use",
	"Outputs to file <arg>",
	"Uses password (PIN) <arg>",
	"Wait for card insertion",
	"Verbose operation. Use several times to enable debug output.",
	"DNSKEY/RRSIG owner name",
	"Signature inception",
	"Signature expiration",
};

struct sc_context *ctx = NULL;
struct sc_card *card = NULL;
struct sc_pkcs15_card *p15card = NULL;

static char * get_pin(struct sc_pkcs15_object *obj)
{
	char buf[80];
	char *pincode;
	struct sc_pkcs15_pin_info *pinfo = (struct sc_pkcs15_pin_info *) obj->data;
	
	if (opt_pincode != NULL)
		return strdup(opt_pincode);
	sprintf(buf, "Enter PIN [%s]: ", obj->label);
	while (1) {
		pincode = getpass(buf);
		if (strlen(pincode) == 0)
			return NULL;
		if (strlen(pincode) < pinfo->min_length ||
		    strlen(pincode) > pinfo->max_length)
			continue;
		return strdup(pincode);
	}
}

static int authenticate(const sc_pkcs15_object_t *obj)
{
	sc_pkcs15_pin_info_t	*pin_info;
	sc_pkcs15_object_t	*pin_obj;
	u8			*pin;
	int			r;

	if (obj->auth_id.len == 0)
		return 0;
	r = sc_pkcs15_find_pin_by_auth_id(p15card, &obj->auth_id, &pin_obj);
	if (r)
		return r;

	pin_info = (sc_pkcs15_pin_info_t *) pin_obj->data;
	pin = get_pin(pin_obj);

	return sc_pkcs15_verify_pin(p15card, pin_info,
			pin, pin? strlen((char *) pin) : 0);
}

#ifdef HAVE_OPENSSL
#define GETBN(bn)	((bn)->len? BN_bin2bn((bn)->data, (bn)->len, NULL) : NULL)
static int extract_key(struct sc_pkcs15_object *obj, EVP_PKEY **pk)
{
	struct sc_pkcs15_prkey	*key;
	const char	*pass = NULL;
	int		r;

	while (1) {
		r = sc_pkcs15_read_prkey(p15card, obj, pass, &key);
		if (r != SC_ERROR_PASSPHRASE_REQUIRED)
			break;

		if (pass)
			return SC_ERROR_INTERNAL;
		pass = getpass("Please enter pass phrase "
				"to unlock secret key: ");
		if (!pass || !*pass)
			break;
	}

	if (r < 0)
		return r;

	*pk = EVP_PKEY_new();
	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		{
		RSA	*rsa = RSA_new();

		EVP_PKEY_set1_RSA(*pk, rsa);
		rsa->n = GETBN(&key->u.rsa.modulus);
		rsa->e = GETBN(&key->u.rsa.exponent);
		rsa->d = GETBN(&key->u.rsa.d);
		rsa->p = GETBN(&key->u.rsa.p);
		rsa->q = GETBN(&key->u.rsa.q);
		break;
		}
	case SC_ALGORITHM_DSA:
		{
		DSA	*dsa = DSA_new();

		EVP_PKEY_set1_DSA(*pk, dsa);
		dsa->priv_key = GETBN(&key->u.dsa.priv);
		break;
		}
	default:
		r = SC_ERROR_NOT_SUPPORTED;
	}

	/* DSA keys need additional parameters from public key file */
	if (obj->type == SC_PKCS15_TYPE_PRKEY_DSA) {
		struct sc_pkcs15_id     *id;
		struct sc_pkcs15_object *pub_obj;
		struct sc_pkcs15_pubkey *pub;
		DSA			*dsa;

		id = &((struct sc_pkcs15_prkey_info *) obj->data)->id;
		r = sc_pkcs15_find_pubkey_by_id(p15card, id, &pub_obj);
		if (r < 0)
			goto done;
		r = sc_pkcs15_read_pubkey(p15card, pub_obj, &pub);
		if (r < 0)
			goto done;

		dsa = (*pk)->pkey.dsa;
		dsa->pub_key = GETBN(&pub->u.dsa.pub);
		dsa->p = GETBN(&pub->u.dsa.p);
		dsa->q = GETBN(&pub->u.dsa.q);
		dsa->g = GETBN(&pub->u.dsa.g);
		sc_pkcs15_free_pubkey(pub);
	}

done:	if (r < 0)
		EVP_PKEY_free(*pk);
	sc_pkcs15_free_prkey(key);
	return r;
}

static int sign_ext(struct sc_pkcs15_object *obj,
		u8 *data, size_t len, u8 *out, size_t out_len)
{
	EVP_PKEY *pkey = NULL;
	int	r, nid = -1;

	r = extract_key(obj, &pkey);
	if (r < 0)
		return r;

	switch (obj->type) {
	case SC_PKCS15_TYPE_PRKEY_RSA:
		if (opt_crypt_flags & SC_ALGORITHM_RSA_HASH_MD5) {
			nid = NID_md5;
		} else if (opt_crypt_flags & SC_ALGORITHM_RSA_HASH_SHA1) {
			nid = NID_sha1;
		} else {
			if (len == 16)
				nid = NID_md5;
			else if (len == 20)
				nid = NID_sha1;
			else {
				fprintf(stderr,
					"Invalid input size (%u bytes)\n",
					len);
				return SC_ERROR_INVALID_ARGUMENTS;
			}
		}
		r = RSA_sign(nid, data, len, out, (unsigned int *) &out_len,
				pkey->pkey.rsa);
		if (r <= 0)
			r = SC_ERROR_INTERNAL;
		break;
	case SC_PKCS15_TYPE_PRKEY_DSA:
		r = DSA_sign(NID_sha1, data, len, out, (unsigned int *) &out_len,
				pkey->pkey.dsa);
		if (r <= 0)
			r = SC_ERROR_INTERNAL;
		break;
	}
	if (r >= 0)
		r = out_len;
	EVP_PKEY_free(pkey);
	return r;
}
#endif

static int get_dnskey(const sc_pkcs15_object_t *obj,
		      dns_type_dnskey_t **dnskey)
{
	int r;
	sc_pkcs15_prkey_info_t *prkey_info = (struct sc_pkcs15_prkey_info *) obj->data;
	sc_pkcs15_object_t *pubkey_obj;
	sc_pkcs15_pubkey_t *pubkey = NULL;

	r = sc_pkcs15_find_pubkey_by_id(p15card, &prkey_info->id, &pubkey_obj);

	if (r == SC_ERROR_OBJECT_NOT_FOUND) {
		fprintf(stderr, "Public key not found.\n");
		return 2;
	}

	r = sc_pkcs15_read_pubkey(p15card, pubkey_obj, &pubkey);

	if (r < 0) {
		fprintf(stderr, "Public key enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}

	switch (pubkey->algorithm) {

#ifdef HAVE_OPENSSL
#define GETBN(bn) ((bn)->len? BN_bin2bn((bn)->data, (bn)->len, NULL) : NULL)
	case SC_ALGORITHM_RSA:
		{
		RSA *rsa = RSA_new();
		rsa->n = GETBN(&pubkey->u.rsa.modulus);
		rsa->e = GETBN(&pubkey->u.rsa.exponent);
		*dnskey = RSA_to_DNSKEY(rsa, opt_keyname);
		break;
		}
#endif
	case SC_ALGORITHM_DSA:
		/* XXX add support for DSA here XXX */ 
	default:
		r = SC_ERROR_NOT_SUPPORTED;
	}

	if (pubkey)
		sc_pkcs15_free_pubkey(pubkey);

	return r;

}

static int init_rrsig(const struct sc_pkcs15_object *obj, u_int16_t keytag,
		      const dns_rrset_t *rrset, dns_type_rrsig_t *rrsig)
{
	rrsig->type = DNS_TYPE_DNSKEY;
	rrsig->keytag = keytag;

	switch (obj->type) {
	case SC_PKCS15_TYPE_PRKEY_RSA:
		rrsig->algorithm = DNS_KEYALG_RSASHA1;
		break;
	case SC_PKCS15_TYPE_PRKEY_DSA:
		rrsig->algorithm = DNS_KEYALG_DSA;
		break;
	default:
		rrsig->algorithm = 0;
	}

	rrsig->labels = nlabels(rrset->name);
	rrsig->origttl = rrset->ttl;
	rrsig->expiration = opt_expiration;
	rrsig->inception = opt_inception;
	rrsig->signer = opt_keyname;
	rrsig->siglen = 0; /* UNKNOWN */
	rrsig->sigdata = NULL; /* UNKNOWN */

	return 0;
}

static int sign(const struct sc_pkcs15_object *obj)
{
	u8 buf[1024], out[1024];
	struct sc_pkcs15_prkey_info *key =
	    (struct sc_pkcs15_prkey_info *)obj->data;
	int r, c;
	FILE *outf;
	dns_type_rrsig_t rrsig;
	dns_type_dnskey_t *dnskey;
	dns_rrset_t rrset;

	if (opt_input == NULL) {
		fprintf(stderr, "No input file specified.\n");
		return 2;
	}

	r = get_dnskey(obj, &dnskey);
	if (r < 0)
		return -1;

	memset(&rrset, 0, sizeof rrset);

	r = load_RRSET_from_file(opt_input, &rrset, 1);
	if (r < 0)
		return -1;

	r = init_rrsig(obj, keytag_from_DNSKEY(dnskey), &rrset, &rrsig);
	if (r < 0)
		return -1;

	c = gen_RRSET_HASH(&rrset, &rrsig, buf, sizeof buf);
	if (c < 0) {
		fprintf(stderr, "DEBUG: gen_RRSET_hash failed = %d\n", c);
		return 2;
	}

	r = authenticate(obj);
	if (r < 0) {
		return -1;
	}

	if (obj->type == SC_PKCS15_TYPE_PRKEY_RSA
	    && !(opt_crypt_flags & SC_ALGORITHM_RSA_PAD_PKCS1)
	    && (size_t)c != key->modulus_length/8) {
		fprintf(stderr, "Input has to be exactly %d bytes, when "
		    "using no padding.\n", key->modulus_length/8);
		return 2;
	}
	if (!key->native) {
#ifdef HAVE_OPENSSL
		r = sign_ext((struct sc_pkcs15_object *)obj, buf, c, out,
		    sizeof out);
#else
		fprintf(stderr, "Cannot use extractable key because this "
		    "program was compiled without crypto support.\n");
		r = SC_ERROR_NOT_SUPPORTED;
#endif
	} else {
		r = sc_pkcs15_compute_signature(p15card, obj, opt_crypt_flags,
		    buf, c, out, sizeof out);
	}
	if (r < 0) {
		fprintf(stderr, "Compute signature failed: %s\n",
		    sc_strerror(r));
		return 1;
	}

	rrsig.siglen = r;
	rrsig.sigdata = out;

	if (opt_output != NULL) {
		outf = fopen(opt_output, "wb");
		if (outf == NULL) {
			fprintf(stderr, "Unable to open '%s' for writing.\n",
			    opt_output);
			return -1;
		}
	} else {
		outf = stdout;
	}

	write_RRSIG(outf, &rrsig, opt_keyname);

	if (outf != stdout)
		fclose(outf);
	
	return 0;
}

static int export(const struct sc_pkcs15_object *obj)
{
	int r;
	dns_type_dnskey_t *dnskey;
	FILE *outf;

	r = get_dnskey(obj, &dnskey);
	if (r < 0) {
		return -1;
	}

	if (opt_output != NULL) {
		outf = fopen(opt_output, "wb");
		if (outf == NULL) {
			fprintf(stderr, "Unable to open '%s' for writing.\n", opt_output);
			return -1;
		}
	} else {
		outf = stdout;
	}

	if (verbose) {
		fprintf(stderr, "Exporting DNSKEY with keytag %u\n",
			keytag_from_DNSKEY(dnskey));
	}

	r = write_DNSKEY(outf, dnskey, opt_keyname);

	if (outf != stdout)
		fclose(outf);

	return r;
}

static int get_key(unsigned int usage, sc_pkcs15_object_t **result)
{
	sc_pkcs15_object_t *key;
	const char	*usage_name;
	sc_pkcs15_id_t	id;
	int		r;

	usage_name = (usage & SC_PKCS15_PRKEY_USAGE_SIGN)? "signature" : "decryption";

	if (opt_key_id != NULL) {
		sc_pkcs15_hex_string_to_id(opt_key_id, &id);
		r = sc_pkcs15_find_prkey_by_id_usage(p15card, &id, usage, &key);
		if (r < 0) {
			fprintf(stderr, "Unable to find private %s key '%s': %s\n",
				usage_name, opt_key_id, sc_strerror(r));
			return 2;
		}
	} else {
		r = sc_pkcs15_find_prkey_by_id_usage(p15card, NULL, usage, &key);
		if (r < 0) {
			fprintf(stderr, "Unable to find any private %s key: %s\n",
				usage_name, sc_strerror(r));
			return 2;
		}
	}

	*result = key;

	return r;
}

int main(int argc, char * const argv[])
{
	int err = 0, r, c, long_optind = 0;
	int do_sign = 0;
	int do_export = 0;
	int action_count = 0;
        struct sc_pkcs15_object *key;

	setenv("TZ", "UTC", 1);

	while (1) {
		c = getopt_long(argc, argv, "sek:r:i:o:n:c:x:vw", options, &long_optind);
		if (c == -1)
			break;
		if (c == '?')
			print_usage_and_die();
		switch (c) {
		case 's':
			do_sign++;
			action_count++;
			break;
		case 'e':
			do_export++;
			action_count++;
			break;
		case 'k':
			opt_key_id = optarg;
			action_count++;
			break;
		case 'r':
			opt_reader = atoi(optarg);
			break;
		case 'i':
			opt_input = optarg;
			break;
		case 'o':
			opt_output = optarg;
			break;
		case 'v':
			verbose++;
			break;
		case 'p':
			opt_pincode = optarg;
			break;
		case 'w':
			opt_wait = 1;
			break;
		case 'n':
			opt_keyname = optarg;
			break;
		case 'c':
			opt_inception = string2time(optarg);
			break;
		case 'x':
			opt_expiration = string2time(optarg);
			break;
		}
	}

	if (opt_keyname == NULL) {
		fprintf(stderr, "DNSKEY/RRSIG owner name "
			"must be specified when signing.\n");
		return 1;
	}

	if (do_sign && (opt_inception == 0 || opt_expiration == 0)) {
		fprintf(stderr, "Signature inception and expiration "
			"must be specified when signing.\n");
		return 1;
	}

	if (action_count == 0)
		print_usage_and_die();
	r = sc_establish_context(&ctx, app_name);
	if (r) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}
	if (verbose > 1)
		ctx->debug = verbose-1;

	err = connect_card(ctx, &card, opt_reader, 0, opt_wait, verbose);
	if (err)
		goto end;

	if (verbose)
		fprintf(stderr, "Trying to find a PKCS #15 compatible card...\n");
	r = sc_pkcs15_bind(card, &p15card);
	if (r) {
		fprintf(stderr, "PKCS #15 initialization failed: %s\n", sc_strerror(r));
		err = 1;
		goto end;
	}
	if (verbose)
		fprintf(stderr, "Found %s!\n", p15card->label);

	if (do_export) {
		if ((err = get_key(opt_usage, &key)) ||
		    (err = export(key)))
			goto end;
		action_count--;
	}
	if (do_sign) {
		if ((err = get_key(opt_usage, &key)) ||
		    (err = sign(key)))
			goto end;
		action_count--;
	}
end:
	if (p15card)
		sc_pkcs15_unbind(p15card);
	if (card) {
#if 1
		sc_unlock(card);
#endif
		sc_disconnect_card(card, 0);
	}
	if (ctx)
		sc_release_context(ctx);
	return err;
}
