/*	$Id$	*/

/*
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>

#include "pkcs15-util.h"

int connect_card(sc_context_t *ctx, sc_card_t **cardp,
		 int reader_id, int slot_id, int wait, int verbose)
{
	sc_reader_t *reader;
	sc_card_t *card;
	int r;

	if (wait) {
		struct sc_reader *readers[16];
		int slots[16];
		int i, j, k, found;
		unsigned int event;

		for (i = k = 0; i < ctx->reader_count; i++) {
			if (reader_id >= 0 && reader_id != i)
				continue;
			reader = ctx->reader[i];
			for (j = 0; j < reader->slot_count; j++, k++) {
				readers[k] = reader;
				slots[k] = j;
			}
		}

		printf("Waiting for card to be inserted...\n");
		r = sc_wait_for_event(readers, slots, k,
				SC_EVENT_CARD_INSERTED,
				&found, &event, -1);
		if (r < 0) {
			fprintf(stderr,
				"Error while waiting for card: %s\n",
				sc_strerror(r));
			return 3;
		}

		reader = readers[found];
		slot_id = slots[found];
	} else {
		if (reader_id < 0)
			reader_id = 0;
		if (ctx->reader_count == 0) {
			fprintf(stderr,
				"No smart card readers configured.\n");
			return 1;
		}
		if (reader_id >= ctx->reader_count) {
			fprintf(stderr,
				"Illegal reader number. "
				"Only %d reader(s) configured.\n",
				ctx->reader_count);
			return 1;
		}

		reader = ctx->reader[reader_id];
		slot_id = 0;
		if (sc_detect_card_presence(reader, 0) <= 0) {
			fprintf(stderr, "Card not present.\n");
			return 3;
		}
	}

	if (verbose)
		printf("Connecting to card in reader %s...\n", reader->name);
	if ((r = sc_connect_card(reader, slot_id, &card)) < 0) {
		fprintf(stderr,
			"Failed to connect to card: %s\n",
			sc_strerror(r));
		return 1;
	}

	if (verbose)
		printf("Using card driver %s.\n", card->driver->name);

	if ((r = sc_lock(card)) < 0) {
		fprintf(stderr,
			"Failed to lock card: %s\n",
			sc_strerror(r));
		sc_disconnect_card(card, 0);
		return 1;
	}

	*cardp = card;
	return 0;
}

void print_usage_and_die(void)
{
	int i = 0;
	printf("Usage: %s [OPTIONS]\nOptions:\n", app_name);

	while (options[i].name) {
		char buf[40], tmp[5];
		const char *arg_str;
		
		/* Skip "hidden" options */
		if (option_help[i] == NULL) {
			i++;
			continue;
		}

		if (options[i].val > 0 && options[i].val < 128)
			sprintf(tmp, ", -%c", options[i].val);
		else
			tmp[0] = 0;
		switch (options[i].has_arg) {
		case 1:
			arg_str = " <arg>";
			break;
		case 2:
			arg_str = " [arg]";
			break;
		default:
			arg_str = "";
			break;
		}
		sprintf(buf, "--%s%s%s", options[i].name, tmp, arg_str);
		if (strlen(buf) > 29) {
			printf("  %s\n", buf);
			buf[0] = '\0';
		}
		printf("  %-29s %s\n", buf, option_help[i]);
		i++;
	}
	exit(2);
}
