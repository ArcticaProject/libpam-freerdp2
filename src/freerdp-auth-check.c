/*
 * Copyright © 2012 Canonical Ltd.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 3, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranties of
 * MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Ted Gould <ted@canonical.com>
 */

#include <freerdp/freerdp.h>
#include <freerdp/channels/channels.h>
#include <string.h>
#include <sys/mman.h>
#include <winpr/wlog.h>


BOOL
auth_context_new (freerdp * instance, rdpContext * context)
{
	return TRUE;
}

void
auth_context_free (freerdp * instance, rdpContext * context)
{
	return;
}

BOOL
auth_pre_connect (freerdp * instance)
{
	return TRUE;
}

BOOL
auth_post_connect (freerdp * instance)
{
	return TRUE;
}

int
main (int argc, char * argv[])
{
	char password[512];
	if (argc != 4) {
		printf("Not enough params\n\n");
		printf("Usage: freerdp-auth-check <host>[:<port>] <user> <domain> <password>\n\n");
		return -1;
	}

	if (scanf("%511s", password) != 1) {
		return -1;
	}

	if (mlock(password, sizeof(password)) != 0) {
		return -1;
	}

#ifndef ENABLE_WLOG
	wLog* root = WLog_GetRoot();

	if (!WLog_SetStringLogLevel(root, "OFF")){
		return -1;
	}
#endif
	freerdp * instance = freerdp_new();

	instance->PreConnect = auth_pre_connect;
	instance->PostConnect = auth_post_connect;

	instance->ContextSize = sizeof(rdpContext);
	instance->ContextNew = auth_context_new;
	instance->ContextFree = auth_context_free;

	if (!freerdp_context_new(instance)) {
		printf("Coudln't create freerdp context\n");
		return -1;
	}

	char * colonloc = strstr(argv[1], ":");
	if (colonloc != NULL) {
		/* We've got a port to deal with */
		colonloc[0] = '\0';
		colonloc++;

		instance->settings->ServerPort = strtoul(colonloc, NULL, 10);
	}

	instance->settings->AuthenticationOnly = TRUE;
	instance->settings->ServerHostname = argv[1];
	instance->settings->Username = argv[2];
	instance->settings->Domain = argv[3];
	instance->settings->Password = password;

	BOOL connection_successful;
	connection_successful = freerdp_connect(instance);
	freerdp_disconnect(instance);

	memset(password, 0, sizeof(password));
	munlock(password, sizeof(password));
	instance->settings->Password = NULL;
	instance->settings->ServerHostname = NULL;
	instance->settings->Username = NULL;
	instance->settings->Domain = NULL;

	int retval = 0;
	if (!connection_successful) {
		retval = freerdp_get_last_error(instance->context);
	}

	freerdp_context_free(instance);
	freerdp_free(instance);

	return retval;
}
