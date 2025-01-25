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
#include <freerdp/version.h>
#include <string.h>
#include <sys/mman.h>
#include <winpr/wlog.h>


BOOL
auth_context_new (freerdp __attribute__((unused)) *instance, rdpContext __attribute__((unused)) *context)
{
	return TRUE;
}

void
auth_context_free (freerdp __attribute__((unused)) *instance, rdpContext __attribute__((unused)) *context)
{
	return;
}

BOOL
auth_pre_connect (freerdp __attribute__((unused)) *instance)
{
	return TRUE;
}

BOOL
auth_post_connect (freerdp __attribute__((unused)) *instance)
{
	return TRUE;
}

int
main (int argc, char *argv[])
{
	char password[512];
	if (argc != 4) {
		printf("Usage: echo <passwd> | freerdp-auth-check <host>[:<port>] <user> <domain>\n\n");
		printf("ERROR: Incorrect number of parameters.\n\n");
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
		printf("Couldn't create freerdp_context\n");
		return -1;
	}

	char * colonloc = strstr(argv[1], ":");
	if (colonloc != NULL) {
		/* We've got a port to deal with */
		colonloc[0] = '\0';
		colonloc++;
#if FREERDP_VERSION_MAJOR >= 3
		freerdp_settings_set_uint32(instance->context->settings, FreeRDP_ServerPort, strtoul(colonloc, NULL, 10));
#else
		instance->settings->ServerPort = strtoul(colonloc, NULL, 10);
#endif
	}

#if FREERDP_VERSION_MAJOR >= 3
	freerdp_settings_set_bool(instance->context->settings, FreeRDP_AuthenticationOnly, TRUE);
	freerdp_settings_set_string(instance->context->settings, FreeRDP_ServerHostname, argv[1]);
	freerdp_settings_set_string(instance->context->settings, FreeRDP_Username, argv[2]);
	freerdp_settings_set_string(instance->context->settings, FreeRDP_Domain, argv[3]);
	freerdp_settings_set_string(instance->context->settings, FreeRDP_Password, password);
#else
	instance->settings->AuthenticationOnly = TRUE;
	instance->settings->ServerHostname = argv[1];
	instance->settings->Username = argv[2];
	instance->settings->Domain = argv[3];
	instance->settings->Password = password;
#endif

	BOOL connection_successful;
	connection_successful = freerdp_connect(instance);
	freerdp_disconnect(instance);

	memset(password, 0, sizeof(password));
	munlock(password, sizeof(password));
#if FREERDP_VERSION_MAJOR >= 3
	freerdp_settings_set_string(instance->context->settings, FreeRDP_Password, NULL);
	freerdp_settings_set_string(instance->context->settings, FreeRDP_ServerHostname, NULL);
	freerdp_settings_set_string(instance->context->settings, FreeRDP_Username, NULL);
	freerdp_settings_set_string(instance->context->settings, FreeRDP_Domain, NULL);
#else
	instance->settings->Password = NULL;
	instance->settings->ServerHostname = NULL;
	instance->settings->Username = NULL;
	instance->settings->Domain = NULL;
#endif

	int retval = 0;
	if (!connection_successful) {
		retval = freerdp_get_last_error(instance->context);
	}

	freerdp_context_free(instance);
	freerdp_free(instance);

	return retval;
}
