/* 
 * Copyright (C) 2003 by CERN/IT/ADC/CA 
 * All rights reserved
 */

/** cgsi_plugin.h - Header file for the GSI gSOAP plugin
 *
 * @file cgsi_plugin.h
 * @author Ben Couturier CERN, IT/ADC
 *
 * This is a GSI plugin for gSOAP. It uses the globus GSI libraries to implement
 * GSI secure authentification and encryption on top of gSOAP.
 * The globus GSI bundle is necessary for the plugin to compile and run.
 *
 */

#include <stdsoap2.h>

#define CGSI_OPT_CLIENT             0x1
#define CGSI_OPT_SERVER             0x2
#define CGSI_OPT_DELEG_FLAG         0x4
#define CGSI_OPT_SSL_COMPATIBLE     0x8
#define CGSI_OPT_DISABLE_NAME_CHECK 0x10

int cgsi_plugin(struct soap *soap, struct soap_plugin *plugin, void *arg);
int client_cgsi_plugin(struct soap *soap, struct soap_plugin *plugin, void *arg);
int server_cgsi_plugin(struct soap *soap, struct soap_plugin *plugin, void *arg);

int is_context_established(struct soap *soap);
int get_client_dn(struct soap *soap, char *dn, size_t dnlen);
int get_client_username(struct soap *soap, char *username, size_t dnlen);
