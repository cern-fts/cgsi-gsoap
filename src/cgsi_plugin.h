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

/**
 * Options that can be specified when initializing the
 * cgsi_plugin (in the arg parameter) 
 */
#define CGSI_OPT_CLIENT             0x1
#define CGSI_OPT_SERVER             0x2
#define CGSI_OPT_DELEG_FLAG         0x4
#define CGSI_OPT_SSL_COMPATIBLE     0x8
#define CGSI_OPT_DISABLE_NAME_CHECK 0x10

/**
 * Helper function to create the gsoap object and
 * the cgsi_plugin at the same time.
 * This function assumes that a client plugin is specified,
 * to create a server plugin, use the CGSI_OPT_SERVER option.
 *
 * @param soap The soap structure for the request
 * @param cgsi_options The parameters for the plugin creation
 *                     (bitwise or of the different options).
 *
 * @return 0 if successful, -1 otherwise
 */
int soap_cgsi_init(struct soap *soap, int cgsi_options);

/**
 * Generic contructor for the cgsi_plugin
 *
 * @param soap The soap structure for the request
 * @param plugin Pointer to the plugin data structure
 * @param arg The parameters for the plugin creation
 *
 * @return 0 if successful, -1 otherwise
 */
int cgsi_plugin(struct soap *soap, struct soap_plugin *plugin, void *arg);

/**
 * Client contructor for the cgsi_plugin
 *
 * @param soap The soap structure for the request
 * @param plugin Pointer to the plugin data structure
 * @param arg The parameters for the plugin creation (CGSI_OPT_CLIENT assumed)
 *
 * @return 0 if successful, -1 otherwise
 */
int client_cgsi_plugin(struct soap *soap, struct soap_plugin *plugin, void *arg);

/**
 * Server contructor for the cgsi_plugin
 *
 * @param soap The soap structure for the request
 * @param plugin Pointer to the plugin data structure
 * @param arg The parameters for the plugin creation (CGSI_OPT_SERVER assumed)
 *
 * @return 0 if successful, -1 otherwise
 */
int server_cgsi_plugin(struct soap *soap, struct soap_plugin *plugin, void *arg);

/**
 * Checks whether the security context has been established properly
 *
 * @param soap The soap structure for the request
 *
 * @return 1 if context established, 0 otherwise
 */
int is_context_established(struct soap *soap);

/**
 * Gets the Distinguished name (DN) of the client
 *
 * @param soap The soap structure for the request
 * @param dn Pointer to a buffer where the DN is to be written
 * @param dnlen The length of the buffer
 *
 * @return 0 if successful, -1 otherwise
  */
int get_client_dn(struct soap *soap, char *dn, size_t dnlen);

/**
 * Gets the username (DN) of the client
 *
 * @param soap The soap structure for the request
 * @param username Pointer to a buffer where the username is to be written
 * @param dnlen The length of the buffer
 *
 * @return 0 if successful, -1 otherwise
 */
int get_client_username(struct soap *soap, char *username, size_t dnlen);

/**
 * Export the delegated credentials (if available) to a file
 *
 * @param soap The soap structure for the request
 * @param filename Name of the file where the credentials are to be written
 *
 * @return 0 if successful, -1 otherwise
 */
int export_delegated_credentials(struct soap *soap, char *filename);

/**
 * Checks whether the client delegated credentials to the server
 *
 * @param soap The soap structure for the request
 *
 * @return 1 if there are some delegated credentials, 0 otherwise
 */
int has_delegated_credentials(struct soap *soap);

/**
 * Sets the env variable for GSI to use the proxy in the specified filename
 *
 * @param soap The soap structure for the request
 * @param filename Name of the file where credentials are stored
 *
 * @return 0 if successful, -1 otherwise
 */
int set_default_proxy_file(struct soap *soap, char *filename);

/**
 * Clears the env variable used by GSI to specify the proxy filename
 *
 * @param unlink_file Set to 1 if you want to destroy the credential file as well
 *
 */
void clear_default_proxy_file(int unlink_file);









