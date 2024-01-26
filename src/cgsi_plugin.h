/*
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** cgsi_plugin.h - Header file for the GSI gSOAP plugin
 *
 * @file cgsi_plugin.h
 * @brief Header file for the GSI gSOAP plugin
 * @author Ben Couturier CERN, IT/ADC
 *
 * This is a GSI plugin for gSOAP. It uses the globus GSI libraries to implement
 * GSI secure authentication and encryption on top of gSOAP.
 * The globus GSI bundle is necessary for the plugin to compile and run.
 *
 */

#include <stdsoap2.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Options that can be specified when initializing the
 * cgsi_plugin (in the arg parameter):
 */
/** The program acts as a client. */
#define CGSI_OPT_CLIENT             0x1
/** The program acts as a server. */
#define CGSI_OPT_SERVER             0x2
/** Initiate delegation over the HTTPG protocol. */
#define CGSI_OPT_DELEG_FLAG         0x4
/** Using pure SSL protocol, for compatibility. */
#define CGSI_OPT_SSL_COMPATIBLE     0x8
/** Disable comparing the server's host name with its certificate's CN. */
#define CGSI_OPT_DISABLE_NAME_CHECK 0x10
/** Keep alive the HTTP connection. */
#define CGSI_OPT_KEEP_ALIVE         0x20
/** Disable DN->userid mapping via gridmap-file. */
#define CGSI_OPT_DISABLE_MAPPING    0x40
/** Disable connect time VOMS parsing for better error handling
 *  via an explicit call to retrieve_voms_creds() */
#define CGSI_OPT_DISABLE_VOMS_CHECK 0x80
/** Allow client and server to only connect together when
 *  they have the same identity */
#define CGSI_OPT_ALLOW_ONLY_SELF    0x100

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
 * Generic constructor for the cgsi_plugin
 *
 * @param soap The soap structure for the request
 * @param plugin Pointer to the plugin data structure
 * @param arg The parameters for the plugin creation
 *
 * @return 0 if successful, -1 otherwise
 */
int cgsi_plugin(struct soap *soap, struct soap_plugin *plugin, void *arg);

/**
 * Client constructor for the cgsi_plugin
 *
 * @param soap The soap structure for the request
 * @param plugin Pointer to the plugin data structure
 * @param arg The parameters for the plugin creation (CGSI_OPT_CLIENT assumed)
 *
 * @return 0 if successful, -1 otherwise
 */
int client_cgsi_plugin(struct soap *soap, struct soap_plugin *plugin, void *arg);

/**
 * Server constructor for the cgsi_plugin
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
 * Make the delegated credential available as a token in memory.
 * The soap structure retains ownership of the memory. The user should
 * not free the pointer returned by this function, nor use it after the soap
 * object becomes invalid.
 *
 * @param soap The soap structure that is the target of the request
 * @param buffer Pointer to a void pointer which will be set to reference the credential token.
 * @param length Pointer to a length that will be set to the size of the credential token
 *
 * @return 0 if successful, -1 otherwise
 */
int get_delegated_credentials(struct soap *soap, void **buffer, size_t *length);

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

/**
 * Parses the optional VOMS extension of the peer certificate.
 * It has to be called before get_client_voname() and get_client_roles()!
 *
 * @param soap The soap structure for the request
 *
 * @return 0 if successful, -1 otherwise
 *           SOAP Fault structure contains the detailed description.
 */
int retrieve_voms_creds(struct soap *soap);
int retrieve_userca_and_voms_creds(struct soap *soap);

/**
 * Returns the client CA
 *
 * @param soap The soap structure for the request
 *
 * @return The client CA is allocated in the soap structure (DON'T free),
 *         NULL otherwise
 */
char *get_client_ca(struct soap *soap);

/**
 * Returns the client VO name if it was provided in the certificate
 *
 * @param soap The soap structure for the request
 *
 * @return The client voname is malloced in the soap structure (DON'T free),
 *         NULL otherwise
 */
char *get_client_voname(struct soap *soap);

/**
 * Returns the client VO roles if they were provided in the certificate
 *
 * @param soap The soap structure for the request
 *
 * @param nbfqans The number of returned Fully Qualified Attribute Names
 *
 * @return The client roles are malloced in the soap structure (DON'T free),
 *         NULL otherwise
 */
char ** get_client_roles(struct soap *soap, int* nbfqans);


/**
 * Adjust CGSI-plugin's behaviour by setting one or more flags.  If a
 * flag is not present in args then that flag is unaffected by this
 * operation.  If a flag is currently set then attempting to set it
 * will have no effect.
 *
 * @param soap The soap structure from gSOAP
 *
 * @param is_server 0 if client, 1 if server
 *
 * @param flags Bitwise OR of the flags to be set.
 *
 * @return 0 on success, -1 on error.
 */
int cgsi_plugin_set_flags(struct soap *soap, int is_server, int flags);

/**
 * Adjust CGSI-plugin's behaviour by clearing one or more flags. If a
 * flag is not present in args then it is unaffected by this
 * operation.  If a flag is currently cleared then attempting to clear
 * it will have no effect.
 *
 * @param soap The soap structure from gSOAP
 *
 * @param is_server 0 if client, 1 if server
 *
 * @param flags Bitwise OR of the flags to be cleared.
 *
 * @return 0 on success, -1 on error.
 */
int cgsi_plugin_clr_flags(struct soap *soap, int is_server, int flags);

/**
 * Discover the current set of flags that are in effect.
 *
 * @param soap The soap structure from gSOAP
 *
 * @param is_server 0 if client, 1 if server
 *
 * @return the set of flags or -1 on error
 */
int cgsi_plugin_get_flags(struct soap *soap, int is_server);

/**
 * Set credentials without using environment variables
 *
 * @param soap The soap structure for the request
 * @param is_server 0 if client, 1 if server
 * @param x509_cert The certificate. If it is a proxy, you only need to specify this one
 * @param x509_key  The key. Will be ignored if x509_cert is NULL!
 *
 * @return 0 on success, -1 on error.
 */
int cgsi_plugin_set_credentials(struct soap *soap, int is_server, const char* x509_cert, const char* x509_key);

#ifdef __cplusplus
}
#endif
