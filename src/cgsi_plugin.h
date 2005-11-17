/*  
 *  
 * Copyright (c) CERN. 2005. 
 * All rights not expressly granted under this license are reserved. 
 * 
 * Installation, use, reproduction, display, modification and redistribution 
 * of this software, with or without modification, in source and binary forms, 
 * are permitted on a non- exclusive basis. Any exercise of rights by you under 
 * this license is subject to the following conditions:
 * 
 * 1. Redistributions of this software, in whole or in part, with or without 
 * modification, must reproduce the above copyright notice and these license 
 * conditions in this software, the user documentation and any other materials 
 * provided with the redistributed software. 
 * 
 * 2. The user documentation, if any, included with a redistribution, must 
 * include the following notice:
 * "This product includes software developed by CERN (http://cern.ch/castor)." 
 * 
 * If that is where third-party acknowledgments normally appear, this acknowledgment 
 * must be reproduced in the modified version of this software itself.
 * 
 * 3. The name "CGSI-gSOAP" may not be used to endorse or promote software, or 
 * products derived therefrom, except with prior written permission by CERN 
 * (ben.couturier@cern.ch). If this software is redistributed in modified form, 
 * the name and reference of the modified version must be clearly distinguishable 
 * from that of this software.
 * 
 * 4. You are under no obligation to provide anyone with any modifications of this 
 * software that you may develop, including but not limited to bug fixes, patches, 
 * upgrades or other enhancements or derivatives of the features, functionality or 
 * performance of this software. However, if you publish or distribute your modifications 
 * without contemporaneously requiring users to enter into a separate written license 
 * agreement, then you are deemed to have granted CERN a license to your modifications, 
 * including modifications protected by any patent owned by you, under the conditions 
 * of this license. 
 * 
 * 5. You may not include this software in whole or in part in any patent or patent 
 * application in respect of any modification of this software developed by you. 
 * 
 * 
 * 
 * 6. DISCLAIMER 
 * 
 * THIS SOFTWARE IS PROVIDED BY CERN "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
 * INCLUDING, BUT NOT LIMITED TO, IMPLIED WARRANTIES OF MERCHANTABILITY, 
 * OF SATISFACTORY QUALITY, AND FITNESS FOR A PARTICULAR PURPOSE OR USE ARE DISCLAIMED. 
 * CERN MAKES NO REPRESENTATION THAT THE SOFTWARE AND MODIFICATIONS THEREOF, 
 * WILL NOT INFRINGE ANY PATENT, COPYRIGHT, TRADE SECRET OR OTHER PROPRIETARY RIGHT. 
 * 
 * 7. LIMITATION OF LIABILITY
 * 
 * CERN SHALL HAVE NO LIABILITY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, CONSEQUENTIAL, 
 * EXEMPLARY, OR PUNITIVE DAMAGES OF ANY CHARACTER INCLUDING, WITHOUT LIMITATION, 
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES, LOSS OF USE, DATA OR PROFITS, OR BUSINESS 
 * INTERRUPTION, HOWEVER CAUSED AND ON ANY THEORY OF CONTRACT, WARRANTY, TORT 
 * (INCLUDING NEGLIGENCE), PRODUCT LIABILITY OR OTHERWISE, ARISING IN ANY WAY OUT OF 
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. 
 * 
 * 8. This license shall terminate with immediate effect and without notice if you fail 
 * to comply with any of the terms of this license, or if you institute litigation 
 * against CERN with regard to this software. 
 *
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

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Options that can be specified when initializing the
 * cgsi_plugin (in the arg parameter) 
 */
#define CGSI_OPT_CLIENT             0x1
#define CGSI_OPT_SERVER             0x2
#define CGSI_OPT_DELEG_FLAG         0x4
#define CGSI_OPT_SSL_COMPATIBLE     0x8
#define CGSI_OPT_DISABLE_NAME_CHECK 0x10
#define CGSI_OPT_KEEP_ALIVE         0x20  

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

/**
 * Returns the client VO name if it was provided in the certificate
 *
 * @param soap The soap structure for the request
 *
 * @return The client voname malloced in the soap structure (DON"T free), NULL otherwise
 */
char *get_client_voname(struct soap *soap);

/**
 * Returns the client VO roles if they were provided in the certificate
 *
 * @param soap The soap structure for the request
 *
 * @return The client voname malloced in the soap structure (DON"T free), NULL otherwise
 */
char ** get_client_roles(struct soap *soap, int* nbfqans);


#ifdef __cplusplus
}
#endif






