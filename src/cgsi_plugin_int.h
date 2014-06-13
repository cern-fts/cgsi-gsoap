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

/** cgsi_plugin_int.h - Header file for the GSI gSOAP plugin
 *
 * @file cgsi_plugin_int.h
 * @author Ben Couturier CERN, IT/ADC
 *
 * This is a GSI plugin for gSOAP. It uses the globus GSI libraries to implement
 * GSI secure authentification and encryption on top of gSOAP.
 * The globus GSI bundle is necessary for the plugin to compile and run.
 *
 */

#include <globus_gss_assist.h>
#include <cgsi_plugin.h>
#include <stdsoap2.h>

#define CGSI_TRACE "CGSI_TRACE"
#define CGSI_TRACEFILE "CGSI_TRACEFILE"

#define CLIENT_PLUGIN_ID "CGSI_PLUGIN_CLIENT_1.0" /* plugin identification */
#define SERVER_PLUGIN_ID "CGSI_PLUGIN_SERVER_1.0" /* plugin identification */
#define CGSI_PLUGIN  "CGSI-gSOAP"

#define CGSI_MAXNAMELEN 512

struct cgsi_plugin_data
{
    int context_established;
    gss_cred_id_t credential_handle;
    gss_ctx_id_t  context_handle;
    int socket_fd;
    int (*fsend)(struct soap*, const char*, size_t);
    size_t (*frecv)(struct soap*, char*, size_t);
    int (*fopen)(struct soap*, const char*, const char*, int);
    int (*fclose)(struct soap*);
    char client_name[CGSI_MAXNAMELEN];
    char server_name[CGSI_MAXNAMELEN];
    char username[CGSI_MAXNAMELEN];
    char user_ca[CGSI_MAXNAMELEN];
    int nb_iter;
    int disable_hostname_check;
    int context_flags;
    int trace_mode;
    char trace_file[CGSI_MAXNAMELEN];
    gss_cred_id_t deleg_credential_handle;
    int deleg_cred_set;
    gss_buffer_t buffered_in;
    /* API-defined credentials */
    char* x509_cert;
    char* x509_key;
    /* Pointers to VOMS data */
    char *voname;
    char **fqan;
    int nbfqan;
    int disable_mapping;
    int disable_voms_check;
    int allow_only_self;
    int had_send_error;
    void *deleg_credential_token;
    size_t deleg_credential_token_len;
};
