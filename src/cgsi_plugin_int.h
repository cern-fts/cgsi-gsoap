/* 
 * Copyright (C) 2003 by CERN/IT/ADC/CA 
 * All rights reserved
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

#include <cgsi_plugin.h>
#include <globus_gss_assist.h>
#include <stdsoap2.h>

#define CGSI_TRACE "CGSI_TRACE"
#define CGSI_TRACEFILE "CGSI_TRACEFILE"

#define CLIENT_PLUGIN_ID "CGSI_PLUGIN_CLIENT_1.0" /* plugin identification */
#define SERVER_PLUGIN_ID "CGSI_PLUGIN_SERVER_1.0" /* plugin identification */
#define CGSI_PLUGIN  "CGSI-gSOAP"

#define MAXNAMELEN 512

struct cgsi_plugin_data {
    int context_established;
    gss_cred_id_t credential_handle;
    gss_ctx_id_t  context_handle;
    int socket_fd;
    int (*fsend)(struct soap*, const char*, size_t);
    size_t (*frecv)(struct soap*, char*, size_t);
    int (*fopen)(struct soap*, const char*, const char*, int);
    int (*fclose)(struct soap*);
    char client_name[MAXNAMELEN];
    char server_name[MAXNAMELEN];
    char username[MAXNAMELEN];    
    int nb_iter;
    int disable_hostname_check; 
    int context_flags;
    int trace_mode;
    char trace_file[MAXNAMELEN];
    gss_cred_id_t deleg_credential_handle;
    int deleg_cred_set;
    /* Pointers to VOMS data */
    char *voname;
    char **fqan;
    int nbfqan;
};



