/*
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://public.eu-egee.org/partners/ for details on 
 * the copyright holders.
 * For license conditions see the license file or
 * http://eu-egee.org/license.html
 */

#ifndef lint
static char sccsid[] = "@(#)";
#endif /* not lint */


/** cgsi_plugin.c - GSI plugin for gSOAP
 *
 * @file cgsi_plugin.c
 * @author Ben Couturier CERN, IT/ADC
 *
 * This is a GSI plugin for gSOAP. It uses the globus GSI libraries to implement
 * GSI secure authentification and encryption on top of gSOAP.
 * The globus GSI bundle is necessary for the plugin to compile and run.
 *
 */
#include <stdio.h>
#include "cgsi_plugin_int.h" 
#if defined(USE_VOMS)
#include "gssapi_openssl.h"
#include "globus_gsi_credential.h"
#include "voms_apic.h"
#endif

#define BUFSIZE 1024
#define TBUFSIZE 256

static char *client_plugin_id = CLIENT_PLUGIN_ID;
static char *server_plugin_id = SERVER_PLUGIN_ID;

int (*soap_fsend)(struct soap*, const char*, size_t); 
size_t (*soap_frecv)(struct soap*, char*, size_t); 

static int server_cgsi_plugin_init(struct soap *soap, struct cgsi_plugin_data *data);
static int server_cgsi_plugin_send(struct soap *soap, const char *buf, size_t len);
static size_t server_cgsi_plugin_recv(struct soap *soap, char *buf, size_t len);
static int server_cgsi_plugin_accept(struct soap *soap);
static int server_cgsi_plugin_close(struct soap *soap);
static int server_cgsi_map_dn(struct soap *soap);

static int client_cgsi_plugin_init(struct soap *soap, struct cgsi_plugin_data *data);
static int client_cgsi_plugin_open(struct soap *soap, const char *endpoint, const char *hostname, int port);
static int client_cgsi_plugin_send(struct soap *soap, const char *buf, size_t len);
static size_t client_cgsi_plugin_recv(struct soap *soap, char *buf, size_t len);
static int client_cgsi_plugin_close(struct soap *soap);

static int cgsi_plugin_compare_name(const char *dn, const char *hostname);
static int cgsi_plugin_copy(struct soap *soap, struct soap_plugin *dst, struct soap_plugin *src);
static void cgsi_plugin_delete(struct soap *soap, struct soap_plugin *p);
static int cgsi_plugin_send(struct soap *soap, const char *buf, size_t len, char *plugin_id);
static size_t cgsi_plugin_recv(struct soap *soap, char *buf, size_t len, char *plugin_id);
static int cgsi_plugin_close(struct soap *soap, char *plugin_id);
 
int cgsi_plugin_send_token(void *arg, void *token, size_t token_length);
int cgsi_plugin_recv_token(void *arg, void **token, size_t *token_length);
void cgsi_plugin_print_token(struct cgsi_plugin_data *data, char *token, int length);
static void cgsi_gssapi_err(struct soap *soap, char *msg, OM_uint32 maj_stat, OM_uint32 min_stat);
static void cgsi_err(struct soap *soap, char *msg);
static int cgsi_display_status_1(char *m, OM_uint32 code, int type, char *buf, int buflen);
static int cgsi_parse_opts(struct cgsi_plugin_data *p, void *arg);
static struct cgsi_plugin_data* get_plugin(struct soap *soap);
static int setup_trace(struct cgsi_plugin_data *data);
static int trace(struct cgsi_plugin_data *data, char *tracestr);
static void cgsi_plugin_globus_modules(int activate);
static int cgsi_plugin_get_voms_creds_from_ctx(struct soap *soap,
					       gss_ctx_id_t context_handle);

/******************************************************************************/
/* Plugin constructor            */
/* Defaults to client in case nothing is specified                            */
/******************************************************************************/
int cgsi_plugin(struct soap *soap, struct soap_plugin *p, void *arg) {
    int opts;
    
    if (arg == NULL) {
      return client_cgsi_plugin(soap, p, NULL);
    }

    opts = *((int *)arg);
    if (opts & CGSI_OPT_SERVER) {
      return server_cgsi_plugin(soap, p, arg);
    } else {
      return client_cgsi_plugin(soap, p, arg);
    }
}

/******************************************************************************/
/* SERVER Plugin functions */
/******************************************************************************/

/**
 * Constructor for the server plugin
 */
int server_cgsi_plugin(struct soap *soap, struct soap_plugin *p, void *arg) {

    /* Activate globus modules */
    cgsi_plugin_globus_modules(1);

    p->id = server_plugin_id;
    p->data = (void*)calloc(sizeof(struct cgsi_plugin_data), 1);
    p->fcopy = cgsi_plugin_copy;
    p->fdelete = cgsi_plugin_delete;
    if (p->data) {
        if (server_cgsi_plugin_init(soap, (struct cgsi_plugin_data*)p->data)) {
            free(p->data); /* error: could not init */
            cgsi_plugin_globus_modules(0);
            return SOAP_EOM; /* return error */
        }
	cgsi_parse_opts((struct cgsi_plugin_data*)p->data, arg);
    }
    return SOAP_OK;
}

/**
 * Initializes the plugin data object
 */
static int server_cgsi_plugin_init(struct soap *soap, struct cgsi_plugin_data *data) { 
    
    /* Setting up the functions */
    data->fclose = soap->fclose;
    soap_fsend = soap->fsend;
    soap_frecv = soap->frecv;
    data->fsend = soap->fsend;
    data->frecv = soap->frecv;
    data->context_established = 0;
    data->nb_iter = 0;
    data-> deleg_cred_set = 0;
    data->deleg_credential_handle = GSS_C_NO_CREDENTIAL;
    data->credential_handle = GSS_C_NO_CREDENTIAL;
    data->context_handle = GSS_C_NO_CONTEXT;
    data->voname = NULL;
    data->fqan = NULL;
    data->nbfqan = 0;
    setup_trace(data);
    soap->fclose = server_cgsi_plugin_close;
    soap->fsend = server_cgsi_plugin_send;
    soap->frecv = server_cgsi_plugin_recv;
    return SOAP_OK;
}

/**
 * Wrapper to encrypt/send data from the server
 */
static int server_cgsi_plugin_send(struct soap *soap, const char *buf, size_t len){
    return cgsi_plugin_send(soap, buf, len, server_plugin_id);
}

/**
 * Wrapper to receive data. It accepts the context if that has not been done yet.
 *
 * BEWARE: In this function returning 0 is the error condition !
 */
static size_t server_cgsi_plugin_recv(struct soap *soap, char *buf, size_t len){

    struct cgsi_plugin_data *data = (struct cgsi_plugin_data*)soap_lookup_plugin(soap, server_plugin_id);
    
    if (data == NULL) {
        cgsi_err(soap, "Server recv: could not get data structure");
        return 0;
    }

    /* Establishing the context if not done yet */
    if (data->context_established == 0) {

        trace(data, "### Establishing new context !\n");

        if (server_cgsi_plugin_accept(soap) != 0) {
            /* SOAP fault already reported in the underlying calls */
            trace(data, "Context establishment FAILED !\n");

            /* If the context establishment fails, we close the socket to avoid
               gSOAP trying to send an error back to the client ! */
            soap_closesock(soap);
            return 0;
        }
        
    } else {
        trace(data, "### Context already established!\n");
    }

    if (data->disable_mapping == 0) {
        /* Now doing username uid gid lookup */
        /* Performing the user mapping ! */
        if (server_cgsi_map_dn(soap)!=0){
            /* Soap fault already filled */
            return 0;
        }
    }

    return cgsi_plugin_recv(soap, buf, len, server_plugin_id); 
}

/**
 * Function that accepts the security context in the server.
 * The server credentials are loaded every-time.
 */
static int server_cgsi_plugin_accept(struct soap *soap) {
    struct cgsi_plugin_data *data;
    OM_uint32         major_status = 0;
    OM_uint32         minor_status = 0;
    OM_uint32         ret_flags =  0;
    gss_buffer_desc send_tok, recv_tok;
    gss_name_t client = GSS_C_NO_NAME;
    gss_name_t server;
    gss_buffer_desc name;
    OM_uint32  acc_sec_min_stat;
    OM_uint32           time_req;
    gss_cred_id_t       delegated_cred_handle = GSS_C_NO_CREDENTIAL;
    gss_channel_bindings_t  input_chan_bindings = GSS_C_NO_CHANNEL_BINDINGS;
    gss_OID doid = GSS_C_NO_OID;

  
    /* Getting the plugin data object */
    data = (struct cgsi_plugin_data *) soap_lookup_plugin (soap, server_plugin_id);
    if (!data) {
        cgsi_err(soap, "Error looking up plugin data");
        return -1;
    }

    ret_flags = data->context_flags;
    {
        char buf[TBUFSIZE];
        snprintf(buf, TBUFSIZE-1, "Server accepting context with flags: %xd\n", ret_flags);
        trace(data, buf);
    }

    /* Getting the credenttials */
    data->credential_handle = GSS_C_NO_CREDENTIAL;

    /* Specifying GSS_C_NO_NAME for the name or the server will
       force it to take the default host certificate */
    major_status = gss_acquire_cred(&minor_status,
                                    GSS_C_NO_NAME,
                                    0,
                                    GSS_C_NULL_OID_SET,
                                    GSS_C_ACCEPT,
                                    &(data->credential_handle),
                                    NULL,
                                    NULL);

    
    if (major_status != GSS_S_COMPLETE) {
        cgsi_gssapi_err(soap, 
                        "Could NOT load server credentials",
                        major_status,
                        minor_status);
        trace(data, "Could not load server credentials !\n");

        return -1;
    }

    /* Now keeping the credentials name in the data structure */
    major_status = gss_inquire_cred(&minor_status,
                                    data->credential_handle,
                                    &server,
                                    NULL,
                                    NULL,
                                    NULL);
    if (major_status != GSS_S_COMPLETE) {
        cgsi_gssapi_err(soap,  "Error inquiring credentials", major_status, minor_status);
        return -1;
    }
  
    /* Keeping the name in the plugin */
    major_status = gss_display_name(&minor_status, server, &name, (gss_OID *) NULL);
    if (major_status != GSS_S_COMPLETE) {
        cgsi_gssapi_err(soap,  "Error displaying server name", major_status, minor_status);
        return -1;
    }

    strncpy(data->server_name, name.value, MAXNAMELEN);

    {
        char buf[TBUFSIZE];
        snprintf(buf, TBUFSIZE-1, "The server is:<%s>\n", data->server_name);
        trace(data, buf);
    }

    (void)gss_release_name(&minor_status, &server);
    (void) gss_release_buffer(&minor_status, &name); 

    /* Now doing GSI authentication */
    /* First initialize the context and then loop over
       gss_accept_sec_context */
    data->context_handle = GSS_C_NO_CONTEXT;
    do {
        data->nb_iter++;
        
        if (cgsi_plugin_recv_token(soap, &(recv_tok.value), &(recv_tok.length)) < 0) {
            /* Soap fault already reported ! */

		trace(data, "Error receiving token !\n");

		return -1;
        }
        
        major_status = gss_accept_sec_context(&acc_sec_min_stat,
                                              &(data->context_handle),
                                              (data->credential_handle),
                                              &recv_tok,
                                              input_chan_bindings,
                                              &client,
                                              &doid,
                                              &send_tok,
                                              &ret_flags,
                                              &time_req,
                                              &delegated_cred_handle);


        if (major_status!=GSS_S_COMPLETE && major_status!=GSS_S_CONTINUE_NEEDED) {
            cgsi_gssapi_err(soap, "Could not accept security context",
                            major_status,
                            acc_sec_min_stat);

		trace(data, "Exiting due to a bad return code (1)\n");

		(void) gss_release_buffer(&minor_status, &recv_tok);
            
            if (data->context_handle != GSS_C_NO_CONTEXT)
                (void)gss_delete_sec_context(&minor_status,
                                             &(data->context_handle),
                                             GSS_C_NO_BUFFER);
            return -1;
        }

        (void) gss_release_buffer(&minor_status, &recv_tok);

        if (send_tok.length != 0) {

            if (cgsi_plugin_send_token(soap, send_tok.value, send_tok.length) < 0) {
                (void) gss_release_buffer(&minor_status, &send_tok);

		      trace(data, "Exiting due to a bad return code (2)\n");

                /* Soap fault already reported by underlying layer */
                return -1;
            } /* If token has 0 length, then just try again (it is NOT an error condition)! */
            
            
        } 

        (void) gss_release_buffer(&minor_status, &send_tok);

    } while (major_status & GSS_S_CONTINUE_NEEDED);
    
    /* Keeping the name in the plugin */
    major_status = gss_display_name(&minor_status, client, &name, (gss_OID *) NULL);
    if (major_status != GSS_S_COMPLETE) {
        cgsi_gssapi_err(soap,  "Error displaying name", major_status, minor_status);
        return -1;
    }

    strncpy(data->client_name, name.value, MAXNAMELEN);

   {
        char buf[TBUFSIZE];
        snprintf(buf, TBUFSIZE-1,  "The client is:<%s>\n", data->client_name);
        trace(data, buf);
    }

    if (cgsi_plugin_get_voms_creds_from_ctx(soap, data->context_handle) != 0) {
        /* the error description should be already set */
        return -1;
    }

    /* Setting the flag as even the mapping went ok */
    data->context_established = 1;

    /* Save the delegated credentials */
    if ((ret_flags & GSS_C_DELEG_FLAG) && (delegated_cred_handle != GSS_C_NO_CREDENTIAL)) {
        gss_name_t deleg_name;
        gss_buffer_desc namebuf;
 
        OM_uint32 lifetime;
        gss_cred_usage_t usage;
        
        data->deleg_credential_handle = delegated_cred_handle;
        data->deleg_cred_set = 1;
        trace(data, "deleg_cred 1\n");

        /* Now keeping the credentials name in the data structure */
        major_status = gss_inquire_cred(&minor_status,
                                        data->deleg_credential_handle,
                                        &deleg_name,
                                        &lifetime,
                                        &usage,
                                        NULL);

        if (major_status != GSS_S_COMPLETE) {
            cgsi_gssapi_err(soap,  "Error inquiring delegated credentials", major_status, minor_status);
            return -1;
        }
  
        /* Keeping the name in the plugin */
        major_status = gss_display_name(&minor_status, deleg_name , &namebuf, (gss_OID *) NULL);
        if (major_status != GSS_S_COMPLETE) {
            cgsi_gssapi_err(soap,  "Error displaying delegated credentials name", major_status, minor_status);
            return -1;
        }

        {
            char buf[TBUFSIZE];
            snprintf(buf, TBUFSIZE-1, "The delegated credentials are for:<%s>\n", (char *)namebuf.value);
            trace(data, buf);
        }
        
        (void)gss_release_name(&minor_status, &deleg_name);
        (void) gss_release_buffer(&minor_status, &namebuf); 

        
    } else {
        trace(data, "deleg_cred 0\n");
    }
    
    (void)gss_release_name(&minor_status, &client);
    (void) gss_release_buffer(&minor_status, &name); 

    return 0;
}

/**
 * Looks up the client name and maps the username/uid/gid accordingly
 */
static int server_cgsi_map_dn(struct soap *soap) {

    char *p;
    struct cgsi_plugin_data *data;
    
    /* Getting the plugin data object */
    data = (struct cgsi_plugin_data *) soap_lookup_plugin (soap, server_plugin_id);
    if (!data) {
        cgsi_err(soap, "Error looking up plugin data");
        return -1;
    }
    
    if (!globus_gss_assist_gridmap(data->client_name, &p)){
        /* We have a mapping */
        strncpy(data->username, p, MAXNAMELEN);

        {
            char buf[TBUFSIZE];
            snprintf(buf, TBUFSIZE-1, "The client is mapped to user:<%s>\n", data->username);
            trace(data, buf);
        }

        free(p);
    } else {
        char buf[BUFSIZE];

        {
            char buf[TBUFSIZE];
            snprintf(buf, TBUFSIZE-1, "Could not find mapping for: %s\n", data->client_name);
            trace(data, buf);
        }
        
        data->username[0]=0;
        snprintf(buf, BUFSIZE, "Could not find mapping for: %s\n", data->client_name);
        cgsi_err(soap, buf);
        return -1;
    }

    return 0;
    
}




static int server_cgsi_plugin_close(struct soap *soap) {
    return cgsi_plugin_close(soap, server_plugin_id);
}

/******************************************************************************/
/* CLIENT Plugin functions */
/******************************************************************************/


/**
 * Constructor for the client plugin
 */
int client_cgsi_plugin(struct soap *soap, struct soap_plugin *p, void *arg) {

    /* Activate globus modules */
    cgsi_plugin_globus_modules(1);

    p->id = client_plugin_id;
    p->data = (void*)calloc(sizeof(struct cgsi_plugin_data), 1);
    p->fcopy = cgsi_plugin_copy;
    p->fdelete = cgsi_plugin_delete;
    if (p->data) {
        if (client_cgsi_plugin_init(soap, (struct cgsi_plugin_data*)p->data)) {
            free(p->data); /* error: could not init */
            cgsi_plugin_globus_modules(0);
            return SOAP_EOM; /* return error */
        }     
        cgsi_parse_opts((struct cgsi_plugin_data*)p->data, arg);
    }
    return SOAP_OK;
}


static int client_cgsi_plugin_init(struct soap *soap, struct cgsi_plugin_data *data) { 


    /* Setting up the functions */
    data->fopen = soap->fopen;
    data->fclose = soap->fclose;
    soap_fsend = soap->fsend;
    soap_frecv = soap->frecv;
    data->fsend = soap->fsend;
    data->frecv = soap->frecv;
    data->context_established = 0;    
    data->nb_iter = 0;
    data-> deleg_cred_set = 0;
    data->deleg_credential_handle = GSS_C_NO_CREDENTIAL;
    data->credential_handle = GSS_C_NO_CREDENTIAL;
    data->context_handle = GSS_C_NO_CONTEXT;
    setup_trace(data);
    
    soap->fopen = client_cgsi_plugin_open;
    soap->fclose = client_cgsi_plugin_close;
    soap->fsend = client_cgsi_plugin_send;
    soap->frecv = client_cgsi_plugin_recv;

    return SOAP_OK;
}


static int client_cgsi_plugin_open(struct soap *soap,
                     const char *endpoint,
                     const char *hostname,
                     int port) {

    OM_uint32 major_status = 0;
    OM_uint32 minor_status = 0;
    OM_uint32 ret_flags = 0;
    OM_uint32 init_sec_min_stat;
    struct cgsi_plugin_data *data;
    gss_name_t client = GSS_C_NO_NAME;
    gss_buffer_desc name;
    gss_buffer_desc send_tok, recv_tok, *token_ptr;
    gss_OID oid;
    
    /* Looking up plugin data */
    data = (struct cgsi_plugin_data*)soap_lookup_plugin(soap, client_plugin_id);

    /* Getting the credenttials */
    data->credential_handle = GSS_C_NO_CREDENTIAL;

    major_status = gss_acquire_cred(&minor_status,
                                    GSS_C_NO_NAME,
                                    0,
                                    GSS_C_NULL_OID_SET,
                                    GSS_C_INITIATE,
                                    &(data->credential_handle),
                                    NULL,
                                    NULL);
    
    
    if (major_status != GSS_S_COMPLETE) {
        cgsi_gssapi_err(soap, 
                        "Could NOT load client credentials",
                        major_status,
                        minor_status);
        return -1;
    }
    
    /* Now keeping the credentials name in the data structure */
    major_status = gss_inquire_cred(&minor_status,
                                    data->credential_handle,
                                    &client,
                                    NULL,
                                    NULL,
                                    NULL);
    if (major_status != GSS_S_COMPLETE) {
        cgsi_gssapi_err(soap,  "Error inquiring credentials", major_status, minor_status);
        return -1;
    }
  
    /* Keeping the name in the plugin */
    major_status = gss_display_name(&minor_status, client, &name, (gss_OID *) NULL);
    if (major_status != GSS_S_COMPLETE) {
        cgsi_gssapi_err(soap,  "Error displaying client name", major_status, minor_status);
        return -1;
    }

    strncpy(data->client_name, name.value, MAXNAMELEN);

    (void)gss_release_buffer(&minor_status, &name);
    (void)gss_release_name(&minor_status, &client);
       
    
    {
        char buf[TBUFSIZE];
        snprintf(buf, TBUFSIZE-1, "The client is:<%s>\n", data->client_name);
        trace(data, buf);
    }

    /* Opening the connection to the server */
    if (data->fopen == NULL) {
      cgsi_err(soap, "data->fopen is NULL !");
      return -1;
    }
    

    data->socket_fd = data->fopen(soap, endpoint, hostname, port);
    if (data->socket_fd < 0) {
        cgsi_err(soap, "Could not open connection !");
        return -1;
    }
      
    token_ptr = GSS_C_NO_BUFFER;
    data->context_handle = GSS_C_NO_CONTEXT;
    do {

        data->nb_iter++;

        {
            char buf[TBUFSIZE];
            snprintf(buf, TBUFSIZE-1, "Iteration:<%d>\n", data->nb_iter);
            trace(data, buf);
        }

        major_status = gss_init_sec_context(&init_sec_min_stat,
                                            data->credential_handle,
                                            &(data->context_handle),
                                            GSS_C_NO_NAME,
                                            oid,
                                            data->context_flags,
                                            0,
                                            NULL,	/* no channel bindings */
                                            token_ptr,
                                            NULL,	/* ignore mech type */
                                            &send_tok,
                                            &ret_flags,
                                            NULL);	/* ignore time_rec */
  
        if (data->context_handle == NULL) {
            cgsi_gssapi_err(soap, "Error creating context", major_status, minor_status);
            trace(data, "Error: the context is null\n");

            /* return -1; */
         }
        
        if (token_ptr != GSS_C_NO_BUFFER)
            (void) gss_release_buffer(&minor_status, &recv_tok);

        if (major_status!=GSS_S_COMPLETE && major_status!=GSS_S_CONTINUE_NEEDED) {
            cgsi_gssapi_err(soap, "Error initializing context",  major_status, minor_status);

            if (data->context_handle != GSS_C_NO_CONTEXT)
                gss_delete_sec_context(&minor_status, &(data->context_handle),
                                       GSS_C_NO_BUFFER);
            return -1;
        }
                
        if (send_tok.length > 0) {
            
            if (cgsi_plugin_send_token(soap,  send_tok.value, send_tok.length) < 0) {
                (void) gss_release_buffer(&minor_status, &send_tok);
                /* Soap fault already reported */
                trace(data, "Error sending token !\n");
                return -1;
            }
        }
        (void) gss_release_buffer(&minor_status, &send_tok);
       
        
        if (major_status & GSS_S_CONTINUE_NEEDED) {
            
            if (cgsi_plugin_recv_token(soap, &(recv_tok.value), &(recv_tok.length)) < 0) {
                /* fault already reported */
                return -1;
            }
            token_ptr = &recv_tok;   
        } 
        
    } while (major_status == GSS_S_CONTINUE_NEEDED);
    

    
    /* Now check the server name */
    {
        OM_uint32 maj_stat, min_stat;
        gss_name_t src_name, tgt_name;
        OM_uint32 lifetime, ctx;
        gss_OID mech;
        int local, isopen;
        gss_buffer_desc server_name;
        int match;
        char buf[BUFSIZE];
        
        maj_stat = gss_inquire_context(&minor_status,
                                       data->context_handle,
                                       &src_name,
                                       &tgt_name,
                                       &lifetime,
                                       &mech,
                                       &ctx,
                                       &local,
                                       &isopen);

        if (maj_stat != GSS_S_COMPLETE) {
            cgsi_gssapi_err(soap, 
                            "Error inquiring context",
                            maj_stat,
                            min_stat);
            return -1;
        }
                                           
        maj_stat = gss_display_name(&min_stat, tgt_name, &server_name, (gss_OID *) NULL);
        if (maj_stat != GSS_S_COMPLETE) {
            cgsi_gssapi_err(soap,  "Error displaying name", maj_stat, min_stat);
            return -1;
        }

        strncpy(data->server_name, server_name.value, MAXNAMELEN);
            
        {
            char buf[TBUFSIZE];
            snprintf(buf, TBUFSIZE-1, "Server:<%s>\n", (char *)server_name.value);
            buf[TBUFSIZE-1] = '\0';
            trace(data, buf);
        }
        
        match = cgsi_plugin_compare_name(server_name.value, hostname);

        if (match != 0) {
            snprintf(buf, BUFSIZE-1, "DN %s and hostname %s do NOT match !\n", 
                     (char *)(server_name.value), hostname);
            buf[BUFSIZE-1]='\0';
        }

        
        (void)gss_release_buffer(&min_stat, &server_name);
        (void)gss_release_name(&min_stat, &tgt_name);
        (void)gss_release_name(&min_stat, &src_name);

        if (match != 0 && data->disable_hostname_check != 1) {
            cgsi_err(soap, buf);
            return -1;
        }
        
    }

    data->context_established = 1;    
    return data->socket_fd;
}


static int client_cgsi_plugin_send(struct soap *soap, const char *buf, size_t len) {
    return cgsi_plugin_send(soap, buf, len, client_plugin_id);
}

static size_t client_cgsi_plugin_recv(struct soap *soap, char *buf, size_t len) {
    return cgsi_plugin_recv(soap, buf, len, client_plugin_id);
}

static int client_cgsi_plugin_close(struct soap *soap) {
    return cgsi_plugin_close(soap, client_plugin_id);
}

 

/******************************************************************************/
/* COMMON Plugin functions */
/******************************************************************************/

/**
 * returns 0 if the hostname matches the distinguished name (dn).
 */
static int cgsi_plugin_compare_name(const char *dn, const char *hostname) {

    char *pos;
    char *tofind= "CN=host/";
    
    pos = strstr(dn, tofind);
    if (pos==NULL) {
        return -1;
    }

    pos += strlen(tofind);
    if (strncmp(hostname, pos, strlen(hostname))==0) {
        return 0;
    }

    return -1;
}


static int cgsi_plugin_copy(struct soap *soap, struct soap_plugin *dst, struct soap_plugin *src) {
    *dst = *src;
    dst->data =  (struct cgsi_plugin_data *)malloc(sizeof(struct cgsi_plugin_data));
    if (dst->data == NULL) return SOAP_FATAL_ERROR;
    memcpy(dst->data, src->data, sizeof(struct cgsi_plugin_data));

    /* Activate globus modules, as the new object will also need them */
    cgsi_plugin_globus_modules(1);

    return SOAP_OK;
}

static void cgsi_plugin_delete(struct soap *soap, struct soap_plugin *p){
    OM_uint32 min_stat;
    struct cgsi_plugin_data *data;
    
    if (p->data == NULL) {
        cgsi_plugin_globus_modules(0);
        return;
    } else {
        data = (struct cgsi_plugin_data *)p->data;
    }

    /* Deleting the context */
    if (data->context_handle != NULL) {
        gss_delete_sec_context(&min_stat, &(data->context_handle), GSS_C_NO_BUFFER);
    }
    
    /* Freeing delegated credentials if present */
    if (data->deleg_cred_set != 0) {
        gss_release_cred(&min_stat, &(data->deleg_credential_handle));
    }

    if (data->credential_handle != NULL) {
        gss_release_cred(&min_stat, &(data->credential_handle));
    }
 
    /* Clearing the VOMS attributes */
    if (data->voname != NULL) {
      free(data->voname);
    }

    /* fqan is a NULL terminated array of char * */
    if (data->fqan != NULL) {
      int i;
      for (i = 0; i < data->nbfqan; i++)
	free(data->fqan[i]);
      free(data->fqan);
    }
    
    free(p->data); /* free allocated plugin data (this function is not called for shared plugin data) */

    /* Deactivate globus modules */
    cgsi_plugin_globus_modules(0);
}


static int cgsi_plugin_close(struct soap *soap, char *plugin_id) {

    OM_uint32 major_status;
    OM_uint32 minor_status;
    gss_buffer_desc output_buffer_desc;
    gss_buffer_t output_buffer;
    struct cgsi_plugin_data *data = (struct cgsi_plugin_data*)soap_lookup_plugin(soap, plugin_id);

    if (data == NULL) {
        cgsi_err(soap, "Close: could not get data structure");
        return -1;
    }
    
    output_buffer = &output_buffer_desc;
    
    if (data->context_established == 1) {

        major_status = gss_delete_sec_context(&minor_status, &(data->context_handle), output_buffer);
        if (major_status != GSS_S_COMPLETE) {
            cgsi_gssapi_err(soap, 
                            "Error deleting context",
                            major_status,
                            minor_status);
        } else {
	  /*cgsi_plugin_send_token( (void *)soap, output_buffer->value, output_buffer->length);*/   
            gss_release_buffer(&minor_status, output_buffer);
            data->context_established = 0;
        }
    }
    if (data->fclose != NULL) {
      return data->fclose(soap);
    } else {
      cgsi_err(soap, "Close: data->fclose is NULL");
      return -1;      
    }
    
    
}


static int cgsi_plugin_send(struct soap *soap, const char *buf, size_t len, char *plugin_id) {

    OM_uint32 major_status;
    OM_uint32 minor_status;
    gss_buffer_desc input_tok;
    gss_buffer_desc output_tok;
    int conf_state;
    
    struct cgsi_plugin_data *data = (struct cgsi_plugin_data*)soap_lookup_plugin(soap, plugin_id);

    trace(data, "<Sending SOAP Packet>-------------\n");
    trace(data, (char *)buf);
    trace(data, "\n----------------------------------\n");

    input_tok.value = (char *)buf;
    input_tok.length = len;
    
    major_status = gss_wrap(&minor_status,
                            data->context_handle,
                            0,
                            GSS_C_QOP_DEFAULT,
                            &input_tok,
                            &conf_state,
                            &output_tok);
    
    if (major_status != GSS_S_COMPLETE) {
        cgsi_gssapi_err(soap, 
                        "Error wrapping the data",
                        major_status,
                        minor_status);
        return -1;
    }
    
    if (cgsi_plugin_send_token((void *)soap,
                               output_tok.value,
                               output_tok.length) != 0) {
        /* Soap fault already reported */
        return -1;
    }

    gss_release_buffer(&minor_status, &output_tok);
    
    return SOAP_OK;

    
    
}

static size_t cgsi_plugin_recv(struct soap *soap, char *buf, size_t len, char *plugin_id) {

    OM_uint32 major_status;
    OM_uint32 minor_status, minor_status1;
    int token_status;
    size_t tmplen;
    gss_buffer_desc                       input_token_desc  = GSS_C_EMPTY_BUFFER;
    gss_buffer_t                          input_token       = &input_token_desc;
    gss_buffer_desc                       output_token_desc = GSS_C_EMPTY_BUFFER;
    gss_buffer_t                          output_token      = &output_token_desc;

    
    struct cgsi_plugin_data *data = (struct cgsi_plugin_data*)soap_lookup_plugin(soap, plugin_id);


    token_status = cgsi_plugin_recv_token((void *)soap,
                                          &input_token->value,
                                          &input_token->length);

    
    if (token_status != 0) {
        trace(data, "Token status <> 0\n");
        /* Soap fault already reported */
        return 0;
    }
    
    major_status = gss_unwrap(&minor_status,
                              data->context_handle,
                              input_token,
                              output_token,
                              NULL,
                              NULL);
        
        
    gss_release_buffer(&minor_status1,
                       input_token);
        
    
    if (major_status != GSS_S_COMPLETE || token_status != 0) {
        cgsi_gssapi_err(soap, 
                        "Error unwrapping the data",
                        major_status,
                        minor_status);
        return 0;
    }

    if (output_token->length > len) {
        cgsi_err(soap, "Message too long for buffer\n");
        return 0;
    }


    memcpy(buf, output_token->value, output_token->length);
    tmplen = output_token->length;
    
    gss_release_buffer(&minor_status1,
                       output_token);
   
    trace(data, "<Recving SOAP Packet>-------------\n");
    trace(data, buf);
    trace(data, "\n----------------------------------\n");
    
    return (size_t) tmplen;

}


#define SSLHSIZE 5

int cgsi_plugin_recv_token(arg, token, token_length)
void *arg;
void ** token;
size_t * token_length;
{
     int ret, rem;
     char *tok, *p;
     int len;
     char readbuf[SSLHSIZE];
     struct soap *soap = (struct soap *)arg;
     struct cgsi_plugin_data *data;

     if (soap == NULL) {
         cgsi_err(soap, "Error: SOAP object is NULL");
         return -1;
     }
     
     data = get_plugin(soap);
     
     /* Reads SSL Record layer header ! */
     p = readbuf;
     rem = SSLHSIZE;
     while (rem>0) {
       /* trace(data, "%d Remaining %d\n", getpid(), rem); */
       ret = soap_frecv(soap, p, rem);
       if (ret <= 0) { /* BEWARE soap_recv returns 0 when an error occurs ! */
         char buf[BUFSIZE];
         snprintf(buf, BUFSIZE, "Error reading token data: %s\n", strerror(errno));
         cgsi_err(soap, buf);
         return -1;
       }
       p = p + ret;
       rem = rem - ret;
     }


     /* Initialization, len will contain the length of the message */
     len = 0;
     p = (char *)&len;
     
     /* Checking whether we have a SSL V2 Client Hello */
     if (readbuf[0] == (char)0x80) {
         *(p+3) = readbuf[1];
         len = ntohl(len);

         /* In the case of SSLv2, we have just read 3 bytes that do NOT
            belong to the Record layer, we have to deduct them from
            the length (if possible XXX -> to be checked) */

         len = len -3;

     } else {
         /* We have SSLv3 or TLS */
     

         /* Getting the packet length from the last two bytes ! */
         /* of the readbuf */
         *(p+2) = readbuf[3];
         *(p+3) = readbuf[4];
         
         /* Converting length to machine byte order ! */
         len = ntohl(len);
         
     }    

     /* AT this point, the token length is len + the number of bytes already read,
        i.e. SSLHSIZE */

     tok  = (char *) malloc(len + SSLHSIZE);
     if ( (len+SSLHSIZE) && tok == NULL) {
         cgsi_err(soap, "Out of memory allocating token data\n");
         return -1;
     }

     memcpy(tok, readbuf, SSLHSIZE);
     rem = len;
     p = (char *) (tok + SSLHSIZE);	
     
     /* Looping on the data still to read */
     while (rem > 0) { 
       ret =  soap_frecv(soap, p, rem);
       if (ret <= 0) {
         char buf[BUFSIZE];
         snprintf(buf, BUFSIZE, "Error reading token data: %s\n", strerror(errno));
         cgsi_err(soap, buf);
         free(tok);
         return -1;
       } 
       p = p + ret;
       rem = rem - ret;
     }

     {
         char buf[TBUFSIZE];
         snprintf(buf, TBUFSIZE-1,  "================= RECVING: %x\n", len + SSLHSIZE);
         trace(data, buf);
     }
     cgsi_plugin_print_token(data, tok, len+SSLHSIZE);

     *token_length = (len + SSLHSIZE);
     *token = tok; 
     return 0;
}


int cgsi_plugin_send_token(arg,token,token_length)
    void *    arg;
    void *    token;
    size_t    token_length;
{
    int ret;
    struct cgsi_plugin_data *data;
    struct soap *soap = (struct soap *)arg;
    
    if (soap == NULL) {
        cgsi_err(soap, "Error: SOAP object is NULL");
        return -1;
    }
    
    data = get_plugin(soap);

    {
         char buf[TBUFSIZE];
         snprintf(buf, TBUFSIZE-1,  "================= SENDING: %x\n", 
                  (unsigned int)token_length);
         trace(data, buf);
     }
     cgsi_plugin_print_token(data, token, token_length);
     
     /* We send the whole token knowing it is a SSL token */
     
     ret =  soap_fsend(soap, token, token_length);
     if (ret < 0) {
         char buf[BUFSIZE];
         snprintf(buf, BUFSIZE,"Error sending token data: %s\n", strerror(errno));
         cgsi_err(soap, buf);
         return -1;
     } else if (ret != SOAP_OK) {
           char buf[BUFSIZE];
           snprintf(buf, BUFSIZE,  "sending token data: %d of %d bytes written\n", 
                    ret, (int)token_length);
           cgsi_err(soap, buf);
         return -1;
     }
     
     return 0;
}

void cgsi_plugin_print_token(data, token, length)
    struct cgsi_plugin_data *data;
    char *token;
    int length;
{
    int i;
    unsigned char *p = token;
    char buf[TBUFSIZE];
    
    for (i=0; i < length; i++, p++) {
/*         if (i== 100) */
/*             goto exit_loop; */
        snprintf(buf, TBUFSIZE,"%02x ", *p);
        trace(data, buf);
        if ((i % 16) == 15) { 
/*              fprintf(f, "\t        "); */
/*              for (j=15; j >= 0; j--) { */
/*                  fprintf(f, "%c", *(p-j)); */
/*              } */
             trace(data, "\n");
        }
    }
/*   exit_loop: */
    trace(data, "\n");
}


/**
 * Function to display the GSS-API errors
 */
static void cgsi_gssapi_err(struct soap *soap, char *msg, OM_uint32 maj_stat, OM_uint32 min_stat) {

    int ret;
    char buffer[BUFSIZE];
    int bufsize;
    char *buf;
    struct cgsi_plugin_data *data;
    int isclient = 1;

    /* Check if we are a client */
    data = (struct cgsi_plugin_data*)soap_lookup_plugin(soap, client_plugin_id);
    if (data == NULL) {
        isclient = 0;
    }

    bufsize = BUFSIZE;
    strncpy(buffer, CGSI_PLUGIN ": ", bufsize);
    buf = buffer +strlen(buffer); 
    bufsize -= strlen(buffer);

    ret =  cgsi_display_status_1(msg, maj_stat, GSS_C_GSS_CODE, buf, bufsize);
    cgsi_display_status_1(msg, min_stat, GSS_C_MECH_CODE, buf + ret, bufsize - ret);

    if (isclient) {
        soap_sender_fault(soap, buffer, NULL);
    } else {
        soap_receiver_fault(soap, buffer, NULL);
    }
}

/**
  * Displays the GSS-API error messages in the error buffer
 */
static int cgsi_display_status_1(char *m, OM_uint32 code, int type, char *buf, int buflen) {
     OM_uint32 maj_stat, min_stat;
     gss_buffer_desc msg;
     OM_uint32 msg_ctx;
     int ret;

     msg_ctx = 0;
     while (1) {
         maj_stat = gss_display_status(&min_stat, code,
                                       type, GSS_C_NULL_OID,
                                       &msg_ctx, &msg);
         
         ret = snprintf(buf, buflen, "%s\n", (char *)msg.value); 
         (void) gss_release_buffer(&min_stat, &msg);
         
         if (!msg_ctx)
             break;
     }

     return ret;
}

static void cgsi_err(struct soap *soap, char *msg) {

    struct cgsi_plugin_data *data;
    int isclient = 1;
    char buffer[BUFSIZE];
    int bufsize;
    char *buf;
    
    /* Check if we are a client */
    data = (struct cgsi_plugin_data*)soap_lookup_plugin(soap, client_plugin_id);
    if (data == NULL) {
        isclient = 0;
    }
    
    bufsize = BUFSIZE;
    strncpy(buffer, CGSI_PLUGIN ": ", bufsize);
    buf = buffer +strlen(buffer); 
    bufsize -= strlen(buffer);
    strncpy(buf, msg, bufsize);

    if (isclient) {
        soap_sender_fault(soap, buffer, NULL);
    } else {
        soap_receiver_fault(soap, buffer, NULL);
    }
}

/**
 * Parses the argument passed to the plugin constructor
 * and initializes the plugin_data object accordingly
 */
static int cgsi_parse_opts(struct cgsi_plugin_data *p, void *arg) {
  int opts;

  /* Default values */
  p->disable_hostname_check = 0;
  p->disable_mapping = 0;
  p->context_flags = GSS_C_CONF_FLAG | GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG;

  if (arg == NULL) {
      /* Default is just confidentiality and mutual authentication */
      return 0;
  }
  
  opts = (*((int *)arg));

  if (opts & CGSI_OPT_DELEG_FLAG) {
    p->context_flags |= GSS_C_DELEG_FLAG;
  }

  if (opts & CGSI_OPT_SSL_COMPATIBLE) {
    p->context_flags |= GSS_C_GLOBUS_SSL_COMPATIBLE;
  }
  
  if (opts & CGSI_OPT_DISABLE_NAME_CHECK) {
    p->disable_hostname_check = 1;
  }
  
  if (opts & CGSI_OPT_DISABLE_MAPPING) {
    p->disable_mapping = 1;
  }
  
  return 0;

}

/**
 * Look's up the plugin, be it client or server
 */
static struct cgsi_plugin_data* get_plugin(struct soap *soap) {

    struct cgsi_plugin_data *data = NULL;

    /* Check if we are a client */
    data = (struct cgsi_plugin_data*)soap_lookup_plugin(soap, client_plugin_id);
    if (data == NULL) {
        data = (struct cgsi_plugin_data*)soap_lookup_plugin(soap, server_plugin_id);            
    }
    
    return data;
}


/**
 * Returns 1 if the context has been extablished, 0 if not,
 * or -1 if an error happened during plugin lookup.
 *
 */
int is_context_established(struct soap *soap) {

    struct cgsi_plugin_data *data = NULL;

    data = get_plugin(soap);
    if (data == NULL) return -1;

    return data->context_established;
}

/**
 * Copies the client DN in the buffer passed.
 * Returns 0 if everything ok, -1 otherwise.
 *
 */
int get_client_dn(struct soap *soap, char *dn, size_t dnlen) {
    struct cgsi_plugin_data *data = NULL;
    data = get_plugin(soap);
    if (data == NULL) return -1;

    memset(dn, '\0', dnlen);
    strncpy(dn, data->client_name, dnlen);
    return 0;
}

/**
 * Copies the client username in the buffer passed.
 * Returns 0 if everything ok, -1 otherwise.
 *
 */
int get_client_username(struct soap *soap, char *username, size_t usernamelen) {
    struct cgsi_plugin_data *data = NULL;
    data = get_plugin(soap);
    if (data == NULL) return -1;

    memset(username, '\0', usernamelen);
    strncpy(username, data->username, usernamelen);
    return 0;
}



/**
 * Checks the environment to setup the trace mode,
 * if CGSI_TRACE is set
 * If CGSI_TRACEFILE is set, the output is written to that file,
 * otherwise, it is sent to stderr.
 */
static int setup_trace(struct cgsi_plugin_data *data) {
    char *envar;

    data->trace_mode=0;
    data->trace_file[0]= data->trace_file[MAXNAMELEN-1]= '\0';

    envar = getenv(CGSI_TRACE);
    if (envar != NULL) {
        data->trace_mode=1;
        envar = getenv(CGSI_TRACEFILE);
        if (envar != NULL) {
            strncpy(data->trace_file, envar, MAXNAMELEN-1);
        }
    } 
    return 0;
}


static int trace(struct cgsi_plugin_data *data, char *tracestr) {

    if (!data->trace_mode) {
        return 0;
    }

    /* If no trace file defined, write to stderr */
    if (data->trace_file[0]=='\0') {
        fprintf(stderr, tracestr);
    } else {
        int fd;
        fd = open(data->trace_file, O_CREAT|O_WRONLY|O_APPEND, 0644);
        if (fd <0) return -1;
        write(fd, tracestr, strlen(tracestr));
        close(fd);
    }
    return 0;
}

int export_delegated_credentials(struct soap *soap, char *filename) {
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc buffer = GSS_C_EMPTY_BUFFER;
    int fd, rc;
    struct cgsi_plugin_data *data;
    
    if (soap == NULL) {
        return -1;
    }
    
    data = (struct cgsi_plugin_data*)soap_lookup_plugin(soap,
                                                        server_plugin_id);

    if (data == NULL) {
        cgsi_err(soap, "export delegated credentials: could not get data structure");
        return -1;
    }

    if (data->deleg_cred_set == 0) {
        cgsi_err(soap, "export delegated credentials: delegated credentials not set");
        return -1;
    }

    maj_stat = gss_export_cred(&min_stat,
                               data->deleg_credential_handle,
                               GSS_C_NO_OID,
                               0,
                               &buffer);

    if (maj_stat != GSS_S_COMPLETE) {
        cgsi_gssapi_err(soap,  "Error exporting  credentials", maj_stat, min_stat);
        return -1;
    }


    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        cgsi_err(soap, "export delegated credentials: could not open temp file");
        return -1;
    }

    rc = write(fd, buffer.value, buffer.length); 
    if (rc != buffer.length) {
        char buf[TBUFSIZE];
        snprintf(buf, TBUFSIZE-1, "export delegated credentials: could not write to file (%s)",
                 strerror(errno));
        cgsi_err(soap, buf);
        return -1;
    }

    rc = close(fd);
    if (rc < 0) {
        char buf[TBUFSIZE];
        snprintf(buf, TBUFSIZE-1, "export delegated credentials: could not close file (%s)",
                 strerror(errno));
        cgsi_err(soap, buf);
        return -1;
    }

    return 0;
}


#define PROXY_ENV_VAR "X509_USER_PROXY"

int set_default_proxy_file(struct soap *soap, char *filename) {
    int rc;
    
    rc = setenv(PROXY_ENV_VAR, filename, 1);
    if (rc < 0) {
        char buf[TBUFSIZE];
        snprintf(buf, TBUFSIZE-1, "set default proxy file: could not setenv (%s)",
                 strerror(errno));
        cgsi_err(soap, buf);
        return -1;
    }
    return 0;
}


void clear_default_proxy_file(int unlink_file) {
    char *proxy_file;

    /* Removing the credentials file if flagged so */
    if (unlink_file) {
        proxy_file = getenv(PROXY_ENV_VAR);
        if (proxy_file != NULL) {
            unlink(proxy_file);
        }
    }

    /* Clearing the environment variable */
    unsetenv(PROXY_ENV_VAR);
}


int has_delegated_credentials(struct soap *soap) {
    struct cgsi_plugin_data *data;
    
    if (soap == NULL) {
        return -1;
    }
    
    data = (struct cgsi_plugin_data*)soap_lookup_plugin(soap,
                                                        server_plugin_id);

    if (data == NULL) {
        cgsi_err(soap, "export delegated credentials: could not get data structure");
        return -1;
    }

    if (data->deleg_cred_set != 0) {
         return 1;
    }
    
    return 0;
}


int soap_cgsi_init(struct soap *soap, int cgsi_options) {
    int params, rc;

    params = cgsi_options;
    if( cgsi_options & CGSI_OPT_KEEP_ALIVE )
        soap_init2( soap, SOAP_IO_KEEPALIVE, SOAP_IO_KEEPALIVE );
    else
	soap_init(soap);
    rc = soap_register_plugin_arg(soap, cgsi_plugin, &params);
    if (rc < 0) return -1;

    return 0;
}


/**
 * Activate or deactivate required globus modules
 */
static void cgsi_plugin_globus_modules(int activate) {

    if (activate) {
        (void) globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);
        (void) globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);
    } else {
        (void) globus_module_deactivate(GLOBUS_GSI_GSSAPI_MODULE);
        (void) globus_module_deactivate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    }
}


 
/*****************************************************************
 *                                                               *
 *               VOMS FUNCTIONS                                  *
 *                                                               *
 *****************************************************************/

static int cgsi_plugin_get_voms_creds_from_ctx(struct soap *soap,
					       gss_ctx_id_t context_handle){

  int ret = 0;
#if defined(USE_VOMS)

  int error= 0;
  X509 *px509_cred= NULL;
  STACK_OF(X509) *px509_chain = NULL;
  struct vomsdata *vd= NULL;
  struct voms **volist = NULL;
  /*  struct voms vo; */
  gss_ctx_id_desc * context;
  gss_cred_id_t cred;  
  /* Internally a gss_cred_id_t type is a pointer to a gss_cred_id_desc */
  gss_cred_id_desc *       cred_desc = NULL;
  globus_gsi_cred_handle_t gsi_cred_handle;
  struct cgsi_plugin_data *data;  
  
  ret = -1;

  if (soap == NULL) {
    return -1;
  }
    
  data = (struct cgsi_plugin_data*)soap_lookup_plugin(soap,
						      server_plugin_id);

  /* Downcasting the context structure  */
  context = (gss_ctx_id_desc *) context_handle;
  cred = context->peer_cred_handle;

  /* cast to gss_cred_id_desc */
  if (cred == GSS_C_NO_CREDENTIAL) {
    goto leave;
  }

  cred_desc = (gss_cred_id_desc *) cred;
  
  if (globus_module_activate(GLOBUS_GSI_CREDENTIAL_MODULE) != GLOBUS_SUCCESS) {
    goto leave;
  }
  
  /* Getting the X509 certicate */
  gsi_cred_handle = cred_desc->cred_handle;
  if (globus_gsi_cred_get_cert(gsi_cred_handle, &px509_cred) != GLOBUS_SUCCESS) {
    globus_module_deactivate(GLOBUS_GSI_CREDENTIAL_MODULE);
    goto leave;
  }
  
  /* Getting the certificate chain */
  if (globus_gsi_cred_get_cert_chain (gsi_cred_handle, &px509_chain) != GLOBUS_SUCCESS) {
    X509_free (px509_cred);
    (void)globus_module_deactivate (GLOBUS_GSI_CREDENTIAL_MODULE);
    goto leave;
  }
  
  /* No need for the globus module anymore, the rest are calls to VOMS */
  (void)globus_module_deactivate (GLOBUS_GSI_CREDENTIAL_MODULE);
  
  if ((vd = VOMS_Init (NULL, NULL)) == NULL) {
    goto leave;
  }
  
  if (VOMS_Retrieve (px509_cred, px509_chain, RECURSE_CHAIN, vd, &error) == 0) {
    char buffer[BUFSIZE];
    VOMS_ErrorMessage(vd, error, buffer, BUFSIZE);
    cgsi_err(soap, buffer);
    goto leave;
  }
  
  volist = vd->data;
  
  if (volist !=NULL) {
    int i = 0;
    int nbfqan;
    
    /* Copying the voname */
    if ((*volist)->voname != NULL) {
      data->voname = strdup((*volist)->voname);
    }
    
    
    /* Counting the fqans before allocating the array */
    while( volist[0]->fqan[i] != NULL) {
      i++;
    }
    nbfqan = i;
    
    if (nbfqan > 0) {
      data->fqan = malloc(sizeof(char *) * (i+1));
      if (data->fqan != NULL) {
	for (i=0; i<nbfqan; i++) {
	  data->fqan[i] = strdup( volist[0]->fqan[i]);   
	}
	data->fqan[nbfqan] = NULL;
	data->nbfqan = nbfqan;
      }
    } /* if (nbfqan > 0) */
  }
  
  ret = 0;

 leave:  
  if (vd) VOMS_Destroy (vd);  
  if (px509_cred) X509_free (px509_cred);
  if (px509_chain) sk_X509_pop_free(px509_chain,X509_free);
#endif  

  return ret;
}

/* Returns the VO name, if it could be retrieved via VOMS */
char *get_client_voname(struct soap *soap) {
  struct cgsi_plugin_data *data;  

  if (soap == NULL) return NULL;
  data = (struct cgsi_plugin_data*)soap_lookup_plugin(soap,
						      server_plugin_id);
  if (data == NULL) return NULL;
  return data->voname;
}

char **get_client_roles(struct soap *soap, int *nbfqan) {
  struct cgsi_plugin_data *data;  
  if (nbfqan != NULL) *nbfqan = 0;
  if (soap == NULL) return NULL;
  data = (struct cgsi_plugin_data*)soap_lookup_plugin(soap,
						      server_plugin_id);
  if (data == NULL) return NULL;
  if (nbfqan != NULL) {
    *nbfqan = data->nbfqan;
  }
  return data->fqan;
}
