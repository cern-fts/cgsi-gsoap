/*
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://public.eu-egee.org/partners/ for details on 
 * the copyright holders.
 * For license conditions see the license file or
 * http://eu-egee.org/license.html
 *
 * Authors: 
 *      Akos Frohner <Akos.Frohner@cern.ch>
 *
 * Simple test server for CGSI-gSOAP.
 */

#include <stdio.h>
#include <unistd.h>
#include "cgsi_plugin.h"
#include "cgsi_gsoap_testH.h"
#include "cgsi_gsoap_test.nsmap"

const static char HTTP_PREFIX[]  = "http:";
const static char HTTPS_PREFIX[] = "https:";
const static char HTTPG_PREFIX[] = "httpg:";

int cgsi_USCOREgsoap_USCOREtest__getAttributes(struct soap *psoap, 
    struct cgsi_USCOREgsoap_USCOREtest__getAttributesResponse *response) {
    char **roles;
    char *attributes;
    int nbfqans, i;
    int length = 1000;
    
    if (retrieve_voms_credentials(psoap)) {
        return SOAP_SVR_FAULT;
    }
    
    roles = get_client_roles(psoap, &nbfqans);
    
    if (roles != NULL) {
        length += nbfqans;
        for (i = 0; i < nbfqans; i++) {
            length += strlen(roles[i]);
        }
    }

    attributes = malloc(length);
    get_client_dn(psoap, attributes, length);
    
    if (roles != NULL) {
        strncat(attributes, "\nFQANs:\n", length);
        for (i = 0; i < nbfqans; i++) {
            strncat(attributes, roles[i], length);
            strncat(attributes, "\n", length);
        }
    }

    fprintf(stdout, "INFO: Client with the following attributes:\n%s\n", attributes);
    fflush(stdout);

    response->getAttributesReturn = soap_strdup(psoap, attributes);

    free(attributes);

    return SOAP_OK;
}

int main(int argc, char **argv) {
    int i, ret;
    int s; // slave socket
    struct soap *psoap;
    char endpoint[] = "https://localhost:8111/cgsi-gsoap-test";
    int to_serve = 1;

    if (argc > 1) {
        to_serve = atoi(argv[1]);
    }
    fprintf(stdout, "INFO: CGSI-gSOAP test server is going to serve %d requests.\n", to_serve);
    fflush(stdout);

    psoap = soap_new();

    /* Register the CGSI plugin if secure communication is requested */
    if (endpoint && !strncmp(endpoint, HTTPS_PREFIX, strlen(HTTPS_PREFIX)))
        ret = soap_cgsi_init(psoap, CGSI_OPT_SERVER | CGSI_OPT_DISABLE_MAPPING | CGSI_OPT_SSL_COMPATIBLE);
    else if (endpoint && !strncmp(endpoint, HTTPG_PREFIX, strlen(HTTPG_PREFIX)))
        ret = soap_cgsi_init(psoap, CGSI_OPT_SERVER | CGSI_OPT_DISABLE_MAPPING |CGSI_OPT_DELEG_FLAG);
    else {
        fprintf(stdout, "ERROR: Not secure endpoint '%s'\n", endpoint);
        exit(EXIT_FAILURE);
    }

    if (ret) {
        fprintf(stdout, "ERROR: Failed to initialize the SOAP layer\n");
        exit(EXIT_FAILURE);
    }

    if (soap_set_namespaces(psoap, namespaces)) {
        fprintf(stdout, "ERROR: Failed to set namespaces\n");
        soap_print_fault(psoap, stdout);
        exit(EXIT_FAILURE);
    }

    // making these short for tests
    psoap->max_keep_alive = 5;
    psoap->accept_timeout = 60;
    psoap->recv_timeout = 5;
    psoap->send_timeout = 5;

    if( soap_bind(psoap, NULL, 8111, 100) < 0 ) {
        fprintf(stdout, "ERROR: soap_bind has failed.\n");
        soap_print_fault(psoap, stdout);
        soap_destroy(psoap);
        exit(EXIT_FAILURE);
    }

    /* main loop */

    for (i = 0; i < to_serve; i++) {
        s = soap_accept(psoap);
        if (s < 0) {
            soap_print_fault(psoap, stdout);
            break;
        }
        fprintf(stdout, "\nINFO: ==================================================\n");
        fprintf(stdout, "INFO: %d: accepted connection from IP=%d.%d.%d.%d socket=%d\n", i,
            (int)((psoap->ip >> 24) & 0xFF), 
            (int)((psoap->ip >> 16) & 0xFF), 
            (int)((psoap->ip >> 8) & 0xFF), 
            (int)(psoap->ip & 0xFF), s);
         if (soap_serve(psoap) != SOAP_OK) // process RPC request
            soap_print_fault(psoap, stdout); // print error
         fprintf(stdout, "INFO: request served\n");
         fflush(stdout);
         soap_destroy(psoap); // clean up class instances
         soap_end(psoap); // clean up everything and close socket
    }

    soap_closesock(psoap);
    soap_done(psoap);
    fprintf(stdout, "server is properly shut down\n");

    return EXIT_SUCCESS;
}

