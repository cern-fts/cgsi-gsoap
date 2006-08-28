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
 * Simple test client for CGSI-gSOAP.
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

    response->getAttributesReturn = soap_strdup(psoap, "works!");

    return SOAP_OK;
}

int main(int argc, char **argv) {
    int i, ret;
    int s; // slave socket
    struct soap *psoap;
    char *attributes = NULL;
    char endpoint[] = "https://localhost:8111/cgsi-gsoap-test";

    printf("CGSI-gSOAP test server\n");

    psoap = soap_new();

    /* Register the CGSI plugin if secure communication is requested */
    if (endpoint && !strncmp(endpoint, HTTPS_PREFIX, strlen(HTTPS_PREFIX)))
        ret = soap_cgsi_init(psoap, CGSI_OPT_SERVER | CGSI_OPT_SSL_COMPATIBLE);
    else if (endpoint && !strncmp(endpoint, HTTPG_PREFIX, strlen(HTTPG_PREFIX)))
        ret = soap_cgsi_init(psoap, CGSI_OPT_SERVER | CGSI_OPT_DELEG_FLAG);
    else {
        printf("ERROR: Not secure endpoint '%s'\n", endpoint);
        exit(EXIT_FAILURE);
    }

    if (ret) {
        printf("ERROR: Failed to initialize the SOAP layer\n");
        exit(EXIT_FAILURE);
    }

    if (soap_set_namespaces(psoap, namespaces)) {
        printf("ERROR: Failed to set namespaces\n");
        soap_print_fault(psoap, stderr);
        exit(EXIT_FAILURE);
    }

    if( soap_bind(psoap, NULL, 8111, 100) < 0 ) {
        printf("ERROR in bind.\n");
        soap_print_fault(psoap, stderr);
        soap_destroy(psoap);
        exit(EXIT_FAILURE);
    }

    /* main loop */

    for (i = 0; i < 1; i++) {
        s = soap_accept(psoap);
        if (s < 0) {
            soap_print_fault(psoap, stderr);
            break;
        }
        fprintf(stderr, "%d: accepted connection from IP=%d.%d.%d.%d socket=%d\n", i,
            (psoap->ip >> 24)&0xFF, 
            (psoap->ip >> 16)&0xFF, 
            (psoap->ip >> 8)&0xFF, 
            psoap->ip&0xFF, s);
         if (soap_serve(psoap) != SOAP_OK) // process RPC request
            soap_print_fault(psoap, stderr); // print error
         fprintf(stderr, "request served\n");
         soap_destroy(psoap); // clean up class instances
         soap_end(psoap); // clean up everything and close socket
    }

    soap_done(psoap);

    return EXIT_SUCCESS;
}

