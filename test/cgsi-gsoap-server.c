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

#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include "cgsi_plugin.h"
#include "cgsi_gsoap_testH.h"
#include "cgsi_gsoap_test.nsmap"

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

void parse_options(int argc, char **argv, int *flags, int *port, int *to_serve) {
    *flags = CGSI_OPT_SERVER | CGSI_OPT_DISABLE_MAPPING;
    *port = 8111;
    *to_serve = 1;
    int c;
     
    while ((c = getopt(argc, argv, "p:r:sgo")) != -1) switch (c) {
        case 'h':
            printf("Usage: %s -p PORT (-s|-g) -o\n", argv[0]);
            fflush(stdout);
            exit (EXIT_SUCCESS);
            break;
        case 'p':
            *port = atoi(optarg);
            fprintf(stdout, "INFO: port number = %d\n", *port);
            fflush(stdout);
            break;
        case 'r':
            *to_serve = atoi(optarg);
            fprintf(stdout, "INFO: requests to be served = %d\n", *to_serve);
            fflush(stdout);
            break;
        case 's':
            *flags |= CGSI_OPT_SSL_COMPATIBLE;
            fprintf(stdout, "INFO: SSL compatible mode\n");
            fflush(stdout);
            break;
        case 'g':
            *flags |= CGSI_OPT_DELEG_FLAG;
            fprintf(stdout, "INFO: enabled HTTPG delegation\n");
            fflush(stdout);
            break;
        case 'o':
            *flags |= CGSI_OPT_DISABLE_VOMS_CHECK;
            fprintf(stdout, "INFO: disabled VOMS parsing during authentication\n");
            fflush(stdout);
            break;
        case ':':
            fprintf(stderr, "ERROR: Option argument is missing\n");
            fflush(stderr);
            exit(EXIT_FAILURE);
        case '?':
            fprintf(stderr, "ERROR: Unknown command line option\n");
            fflush(stderr);
            exit(EXIT_FAILURE);
        default:
            fprintf(stderr, "ERROR: Illegal command line arguments:%s\n", optarg);
            fflush(stderr);
            exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv) {
    int s; // slave socket
    struct soap *psoap;
    int flags, i;
    int port = 8111;
    int to_serve = 1;

    parse_options(argc, argv, &flags, &port, &to_serve);
    fprintf(stdout, "INFO: CGSI-gSOAP test server is going to serve %d requests.\n", to_serve);
    fflush(stdout);

    psoap = soap_new();
    if (psoap == NULL) {
        fprintf(stdout, "ERROR: Failed to create a SOAP instance\n");
        exit(EXIT_FAILURE);
    }

    if (soap_cgsi_init(psoap, flags)) {
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

    if( soap_bind(psoap, NULL, port, 100) < 0 ) {
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

