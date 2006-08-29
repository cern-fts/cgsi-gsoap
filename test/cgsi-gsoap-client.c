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

struct soap *test_setup(const char *endpoint) {
    struct soap *psoap;
    int ret;

    psoap = soap_new();

    /* Register the CGSI plugin if secure communication is requested */
    if (endpoint && !strncmp(endpoint, HTTPS_PREFIX, strlen(HTTPS_PREFIX)))
        ret = soap_cgsi_init(psoap, CGSI_OPT_DISABLE_NAME_CHECK | CGSI_OPT_SSL_COMPATIBLE);
    else if (endpoint && !strncmp(endpoint, HTTPG_PREFIX, strlen(HTTPG_PREFIX)))
        ret = soap_cgsi_init(psoap, CGSI_OPT_DISABLE_NAME_CHECK);
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
        exit(EXIT_FAILURE);
    }

    // making these short for tests
    psoap->recv_timeout = 5;
    psoap->send_timeout = 5;

    return psoap;
}

char *getAttributes(struct soap *psoap, const char *endpoint) {
    int ret;
    struct cgsi_USCOREgsoap_USCOREtest__getAttributesResponse get_resp;

    ret = soap_call_cgsi_USCOREgsoap_USCOREtest__getAttributes(psoap, 
        endpoint, NULL, &get_resp);

    if ( SOAP_OK != ret ) {
        printf("ERROR: gSOAP error\n");
        soap_print_fault(psoap, stderr);
        exit(EXIT_FAILURE);
    }

    return strdup(get_resp.getAttributesReturn);
}

void test_destroy(struct soap *psoap) {
    soap_destroy(psoap);
    soap_end(psoap);
    soap_done(psoap);
    free(psoap);
}

int main(int argc, char **argv) {
    struct soap *psoap;
    char *attributes = NULL;
    char endpoint[] = "https://localhost:8111/cgsi-gsoap-test";

    printf("CGSI-gSOAP test client\n");

    psoap = test_setup(endpoint);

    attributes = getAttributes(psoap, endpoint);
    if (attributes) {
        printf("Server responded: %s\n", attributes);
        free(attributes);
        attributes = NULL;
    }

    test_destroy(psoap);

    return EXIT_SUCCESS;
}

