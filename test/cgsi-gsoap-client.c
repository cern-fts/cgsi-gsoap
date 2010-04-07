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

struct soap *test_setup(const char *endpoint, int delegate, int namecheck, int allow_only_self) {
    struct soap *psoap;
    int ret,flags;

    psoap = soap_new();

    /* Register the CGSI plugin if secure communication is requested */
    if (endpoint && !strncmp(endpoint, HTTPS_PREFIX, strlen(HTTPS_PREFIX))) {
        flags = CGSI_OPT_SSL_COMPATIBLE;
    } else if (endpoint && !strncmp(endpoint, HTTPG_PREFIX, strlen(HTTPG_PREFIX))) {
        flags = 0;
    } else {
        printf("ERROR: Not secure endpoint '%s'\n", endpoint);
        exit(EXIT_FAILURE);
    }

    if (allow_only_self) flags |= CGSI_OPT_ALLOW_ONLY_SELF;
    if (!namecheck) flags |= CGSI_OPT_DISABLE_NAME_CHECK;
    if (delegate) flags |= CGSI_OPT_DELEG_FLAG;

    ret = soap_cgsi_init(psoap, flags);

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
    char *endpoint = "https://localhost:8111/cgsi-gsoap-test";
    int i, delegate=0, namecheck=0, allow_only_self=0;

    for(i=0;i<argc;i++) {
      if (!strcmp(argv[i],"-d")) delegate++;
      else if (!strcmp(argv[i],"-n")) namecheck++;
      else if (!strcmp(argv[i],"-l")) allow_only_self++;
      else endpoint = argv[i];
    }

    printf("CGSI-gSOAP test client using endpoint='%s'\n", endpoint);

    if (delegate) {
      printf("INFO: Going to try to delegate credentials to server\n");
    }

    if (allow_only_self) {
      printf("INFO: will require that the server has the same identity as the client\n");
    } else if (!namecheck) {
      printf("INFO: will do reverse name check of the server's IP and match it aginst the DN\n");
    } else {
      printf("INFO: will match the hostname specified in the endpoint against the server's DN\n");
    }

    psoap = test_setup(endpoint,delegate,namecheck,allow_only_self);

    attributes = getAttributes(psoap, endpoint);
    if (attributes) {
      printf("Server responded: %s\n", attributes);
      free(attributes);
      attributes = NULL;
    }

    test_destroy(psoap);

    return EXIT_SUCCESS;
}
