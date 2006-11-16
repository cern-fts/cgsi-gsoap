#!/bin/bash
#
# Copyright (c) Members of the EGEE Collaboration. 2004.
# See http://public.eu-egee.org/partners/ for details on 
# the copyright holders.
# For license conditions see the license file or
# http://eu-egee.org/license.html
#
# Authors: 
#      Akos Frohner <Akos.Frohner@cern.ch>
#

TEST_MODULE='CGSI-gSOAP'
TEST_REQUIRES='cgsi-gsoap-client cgsi-gsoap-server'
export PATH=$PATH:.

if [ -f 'shunit' ]; then source shunit; fi
if [ -f '../../test/shunit' ]; then source ../../test/shunit; fi

function server_start {
    export X509_USER_CERT=$TEST_CERT_DIR/grid-security/hostcert.pem
    export X509_USER_KEY=$TEST_CERT_DIR/grid-security/hostkey.pem
    unset X509_USER_PROXY

    if [ 'yes' = "$TEST_VERBOSE" ]; then
        echo "  export X509_USER_CERT=$X509_USER_CERT"
        echo "  export X509_USER_KEY=$X509_USER_KEY"
        #export CGSI_TRACE='yes'
    fi
    cgsi-gsoap-server $@ >$tempbase.server.log 2>&1 &
    echo $! >$tempbase.server.pid
}

function server_stop {
    kill $(cat $tempbase.server.pid) 2>/dev/null
    echo "Server output:"
    echo "=============="
    cat $tempbase.server.log
    rm $tempbase.server.pid $tempbase.server.log
}

function test_old_behaviour {
    echo "------------------------------------------------------------"
    echo " testing the old behaviour with connection time VOMS parsing"
    echo "------------------------------------------------------------"

    PORT=8110
    ENDPOINT="https://localhost:$PORT/cgsi-gsoap-test"

    server_start -r 5 -s -p $PORT

    unset X509_USER_CERT
    unset X509_USER_KEY

    export X509_USER_PROXY=$TEST_CERT_DIR/home/voms-acme.pem
    test_success /org.acme cgsi-gsoap-client $ENDPOINT

    export X509_USER_PROXY=$TEST_CERT_DIR/home/voms-acme-Radmin.pem
    test_success /org.acme/Role=Admin cgsi-gsoap-client $ENDPOINT

    export X509_USER_PROXY=$TEST_CERT_DIR/home/voms-acme-Gproduction.pem
    test_success /org.acme/production cgsi-gsoap-client $ENDPOINT

    export X509_USER_PROXY=$TEST_CERT_DIR/home/vomswv-acme.pem
    test_failure "CGSI-gSOAP: Error reading token data: Transport endpoint is not connected" cgsi-gsoap-client $ENDPOINT

    export X509_USER_PROXY=$TEST_CERT_DIR/home/voms-acme.pem
    test_success /org.acme cgsi-gsoap-client $ENDPOINT

    server_stop
}

function test_new_behaviour {
    echo "-----------------------------------------------------"
    echo " testing the new behaviour with explicit VOMS parsing"
    echo "-----------------------------------------------------"

    PORT=8111
    ENDPOINT="https://localhost:$PORT/cgsi-gsoap-test"

    server_start -r 5 -s -p $PORT -o

    unset X509_USER_CERT
    unset X509_USER_KEY

    export X509_USER_PROXY=$TEST_CERT_DIR/home/voms-acme.pem
    test_success /org.acme cgsi-gsoap-client $ENDPOINT

    export X509_USER_PROXY=$TEST_CERT_DIR/home/voms-acme-Radmin.pem
    test_success /org.acme/Role=Admin cgsi-gsoap-client $ENDPOINT

    export X509_USER_PROXY=$TEST_CERT_DIR/home/voms-acme-Gproduction.pem
    test_success /org.acme/production cgsi-gsoap-client $ENDPOINT

    export X509_USER_PROXY=$TEST_CERT_DIR/home/vomswv-acme.pem
    test_failure "CGSI-gSOAP: Cannot find certificate of AC issuer for vo org.acme" cgsi-gsoap-client $ENDPOINT

    export X509_USER_PROXY=$TEST_CERT_DIR/home/voms-acme.pem
    test_success /org.acme cgsi-gsoap-client $ENDPOINT

    server_stop
}

function test_stress {
    echo "---------------------------------------"
    echo " stress test with explicit VOMS parsing"
    echo "---------------------------------------"

    PORT=8112
    ENDPOINT="https://localhost:$PORT/cgsi-gsoap-test"
    ITERATIONS=1000

    server_start -r $ITERATIONS -s -p $PORT -o

    unset X509_USER_CERT
    unset X509_USER_KEY

    export X509_USER_PROXY=$TEST_CERT_DIR/home/voms-acme.pem

    i=0
    while [ $i -lt $ITERATIONS ]; do
        echo "$i/$ITERATIONS"
        test_success /org.acme cgsi-gsoap-client $ENDPOINT
        i=$(( $i + 1 ))
    done

    server_stop
}

test_old_behaviour
test_new_behaviour
test_stress

test_summary

