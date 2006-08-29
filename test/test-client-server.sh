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
    to_serve=$1
    export X509_USER_CERT=$TEST_CERT_DIR/grid-security/hostcert.pem
    export X509_USER_KEY=$TEST_CERT_DIR/grid-security/hostkey.pem
    unset X509_USER_PROXY

    if [ 'yes' = "$TEST_VERBOSE" ]; then
        echo "  export X509_USER_CERT=$X509_USER_CERT"
        echo "  export X509_USER_KEY=$X509_USER_KEY"
        #export CGSI_TRACE='yes'
    fi
    cgsi-gsoap-server $to_serve >$tempbase.server.log 2>&1 &
    echo $! >$tempbase.server.pid
}

function server_stop {
    kill $(cat $tempbase.server.pid) 2>/dev/null
    echo "Server output:"
    echo "=============="
    cat $tempbase.server.log
    rm $tempbase.server.pid $tempbase.server.log
}

server_start 5

unset X509_USER_CERT
unset X509_USER_KEY

export X509_USER_PROXY=$TEST_CERT_DIR/home/voms-acme.pem
test_success /org.acme cgsi-gsoap-client

export X509_USER_PROXY=$TEST_CERT_DIR/home/voms-acme-Radmin.pem
test_success /org.acme/Role=Admin cgsi-gsoap-client

export X509_USER_PROXY=$TEST_CERT_DIR/home/voms-acme-Gproduction.pem
test_success /org.acme/production cgsi-gsoap-client

export X509_USER_PROXY=$TEST_CERT_DIR/home/vomswv-acme.pem
test_failure "SOAP FAULT" cgsi-gsoap-client

export X509_USER_PROXY=$TEST_CERT_DIR/home/voms-acme.pem
test_success /org.acme cgsi-gsoap-client

server_stop

test_summary

