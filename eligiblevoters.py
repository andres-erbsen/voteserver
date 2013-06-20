#!/usr/bin/env python2
# Based on python-esteid by Martin Paljak, MIT license
# Modified by Andres Erbsen, distributed under MIT license

from hashlib import sha256
import ldap
from sys import stdin
import os.path
import OpenSSL.crypto, datetime

MID = "ESTEID (MOBIIL-ID)"
DIGI = "ESTEID (DIGI-ID)"
IDCARD = "ESTEID"

AUTH = "Authentication"
SIGN = "Digital Signature"

LDAP_SERVER = "ldap://ldap.sk.ee"

class LdapError(Exception):
    pass

def todatetime(time):
    ret = None
    try:
        ret = datetime.datetime.strptime(time, "%Y%m%d%H%M%SZ")
    except ValueError:
        ret = datetime.datetime.strptime(time, "%Y%m%d%H%M%S%z")
    return ret


def get_esteid_cert(idcode, cert_type, chip_type):
    """
    Fetches the certificate of the idcode owner from SK LDAP.
    """
    assert idcode.isdigit() and len(idcode) == 11

    server = ldap.initialize(LDAP_SERVER)
    q = server.search('ou=%s,o=%s,c=EE' % (cert_type, chip_type),
            ldap.SCOPE_SUBTREE,
            'serialNumber=%s' % idcode,
            ['userCertificate;binary'])
    result = server.result(q, timeout=10)
    if result[0] != ldap.RES_SEARCH_RESULT:
        raise LdapError("Unexpected result type.")
    if not result[1]:
        raise LdapError("No results from LDAP query.")
    valid_cert = None
    for response in result[1]:
        if len(response) != 2 or not isinstance(response[1], dict) \
                or not response[1].has_key('userCertificate;binary') \
                or not response[1]['userCertificate;binary'] \
                or not isinstance(response[1]['userCertificate;binary'], list):
            raise LdapError("Unexpected result format.")
        for cert_string in response[1]['userCertificate;binary']:
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_string)
            if todatetime(cert.get_notBefore()) <= datetime.datetime.now() \
                    and todatetime(cert.get_notAfter()) >= datetime.datetime.now():
                if valid_cert != None:
                    raise LdapError("Too many certificates")
                valid_cert = cert_string
    if valid_cert == None:
        raise LdapError("No valid certificates")
    return valid_cert


if __name__ == '__main__':
	os.makedirs('voters')
	for idcode in stdin.read().split():
		cert = get_esteid_cert(idcode, AUTH, IDCARD)
		open(os.path.join('voters', idcode+'.cer'),'w+').write(cert)
		
