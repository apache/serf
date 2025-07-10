#!/usr/bin/env python

#
# ===================================================================
#   Licensed to the Apache Software Foundation (ASF) under one
#   or more contributor license agreements.  See the NOTICE file
#   distributed with this work for additional information
#   regarding copyright ownership.  The ASF licenses this file
#   to you under the Apache License, Version 2.0 (the
#   "License"); you may not use this file except in compliance
#   with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing,
#   software distributed under the License is distributed on an
#   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#   KIND, either express or implied.  See the License for the
#   specific language governing permissions and limitations
#   under the License.
# ===================================================================
#

# This script creates the private keys and certificates required for
# running the serf test suite.
#
# It should be run from the test/certs folder without arguments.
# Certificates will be created in the test/certs folder, private keys in the
# test/certs/private folder.
#
# You'll need to install 'cryptography' for this script to work.

from datetime import datetime, timedelta, UTC
from ipaddress import IPv4Address, IPv6Address

from cryptography.x509 import (
    AccessDescription,
    Certificate,
    CertificateBuilder,
    RevokedCertificateBuilder,
    CertificateRevocationListBuilder,
    CRLReason, ReasonFlags,
    Name, NameAttribute, NameOID,
    SubjectKeyIdentifier,
    AuthorityKeyIdentifier,
    AuthorityInformationAccess,
    DNSName, IPAddress,
    UniformResourceIdentifier)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    pkcs12)
from cryptography.x509.extensions import (
    BasicConstraints,
    ExtendedKeyUsage,
    SubjectAlternativeName)
from cryptography.x509.oid import (
    ExtendedKeyUsageOID,
    AuthorityInformationAccessOID)


# for serf, update this number every time the certs are updated.
SERIAL_NUMBER=20250711

KEY_ALGO = rsa
KEY_EXPONENT = 65537
KEY_SIZE = 2048
SIGN_ALGO = SHA256()
NOT_BEFORE = datetime(2025, 6, 18, 10, 39, 14, 0, UTC)
NOT_AFTER = datetime(2125, 5, 25, 10, 39, 14, 0, UTC)


def create_key(keyfile, passphrase=None):
    key = KEY_ALGO.generate_private_key(KEY_EXPONENT, KEY_SIZE)
    if type(passphrase) is type(b''):
        encryption = BestAvailableEncryption(passphrase)
    else:
        encryption = NoEncryption()

    with open(keyfile, 'wb') as fd:
        fd.write(key.private_bytes(encoding=Encoding.PEM,
                                   format=PrivateFormat.PKCS8,
                                   encryption_algorithm=encryption))
    return key


def create_pkcs12(name, key, cert, issuer, pkcs12file, passphrase=None):
    if type(passphrase) is type(b''):
        encryption = BestAvailableEncryption(passphrase)
    else:
        encryption = NoEncryption()

    with open(pkcs12file, 'wb') as fd:
        fd.write(pkcs12.serialize_key_and_certificates(
            name, key, cert, [issuer], encryption))


def create_crl(revokedcert, cakey, cacert, crlfile):
    revoked = (RevokedCertificateBuilder()
               .serial_number(revokedcert.serial_number)
               .revocation_date(datetime.now(UTC))
               .add_extension(CRLReason(ReasonFlags.unspecified), critical=False)
               .build())

    crl = (CertificateRevocationListBuilder()
           .issuer_name(cacert.subject)
           .last_update(NOT_BEFORE)
           .next_update(NOT_AFTER)
           .add_revoked_certificate(revoked)
           .sign(cakey, SIGN_ALGO))

    with open(crlfile, 'wb') as fd:
        fd.write(crl.public_bytes(Encoding.PEM))


# subjectAltName
def create_cert(subjectkey, certfile, issuer=None, issuerkey=None, country='',
                state='', city='', org='', ou='', cn='', email='', ca=False,
                not_before=NOT_BEFORE, not_after=NOT_AFTER,
                subjectAltName=None, ocsp_responder_url=None, ocsp_signer=False):
    '''
    Create a X509 signed certificate.

    subjectAltName
        Array of fully qualified subject alternative names (use OpenSSL syntax):
        For a DNS entry, use: ['DNS:localhost']. Other options are 'email', 'URI', 'IP'.
    '''

    subject = []
    if country:
        subject.append(NameAttribute(NameOID.COUNTRY_NAME, country))
    if state:
        subject.append(NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    if city:
        subject.append(NameAttribute(NameOID.LOCALITY_NAME, city))
    if org:
        subject.append(NameAttribute(NameOID.ORGANIZATION_NAME, org))
    if ou:
        subject.append(NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    if cn:
        subject.append(NameAttribute(NameOID.COMMON_NAME, cn))
    if email:
        subject.append(NameAttribute(NameOID.EMAIL_ADDRESS, email))

    pubkey = subjectkey.public_key()
    builder = (CertificateBuilder()
               .serial_number(SERIAL_NUMBER)
               .subject_name(Name(subject))
               .public_key(pubkey)
               .not_valid_before(not_before)
               .not_valid_after(not_after))
    if issuer is None:
        # self-signed certificate
        builder = builder.issuer_name(Name(subject))
        issuerkey = subjectkey
    else:
        builder = builder.issuer_name(issuer.subject)

    if ca:
        bc = BasicConstraints(ca=True, path_length=None)
        ski = SubjectKeyIdentifier.from_public_key(pubkey)
        aki = AuthorityKeyIdentifier.from_issuer_public_key(issuerkey.public_key())
        builder = (builder
                   .add_extension(bc, critical=False)
                   .add_extension(ski, critical=False)
                   .add_extension(aki, critical=False))

    if subjectAltName:
        alt = []
        for name in subjectAltName:
            if name.startswith('DNS:'):
                alt.append(DNSName(name[4:]))
            if name.startswith('IP4:'):
                alt.append(IPAddress(IPv4Address(name[4:])))
            if name.startswith('IP6:'):
                alt.append(IPAddress(IPv6Address(name[4:])))
        if alt:
            builder = builder.add_extension(SubjectAlternativeName(alt),
                                            critical=True if not cn else False)

    if ocsp_responder_url:
        ocsp = AccessDescription(AuthorityInformationAccessOID.OCSP,
                                 UniformResourceIdentifier(ocsp_responder_url))
        builder = builder.add_extension(
            AuthorityInformationAccess([ocsp]),
            critical=False)

    if ocsp_signer:
        builder = builder.add_extension(
            ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
            critical=True)

    cert = builder.sign(issuerkey, SIGN_ALGO)

    with open(certfile, 'wb') as fd:
        fd.write(cert.public_bytes(Encoding.PEM))
    return cert


if __name__ == '__main__':
    # root CA key pair and certificate.
    # This key will be used to sign the intermediate CA certificate
    rootcakey = create_key('private/serfrootcakey.pem', b'serftest')

    rootcacert = create_cert(subjectkey=rootcakey,
                             certfile='serfrootcacert.pem',
                             country='BE', state='Antwerp', city='Mechelen',
                             org='In Serf we trust, Inc.',
                             ou='Test Suite Root CA', cn='Serf Root CA',
                             email='serfrootca@example.com', ca=True)

    # intermediate CA key pair and certificate
    # This key will be used to sign all server certificates
    cakey = create_key('private/serfcakey.pem', b'serftest')

    cacert = create_cert(subjectkey=cakey, certfile='serfcacert.pem',
                         issuer=rootcacert, issuerkey=rootcakey,
                         country='BE', state='Antwerp', city='Mechelen',
                         org='In Serf we trust, Inc.',
                         ou='Test Suite CA', cn='Serf CA',
                         email='serfca@example.com', ca=True)

    # server key pair
    # server certificate, no errors
    serverkey = create_key('private/serfserverkey.pem', b'serftest')

    servercert = create_cert(subjectkey=serverkey,
                             certfile='serfservercert.pem',
                             issuer=cacert, issuerkey=cakey,
                             country='BE', state='Antwerp', city='Mechelen',
                             org='In Serf we trust, Inc.',
                             ou='Test Suite Server', cn='localhost',
                             email='serfserver@example.com')

    # server certificate that expired a year ago
    expiredcert = create_cert(subjectkey=serverkey,
                              certfile='serfserver_expired_cert.pem',
                              issuer=cacert, issuerkey=cakey,
                              country='BE', state='Antwerp', city='Mechelen',
                              org='In Serf we trust, Inc.',
                              ou='Test Suite Server', cn='localhost',
                              email='serfserver@example.com',
                              not_before=NOT_BEFORE - timedelta(days=365),
                              not_after=NOT_BEFORE - timedelta(days=355))

    # server certificate that will be valid in 100 years
    notyetvalidcert = create_cert(subjectkey=serverkey,
                                  certfile='serfserver_future_cert.pem',
                                  issuer=cacert, issuerkey=cakey,
                                  country='BE', state='Antwerp', city='Mechelen',
                                  org='In Serf we trust, Inc.',
                                  ou='Test Suite Server', cn='localhost',
                                  email='serfserver@example.com',
                                  not_before=NOT_AFTER,
                                  not_after=NOT_AFTER + timedelta(days=10))

    # server certificate with SubjectAltName and empty CN
    san_nocncert = create_cert(subjectkey=serverkey,
                               certfile='serfserver_san_nocn_cert.pem',
                               issuer=cacert, issuerkey=cakey,
                               country='BE', state='Antwerp', city='Mechelen',
                               org='In Serf we trust, Inc.',
                               ou='Test Suite Server',
                               cn='',
                               email='serfserver@example.com',
                               subjectAltName=['DNS:localhost'])

    # server certificate with OCSP responder URL
    ocspcert = create_cert(subjectkey=serverkey,
                           certfile='serfserver_san_ocsp_cert.pem',
                           issuer=cacert, issuerkey=cakey,
                           country='BE', state='Antwerp', city='Mechelen',
                           org='In Serf we trust, Inc.',
                           ou='Test Suite Server',
                           cn='localhost',
                           email='serfserver@example.com',
                           subjectAltName=['DNS:localhost'],
                           ocsp_responder_url='http://localhost:17080')

    # OCSP responder certifi
    ocsprspcert = create_cert(subjectkey=serverkey,
                              certfile='serfocspresponder.pem',
                              issuer=cacert, issuerkey=cakey,
                              country='BE', state='Antwerp', city='Mechelen',
                              org='In Serf we trust, Inc.',
                              ou='Test Suite Server',
                              cn='localhost',
                              email='serfserver@example.com',
                              ocsp_signer=True)

    # client key pair and certificate
    clientkey = create_key('private/serfclientkey.pem', b'serftest')

    clientcert = create_cert(subjectkey=clientkey,
                             certfile='serfclientcert.pem',
                             issuer=cacert, issuerkey=cakey,
                             country='BE', state='Antwerp', city='Mechelen',
                             org='In Serf we trust, Inc.',
                             ou='Test Suite Client', cn='Serf Client',
                             email='serfclient@example.com')

    clientpkcs12 = create_pkcs12(b'serfclient', clientkey, clientcert, cacert,
                                 'serfclientcert.p12', b'serftest')

    # crl
    crl = create_crl(servercert, cakey, cacert, 'serfservercrl.pem')
