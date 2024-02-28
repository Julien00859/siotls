#!/bin/bash

if test ! -f genkeys.sh
then
    echo Refusing to generate keys outside of the toolbox
    exit 1
fi
mkdir -p keys
rm keys/*
cd keys

# reset auto generated files
touch index.txt
echo 1000 > serial
cat > openssl.conf <<EOF
# OpenSSL configuration file.
# Largely inspired from https://jamielinux.com/docs/openssl-certificate-authority/appendix/root-configuration-file.html

[ ca ]
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = $(pwd)
certs             = $(pwd)
new_certs_dir     = $(pwd)
database          = $(pwd)/index.txt
serial            = $(pwd)/serial
RANDFILE          = $(pwd)/.rand

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 1
preserve          = no
default_md        = sha256
policy            = policy0

[ policy0 ]
countryName             = match
localityName            = match
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = ca_cert

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
localityName                    = Locality Name
commonName                      = Common Name
emailAddress                    = Email Address

[ ca_cert ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ any_cert ]
basicConstraints = CA:FALSE
nsCertType = server, client, email
nsComment = "OpenSSL Generated Any Purpose Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment


[ client_cert ]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection


[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost
EOF

# create CA keys
openssl genpkey -out ca-ec.key.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-256
openssl genpkey -out ca-ed25519.key.pem -algorithm ED25519
openssl genpkey -out ca-ed448.key.pem -algorithm ED448
openssl genpkey -out ca-rsa.key.pem -algorithm RSA
openssl genpkey -out ca-rsa-pss.key.pem -algorithm RSA-PSS
openssl genpkey -out ca-rsa-pss-digest.key.pem -algorithm RSA-PSS -pkeyopt rsa_pss_keygen_md:sha256
openssl genpkey -out ca-x25519.key.pem -algorithm X25519
openssl genpkey -out ca-x448.key.pem -algorithm X448

# create user keys
openssl genpkey -out user-ec.key.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-256
openssl genpkey -out user-ed25519.key.pem -algorithm ED25519
openssl genpkey -out user-ed448.key.pem -algorithm ED448
openssl genpkey -out user-rsa.key.pem -algorithm RSA
openssl genpkey -out user-rsa-pss.key.pem -algorithm RSA-PSS
openssl genpkey -out user-rsa-pss-digest.key.pem -algorithm RSA-PSS -pkeyopt rsa_pss_keygen_md:sha256
openssl genpkey -out user-x25519.key.pem -algorithm X25519
openssl genpkey -out user-x448.key.pem -algorithm X448


set -x
for key in ca*.key.pem
do
    # generate self-signed cert for this CA key
    caname=${key%.*.*}
    openssl req -config openssl.conf -x509 -days 1 \
                -extensions ca_cert -key $key -out $caname.cert.pem \
                -subj "/C=BE/L=Houtesiplou/CN=Houtesiplou $caname" #&& \
    #openssl x509 -noout -text -in $caname.cert.pem > $caname.txt

    # sign all user keys using this CA key/cert
    for key in user*.key.pem
    do
        username=$caname-${key%.*.*}
        openssl req -config openssl.conf -new \
                -key $key -out $username.csr.pem \
                -subj "/C=BE/L=Houtesiplou/CN=Houtesiplou $username" && \
        openssl ca -config openssl.conf -md sha256 -batch -days 1 -notext \
                   -extensions any_cert -keyfile $caname.key.pem -cert $caname.cert.pem \
                   -in $username.csr.pem -out $username.cert.pem #&& \
        #openssl x509 -noout -text -in $username.cert.pem > $username.txt
    done
done
set +x

# remove useless files
rm 1*.pem *.csr.pem ca*.key.pem index* serial*

# restore debug and list keys
set +x
echo -e "\nDone! Here are your files:"
find $(pwd) -name '*.*.pem' | sort
