from __future__ import division, print_function, unicode_literals

__copyright__ = '''\
Copyright (C) m-click.aero GmbH

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
'''

import OpenSSL.crypto
import cryptography.hazmat.backends
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.serialization.pkcs12
import cryptography.x509.oid
import datetime
import os
import requests.adapters
import ssl
import tempfile
import urllib3.contrib.pyopenssl

try:
    from ssl import PROTOCOL_TLS as default_ssl_protocol
except ImportError:
    from ssl import PROTOCOL_SSLv23 as default_ssl_protocol

def check_cert_not_after(cert):
    cert_not_after = cert.not_valid_after
    if cert_not_after < datetime.datetime.utcnow():
        raise ValueError('Client certificate expired: Not After: {cert_not_after:%Y-%m-%d %H:%M:%SZ}'.format(**locals()))

def create_pyopenssl_sslcontext(pkcs12_data, pkcs12_password_bytes, ssl_protocol=default_ssl_protocol):
    private_key, cert, ca_certs = cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates(
        pkcs12_data,
        pkcs12_password_bytes
    )
    check_cert_not_after(cert)
    ssl_context = urllib3.contrib.pyopenssl.PyOpenSSLContext(ssl_protocol)
    ssl_context._ctx.use_certificate(OpenSSL.crypto.X509.from_cryptography(cert))
    if ca_certs:
        for ca_cert in ca_certs:
            check_cert_not_after(ca_cert)
            ssl_context._ctx.add_extra_chain_cert(OpenSSL.crypto.X509.from_cryptography(ca_cert))
    ssl_context._ctx.use_privatekey(OpenSSL.crypto.PKey.from_cryptography_key(private_key))
    return ssl_context

def create_ssl_sslcontext(pkcs12_data, pkcs12_password_bytes, ssl_protocol=default_ssl_protocol):
    private_key, cert, ca_certs = cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates(
        pkcs12_data,
        pkcs12_password_bytes
    )
    check_cert_not_after(cert)
    ssl_context = ssl.SSLContext(ssl_protocol)
    with tempfile.NamedTemporaryFile(delete=False) as c:
        try:
            pk_buf = private_key.private_bytes(
                cryptography.hazmat.primitives.serialization.Encoding.PEM,
                cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL,
                cryptography.hazmat.primitives.serialization.KeySerializationEncryption
            )
            c.write(pk_buf)
            buf = cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM)
            c.write(buf)
            if ca_certs:
                for ca_cert in ca_certs:
                    check_cert_not_after(ca_cert)
                    buf = ca_cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM)
                    c.write(buf)
            c.flush()
            c.close()
            ssl_context.load_cert_chain(c.name, password=pkcs12_password_bytes)
        finally:
            os.remove(c.name)
    return ssl_context

class Pkcs12Adapter(requests.adapters.HTTPAdapter):

    def __init__(self, *args, **kwargs):
        pkcs12_data = kwargs.pop('pkcs12_data', None)
        pkcs12_filename = kwargs.pop('pkcs12_filename', None)
        pkcs12_password = kwargs.pop('pkcs12_password', None)
        ssl_protocol = kwargs.pop('ssl_protocol', default_ssl_protocol)
        if pkcs12_data is None and pkcs12_filename is None:
            raise ValueError('Both arguments "pkcs12_data" and "pkcs12_filename" are missing')
        if pkcs12_data is not None and pkcs12_filename is not None:
            raise ValueError('Argument "pkcs12_data" conflicts with "pkcs12_filename"')
        if pkcs12_password is None:
            raise ValueError('Argument "pkcs12_password" is missing')
        if pkcs12_filename is not None:
            with open(pkcs12_filename, 'rb') as pkcs12_file:
                pkcs12_data = pkcs12_file.read()
        if isinstance(pkcs12_password, bytes):
            pkcs12_password_bytes = pkcs12_password
        else:
            pkcs12_password_bytes = pkcs12_password.encode('utf8')
        self.ssl_context = create_pyopenssl_sslcontext(pkcs12_data, pkcs12_password_bytes, ssl_protocol)
        super(Pkcs12Adapter, self).__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        if self.ssl_context:
            kwargs['ssl_context'] = self.ssl_context
        return super(Pkcs12Adapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        if self.ssl_context:
            kwargs['ssl_context'] = self.ssl_context
        return super(Pkcs12Adapter, self).proxy_manager_for(*args, **kwargs)

def request(*args, **kwargs):
    pkcs12_data = kwargs.pop('pkcs12_data', None)
    pkcs12_filename = kwargs.pop('pkcs12_filename', None)
    pkcs12_password = kwargs.pop('pkcs12_password', None)
    ssl_protocol = kwargs.pop('ssl_protocol', default_ssl_protocol)
    if pkcs12_data is None and pkcs12_filename is None and pkcs12_password is None:
        return requests.request(*args, **kwargs)
    if 'cert' in  kwargs:
        raise ValueError('Argument "cert" conflicts with "pkcs12_*" arguments')
    with requests.Session() as session:
        pkcs12_adapter = Pkcs12Adapter(
            pkcs12_data=pkcs12_data,
            pkcs12_filename=pkcs12_filename,
            pkcs12_password=pkcs12_password,
            ssl_protocol=ssl_protocol,
        )
        session.mount('https://', pkcs12_adapter)
        return session.request(*args, **kwargs)

def delete(*args, **kwargs):
    return request('delete', *args, **kwargs)

def get(*args, **kwargs):
    kwargs.setdefault('allow_redirects', True)
    return request('get', *args, **kwargs)

def head(*args, **kwargs):
    kwargs.setdefault('allow_redirects', False)
    return request('head', *args, **kwargs)

def options(*args, **kwargs):
    kwargs.setdefault('allow_redirects', True)
    return request('options', *args, **kwargs)

def patch(*args, **kwargs):
    return request('patch', *args, **kwargs)

def post(*args, **kwargs):
    return request('post', *args, **kwargs)

def put(*args, **kwargs):
    return request('put', *args, **kwargs)

def selftest():
    key = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(public_exponent=65537, key_size=4096)
    cert = cryptography.x509.CertificateBuilder().subject_name(
        cryptography.x509.Name([
            cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COMMON_NAME, 'test'),
        ])
    ).issuer_name(
        cryptography.x509.Name([
            cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COMMON_NAME, 'test'),
        ])
    ).public_key(
        key.public_key()
    ).serial_number(
        cryptography.x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=1)
    ).sign(
        key,
        cryptography.hazmat.primitives.hashes.SHA512(),
        cryptography.hazmat.backends.default_backend()
    )
    pkcs12_data = cryptography.hazmat.primitives.serialization.pkcs12.serialize_key_and_certificates(
        name=b'test',
        key=key,
        cert=cert,
        cas=[cert, cert, cert],
        encryption_algorithm=cryptography.hazmat.primitives.serialization.BestAvailableEncryption(b'correcthorsebatterystaple')
    )
    response = get(
        'https://example.com/',
        pkcs12_data=pkcs12_data,
        pkcs12_password='correcthorsebatterystaple'
    )
    if response.status_code != 200:
        raise Exception('Unexpected response: {response!r}'.format(**locals()))
    print('Selftest succeeded.')

if __name__ == '__main__':
    selftest()
