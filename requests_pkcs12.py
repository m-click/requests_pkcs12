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

import cryptography.hazmat.backends
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.serialization.pkcs12
import cryptography.x509.oid
import datetime
import os
import requests.adapters
import secrets
import ssl
import tempfile

try:
    from ssl import PROTOCOL_TLS_CLIENT as default_ssl_protocol
except ImportError:
    from ssl import PROTOCOL_SSLv23 as default_ssl_protocol

def _check_cert_not_after(cert):
    cert_not_after = cert.not_valid_after_utc
    if cert_not_after < datetime.datetime.now(datetime.timezone.utc):
        raise ValueError('Client certificate expired: Not After: {cert_not_after:%Y-%m-%d %H:%M:%SZ}'.format(**locals()))

def _create_sslcontext(pkcs12_data, pkcs12_password_bytes, ssl_protocol):
    private_key, cert, ca_certs = cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates(
        pkcs12_data,
        pkcs12_password_bytes
    )
    _check_cert_not_after(cert)
    ssl_context = ssl.SSLContext(ssl_protocol)
    with tempfile.NamedTemporaryFile(delete=False) as c:
        try:
            tmp_pkcs12_password_bytes = secrets.token_bytes(128//8)
            pk_buf = private_key.private_bytes(
                cryptography.hazmat.primitives.serialization.Encoding.PEM,
                cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8,
                cryptography.hazmat.primitives.serialization.BestAvailableEncryption(password=tmp_pkcs12_password_bytes)
            )
            c.write(pk_buf)
            buf = cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM)
            c.write(buf)
            if ca_certs:
                for ca_cert in ca_certs:
                    _check_cert_not_after(ca_cert)
                    buf = ca_cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM)
                    c.write(buf)
            c.flush()
            c.close()
            ssl_context.load_cert_chain(c.name, password=tmp_pkcs12_password_bytes)
        finally:
            os.remove(c.name)
    return ssl_context

class Pkcs12Adapter(requests.adapters.HTTPAdapter):

    def __init__(self, *args, **kwargs):
        pkcs12_data = kwargs.pop('pkcs12_data', None)
        pkcs12_filename = kwargs.pop('pkcs12_filename', None)
        pkcs12_password = kwargs.pop('pkcs12_password', None)
        ssl_protocol_or_none = kwargs.pop('ssl_protocol', None)
        if pkcs12_data is None and pkcs12_filename is None:
            raise ValueError('Both arguments "pkcs12_data" and "pkcs12_filename" are missing')
        if pkcs12_data is not None and pkcs12_filename is not None:
            raise ValueError('Argument "pkcs12_data" conflicts with "pkcs12_filename"')
        if pkcs12_filename is not None:
            with open(pkcs12_filename, 'rb') as pkcs12_file:
                pkcs12_data = pkcs12_file.read()
        if pkcs12_password is None:
            pkcs12_password_bytes = None
        elif isinstance(pkcs12_password, bytes):
            pkcs12_password_bytes = pkcs12_password
        elif isinstance(pkcs12_password, str):
            pkcs12_password_bytes = pkcs12_password.encode('utf8')
        else:
            raise TypeError('Password must be a None, string or bytes.')
        if ssl_protocol_or_none is None:
            ssl_protocol = default_ssl_protocol
        else:
            ssl_protocol = ssl_protocol_or_none
        self.ssl_context = _create_sslcontext(pkcs12_data, pkcs12_password_bytes, ssl_protocol)
        super(Pkcs12Adapter, self).__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        if self.ssl_context:
            kwargs['ssl_context'] = self.ssl_context
        return super(Pkcs12Adapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        if self.ssl_context:
            kwargs['ssl_context'] = self.ssl_context
        return super(Pkcs12Adapter, self).proxy_manager_for(*args, **kwargs)

    def cert_verify(self, conn, url, verify, cert):
        check_hostname = self.ssl_context.check_hostname
        try:
            if verify is False:
                self.ssl_context.check_hostname = False
            return super(Pkcs12Adapter, self).cert_verify(conn, url, verify, cert)
        finally:
            self.ssl_context.check_hostname = check_hostname

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        check_hostname = self.ssl_context.check_hostname
        try:
            if verify is False:
                self.ssl_context.check_hostname = False
            return super(Pkcs12Adapter, self).send(request, stream, timeout, verify, cert, proxies)
        finally:
            self.ssl_context.check_hostname = check_hostname

def request(*args, **kwargs):
    pkcs12_data = kwargs.pop('pkcs12_data', None)
    pkcs12_filename = kwargs.pop('pkcs12_filename', None)
    pkcs12_password = kwargs.pop('pkcs12_password', None)
    ssl_protocol = kwargs.pop('ssl_protocol', None)
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

def _create_test_cert_pkcs12(key, cert, pkcs12_password_for_creation):
    if pkcs12_password_for_creation is None:
        algorithm = cryptography.hazmat.primitives.serialization.NoEncryption()
    else:
        algorithm = cryptography.hazmat.primitives.serialization.BestAvailableEncryption(pkcs12_password_for_creation)
    pkcs12_data = cryptography.hazmat.primitives.serialization.pkcs12.serialize_key_and_certificates(
        name=b'test',
        key=key,
        cert=cert,
        cas=[cert, cert, cert],
        encryption_algorithm=algorithm
    )
    return pkcs12_data

def _execute_test_case(test_case_name, key, cert, pkcs12_password_for_creation, pkcs12_password, expected_status_code, expected_exception_message):
    print(f"Testing {test_case_name}")
    try:
        pkcs12_data = _create_test_cert_pkcs12(key, cert, pkcs12_password_for_creation)
        response = get(
            'https://example.com/',
            pkcs12_data=pkcs12_data,
            pkcs12_password=pkcs12_password
        )
        if response.status_code != expected_status_code:
            raise Exception('Unexpected response: {response!r}'.format(**locals()))
        if expected_exception_message is not None:
            raise Exception('Missing expected exception: {expected_exception_message!r}'.format(**locals()))
    except ValueError as e:
        if expected_exception_message is None or str(e) != expected_exception_message:
            raise(e)

def test():
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
    _execute_test_case('with encryption, password provided as bytes', key, cert, b'correcthorsebatterystaple', b'correcthorsebatterystaple', 200, None)
    _execute_test_case('with encryption, password provided as string', key, cert, b'correcthorsebatterystaple', 'correcthorsebatterystaple', 200, None)
    _execute_test_case('with empty password provided as bytes', key, cert, None, b'', 200, None)
    _execute_test_case('with empty password provided as string', key, cert, None, '', 200, None)
    _execute_test_case('without encryption', key, cert, None, None, 200, None)
    print('All tests succeeded.')
