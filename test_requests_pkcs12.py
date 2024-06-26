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
from requests_pkcs12 import _execute_test_case


def test_requests_pkcs12():
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
