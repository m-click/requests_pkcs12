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

from OpenSSL.crypto import load_pkcs12
from requests import Session
from requests import request as request_orig
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.contrib.pyopenssl import PyOpenSSLContext
from ssl import PROTOCOL_TLSv1_2

class Pkcs12Adapter(HTTPAdapter):

    def __init__(self, *args, **kwargs):
        pkcs12_data = kwargs.pop('pkcs12_data', None)
        pkcs12_filename = kwargs.pop('pkcs12_filename', None)
        pkcs12_password = kwargs.pop('pkcs12_password', None)
        if pkcs12_data is None and pkcs12_filename is None:
            raise ValueError('Both arguments "pkcs12_data" and "pkcs12_filename" are missing')
        if pkcs12_data is not None and pkcs12_filename is not None:
            raise ValueError('Argument "pkcs12_data" conflicts with "pkcs12_filename"')
        if pkcs12_password is None:
            raise ValueError('Argument "pkcs12_password" is missing')
        if pkcs12_filename is not None:
            with open(pkcs12_filename, 'rb') as pkcs12_file:
                self._pkcs12_data = pkcs12_file.read()
        else:
            self._pkcs12_data = pkcs12_data
        if isinstance(pkcs12_password, bytes):
            self._pkcs12_password_bytes = pkcs12_password
        else:
            self._pkcs12_password_bytes = pkcs12_password.encode('utf8')
        super(Pkcs12Adapter, self).__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self._create_ssl_context()
        return super(Pkcs12Adapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs['ssl_context'] = self._create_ssl_context()
        return super(Pkcs12Adapter, self).proxy_manager_for(*args, **kwargs)

    def _create_ssl_context(self):
        p12 = load_pkcs12(self._pkcs12_data, self._pkcs12_password_bytes)
        ssl_context = PyOpenSSLContext(PROTOCOL_TLSv1_2)
        ssl_context._ctx.use_certificate(p12.get_certificate())
        ssl_context._ctx.use_privatekey(p12.get_privatekey())
        return ssl_context

def request(*args, **kwargs):
    pkcs12_data = kwargs.pop('pkcs12_data', None)
    pkcs12_filename = kwargs.pop('pkcs12_filename', None)
    pkcs12_password = kwargs.pop('pkcs12_password', None)
    if pkcs12_data is None and pkcs12_filename is None and pkcs12_password is None:
        return request_orig(*args, **kwargs)
    if 'cert' in  kwargs:
        raise ValueError('Argument "cert" conflicts with "pkcs12_*" arguments')
    with Session() as session:
        pkcs12_adapter = Pkcs12Adapter(
            pkcs12_data=pkcs12_data,
            pkcs12_filename=pkcs12_filename,
            pkcs12_password=pkcs12_password,
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
