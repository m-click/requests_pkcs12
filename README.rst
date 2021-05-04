PKCS#12 support for requests
============================

This library adds PKCS#12 support to the Python `requests <http://python-requests.org>`__ library.

It is a **clean implementation**: it uses neither monkey patching nor temporary files. Instead, it is integrated into ``requests`` as
recommended by its authors: creating a custom ``TransportAdapter``, which provides a custom ``SSLContext``.

This library is meant to be a transitional solution until this functionality is provided by ``requests`` directly. However, that will take some time. See the `corresponding issue <https://github.com/requests/requests/issues/1573>`__ for more details.

Usage
-----

For simple one-off requests you can use this library as a drop-in replacement for the ``requests`` library:

.. code:: python

   from requests_pkcs12 import get

   r = get('https://example.com/test', pkcs12_filename='clientcert.p12', pkcs12_password='correcthorsebatterystaple')

If you are using `requests sessions <https://requests.readthedocs.io/en/master/user/advanced/>`__, use the ``Pkcs12Adapter``:

.. code:: python

   from requests import Session
   from requests_pkcs12 import Pkcs12Adapter

   with Session() as s:
       s.mount('https://example.com', Pkcs12Adapter(pkcs12_filename='clientcert.p12', pkcs12_password='correcthorsebatterystaple'))
       r = s.get('https://example.com/test')

Installation
------------

This library is available as `PyPI package <https://pypi.python.org/pypi/requests-pkcs12>`__:

::

   pip install requests-pkcs12

Alternatively, you can retrieve the latest development version via Git:

::

   git clone https://github.com/m-click/requests_pkcs12

Arguments
---------

The following keyword arguments are supported:

-  ``pkcs12_filename`` is a byte string or unicode string that contains the file name of the encrypted PKCS#12 certificate.

   -  Either this argument or ``pkcs12_data`` must be provided.

-  ``pkcs12_data`` is a byte string that contains the encrypted PKCS#12 certificate data.

   -  Either this argument or ``pkcs12_filename`` must be provided.

-  ``pkcs12_password`` is a byte string or unicode string that contains the password.

   -  This argument must be provided whenever ``pkcs12_filename`` or ``pkcs12_data`` is provided.

-  ``ssl_protocol`` is a protocol version from the ``ssl`` library.

   -  This argument is optional and defaults to ``ssl.PROTOCOL_TLS``.

If you use these parameters, don’t use the built-in ``cert`` parameter of ``requests`` at the same time. However, do use the other parameters.  In particular, do use `the "verify" parameter <http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification>`__ to verify the server-side certificate.
