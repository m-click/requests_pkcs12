from setuptools import setup
setup(
    name='requests_pkcs12',
    version='1.0.8',
    description='Add PKCS#12 support to the requests library in a clean way, without monkey patching or temporary files',
    long_description='''
    PKCS#12 support for requests
    ============================

    This library adds PKCS#12 support to the Python `requests <http://python-requests.org>`_ library.

    It is a **clean implementation**: it uses neither monkey patching nor temporary files. Instead, it is integrated into ``requests`` as recommended by its authors: creating a custom ``TransportAdapter``, which provides a custom ``SSLContext``.

    This library is meant to be a transitional solution until this functionality is provided by ``requests`` directly. However, that will take some time. See the `corresponding issue <https://github.com/requests/requests/issues/1573>`_ for more details.
    '''.replace('\n    ', '\n'),
    url='https://github.com/m-click/requests_pkcs12',
    author='Volker Diels-Grabsch',
    author_email='volker.diels-grabsch@m-click.aero',
    license='ISC',
    install_requires=[
        'pyOpenSSL (>=0.14)',
        'requests (>=2.18.4)',
    ],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Libraries',
    ],
    py_modules=['requests_pkcs12'],
)
