from setuptools import setup
setup(
    name='requests_pkcs12',
    version=open('version', 'r').read(),
    description='Add PKCS#12 support to the requests library in a clean way, without monkey patching or temporary files',
    long_description=open('README.rst', 'r').read(),
    url='https://github.com/m-click/requests_pkcs12',
    author='Volker Diels-Grabsch',
    author_email='volker.diels-grabsch@m-click.aero',
    license='ISC',
    install_requires=[
        'cryptography (>=3.4.7)',
        'pyOpenSSL (>=20.0.1)',
        'requests (>=2.26.0)',
    ],
    extras_require={
        'dev': [
            'twine (>=3.4.2)',
            'wheel (>=0.37.0)',
        ],
    },
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
