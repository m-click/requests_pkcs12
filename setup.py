from setuptools import setup
setup(
    name='requests_pkcs12',
    version='1.4',
    description='Add PKCS#12 support to the requests library in a clean way, without monkey patching or temporary files',
    long_description=open('README.rst').read(),
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
