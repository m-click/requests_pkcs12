from setuptools import setup
setup(
    name='requests_pkcs12',
    version='1.0.0',
    description='Add PKCS#12 support to the requests library in a clean way, without monkey patching or temporary files',
    url='https://github.com/m-click/requests_pkcs12',
    author='Volker Diels-Grabsch',
    author_email='volker.diels-grabsch@m-click.aero',
    license='ISC',
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
