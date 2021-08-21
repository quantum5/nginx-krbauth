import os

from setuptools import setup

with open(os.path.join(os.path.dirname(__file__), 'README.md')) as f:
    long_description = f.read()

setup(
    name='nginx_krbauth',
    version='0.0.2',
    py_modules=['nginx_krbauth'],
    install_requires=['flask', 'gssapi', 'python-ldap'],

    author='quantum',
    author_email='quantum2048@gmail.com',
    url='https://github.com/quantum5/nginx-krbauth',
    description="LDAP + Kerberos authenticator for nginx's auth_request module.",
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords='ldap kerberos nginx',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Framework :: Flask',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Internet :: WWW/HTTP :: HTTP Servers',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Application',
        'Topic :: Security',
        'Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP',
    ],
)
