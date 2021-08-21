import base64
import binascii
import hashlib
import hmac
import logging
import os
import struct
import time
from typing import Optional

import gssapi
import ldap
from flask import Flask, Response, redirect, request
from gssapi.exceptions import BadMechanismError, GSSError, GeneralError
from werkzeug.routing import Rule

app = Flask(__name__)
app.logger.setLevel(logging.INFO)
app.url_map.add(Rule('/krbauth', endpoint='krbauth.auth'))
app.url_map.add(Rule('/krbauth/check', endpoint='krbauth.check'))

timestamp = struct.Struct('!q')
hmac_digest = hashlib.sha512
digest_size = hmac_digest().digest_size

HMAC_KEY = os.environ['KRBAUTH_HMAC_KEY'].encode('utf-8')
DURATION = int(os.environ.get('KRBAUTH_KEY_DURATION', 3600))
RANDOM_SIZE = int(os.environ.get('KRBAUTH_RANDOM_SIZE', 32))
LDAP_SERVER = os.environ.get('KRBAUTH_LDAP_SERVER')
LDAP_BIND_DN = os.environ.get('KRBAUTH_LDAP_BIND_DN')
LDAP_BIND_AUTHTOK = os.environ.get('KRBAUTH_LDAP_BIND_AUTHTOK')
LDAP_SEARCH_BASE = os.environ.get('KRBAUTH_LDAP_SEARCH_BASE')
LDAP_USER_DN = os.environ.get('KRBAUTH_LDAP_USER_DN')
assert not LDAP_USER_DN or LDAP_USER_DN.count('%s') == 1

GSSAPI_NAME = os.environ.get('KRBAUTH_GSSAPI_NAME')
if GSSAPI_NAME:
    gssapi_name = gssapi.Name(GSSAPI_NAME, gssapi.NameType.hostbased_service)
    gssapi_creds = gssapi.Credentials(name=gssapi_name, usage='accept')
else:
    gssapi_creds = None

COOKIE_SECURE = os.environ.get('KRBAUTH_SECURE_COOKIE', '1').lower() not in ('0', 'no')


class Context:
    def __init__(self, ldap_group: Optional[str]) -> None:
        self.ldap_group = ldap_group

    @classmethod
    def from_request(cls) -> 'Context':
        return cls(ldap_group=request.environ.get('KRBAUTH_LDAP_GROUP'))

    def bytes(self) -> bytes:
        assert self.ldap_group
        return ''.join([self.ldap_group]).encode('utf-8')


def make_cookie(context: Context) -> bytes:
    message = timestamp.pack(int(time.time()) + DURATION) + os.urandom(RANDOM_SIZE) + context.bytes()
    signature = hmac.new(HMAC_KEY, message, hmac_digest).digest()
    return base64.b64encode(signature + message)


def verify_cookie(cookie: Optional[str], context: Context) -> bool:
    if not cookie:
        return False
    try:
        data = base64.b64decode(cookie)
        signature = data[:digest_size]
        message = data[digest_size:]
        ts = timestamp.unpack(message[:timestamp.size])[0]
    except (struct.error, binascii.Error):
        return False
    if ts < time.time():
        return False
    if not hmac.compare_digest(message[timestamp.size + RANDOM_SIZE:], context.bytes()):
        return False
    expected = hmac.new(HMAC_KEY, message, hmac_digest).digest()
    return hmac.compare_digest(expected, signature)


def make_401(reason: str, negotiate: Optional[str] = 'Negotiate', **kwargs) -> Response:
    app.logger.info('Returning unauthorized: %s (%s)', reason, kwargs)
    resp = Response('''\
<html>
<head>
<title>401 Unauthorized</title>
</head>
<body>
<center><h1>401 Unauthorized</h1></center>
<hr>
<center>%s</center>
</body>
</html>
''' % (reason,), status=401)
    if negotiate:
        resp.headers.add('WWW-Authenticate', negotiate)
    if LDAP_USER_DN:
        resp.headers.add('WWW-Authenticate', 'Basic')
    return resp


def auth_success(context: Context, next_url: str) -> Response:
    resp = redirect(next_url, code=307, Response=Response)
    resp.set_cookie('krbauth', make_cookie(context), secure=COOKIE_SECURE, httponly=True, samesite='Strict')
    return resp


def auth_spnego(context: Context, next_url: str) -> Response:
    try:
        in_token = base64.b64decode(request.headers['Authorization'][len('Negotiate '):])
    except binascii.Error:
        return Response(status=400)

    try:
        krb5_ctx = gssapi.SecurityContext(creds=gssapi_creds, usage='accept')
        out_token = krb5_ctx.step(in_token)

        if not krb5_ctx.complete:
            return make_401('Negotiation in progress',
                            negotiate=f'Negotiate {base64.b64encode(out_token).decode("ascii")}')

        krb5_name = krb5_ctx.initiator_name
    except BadMechanismError:
        return make_401('GSSAPI mechanism not supported', negotiate=None)
    except (GSSError, GeneralError) as e:
        return make_401(str(e))

    if LDAP_SERVER and LDAP_SEARCH_BASE and context.ldap_group:
        ldap_ctx = ldap.initialize(LDAP_SERVER)
        if LDAP_BIND_DN and LDAP_BIND_AUTHTOK:
            ldap_ctx.bind_s(LDAP_BIND_DN, LDAP_BIND_AUTHTOK, ldap.AUTH_SIMPLE)
        ldap_filter = '(&(memberOf=%s)(krbPrincipalName=%s))' % (context.ldap_group, krb5_name)
        result = ldap_ctx.search_s(LDAP_SEARCH_BASE, ldap.SCOPE_SUBTREE, ldap_filter, ['cn'])
        if not result:
            return make_401('Did not find LDAP group member', krb5_name=krb5_name)
        app.logger.info('Authenticated via Kerberos as: %s, %s', krb5_name, result[0][0])
    else:
        app.logger.info('Authenticated via Kerberos as: %s', krb5_name)

    return auth_success(context, next_url)


def auth_basic(context: Context, next_url: str) -> Response:
    try:
        token = base64.b64decode(request.headers['Authorization'][6:])
        username, _, password = token.decode('utf-8').partition(':')
    except (binascii.Error, UnicodeDecodeError):
        return Response(status=400)

    if not username or not password:
        return make_401('Invalid username or password')

    assert LDAP_USER_DN is not None
    dn = LDAP_USER_DN % (username,)
    ldap_ctx = ldap.initialize(LDAP_SERVER)
    try:
        ldap_ctx.bind_s(dn, password)
    except ldap.INVALID_CREDENTIALS:
        return make_401('Failed to authenticate to LDAP', dn=dn)

    if context.ldap_group:
        if not ldap_ctx.search_s(dn, ldap.SCOPE_BASE, '(memberof=%s)' % (context.ldap_group,)):
            return make_401('Did not find LDAP group member', dn=dn, group=context.ldap_group)
        app.logger.info('Authenticated via LDAP as: %s in %s', dn, context.ldap_group)
    else:
        app.logger.info('Authenticated via LDAP as: %s', dn)

    return auth_success(context, next_url)


@app.endpoint('krbauth.auth')
def auth() -> Response:
    next_url = request.args.get('next', '/')
    context = Context.from_request()
    authorization = request.headers.get('Authorization', '')

    if authorization.startswith('Negotiate '):
        return auth_spnego(context, next_url)
    if LDAP_USER_DN and authorization.startswith('Basic '):
        return auth_basic(context, next_url)

    return make_401('No Authorization header sent')


@app.endpoint('krbauth.check')
def check() -> Response:
    if verify_cookie(request.cookies.get('krbauth'), Context.from_request()):
        return Response(status=200)
    return Response(status=401)
