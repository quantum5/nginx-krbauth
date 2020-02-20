import base64
import binascii
import hashlib
import hmac
import logging
import os
import time
import socket
import struct
import sys
from urllib.parse import quote

import gssapi
import ldap
from flask import Flask, request, redirect, url_for, Response
from gssapi.exceptions import GSSError, GeneralError

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

timestamp = struct.Struct('!q')
hmac_digest = hashlib.sha512
digest_size = hmac_digest().digest_size

HMAC_KEY = os.environ['KRBAUTH_HMAC_KEY'].encode('utf-8')
DURATION = int(os.environ.get('KRBAUTH_KEY_DURATION', 3600))
RANDOM_SIZE = int(os.environ.get('KRBAUTH_RANDOM_SIZE', 32))
LDAP_SERVER = os.environ['KRBAUTH_LDAP_SERVER']
LDAP_BIND_DN = os.environ.get('KRBAUTH_LDAP_BIND_DN')
LDAP_BIND_AUTHTOK = os.environ.get('KRBAUTH_LDAP_BIND_AUTHTOK')
LDAP_SEARCH_BASE = os.environ['KRBAUTH_LDAP_SEARCH_BASE']

GSSAPI_NAME = os.environ.get('KRBAUTH_GSSAPI_NAME')
if GSSAPI_NAME:
    gssapi_name = gssapi.Name(GSSAPI_NAME, gssapi.NameType.hostbased_service)
    gssapi_creds = gssapi.Credentials(name=gssapi_name, usage='accept')
else:
    gssapi_creds = None

COOKIE_SECURE = os.environ.get('KRBAUTH_SECURE_COOKIE', '1').lower() not in ('0', 'no')


class Context:
    def __init__(self, ldap_group):
        self.ldap_group = ldap_group

    @classmethod
    def from_request(cls):
        return cls(ldap_group=request.environ.get('KRBAUTH_LDAP_GROUP'))

    def bytes(self):
        return ''.join([self.ldap_group]).encode('utf-8')


def make_cookie(context):
    message = timestamp.pack(int(time.time()) + DURATION) + os.urandom(RANDOM_SIZE) + context.bytes()
    signature = hmac.new(HMAC_KEY, message, hmac_digest).digest()
    return base64.b64encode(signature + message)


def verify_cookie(cookie, context):
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
    expected = hmac.new(HMAC_KEY, message, hashlib.sha512).digest()
    return hmac.compare_digest(expected, signature)


def make_401(reason, context, auth='Negotiate', krb5_name=None):
    app.logger.info('Returning unauthorized: %s (krb5_name=%s, ldap_group=%s)', reason, krb5_name, context.ldap_group)
    return Response('''\
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
''' % (reason,), status=401, headers={'WWW-Authenticate': auth})


@app.route('/krbauth')
def auth():
    next = request.args.get('next', '/')
    context = Context.from_request()

    if not request.headers.get('Authorization', '').startswith('Negotiate '):
        return make_401('No Authorization header sent', context)

    try:
        in_token = base64.b64decode(request.headers['Authorization'][10:])
    except binascii.Error:
        return Response(status=400)

    try:
        krb5_ctx = gssapi.SecurityContext(creds=gssapi_creds, usage='accept')
        out_token = krb5_ctx.step(in_token)

        if not krb5_ctx.complete:
            return make_401('Negotiation in progress', context, auth='Negotiate ' + base64.b64encode(out_token))

        krb5_name = krb5_ctx._inquire(initiator_name=True).initiator_name
    except (GSSError, GeneralError) as e:
        return make_401(str(e), context)

    if LDAP_SERVER and context.ldap_group:
        ldap_ctx = ldap.initialize(LDAP_SERVER)
        if LDAP_BIND_DN and LDAP_BIND_AUTHTOK:
            ldap_ctx.bind_s(LDAP_BIND_DN, LDAP_BIND_AUTHTOK, ldap.AUTH_SIMPLE)
        ldap_filter = '(&(memberOf=%s)(krbPrincipalName=%s))' % (context.ldap_group, krb5_name)
        try:
            result = ldap_ctx.search_s(LDAP_SEARCH_BASE, ldap.SCOPE_SUBTREE, ldap_filter, ['cn'])
        except ldap.NO_SUCH_OBJECT:
            return make_401('Did not find LDAP group member', context, krb5_name=krb5_name)
        if not result:
            return make_401('Did not find LDAP group member', context, krb5_name=krb5_name)
        app.logger.info('Authenticated as: %s, %s', krb5_name, result[0][0])
    else:
        app.logger.info('Authenticated as: %s', krb5_name)

    resp = redirect(next, code=307)
    resp.set_cookie('krbauth', make_cookie(context), secure=COOKIE_SECURE, httponly=True, samesite='Strict')
    return resp


@app.route('/krbauth/check')
def check():
    if verify_cookie(request.cookies.get('krbauth'), Context.from_request()):
        return Response(status=200)
    return Response(status=401)