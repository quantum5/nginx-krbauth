# nginx-krbauth [![PyPI](https://img.shields.io/pypi/v/nginx-krbauth.svg)](https://pypi.org/project/nginx-krbauth/) [![PyPI - Format](https://img.shields.io/pypi/format/nginx-krbauth.svg)](https://pypi.org/project/nginx-krbauth/) [![PyPI - Python Version](https://img.shields.io/pypi/pyversions/nginx-krbauth.svg)](https://pypi.org/project/nginx-krbauth/)
LDAP + Kerberos authenticator for nginx's auth_request module.

## Installation

```sh
pip install nginx-krbauth
```

If, for some reason, you want to use the latest code from git:

```sh
pip install git+https://github.com/quantum5/nginx-krbauth.git
```

## Usage

Load `nginx_krbauth:app` into any WSGI compatible server.
Configuration is done through environment variables.

Example:

```ini
[uwsgi]
protocol = uwsgi
socket = /tmp/krbauth.sock
module = nginx_krbauth:app
env = KRB5_KTNAME=FILE:/home/krbauth/.keytab
env = KRBAUTH_HMAC_KEY=hunter2
env = KRBAUTH_LDAP_SERVER=ldapi:///
env = KRBAUTH_LDAP_BIND_DN=cn=http,ou=Apps,dc=example,dc=com
env = KRBAUTH_LDAP_BIND_AUTHTOK=hunter2
env = KRBAUTH_LDAP_SEARCH_BASE=dc=example,dc=com
```

`nginx_krbauth` exports two HTTP endpoints:

* `/krbauth`: This endpoint performs SPNEGO authentication. When done, it
  sets a session cookie and generates a 307 redirect to the URL in the `next`
  GET parameter.
* `/krbauth/check`: The endpoint checks the validity of the session cookie. If
  valid, it returns 200. Otherwise, it returns 401.

The intention is to use `/krbauth/check` as `auth_request` in your `nginx`
configuration. On 401, `nginx` should be configured to generate a redirect to
`/krbauth`.

## Configuration

* `KRB5_KTNAME`: This is actually a Kerberos setting. It should point to a
  keytab file that only the user running `nginx_krbauth` can read containing
  the Kerberos host principals.
* `KRBAUTH_HMAC_KEY` (required): This is the HMAC key used to sign cookies. It
  should be a long random string. Keep it secret!
* `KRBAUTH_KEY_DURATION`: The duration (in seconds) for which the session cookie
  is valid. Default: 1 hour.
* `KRBAUTH_RANDOM_SIZE`: The length of the nonce in the session cookie in bytes.
  Default: 32.
* `KRBAUTH_GSSAPI_NAME`: The GSSAPI name for the service. Leave blank if any
  name in the keytab is fine.
* `KRBAUTH_SECURE_COOKIE`: This controls whether the session cookie is marked as
  HTTPS-only. Default: yes. Set to `0` or `no` to disable.

### LDAP

`nginx_krbauth` can also optionally check LDAP group membership. It does so by
looking up the groups of the LDAP entity whose `krbPrincipalName` attribute
matches the name of the Kerberos principal used to authenticate.

The group is specified through the WSGI environment variable
`KRBAUTH_LDAP_GROUP`. This could be set through `uwsgi_param`, for example.

The following environment variables are used to configure `nginx_krbauth`'s
LDAP support:

* `KRBAUTH_LDAP_SERVER`: The LDAP URI used to connect to the LDAP server.
* `KRBAUTH_LDAP_SEARCH_BASE`: The root of the subtree to search for LDAP
  entities for `krbPrincipalName` and group membership.
* `KRBAUTH_LDAP_BIND_DN`: The DN used to bind to the LDAP server. Leave blank
  for anonymous bind.
* `KRBAUTH_LDAP_BIND_AUTHTOK`: The password used to bind to the LDAP server.
  Leave blank for anonymous bind.

LDAP binding can also be used as a fallback authentication mechanism through
HTTP Basic authentication. This is useful when SPNEGO is not supported, or when
the client does not support Kerberos. To use this, configure:

* `KRBAUTH_LDAP_USER_DN`: A string template to convert usernames into LDAP DNs.
  There should be one `%s` symbol in this string, which will be replaced by the
  username.

## Example `nginx.conf`

```nginx
auth_request /krbauth/check;
error_page 401 = @krbauth;
location @krbauth {
    return 307 /krbauth?next=$request_uri;
}

location /krbauth {
    auth_request off;
    error_page 527 error.html; # To cancel out error_page 401 outside.
    uwsgi_pass unix:/tmp/krbauth.sock;
    uwsgi_pass_request_body off;
    uwsgi_param KRBAUTH_LDAP_GROUP "cn=group,dc=example,dc=com";
    include uwsgi_params;
}
```
