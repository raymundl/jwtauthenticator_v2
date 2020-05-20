from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join
import requests
import json
import jwt
import os
from tornado import (
    gen,
    web,
)
from traitlets import (
    Bool,
    List,
    Unicode,
)


class JSONWebTokenLoginHandler(BaseHandler):
    JWKS_CACHE = '/tmp/_jwks.json'

    async def get(self):
        header_name = self.authenticator.header_name
        cookie_name = self.authenticator.cookie_name
        param_name = self.authenticator.param_name

        auth_header_content = self.request.headers.get(header_name, "") if header_name else None
        auth_cookie_content = self.get_cookie(cookie_name, "") if cookie_name else None
        auth_param_content = self.get_argument(param_name, default="") if param_name else None

        signing_certificate = self.authenticator.signing_certificate
        secret = self.authenticator.secret
        jwks_url = self.authenticator.jwks_url
        save_token = self.authenticator.save_token
        algorithms = self.authenticator.algorithms

        username_claim_field = self.authenticator.username_claim_field
        extract_username = self.authenticator.extract_username
        audience = self.authenticator.expected_audience

        auth_url = self.authenticator.auth_url
        retpath_param = self.authenticator.retpath_param

        _url = url_path_join(self.hub.server.base_url, 'home')
        next_url = self.get_argument('next', default=False)
        if next_url:
            _url = next_url

        if auth_url and retpath_param:
            auth_url += ("{prefix}{param}=https://{host}{url}".format(
                prefix='&' if '?' in auth_url else '?',
                param=retpath_param,
                host=self.request.host,
                url=_url,
            ))

        if auth_header_content:
            token = auth_header_content
        elif auth_cookie_content:
            token = auth_cookie_content
        elif auth_param_content:
            token = auth_param_content
        else:
            return self.auth_failed(auth_url)

        try:
            if jwks_url:
                claims = self.verify_jwt_using_jwks_url(token, jwks_url, audience)
            elif secret:
                claims = self.verify_jwt_using_secret(token, secret, algorithms, audience)
            elif signing_certificate:
                claims = self.verify_jwt_with_claims(token, signing_certificate, audience)
            else:
                return self.auth_failed(auth_url)
        except jwt.exceptions.InvalidTokenError:
            return self.auth_failed(auth_url)
        except Exception as e:
            self.log.error('auth failed with: %s' % e)
            return self.auth_failed(auth_url)

        username = self.retrieve_username(claims, username_claim_field, extract_username=extract_username)
        if save_token:
            user = await self.auth_to_user({
                'name': username,
                'auth_state': {
                    save_token: token
                }
            })
        else:
            user = await self.user_from_username(username)
        self.set_login_cookie(user)
        self.redirect(_url)

    def auth_failed(self, redirect_url):
        if redirect_url:
            self.redirect(redirect_url)
        else:
            raise web.HTTPError(401)

    @staticmethod
    def verify_jwt_with_claims(token, signing_certificate, audience):
        opts = {}
        if not audience:
            opts = {"verify_aud": False}
        with open(signing_certificate, 'r') as rsa_public_key_file:
            return jwt.decode(token, rsa_public_key_file.read(), audience=audience, options=opts)

    @staticmethod
    def verify_jwt_using_secret(json_web_token, secret, algorithms, audience):
        opts = {}
        if not audience:
            opts = {"verify_aud": False}
        return jwt.decode(json_web_token, secret, algorithms=algorithms, audience=audience, options=opts)

    @staticmethod
    def verify_jwt_using_jwks_url(json_web_token, jwks_url, audience):
        opts = {}
        if not audience:
            opts = {"verify_aud": False}
        public_keys = {}
        if os.path.exists(JSONWebTokenLoginHandler.JWKS_CACHE):
            with open(JSONWebTokenLoginHandler.JWKS_CACHE) as fi:
                jwks = json.load(fi)
        else:
            resp = requests.get(jwks_url)
            jwks = resp.json()
            with open(JSONWebTokenLoginHandler.JWKS_CACHE, 'w+') as fo:
                json.dump(jwks, fo)
        for jwk in jwks['keys']:
            kid = jwk['kid']
            public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
        kid = jwt.get_unverified_header(json_web_token)['kid']
        return jwt.decode(json_web_token, key=public_keys[kid], algorithms=['RS256'], audience=audience, options=opts)

    @staticmethod
    def retrieve_username(claims, username_claim_field, extract_username):
        username = claims[username_claim_field]
        if extract_username:
            if "@" in username:
                name, domain = username.split('@')
                if domain.count('.') >= 2:  # company branch name if any
                    subs = domain.split('.')
                    username = '%s-%s' % (name, subs[0])
                else:
                    username = name
        return username


class JSONWebTokenAuthenticator(Authenticator):
    """
    Accept the authenticated JSON Web Token from header.
    """
    auth_url = Unicode(
        config=True,
        help="""URL for redirecting to in the case of invalid auth token""")

    retpath_param = Unicode(
        config=True,
        help="""Name of query param for auth_url to pass return URL""")

    header_name = Unicode(
        default_value='X-Auth-Token',
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token.""")

    cookie_name = Unicode(
        config=True,
        default_value='auth_token',
        help="""The name of the cookie field used to specify the JWT token""")

    param_name = Unicode(
        config=True,
        default_value='auth_token',
        help="""The name of the query parameter used to specify the JWT token""")

    signing_certificate = Unicode(
        config=True,
        help="""
        The public certificate of the private key used to sign the incoming JSON Web Tokens.

        Should be a path to an X509 PEM format certificate filesystem.
        """
    )

    secret = Unicode(
        config=True,
        help="""Shared secret key for siging JWT token. If defined, it overrides any setting for signing_certificate""")

    jwks_url = Unicode(
        config=True,
        help="""Shared JSON Web Key Set URL. If defined, it overrides any setting for signing_certificate""")

    save_token = Unicode(
        config=True,
        help="""If not empty, save JWToken into auth_state and name it by this parameter""")

    algorithms = List(
        default_value=['HS256'],
        config=True,
        help="""Specify which algorithms you would like to permit when validating the JWT""")

    username_claim_field = Unicode(
        default_value='username',
        config=True,
        help="""
        The field in the claims that contains the user name. It can be either a straight username,
        of an email/userPrincipalName.
        """
    )

    extract_username = Bool(
        default_value=True,
        config=True,
        help="""
        Set to true to split username_claim_field and take the part before the first `@`
        """
    )

    expected_audience = Unicode(
        default_value='',
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token."""
    )

    def get_handlers(self, app):
        return [
            (r'/login', JSONWebTokenLoginHandler),
        ]

    @gen.coroutine
    def authenticate(self, *args):
        raise NotImplementedError()

    @gen.coroutine
    def pre_spawn_start(self, user, spawner):
        """Pass upstream token to spawner via environment variable"""
        auth_state = yield user.get_auth_state()
        if auth_state and self.save_token:
            self.log.info('pre_spawn_start with token: %s' % self.save_token)
            spawner.environment[self.save_token.upper()] = auth_state[self.save_token]


class JSONWebTokenLocalAuthenticator(JSONWebTokenAuthenticator, LocalAuthenticator):
    """
    A version of JSONWebTokenAuthenticator that mixes in local system user creation
    """
    pass
