#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import logging
import jwt
from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.compat import bytes_, text_
from pyramid.interfaces import IAuthenticationPolicy, ICSRFStoragePolicy
from pyramid.util import strings_differ
from uuid import uuid4
from zope.interface import implementer

log = logging.getLogger('pyramid_jwt_auth_tkt')

@implementer(IAuthenticationPolicy)
@implementer(ICSRFStoragePolicy)
class JWTAuthTktAuthenticationPolicy(AuthTktAuthenticationPolicy):

    def __init__(self,
                 tkt_secret,
                 jwt_secret,
                 # AuthTkt
                 callback=None,
                 cookie_name='access_token',
                 secure=False,
                 #secure=True,
                 include_ip=False,
                 timeout=None,
                 reissue_time=None,
                 max_age=None,
                 path="/",
                 #http_only=False,
                 http_only=True,
                 wild_domain=True,
                 debug=False,
                 hashalg='sha512',
                 parent_domain=False,
                 domain=None,
                 # JWT
                 public_key=None,
                 algorithm='HS512',
                 leeway=0,
                 expiration=None,
                 default_claims=None,
                 http_header='Authorization',
                 auth_type='JWT',
                 json_encoder=None,
                 ):

        super().__init__(tkt_secret,
                         callback=callback,
                         cookie_name=cookie_name,
                         secure=secure,
                         include_ip=include_ip,
                         timeout=timeout,
                         reissue_time=reissue_time,
                         max_age=max_age,
                         path=path,
                         http_only=http_only,
                         wild_domain=wild_domain,
                         debug=debug,
                         hashalg=hashalg,
                         parent_domain=parent_domain,
                         domain=domain
                         )

        self.jwt_secret     = jwt_secret
        self.public_key     = public_key if public_key is not None else jwt_secret
        self.algorithm      = algorithm
        self.leeway         = leeway
        self.default_claims = default_claims if default_claims else {}
        self.http_header    = http_header
        self.auth_type      = auth_type

        if expiration:
            if not isinstance(expiration, datetime.timedelta):
                expiration = datetime.timedelta(seconds=expiration)
            self.expiration = expiration
        else:
            self.expiration = None

        self.callback = callback
        self.json_encoder = json_encoder

    def create_token(self, principal, csrf_token, expiration=None, **claims):

        payload = self.default_claims.copy()
        payload.update(claims)
        payload['sub'] = principal
        payload['iat'] = iat = datetime.datetime.utcnow()
        payload['jti'] = csrf_token # https://tools.ietf.org/html/rfc7519#section-4.1.7
        expiration = expiration or self.expiration
        if expiration:
            if not isinstance(expiration, datetime.timedelta):
                expiration = datetime.timedelta(seconds=expiration)
            payload['exp'] = iat + expiration
        token = jwt.encode(payload, self.jwt_secret, algorithm=self.algorithm, json_encoder=self.json_encoder)
        if not isinstance(token, str):
            token = token.decode('ascii')
        return token

    def get_claims(self, request):
        token = self.cookie.identify(request)
        if not token:
            return {}
        try:
            claims = jwt.decode(token, self.public_key, algorithms=[self.algorithm], leeway=self.leeway)
        except jwt.InvalidTokenError as e:
            log.warning('Invalid JWT token from %s: %s', request.remote_addr, e)
            return {}
        return claims

    def unauthenticated_userid(self, request):
        """ The userid key within the auth_tkt cookie."""
        result = self.cookie.identify(request)
        if result:
            return result['userid']
        return request.jwt_claims.get('sub')

    def remember(self, request, userid, **kw):
        """ Accepts the following kw args:
                ``max_age=<int-seconds>,
                ``tokens=<sequence-of-ascii-strings>``.
            Return a list of headers which will set appropriate cookies on the response.
        """
        return self.cookie.remember(request, userid, **kw)

    def forget(self, request):
        """ A list of headers which will delete appropriate cookies."""
        return self.cookie.forget(request)

    # ICSRFStoragePolicy
    def new_csrf_token(self, request):
        return text_(uuid4().hex)

    def get_csrf_token(self, request):
        """ Returns the currently active CSRF token by checking the cookies sent with the current request."""
        userid = self.cookie.identify(request) # JWT token is passed in as 'userid' to remember
        print(userid)
        csrf_token = request.jwt_claims.get('jti', None)
        if not csrf_token:
            return 'rut row'
        return csrf_token

    def check_csrf_token(self, request, supplied_token):
        """ Returns ``True`` if the ``supplied_token`` is valid."""
        expected_token = self.get_csrf_token(request)
        return not strings_differ(
            bytes_(expected_token), bytes_(supplied_token))
