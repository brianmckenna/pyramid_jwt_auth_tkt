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

#import traceback

log = logging.getLogger('pyramid_jwt_auth_tkt')

@implementer(IAuthenticationPolicy)
@implementer(ICSRFStoragePolicy)
class JWTAuthTktAuthenticationPolicy(AuthTktAuthenticationPolicy):

    def __init__(self,
                 # cookie required
                 tkt_secret,
                 cookie_name,#    = 'access_token',
                 secure,#         = True,
                 http_only,#      = True,
                 domain,#         = None,
                 # JWT
                 jwt_secret,#     = None,
                 public_key,#     = None,
                 algorithm,#      = 'HS512',
                 leeway,#         = 0,
                 expiration,#     = None,
                 http_header,#    = 'Authorization',
                 auth_type,#      = 'JWT',
                 callback,#       = None,
                 json_encoder,#   = None,
                 # cookie additional
                 include_ip     = False,
                 timeout        = None,
                 reissue_time   = None,
                 max_age        = None,
                 path           = "/",
                 wild_domain    = True,
                 debug          = True,
                 hashalg        = 'sha512',
                 parent_domain  = False,
                 # JWY additional
                 default_claims = None,
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
        # CSRF using 'jti' https://tools.ietf.org/html/rfc7519#section-4.1.7
        payload['jti'] = csrf_token
        expiration = expiration or self.expiration
        if expiration:
            if not isinstance(expiration, datetime.timedelta):
                expiration = datetime.timedelta(seconds=expiration)
            payload['exp'] = iat + expiration
        token = jwt.encode(payload, self.jwt_secret,
                           algorithm=self.algorithm,
                           json_encoder=self.json_encoder)
        if not isinstance(token, str):
            token = token.decode('ascii')
        return token

    def get_claims(self, request):
        """ Claims stored in cookie['userid'] (to use AuthTktCookieHelper).
        No cookie, no claims; No JWT, no claims; Invalid JWT, no claims."""
        identity = self.cookie.identify(request)
        if not identity: # no cookie == no claims
            return {}
        # JWT token stored in 'userid' so we can use AuthTktCookieHelper
        token = identity.get('userid', None)
        if not token:
            return {}
        try:
            claims = jwt.decode(token, self.public_key,
                                algorithms=[self.algorithm],
                                leeway=self.leeway)
        except jwt.InvalidTokenError as e:
            log.warning('Invalid JWT token. [REMOTE_ADDR: %s] %s',
                        request.remote_addr, e)
            return {}
        return claims

    # IAuthenticationPolicy
    def unauthenticated_userid(self, request):
        return request.jwt_claims.get('sub')

    def remember(self, request, userid, **kw):
        return self.cookie.remember(request, userid, **kw)

    def forget(self, request):
        return self.cookie.forget(request)

    # ICSRFStoragePolicy
    def new_csrf_token(self, request):
        return text_(uuid4().hex)

    def get_csrf_token(self, request):
        """ Returns currently active CSRF token by checking cookie,
        generating a new one if needed."""
        csrf_token = request.jwt_claims.get('jti', None)
        if not csrf_token:
            return self.new_csrf_token(request)
        return csrf_token

    def check_csrf_token(self, request, supplied_token):
        """ Returns ``True`` if the ``supplied_token`` is valid."""
        expected_token = self.get_csrf_token(request)
        return not strings_differ(
            bytes_(expected_token), bytes_(supplied_token))
