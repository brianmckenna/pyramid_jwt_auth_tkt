#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .policy import JWTAuthTktAuthenticationPolicy

def includeme(config):
    config.add_directive('set_jwt_auth_tkt_authentication_policy', _set_authentication_policy, action_wrap=True)

def _create_jwt_authentication_policy(config,
                                      # cookie
                                      tkt_secret   = None,
                                      cookie_name  = None,
                                      secure       = None,
                                      http_only    = None,
                                      domain       = None,
                                      # JWT
                                      jwt_secret   = None,
                                      public_key   = None,
                                      algorithm    = None,
                                      expiration   = None,
                                      leeway       = None,
                                      http_header  = None,
                                      auth_type    = None,
                                      callback     = None,
                                      json_encoder = None
                                      ):

    settings = config.get_settings()

    # cookie options
    tkt_secret  = tkt_secret or settings.get('auth.tkt.secret')
    cookie_name = cookie_name or settings.get('auth.tkt.cookie_name')
    secure      = secure or settings.get('auth.tkt.secure')
    http_only   = http_only or settings.get('auth.tkt.http_only')
    domain      = domain or settings.get('auth.tkt.domain')
    # JWT options
    jwt_secret = jwt_secret or settings.get('auth.jwt.secret')
    algorithm = algorithm or settings.get('auth.jwt.algorithm') or 'HS512'
    if algorithm.startswith('RS') or algorithm.startswith('EC'):
        public_key = public_key or settings.get('auth.jwt.public_key')
    else:
        public_key = None
    if expiration is None and 'auth.jwt.expiration' in settings:
        expiration = int(settings.get('auth.jwt.expiration'))
    leeway = int(settings.get('auth.jwt.leeway', 0)) if leeway is None else leeway
    http_header = http_header or settings.get('auth.jwt.http_header') or 'Authorization'
    if http_header.lower() == 'authorization':
        auth_type = auth_type or settings.get('auth.jwt.auth_type') or 'JWT'
    else:
        auth_type = None

    return JWTAuthTktAuthenticationPolicy(
        # cookie
        tkt_secret   = tkt_secret,
        cookie_name  = cookie_name,
        secure       = secure,
        http_only    = http_only,
        domain       = domain,
        # JWT
        jwt_secret   = jwt_secret,
        public_key   = public_key,
        algorithm    = algorithm,
        leeway       = leeway,
        expiration   = expiration,
        http_header  = http_header,
        auth_type    = auth_type,
        callback     = callback,
        json_encoder = json_encoder
    )


def _set_authentication_policy(config,
                               # cookie
                               tkt_secret   = None,
                               cookie_name  = None,
                               secure       = None,
                               http_only    = None,
                               domain       = None,
                               # JWT
                               private_key  = None,
                               public_key   = None,
                               algorithm    = None,
                               expiration   = None,
                               leeway       = None,
                               http_header  = None,
                               auth_type    = None,
                               callback     = None,
                               json_encoder = None
                               ):
    policy = _create_jwt_authentication_policy(config,
                                               # cookie
                                               tkt_secret,
                                               cookie_name,
                                               secure,
                                               http_only,
                                               domain,
                                               # JWT
                                               private_key,
                                               public_key,
                                               algorithm,
                                               expiration,
                                               leeway,
                                               http_header,
                                               auth_type,
                                               callback,
                                               json_encoder
                                               )

    def _request_create_token(request, principal, expiration=None, **claims):
        csrf_token = policy.new_csrf_token(request)
        request.response.headers['X-CSRF-Token'] = csrf_token
        return policy.create_token(principal, csrf_token, expiration, **claims)

    def _request_claims(request):
        return policy.get_claims(request)

    #  TODO: add CSRF

    config.set_default_csrf_options(token=None)
    config.set_csrf_storage_policy(policy)
    config.set_authentication_policy(policy)
    config.add_request_method(_request_create_token, 'create_jwt_token')
    config.add_request_method(_request_claims, 'jwt_claims', reify=True)
