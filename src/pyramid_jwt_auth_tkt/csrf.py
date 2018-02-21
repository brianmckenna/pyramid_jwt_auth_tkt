
from pyramid.compat import text_,
from pyramid.interfaces import ICSRFStoragePolicy
from uuid import uuid4
from zope.interface import implementer

@implementer(ICSRFStoragePolicy)
class CookieCSRFStoragePolicy(object):
    """ An alternative CSRF implementation that stores its information in
    unauthenticated cookies, known as the 'Double Submit Cookie' method in the
    `OWASP CSRF guidelines <https://www.owasp.org/index.php/
    Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#
    Double_Submit_Cookie>`_. This gives some additional flexibility with
    regards to scaling as the tokens can be generated and verified by a
    front-end server.
    .. versionadded:: 1.9
    """
    _token_factory = staticmethod(lambda: text_(uuid4().hex))

    def new_csrf_token(self, request):
        """ Sets a new CSRF token into the request and returns it. """
        token = self._token_factory()
        request.cookies[self.cookie_name] = token
        def set_cookie(request, response):
            self.cookie_profile.set_cookies(
                response,
                token,
            )
        request.add_response_callback(set_cookie)
        return token

    def get_csrf_token(self, request):
        """ Returns the currently active CSRF token by checking the cookies
        sent with the current request."""
        bound_cookies = self.cookie_profile.bind(request)
        token = bound_cookies.get_value()
        if not token:
            token = self.new_csrf_token(request)
        return token

    def check_csrf_token(self, request, supplied_token):
        """ Returns ``True`` if the ``supplied_token`` is valid."""
        expected_token = self.get_csrf_token(request)
        return not strings_differ(
            bytes_(expected_token), bytes_(supplied_token))
