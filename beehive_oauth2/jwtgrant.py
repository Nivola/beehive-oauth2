# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2023 CSI-Piemonte

from __future__ import absolute_import, unicode_literals
import ujson as json
import binascii
from oauthlib.oauth2.rfc6749.clients.base import Client
from oauthlib.oauth2.rfc6749.parameters import prepare_token_request
from oauthlib.oauth2.rfc6749.endpoints.token import TokenEndpoint
from oauthlib.oauth2.rfc6749.endpoints.resource import ResourceEndpoint
from oauthlib.oauth2.rfc6749.endpoints.revocation import RevocationEndpoint
from oauthlib.oauth2.rfc6749.tokens import BearerToken
from beehive_oauth2.model import GrantType
from oauthlib.oauth2.rfc6749.grant_types.base import GrantTypeBase
from oauthlib.oauth2.rfc6749 import errors, parameters
from logging import getLogger
from oauthlib.oauth2.rfc6749.errors import OAuth2Error
from jwt import decode as jwt_decode
from beehive.common.apimanager import ApiManagerError
from jwt.exceptions import MissingRequiredClaimError
from beecell.simple import jsonDumps

log = getLogger(__name__)


def raise_from_error(error, params=None):
    errors.raise_from_error(error, params)
    import inspect
    import sys

    kwargs = {
        "description": params.get("error_description"),
        "uri": params.get("error_uri"),
        "state": params.get("state"),
    }
    for _, cls in inspect.getmembers(sys.modules[__name__], inspect.isclass):
        if cls.error == error:
            raise cls(**kwargs)


parameters.raise_from_error = raise_from_error


class InvalidJwtError(OAuth2Error):
    """The requested jwt is invalid, unknown, or malformed."""

    error = "invalid_jwt"
    status_code = 401


class InvalidUserError(OAuth2Error):
    """The requested user is invalid, unknown, or malformed."""

    error = "invalid_user"
    status_code = 401


class JwtGrant(GrantTypeBase):
    """`JSON Web Token (JWT) Profile for OAuth 2.0 Client`_

    To use a Bearer JWT as an authorization grant, the client uses an
    access token request as defined in Section 4 of the OAuth Assertion
    Framework [RFC7521] with the following specific parameter values and
    encodings.

    The value of the "grant_type" is "urn:ietf:params:oauth:grant-
    type:jwt-bearer".

    The value of the "assertion" parameter MUST contain a single JWT.

    The "scope" parameter may be used, as defined in the OAuth Assertion
    Framework [RFC7521], to indicate the requested scope.

    Authentication of the client is optional, as described in
    Section 3.2.1 of OAuth 2.0 [RFC6749] and consequently, the
    "client_id" is only needed when a form of client authentication that
    relies on the parameter is used.

    The following example demonstrates an access token request with a JWT
    as an authorization grant (with extra line breaks for display
    purposes only):

      POST /token.oauth2 HTTP/1.1
      Host: as.example.com
      Content-Type: application/x-www-form-urlencoded

      grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer
      &assertion=eyJhbGciOiJFUzI1NiIsImtpZCI6IjE2In0.
      eyJpc3Mi[...omitted for brevity...].
      J9l-ZhwP[...omitted for brevity...]

        +---------+                                  +---------------+
        :         :                                  :               :
        :         :>-- A ---- Send JWT ------------->: Authorization :
        : Client  :                                  :     Server    :
        :         :<-- B ---- Access Token ---------<:               :
        :         :                                  :               :
        +---------+                                  +---------------+

    Figure: JWT Flow

    .. _`JSON Web Token (JWT) Profile for OAuth 2.0 Client`: https://tools.ietf.org/html/rfc7523#section-2.1
    """

    def __init__(self, request_validator=None, **kwargs):
        GrantTypeBase.__init__(self, request_validator, **kwargs)
        self.logger = getLogger(self.__class__.__module__ + "." + self.__class__.__name__)
        from beehive_oauth2.controller import Oauth2Controller

        self.controller: Oauth2Controller = request_validator.controller

    def create_token_response(self, request, token_handler):
        """Return token or error in JSON format.

        If the access token request is valid and authorized, the authorization server issues an access token as
        described in `Section 5.1`_.  A refresh token SHOULD NOT be included.  If the request failed client
        authentication or is invalid, the authorization server returns an error response as described in `Section 5.2`_.

        .. _`Section 5.1`: http://tools.ietf.org/html/rfc6749#section-5.1
        .. _`Section 5.2`: http://tools.ietf.org/html/rfc6749#section-5.2
        """
        headers = {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        }
        try:
            log.debug("Validating access token request, %r.", request)
            self.validate_token_request(request)
        except errors.OAuth2Error as e:
            log.debug("Client error in token request. %s.", e)
            return headers, e.json, e.status_code

        token = token_handler.create_token(request, refresh_token=False, save_token=False)

        for modifier in self._token_modifiers:
            token = modifier(token)
        self.request_validator.save_token(token, request)

        log.debug(
            "Issuing token to client id %r (%r), %r.",
            request.client_id,
            request.client,
            token,
        )
        return headers, jsonDumps(token), 200

    def validate_jwt(self, request):
        """Ensure jwt is valid.

        :param request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - JWT Bearer Code Grant
        """
        client = request.ormclient

        # get jwt
        assertion = request.body.get("assertion", None)
        if assertion is None:
            msg = "Jwt token assertion is missing"
            self.logger.error(msg)
            raise InvalidJwtError(description=msg, request=request)

        try:
            # token_uri = request.body['token_uri']
            audience = "nivola"
            public_key = binascii.a2b_base64(client.public_key)
            # decoded = jwt_decode(assertion, public_key, algorithm='RS512', audience=audience)
            decoded = jwt_decode(assertion, public_key, algorithms=["RS512"], audience=audience)
        except MissingRequiredClaimError as ex:
            msg = "Token is missing the claim %s" % ex.claim
            self.logger.error(msg)
            raise InvalidJwtError(description=msg, request=request)
        except Exception as ex:
            self.logger.error(str(ex))
            raise InvalidJwtError(description=str(ex), request=request)

        # verify iss
        iss = client.user.name
        if decoded.get("iss", "") != iss:
            msg = "Jwt iss does not match client %s user" % client.uuid
            self.logger.error(msg)
            raise InvalidJwtError(description=msg, request=request)

        # verify sub
        sub = decoded.get("sub", None)
        if sub is not None:
            cred = sub.split(":")
            if len(cred) < 2:
                raise InvalidJwtError(description="Credential are wrong", request=request)
            request.user, request.secret = cred
        else:
            request.user = client.user.name
            request.secret = None
            self.logger.debug("Jwt sub is not specified. Use client user %s" % client.user_id)

        request.scopes = request.body.get("scope", "").split(",")
        # request.scopes = decoded.get('scope', '').split(',')
        self.logger.info("Validate jwt %s" % decoded)
        return True

    def authenticate_user(self, request):
        """Ensure the username and password are valid.

        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False
        """
        try:
            name_domain = request.user.split("@")
            name = name_domain[0]
            password = None
            secret = request.secret
            login_ip = request.login_ip
            try:
                domain = name_domain[1]
            except:
                domain = "local"
        except:
            raise InvalidUserError(description="User must be <user>@<domain>", request=request)

        # validate input params
        try:
            self.controller.validate_login_params(name, domain, password, login_ip)
        except ApiManagerError as ex:
            raise InvalidUserError(ex.value, request=request)

        # check user
        try:
            dbuser, dbuser_attribs = self.controller.check_login_user(name, domain, password, login_ip)
        except ApiManagerError as ex:
            raise InvalidUserError(ex.value, request=request)

        # login user
        try:
            user, attrib = self.controller.check_base_login(name, domain, secret, login_ip, dbuser, dbuser_attribs)
            request.ormuser = user
            request.user_attribs = attrib
        except ApiManagerError as ex:
            raise InvalidUserError(ex.value, request=request)

        return True

    def validate_token_request(self, request):
        """ """
        try:
            for validator in self.custom_validators.pre_token:
                validator(request)

            if not getattr(request, "grant_type", None):
                raise errors.InvalidRequestError("Request is missing grant type.", request=request)

            if not request.grant_type == GrantType.JWT_BEARER:
                raise errors.UnsupportedGrantTypeError(request=request)

            for param in ("grant_type", "scope"):
                if param in request.duplicate_params:
                    raise errors.InvalidRequestError(description="Duplicate %s parameter." % param, request=request)

            log.debug("Authenticating client, %r.", request)
            if not self.request_validator.authenticate_client(request):
                log.debug("Client authentication failed, %r.", request)
                raise errors.InvalidClientError(request=request)
            else:
                if not hasattr(request.client, "client_id"):
                    raise NotImplementedError(
                        "Authenticate client must set the request.client.client_id attribute " "in authenticate_client."
                    )

            # validate jwt
            self.validate_jwt(request=request)

            # Ensure client is authorized use of this grant type
            self.validate_grant_type(request)

            # validate and authenticate user
            self.authenticate_user(request)

            # request.client_id = request.client_id or request.client.client_id
            self.validate_scopes(request)

            for validator in self.custom_validators.post_token:
                validator(request)
        except:
            self.logger.error("", exc_info=1)
            raise


class JWTClient(Client):
    """A client that implement the use case 'JWTs as Authorization Grants' of
    the rfc7523.
    """

    def prepare_request_body(self, body="", scope=None, **kwargs):
        """Add the client credentials to the request body.

        The client makes a request to the token endpoint by adding the following parameters using the
        "application/x-www-form-urlencoded" format per `Appendix B`_ in the HTTP request entity-body:

        :param scope:   The scope of the access request as described by `Section 3.3`_.
        :param kwargs:  Extra credentials to include in the token request.

        The client MUST authenticate with the authorization server as described in `Section 3.2.1`_.

        The prepared body will include all provided credentials as well as the ``grant_type`` parameter set to
        ``client_credentials``::

            >>> from oauthlib.oauth2 import BackendApplicationClient
            >>> client = BackendApplicationClient('your_id')
            >>> client.prepare_request_body(scope=['hello', 'world'])
            'grant_type=client_credentials&scope=hello+world'

        .. _`Appendix B`: http://tools.ietf.org/html/rfc6749#appendix-B
        .. _`Section 3.3`: http://tools.ietf.org/html/rfc6749#section-3.3
        .. _`Section 3.2.1`: http://tools.ietf.org/html/rfc6749#section-3.2.1
        """
        grant_type = GrantType.JWT_BEARER
        return prepare_token_request(grant_type, body=body, scope=scope, **kwargs)


class JwtApplicationServer(TokenEndpoint, ResourceEndpoint, RevocationEndpoint):
    """An all-in-one endpoint featuring JwtGrant grant and Bearer tokens."""

    def __init__(self, request_validator, token_generator=None, token_expires_in=None, **kwargs):
        """Construct a client credentials grant server.

        :param request_validator: An implementation of oauthlib.oauth2.RequestValidator.
        :param token_expires_in: An int or a function to generate a token expiration offset (in seconds) given a
            oauthlib.common.Request object.
        :param token_generator: A function to generate a token from a request.
        :param kwargs: Extra parameters to pass to authorization-, token-, resource-, and revocation-endpoint
            constructors.
        """
        jwt_grant = JwtGrant(request_validator)
        bearer = BearerToken(request_validator, token_generator, token_expires_in, None)
        TokenEndpoint.__init__(
            self,
            default_grant_type=GrantType.JWT_BEARER,
            grant_types={GrantType.JWT_BEARER: jwt_grant},
            default_token_type=bearer,
        )
        ResourceEndpoint.__init__(self, default_token="Bearer", token_types={"Bearer": bearer})
        RevocationEndpoint.__init__(self, request_validator, supported_token_types=["access_token"])
