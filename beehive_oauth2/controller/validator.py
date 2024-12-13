# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2024 CSI-Piemonte

# -*- coding: utf-8 -*-
import ujson as json
from six import ensure_text
from oauthlib.oauth2 import RequestValidator
from logging import getLogger
from six import ensure_text
from beecell.simple import truncate
from datetime import datetime, timedelta
from beecell.db import ModelError
from beehive_oauth2.model import (
    Oauth2DbManager,
    GrantType,
    Oauth2Client,
    Oauth2AuthorizationCode,
    Oauth2Scope,
)
from beehive.common.data import query, operation, transaction
from beehive_oauth2.jwtgrant import JWTClient
from oauthlib.common import Request
from beehive.common.model.authorization import User, AuthDbManager
from oauthlib.oauth2.rfc6749.clients.web_application import WebApplicationClient
from oauthlib.oauth2.rfc6749.clients.backend_application import BackendApplicationClient
from oauthlib.oauth2.rfc6749 import errors
from beehive.common.apimanager import ApiManagerError
from oauthlib.oauth2.rfc6749.clients.legacy_application import LegacyApplicationClient
from beecell.auth.base import SystemUser
import binascii
from zlib import compress
from beecell.simple import jsonDumps
from sqlalchemy.orm import Session

# from typing import Dict

from .oauth2controller import Oauth2Controller


class Oauth2RequestValidator(RequestValidator):
    def __init__(self, controller: Oauth2Controller = None, *args, **kwargs):
        RequestValidator.__init__(args, **kwargs)
        self.logger = getLogger(self.__class__.__module__ + "." + self.__class__.__name__)
        self.controller = controller
        self.dbmanager = Oauth2DbManager()
        self.dbauth = AuthDbManager()

    def client_authentication_required(self, request, *args, **kwargs):
        """Determine if client authentication is required for current request.

        According to the rfc6749, client authentication is required in the following cases:
            - Resource Owner Password Credentials Grant, when Client type is Confidential or when
              Client was issued client credentials or whenever Client provided client
              authentication, see `Section 4.3.2`_.
            - Authorization Code Grant, when Client type is Confidential or when Client was issued
              client credentials or whenever Client provided client authentication,
              see `Section 4.1.3`_.
            - Refresh Token Grant, when Client type is Confidential or when Client was issued
              client credentials or whenever Client provided client authentication, see
              `Section 6`_

        :param request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Resource Owner Password Credentials Grant
            - Refresh Token Grant

        .. _`Section 4.3.2`: http://tools.ietf.org/html/rfc6749#section-4.3.2
        .. _`Section 4.1.3`: http://tools.ietf.org/html/rfc6749#section-4.1.3
        .. _`Section 6`: http://tools.ietf.org/html/rfc6749#section-6
        """
        return True

    @query
    def authenticate_client(self, request: Request, *args, **kwargs):
        """Authenticate client through means outside the OAuth 2 spec.

        Means of authentication is negotiated beforehand and may for example
        be `HTTP Basic Authentication Scheme`_ which utilizes the Authorization
        header.

        Headers may be accesses through request.headers and parameters found in
        both body and query can be obtained by direct attribute access, i.e.
        request.client_id for client_id in the URL query.

        :param request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Resource Owner Password Credentials Grant (may be disabled)
            - Client Credentials Grant
            - Refresh Token Grant

        .. _`HTTP Basic Authentication Scheme`: http://tools.ietf.org/html/rfc1945#section-11.1
        """
        session: Session = operation.session

        try:
            # get client id
            client_id = request.body["client_id"]
            query = session.query(Oauth2Client).filter_by(uuid=client_id)
            orm_client: Oauth2Client = query.first()
            request.ormclient = orm_client

            if orm_client is None:
                return False

            # get client associated user
            dbuser: User = session.query(User).filter_by(id=orm_client.user_id).first()
            # get user attributes
            dbuser_attribs: dict = {a.name: (a.value, a.desc) for a in dbuser.attrib}
            # get login user
            email: str = dbuser.email
            if email is None:
                email = dbuser.name
            user = SystemUser(dbuser.name, email, None, dbuser.active, login_ip=request.login_ip)
            # set user attributes

            # set user permission
            self.__set_user_perms(dbuser, user)
            # set user roles
            self.__set_user_roles(dbuser, user)
            request.ormuser = user
            request.user_attribs = dbuser_attribs

            request.ormuser = user

            # get grant type
            grant_type = request.body["grant_type"]

            if grant_type == GrantType.AUTHORIZATION_CODE:
                client_secret = request.body["client_secret"]
                if orm_client.client_secret != client_secret:
                    raise ModelError("Client %s authentication failed" % client_id)

                client = WebApplicationClient(client_id=client_id)

            elif grant_type == GrantType.IMPLICIT:
                pass

            elif grant_type == GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIAL:
                client = LegacyApplicationClient(client_id=client_id)

            elif grant_type == GrantType.CLIENT_CRDENTIAL:
                client_secret = request.body["client_secret"]
                if orm_client.client_secret != client_secret:
                    raise ModelError("Client %s authentication failed" % client_id)
                client = BackendApplicationClient(client_id=client_id)

            elif grant_type == GrantType.JWT_BEARER:
                if orm_client is None:
                    raise ModelError("Client %s does not exists" % client_id)
                client = JWTClient(client_id=client_id)

            request.client = client
            self.logger.info("Authenticate client %s" % client_id)
            return True
        except ModelError as ex:
            self.logger.error(ex, exc_info=1)
            return False
        except Exception as ex:
            self.logger.error(ex.message, exc_info=1)
            return False

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        """Ensure client_id belong to a non-confidential client.

        A non-confidential client is one that is not required to authenticate
        through other means, such as using HTTP Basic.

        Note, while not strictly necessary it can often be very convenient
        to set request.client to the client object associated with the
        given client_id.

        :param request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
        """
        raise NotImplementedError("Subclasses must implement authenticate_client_id.")

    @query
    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
        """Ensure that the authorization process represented by this authorization
        code began with this 'redirect_uri'.

        If the client specifies a redirect_uri when obtaining code then that
        redirect URI must be bound to the code and verified equal in this
        method, according to RFC 6749 section 4.1.3.  Do not compare against
        the client's allowed redirect URIs, but against the URI used when the
        code was saved.

        :param client_id: Unicode client identifier
        :param code: Unicode authorization_code.
        :param redirect_uri: Unicode absolute URI
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant (during token request)
        """
        session: Session = operation.session
        try:
            oauth_client = session.query(Oauth2Client).filter_by(uuid=client_id).first()

            auth_code: Oauth2AuthorizationCode = (
                session.query(Oauth2AuthorizationCode)
                .filter_by(client=oauth_client)
                .filter_by(redirect_uri=redirect_uri)
                .filter(Oauth2AuthorizationCode.code.like("%" + code + "%"))
                .first()
            )
            if auth_code is None:
                raise ModelError("Client %s redirect uri does not match" % client_id)

            self.logger.info("Client %s redirect uri matches" % client_id)
            return True
        except ModelError as ex:
            self.logger.error(ex)
            return False

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        """Get the default redirect URI for the client.

        :param client_id: Unicode client identifier
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: The default redirect URI for the client

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """
        raise NotImplementedError("Subclasses must implement get_default_redirect_uri.")

    def get_default_scopes(self, client_id, request: Request, *args, **kwargs):
        """Get the default scopes for the client.

        :param client_id: Unicode client identifier
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: List of default scopes

        Method is used by all core grant types:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials grant
            - Jwt bearer grant
        """

        try:
            client: Oauth2Client = request.ormclient
            scopes = []
            for scope in client.scope:
                scopes.append(scope.name)

            self.logger.info("Get client %s default scopes: %s" % (client_id, scopes))
            return scopes
        except Exception as ex:
            self.logger.error(ex.message, exc_info=1)

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        """Get the list of scopes associated with the refresh token.

        :param refresh_token: Unicode refresh token
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: List of scopes.

        Method is used by:
            - Refresh token grant
        """
        raise NotImplementedError("Subclasses must implement get_original_scopes.")

    def is_within_original_scope(self, request_scopes, refresh_token, request, *args, **kwargs):
        """Check if requested scopes are within a scope of the refresh token.

        When access tokens are refreshed the scope of the new token
        needs to be within the scope of the original token. This is
        ensured by checking that all requested scopes strings are on
        the list returned by the get_original_scopes. If this check
        fails, is_within_original_scope is called. The method can be
        used in situations where returning all valid scopes from the
        get_original_scopes is not practical.

        :param request_scopes: A list of scopes that were requested by client
        :param refresh_token: Unicode refresh_token
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Refresh token grant
        """
        return False

    @query
    def invalidate_authorization_code(self, client_id: str, code: str, request: Request, *args, **kwargs):
        """Invalidate an authorization code after use.

        :param client_id: Unicode client identifier
        :param code: The authorization code grant (request.code).
        :param request: The HTTP Request (oauthlib.common.Request)

        Method is used by:
            - Authorization Code Grant
        """

        session: Session = operation.session
        try:
            auth_code = session.query(Oauth2AuthorizationCode).filter(
                Oauth2AuthorizationCode.code.like("%" + code + "%")
            )
            expires_at = datetime.today() - timedelta(minutes=1)
            auth_code.update({"expires_at": expires_at}, synchronize_session="fetch")

            self.logger.info("Invalidate %s authorization code %s" % (client_id, code))
            return True
        except ModelError as ex:
            self.logger.error(ex)
            return False

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        """Revoke an access or refresh token.

        :param token: The token string.
        :param token_type_hint: access_token or refresh_token.
        :param request: The HTTP Request (oauthlib.common.Request)

        Method is used by:
            - Revocation Endpoint
        """
        raise NotImplementedError("Subclasses must implement revoke_token.")

    def rotate_refresh_token(self, request):
        """Determine whether to rotate the refresh token. Default, yes.

        When access tokens are refreshed the old refresh token can be kept
        or replaced with a new one (rotated). Return True to rotate and
        and False for keeping original.

        :param request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Refresh Token Grant
        """
        return True

    @transaction
    def save_authorization_code(self, client_id, code, request: Request, *args, **kwargs):
        """Persist the authorization_code.

        The code should at minimum be stored with:
            - the client_id (client_id)
            - the redirect URI used (request.redirect_uri)
            - a resource owner / user (request.user)
            - the authorized scopes (request.scopes)
            - the client state, if given (code.get('state'))

        The 'code' argument is actually a dictionary, containing at least a
        'code' key with the actual authorization code:

            {'code': 'sdf345jsdf0934f'}

        It may also have a 'state' key containing a nonce for the client, if it
        chose to send one.  That value should be saved and used in
        'validate_code'.

        :param client_id: Unicode client identifier
        :param code: A dict of the authorization code grant and, optionally, state.
        :param request: The HTTP Request (oauthlib.common.Request)

        Method is used by:
            - Authorization Code Grant
        """

        session = operation.session

        # get client object
        client = session.query(Oauth2Client).filter_by(uuid=client_id).first()

        # get user object
        user = session.query(User).filter_by(id=request.user).first()

        # add code
        data = Oauth2AuthorizationCode(client, user, jsonDumps(code), request.redirect_uri)
        session.add(data)
        session.flush()

        # add scopes
        for scope in request.scopes:
            item = session.query(Oauth2Scope).filter_by(name=scope).first()
            data.scope.append(item)

        self.logger.info("Add authorization code: %s" % data)

    @transaction
    def save_bearer_token(self, token, request: Request, *args, **kwargs):
        """Persist the Bearer token.

        The Bearer token should at minimum be associated with:
            - a client and it's client_id, if available
            - a resource owner / user (request.user)
            - authorized scopes (request.scopes)
            - an expiration time
            - a refresh token, if issued

        The Bearer token dict may hold a number of items::

            {
                'token_type': 'Bearer',
                'access_token': 'askfjh234as9sd8',
                'expires_in': 3600,
                'scope': 'string of space separated authorized scopes',
                'refresh_token': '23sdf876234',  # if issued
                'state': 'given_by_client',  # if supplied by client
            }

        Note that while "scope" is a string-separated list of authorized scopes,
        the original list is still available in request.scopes

        :param client_id: Unicode client identifier
        :param token: A Bearer token dict
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: The default redirect URI for the client

        Method is used by all core grant types issuing Bearer tokens:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant (might not associate a client)
            - Client Credentials grant
            - Jwt Grant
        """
        try:
            session = operation.session

            # get client object
            client = session.query(Oauth2Client).filter_by(uuid=request.client_id).first()

            # Authorization Code Grant - set user
            if request.grant_type == "authorization_code":
                codes, total = self.dbmanager.get_authorization_codes(code=request.code)
                code = codes[0]
                user_id = code.user_id

                # get user
                dbuser = session.query(User).filter_by(id=user_id).first()
                # get user attributes
                dbuser_attribs = {a.name: (a.value, a.desc) for a in dbuser.attrib}
                # get login user
                email = dbuser.email
                if email is None:
                    email = dbuser.name
                user = SystemUser(dbuser.uuid, email, None, dbuser.active, login_ip=request.login_ip)
                # set user attributes

                # set user permission
                self.__set_user_perms(dbuser, user)
                # set user roles
                self.__set_user_roles(dbuser, user)
                request.ormuser = user
                request.user_attribs = dbuser_attribs

            # Authorization Code Grant
            # Implicit Grant
            # Resource Owner Password Credentials Grant (might not associate a client)
            # Jwt Grant
            if request.ormuser is not None:
                user = request.ormuser.get_dict()
                user_id = user.get("id")
                user_name = user.get("name")
                token["user"] = user_id
                token_user = user

            # Client Credentials grant
            else:
                token["user"] = None
                token_user = None
                user_name = None
                user_id = None

            # user_id = data.pop('user')
            timestamp = datetime.now()

            # get user
            # user = self.dbauth.get_users(uuid=user_id)[0][0]

            # get login ip
            login_ip = request.login_ip

            # create identity
            uid = token["access_token"]
            identity = {
                "uid": uid,
                "type": "oauth2",
                "oauth2_type": request.body["grant_type"],
                "user": token_user,
                "timestamp": timestamp,
                "ip": login_ip,
                "scope": request.scope,
            }
            self.logger.debug("Create identity: %s" % (truncate(identity)))

            # set user in thread local variable
            operation.user = (user_id, login_ip, uid)

            # save identity in redis
            self.controller.set_identity(uid, identity, expire=True, expire_time=token["expires_in"])

            self.logger.info("Add bearer token: %s" % token)
            return client.redirect_uri
        except ModelError as ex:
            self.logger.error(ex)
            return None

    @query
    def validate_bearer_token(self, token, scopes, request):
        """Ensure the Bearer token is valid and authorized access to scopes.

        :param token: A string of random characters.
        :param scopes: A list of scopes associated with the protected resource.
        :param request: The HTTP Request (oauthlib.common.Request)

        A key to OAuth 2 security and restricting impact of leaked tokens is
        the short expiration time of tokens, *always ensure the token has not
        expired!*.

        Two different approaches to scope validation:

            1) all(scopes). The token must be authorized access to all scopes
                            associated with the resource. For example, the
                            token has access to ``read-only`` and ``images``,
                            thus the client can view images but not upload new.
                            Allows for fine grained access control through
                            combining various scopes.

            2) any(scopes). The token must be authorized access to one of the
                            scopes associated with the resource. For example,
                            token has access to ``read-only-images``.
                            Allows for fine grained, although arguably less
                            convenient, access control.

        A powerful way to use scopes would mimic UNIX ACLs and see a scope
        as a group with certain privileges. For a restful API these might
        map to HTTP verbs instead of read, write and execute.

        Note, the request.user attribute can be set to the resource owner
        associated with this token. Similarly the request.client and
        request.scopes attribute can be set to associated client object
        and authorized scopes. If you then use a decorator such as the
        one provided for django these attributes will be made available
        in all protected views as keyword arguments.

        :param token: Unicode Bearer token
        :param scopes: List of scopes (defined by you)
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is indirectly used by all core Bearer token issuing grant types:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials Grant
        """
        raise NotImplementedError("Subclasses must implement validate_bearer_token.")

    @query
    def validate_client_id(self, client_id, request: Request, *args, **kwargs):
        """Ensure client_id belong to a valid and active client.

        Note, while not strictly necessary it can often be very convenient
        to set request.client to the client object associated with the
        given client_id.

        :param client_id:
        :param request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """

        session = operation.session
        try:
            client: Oauth2Client = session.query(Oauth2Client).filter_by(uuid=client_id).filter_by(active=True).first()

            if client is None:
                raise ModelError("Client %s is not valid" % client_id)

            request.ormclient = client

            self.logger.info("Validate client %s" % client_id)
            return True
        except ModelError as ex:
            self.logger.error(ex)
            return False

    @query
    def validate_code(self, client_id, code, client, request: Request, *args, **kwargs):
        """Verify that the authorization_code is valid and assigned to the given
        client.

        Before returning true, set the following based on the information stored
        with the code in 'save_authorization_code':

            - request.user
            - request.state (if given)
            - request.scopes
        OBS! The request.user attribute should be set to the resource owner
        associated with this authorization code. Similarly request.scopes
        must also be set.

        :param client_id: Unicode client identifier
        :param code: Unicode authorization code
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
        """
        session = operation.session
        try:
            oauth_client = session.query(Oauth2Client).filter_by(uuid=client_id).first()

            auth_code = (
                session.query(Oauth2AuthorizationCode)
                .filter_by(client=oauth_client)
                .filter(Oauth2AuthorizationCode.code.like("%" + code + "%"))
                .first()
            )
            if auth_code.expires_at < datetime.today():
                raise ModelError("Authorization token %s expired" % code)

            # set request
            request.user = auth_code.user_id
            request.state = json.loads(auth_code.code)["state"]

            scopes = []
            for item in auth_code.scope:
                scopes.append(item.name)

            request.scopes = scopes

            self.logger.info("Validate %s authorization code %s" % (client_id, code))
            return True
        except ModelError as ex:
            self.logger.error(ex)
            return False

    @query
    def validate_grant_type(self, client_id, grant_type, client, request: Request, *args, **kwargs):
        """Ensure client is authorized to use the grant_type requested.

        :param client_id: Unicode client identifier
        :param grant_type: Unicode grant type, i.e. authorization_code, password.
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials Grant
            - Refresh Token Grant
        """

        oauth_client: Oauth2Client = request.ormclient
        if oauth_client.grant_type != grant_type:
            raise ModelError("Client %s is not authorized to use the grant type %s" % (client_id, grant_type))
        self.logger.info("Validate client %s with grant type %s" % (client_id, grant_type))
        return True

    @query
    def validate_redirect_uri(self, client_id, redirect_uri, request: Request, *args, **kwargs):
        """Ensure client is authorized to redirect to the redirect_uri requested.

        All clients should register the absolute URIs of all URIs they intend
        to redirect to. The registration is outside of the scope of oauthlib.

        :param client_id: Unicode client identifier
        :param redirect_uri: Unicode absolute URI
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """

        session = operation.session
        try:
            client = session.query(Oauth2Client).filter_by(uuid=client_id).first()
            if client.redirect_uri != redirect_uri:
                raise ModelError("Redirection uri does not match")
            self.logger.info("Validate client %s redirection uri %s" % (client_id, redirect_uri))
            return True
        except ModelError as ex:
            self.logger.error(ex)
            return False

    @query
    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        """Ensure the Bearer token is valid and authorized access to scopes.

        OBS! The request.user attribute should be set to the resource owner
        associated with this refresh token.

        :param refresh_token: Unicode refresh token
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant (indirectly by issuing refresh tokens)
            - Resource Owner Password Credentials Grant (also indirectly)
            - Refresh Token Grant
        """
        raise NotImplementedError("Subclasses must implement validate_refresh_token.")

    @query
    def validate_response_type(self, client_id, response_type, client, request: Request, *args, **kwargs):
        """Ensure client is authorized to use the response_type requested.

        :param client_id: Unicode client identifier
        :param response_type: Unicode response type, i.e. code, token.
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """

        session = operation.session
        try:
            oauth_client = session.query(Oauth2Client).filter_by(uuid=client_id).first()
            if oauth_client.response_type != response_type:
                raise ModelError("Response type does not match")
            self.logger.info("Validate client %s response type %s" % (client_id, response_type))
            return True
        except ModelError as ex:
            self.logger.error(ex)
            return False

    @query
    def validate_scopes(self, client_id, scopes, client, request: Request, *args, **kwargs):
        """Ensure the client is authorized access to requested scopes.

        :param client_id: Unicode client identifier
        :param scopes: List of scopes (defined by you)
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by all core grant types:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials Grant
            - Jwt bearer Grant
        """
        try:
            oauth_client: Oauth2Client = request.ormclient
            client_scope = [ensure_text(c.name) for c in oauth_client.scope]

            if set(scopes).issubset(set(client_scope)):
                self.logger.info("Validate client %s scopes %s" % (client_id, scopes))
                return True

            raise ModelError("Scopes does not match")
        except ModelError as ex:
            self.logger.error(ex)
            return False

    @query
    def validate_user(self, username, password, client=None, request: Request = None, *args, **kwargs):
        """Ensure the username and password is valid.

        OBS! The validation should also set the user attribute of the request
        to a valid resource owner, i.e. request.user = username or similar. If
        not set you will be unable to associate a token with a user in the
        persistance method used (commonly, save_bearer_token).

        :param username: Unicode username
        :param password: Unicode password
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Resource Owner Password Credentials Grant
        """
        session = operation.session
        try:
            request.user = username
            request.pwd = password
            # request.login_ip
            res = self.authenticate_user(request)
            self.logger.info("Validate user %s: %s" % (username, res))
            return res
        except ApiManagerError:
            return False

    def authenticate_user(self, request: Request, *args, **kwargs):
        """Ensure the username and password is valid.

        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials Grant
            - Jwt bearer Grant
        """
        try:
            name_domain = request.user.split("@")
            name = name_domain[0]
            password = request.pwd
            login_ip = request.login_ip
            try:
                domain = name_domain[1]
            except:
                domain = "local"
        except:
            raise errors.InvalidRequestError("User must be <user>@<domain>", request=request)

        # validate input params
        self.controller.validate_login_params(name, domain, password, login_ip)

        # check user
        dbuser, dbuser_attribs = self.controller.check_login_user(name, domain, password, login_ip)

        # login user
        user, attrib = self.controller.extended_login(name, domain, password, login_ip, dbuser, dbuser_attribs)
        request.ormuser = user
        request.user_attribs = attrib

        return True

    def __set_user_attribs(self, user: SystemUser, attribs):
        """Set user attributes"""
        user.set_attributes(attribs)

    def __set_user_perms(self, dbuser: User, user: SystemUser):
        """Set user permissions"""
        perms = self.dbauth.get_login_permissions(dbuser)
        compress_perms = binascii.b2a_base64(compress(jsonDumps(perms).encode("utf-8")))
        user.set_perms(compress_perms)

    def __set_user_roles(self, dbuser: User, user: SystemUser):
        """Set user roles"""
        roles = self.dbauth.get_login_roles(dbuser)
        user.set_roles([r.name for r in roles])
