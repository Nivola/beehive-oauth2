# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2024 CSI-Piemonte


import os
from inspect import getfile
from typing import Union
from copy import deepcopy
from oauthlib.oauth2 import (
    WebApplicationServer,
    MobileApplicationServer,
    LegacyApplicationServer,
    BackendApplicationServer,
    FatalClientError,
    OAuth2Error,
)
from flask import request
from flask.helpers import url_for
from flask_login import LoginManager

from beecell.simple import (
    id_gen,
    truncate,
    get_value,
    random_password,
    token_gen,
)
from beecell.db import TransactionError
from beecell.flask.render import render_template
from beecell.crypto_util.rsa_crypto import RasCrypto

from beehive.common.apimanager import ApiManagerError
from beehive.common.data import operation, trace
from beehive.common.controller.authorization import BaseAuthController
from beehive.module.auth.controller import AuthController, User
from beehive.module.auth.controller import Token  # DO NOT REMOVE USED IMPLICTLY

from beehive_oauth2.model import (
    Oauth2Client as ModelOauth2Client,
    Oauth2Scope as ModelOauth2Scope,
    Oauth2AuthorizationCode as ModelOauth2AuthorizationCode,
    Oauth2DbManager,
    GrantType,
)
from beehive_oauth2.jwtgrant import JwtApplicationServer

from .oauth2client import Oauth2Client
from .oauth2scope import Oauth2Scope
from .oauth2authorizationcode import Oauth2AuthorizationCode
from .systemuser import SystemUser


class Oauth2Controller(AuthController):
    """Oauth2 controller."""

    version = "v1.0"

    # authorize state
    LOGIN = 0
    SCOPE = 1
    AUTHORIZE = 2

    def __init__(self, module):
        AuthController.__init__(self, module)

        # get module path
        path = os.path.dirname(getfile(Oauth2Controller))

        self.child_classes = [Oauth2Client, Oauth2Scope, Oauth2AuthorizationCode]
        self.manager = Oauth2DbManager()

        try:
            self.path = path
            self.app = module.api_manager.app

            if self.app is not None:
                self.app.template_folder = "%s/templates" % path
                self.app.static_folder = "%s/static" % path

                # setup app babel
                # self.app.babel = Babel(app=self.app, default_locale='it', default_timezone='utc')

                # self.languages = {
                #     'en': 'English',
                #     'it': 'Italian',
                # }

                # setup app login manager
                self.app.login_manager = LoginManager(self.app)
                login_view = "login"
                self.app.login_manager.login_view = login_view

                @self.app.login_manager.user_loader
                def load_user(userid):
                    return SystemUser.load_user(userid)

            # get module reference
            self.authmod = self.module.api_manager.get_module("AuthModule")

            self.auth_uri = "%s/%s/oauth2/authorize" % (
                self.module.api_manager.oauth2_endpoint,
                self.version,
            )
            self.token_uri = "%s/%s/oauth2/token" % (
                self.module.api_manager.oauth2_endpoint,
                self.version,
            )
        except:
            self.logger.warning("", exc_info=True)

    def init_object(self):
        """Register object types, objects and permissions related to module.
        Call this function when initialize system first time.
        """
        BaseAuthController.init_object(self)

    def get_server(
        self, grant_type
    ) -> Union[
        WebApplicationServer,
        MobileApplicationServer,
        LegacyApplicationServer,
        BackendApplicationServer,
        JwtApplicationServer,
    ]:
        """Get server

        :param grant_type: grant type. One of:

            * authorization_code
            * implicit
            * resource_owner_password_credentials
            * client_credentials
            * urn:ietf:params:oauth:grant-type:jwt-bearer

        :return:

            instance of :class:`WebApplicationServer` or
            :class:`MobileApplicationServer` or
            :class:`LegacyApplicationServer` or
            :class:`BackendApplicationServer` or
            :class:`JwtApplicationServer`

        :raise ApiManagerError:
        """
        from .validator import Oauth2RequestValidator

        validator = Oauth2RequestValidator(self)

        if grant_type == GrantType.AUTHORIZATION_CODE:
            server = WebApplicationServer(validator, token_generator=token_gen)

        elif grant_type == GrantType.IMPLICIT:
            server = MobileApplicationServer(validator, token_generator=token_gen)

        elif grant_type == GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIAL:
            server = LegacyApplicationServer(validator, token_generator=token_gen)

        elif grant_type == GrantType.CLIENT_CRDENTIAL:
            server = BackendApplicationServer(validator, token_generator=token_gen)

        elif grant_type == GrantType.JWT_BEARER:
            server = JwtApplicationServer(validator, token_generator=token_gen)

        return server

    def authenticate_client(self, uri, http_method, body, headers):
        """Authenticate client and return credentials

        :param uri:
        :param http_method:
        :param body:
        :param headers:

        :return: client credentials

            {
                'state': '0Zf9apA3I9HFPbR2r5sZGDlIgdj9mi',
                'redirect_uri': 'https://localhost:7443/authorize',
                'response_type': 'code',
                'client_id': '8a994dd1-e96b-4092-8a14-ede3f77d8a2c'
                'scope': ['beehive', 'auth']
            }

        :raise ApiManagerError:
        """
        try:
            # get oauthlib.oauth2 server
            server = self.get_server(GrantType.AUTHORIZATION_CODE)

            scopes, credentials = server.validate_authorization_request(uri, http_method, body, headers)

            # Not necessarily in session but they need to be
            # accessible in the POST view after form submit.
            credentials.pop("request")
            credentials["scope"] = scopes

            self.logger.debug("Validate client credentials %s" % credentials)
            return credentials
        # Errors embedded in the redirect URI back to the client
        except OAuth2Error as e:
            self.logger.error(e, exc_info=True)
            raise ApiManagerError(e, code=420)

        # Errors that should be shown to the user on the provider website
        except FatalClientError as e:
            self.logger.error(e, exc_info=True)
            raise ApiManagerError(e, code=421)

        # Errors
        except Exception as e:
            self.logger.error(str(e), exc_info=True)
            raise ApiManagerError(str(e), code=400)

    def get_credentials(self, session):
        """Get client credentials from session

        :param session: flask session
        :return: client credentials
        :raise ApiManagerError:
        """
        credentials = None
        if "oauth2_credentials" in session:
            # get credentials
            credentials = session["oauth2_credentials"]
        user = session.get("oauth2_user", None)
        credentials["user"] = user["id"]
        self.logger.debug("Get client credentials %s in session" % credentials)
        return credentials

    def save_credentials(self, session, credentials):
        """Save client credentials in session

        :param session:  flask session
        :param credentials:  client credentials
        :return: None
        :raise ApiManagerError:
        """
        session["oauth2_credentials"] = credentials
        self.logger.debug("Set client credentials %s in session" % credentials)

    def check_credentials(self, session, credentials):
        """Check client credentials in session

        :param session:  flask session
        :param credentials:  client credentials
        :return: True if credentials match. False if session is invalidated
        :raise ApiManagerError:
        """
        # get credentials
        session_credentials = session["oauth2_credentials"]

        # check credentials in session meet credentials provided
        if credentials.get("client_id") != session_credentials.get("client_id") or credentials.get(
            "state"
        ) != session_credentials.get("state"):
            # invalidate session
            self.invalidate_session(session)
            return False
        return True

    def invalidate_session(self, session):
        """Remove session from session manager

        :param session:  flask session
        :return: credentials
        :raise ApiManagerError:
        """
        self.app.session_interface.remove_session(session)
        return True

    def check_login(self, session):
        """Check login

        :param session: flask session
        :return: credentials
        :raise ApiManagerError:
        """
        # get cookies
        self.logger.debug("Client cookies: %s" % request.cookies)

        # check session
        self.logger.debug("Active user session: %s" % session.sid)

        # check resource owner already login
        user = session.get("oauth2_user", None)
        self.logger.debug("Active user in session: %s" % user)
        if user is not None:
            return user
        self.logger.warning("No valid user found")
        return None

    def check_login_scopes(self, user):
        """ """
        user_scope = user.get("scope", None)
        if user_scope is not None:
            return user_scope
        return None

    def create_authorization(self, uri, http_method, body, headers, scopes, credentials):
        """Create authorization token

        :param uri: uri
        :param http_method: http_method
        :param body: body
        :param headers: headers
        :param scopes: scopes
        :param credentials: credentials
        :return: credentials
        :raise ApiManagerError:
        """
        try:
            # get oauthlib.oauth2 server
            server = self.get_server(GrantType.AUTHORIZATION_CODE)

            headers, body, status = server.create_authorization_response(
                uri,
                http_method=http_method,
                body=body,
                headers=headers,
                scopes=scopes,
                credentials=credentials,
            )

            res = [body, status, headers]
            self.logger.debug("Create authorization: %s" % res)
            return res

        # Errors embedded in the redirect URI back to the client
        except OAuth2Error as e:
            self.logger.error(e, exc_info=True)
            raise ApiManagerError(e, code=420)

        # Errors that should be shown to the user on the provider website
        except FatalClientError as e:
            self.logger.error(e, exc_info=True)
            raise ApiManagerError(e, code=421)

        # Errors
        except Exception as e:
            self.logger.error(str(e), exc_info=True)
            raise ApiManagerError(str(e), code=400)

    def get_client_scopes(self, session):
        """Get available client scopes to propose resource owner

        :param session: flask session
        :return: credentials
        :raise ApiManagerError:
        """
        msg = ""
        # get client_id
        client_id = session["oauth2_credentials"]["client_id"]
        # get client scope
        scope = session["oauth2_credentials"]["scope"]
        self.logger.debug("Get client %s scopes: %s" % (client_id, scope))
        return msg, client_id, scope

    def set_user_scopes(self, session, scopes):
        """Set user scope in session

        :param session: flask session
        :param scopes: list of user scopes
        :return: credentials
        :raise ApiManagerError:
        """
        credentials = session["oauth2_credentials"]
        credentials["scope"] = scopes
        user = session["oauth2_user"]
        user["scope"] = scopes

        self.logger.debug("Set user %s scopes: %s" % (user["name"], scopes))
        return deepcopy(credentials)

    @trace(entity="Token", op="insert")
    def create_token(self, uri, http_method, body, headers, session, login_ip):
        """Create access token

        :param body: request body
        :param session: flask session
        :return: (body, status, headers)
        :raise ApiManagerError:
        """
        try:
            grant_type = get_value(body, "grant_type", None, exception=True)

            # set token_uri
            body["token_uri"] = self.token_uri

            # set login ip
            body["login_ip"] = login_ip

            # get oauthlib.oauth2 server
            credentials = None
            server = self.get_server(grant_type)
            headers, body, status = server.create_token_response(uri, http_method, body, headers, credentials)
            return (body, status, headers)

        # Errors embedded in the redirect URI back to the client
        except OAuth2Error as ex:
            self.logger.error(ex, exc_info=True)
            raise ApiManagerError(ex, code=420)

        # Errors that should be shown to the user on the provider website
        except FatalClientError as ex:
            self.logger.error(ex, exc_info=True)
            raise ApiManagerError(ex, code=421)

        except ApiManagerError as ex:
            self.logger.error(ex.value, exc_info=True)
            raise ApiManagerError(ex.value, code=400)

        except Exception as ex:
            self.logger.error(str(ex), exc_info=True)
            raise ApiManagerError(str(ex), code=400)

    #
    # login, logout\
    #
    @trace(entity="Token", op="insert")
    def login(self, session, name, domain, password, login_ip):
        """Oauth2 login

        :param session: flask session
        :param name: user name
        :param domain: user authentication domain
        :param password: user password
        :param login_ip: user login_ip
        :return: True
        :raise ApiManagerError:
        """
        # validate input params
        self.validate_login_params(name, domain, password, login_ip)

        # check user
        dbuser, dbuser_attribs = self.check_login_user(name, domain, password, login_ip)

        # check user attributes

        # login user
        user, attrib = self.base_login(name, domain, password, login_ip, dbuser, dbuser_attribs)

        # update session info
        session["oauth2_user"] = {"id": dbuser.id, "name": dbuser.name}

        return True

    @trace(entity="Token", op="insert")
    def logout(self, session):
        """Oauth2 logout

        :TODO

        :param session: flask session
        :return: True
        :raise ApiManagerError:
        """
        redis = self.app.session_interface.redis
        key_prefix = self.app.session_interface.key_prefix
        serializer = self.app.session_interface.serializer

        # domain = self.get_cookie_domain(self.app)
        # path = self.get_cookie_path(self.app)
        """if not session:
            if session.modified:
                redis.delete(key_prefix + session.sid)
                #response.delete_cookie(self.app.session_cookie_name,
                #                       domain=domain, path=path)
            return"""

        # remove user session
        user = session.get("oauth2_user", None)
        if user is None:
            user = {"id": None, "name": None}
        self.logger.debug("Get user in session: %s" % user)
        session["_invalidate"] = True

        # self.delete_user_session(session.sid)
        return user

    def login_domains(self):
        """Get authentication domains

        :return: identity
        :raise ApiManagerError:
        """
        try:
            auth_providers = self.authmod.authentication_manager.auth_providers
            domains = []
            for domain, auth_provider in auth_providers.iteritems():
                domains.append([domain, auth_provider.__class__.__name__])
            return domains
        except ApiManagerError as ex:
            self.logger.error("[%s] %s" % (ex.code, ex.value), exc_info=True)
            raise

    def login_page(self, redirect_uri):
        """Configure login page

        :param redirect_uri: redirect uri
        :return: identity
        :raise ApiManagerError:
        """
        # verify that user is not already authenticated
        # TODO

        # get authentication domains
        try:
            domains = self.login_domains()
        except ApiManagerError as ex:
            msg = ex.value

        if redirect_uri is None:
            redirect_uri = "/%s/sso/identity/summary/" % self.version

        return domains, redirect_uri

    def identity(self, style, token, summary=True):
        """Identity

        :param style: style
        :param token: token
        :param summary: summary [default=True]
        :return: identity
        :raise ApiManagerError:
        """
        msg = None

        # get authentication domains
        try:
            controller = self.authmod.get_controller()
            identity = controller.get_identity(token)
            """
            {'uid':..., 'user':..., 'timestamp':..., 'pubkey':...,
             'seckey':...}
            """

        except ApiManagerError as ex:
            self.logger.error("[%s] %s" % (ex.code, ex.value))
            msg = ex.value

        if summary is True:
            self.logger.debug("Use page style: %s" % style)
            return render_template(
                "identity.html",
                msg=msg,
                identity=identity,
                style=url_for("static", filename=style),
            )
        else:
            return identity

    #
    # scope manipulation methods
    #
    @trace(entity="Oauth2Scope", op="view")
    def get_scope(self, oid):
        """Get single scope.

        :param oid: entity model id or name or uuid
        :return: Oauth2Scope
        :raise ApiManagerError:
        """
        return self.get_entity(Oauth2Scope, ModelOauth2Scope, oid)

    @trace(entity="Oauth2Scope", op="view")
    def get_scopes(self, *args, **kvargs):
        """Get scopes or single scope.

        :param page: users list page to show [default=0]
        :param size: number of users to show in list per page [default=0]
        :param order: sort order [default=DESC]
        :param field: sort field [default=id]
        :return: list of Oauth2Scope
        :raise ApiManagerError:
        """

        def get_entities(*args, **kvargs):
            # get filter field
            # permission = kvargs.get('permission', None)

            # get all scopes
            scopes, total = self.manager.get_scopes(*args, **kvargs)

            return scopes, total

        res, total = self.get_paginated_entities(Oauth2Scope, get_entities, *args, **kvargs)
        return res, total

    @trace(entity="Oauth2Scope", op="insert")
    def add_scope(self, name=None, desc=""):
        """Add new scope.

        :param name: name of the scope
        :param desc: scope desc. [Optional]
        :return: Oauth2Scope uuid
        :raise ApiManagerError:
        """
        # check authorization
        self.check_authorization(Oauth2Scope.objtype, Oauth2Scope.objdef, None, "insert")

        try:
            objid = id_gen()
            scope = self.manager.add_scope(objid, name, desc)

            # add object and permission
            Oauth2Scope(self, oid=scope.id).register_object([objid], desc=desc)

            self.logger.debug("Add new scope: %s" % name)
            return scope.uuid
        except TransactionError as ex:
            self.logger.error(ex, exc_info=True)
            raise ApiManagerError(ex, code=ex.code)
        except Exception as ex:
            self.logger.error(str(ex), exc_info=True)
            raise ApiManagerError(str(ex), code=400)

    #
    # client manipulation methods
    #
    @trace(entity="Oauth2Client", op="view")
    def get_client(self, oid):
        """Get single client.

        :param oid: client id, uuid or name [optional]
        :param uuid: client uuid [optional]
        :param name: client name [optional]
        :return: Oauth2Client
        :raise ApiManagerError:
        """
        return self.get_entity(Oauth2Client, ModelOauth2Client, oid)

    @trace(entity="Oauth2Client", op="view")
    def get_clients(self, *args, **kvargs):
        """Get clients or single client.

        :param page: users list page to show [default=0]
        :param size: number of users to show in list per page [default=0]
        :param order: sort order [default=DESC]
        :param field: sort field [default=id]
        :return: list of Oauth2Client
        :raise ApiManagerError:
        """

        def get_entities(*args, **kvargs):
            # get all clients
            clients, total = self.manager.get_clients(*args, **kvargs)

            return clients, total

        res, total = self.get_paginated_entities(Oauth2Client, get_entities, *args, **kvargs)
        return res, total

    @trace(entity="Oauth2Client", op="insert")
    def add_client(
        self,
        name=None,
        grant_type=None,
        redirect_uri=None,
        desc="",
        response_type="code",
        scopes=[],
        expiry_date=None,
        active=True,
        user=None,
    ):
        """Add new client.

        :param name: client name
        :param client_secret: client secret used for all grant type except JWT
        :param user_id: user id associated to client
        :param desc: client desc. [default='']
        :param private_key: private key used by Jwt grant type. [optional]
        :param public_key: public key used by Jwt grant type. [optional]
        :param grant_type: The grant type the client may utilize. This should only be one per client as each grant type
            has different security properties and it is best to keep them separate to avoid mistakes.
        :param response_type: If using a grant type with an associated response type (eg. Authorization Code Grant) or
            using a grant which only utilizes response types (eg. Implicit Grant). [default=code]
        :param scopes: The list of scopes the client may request access to. If you allow multiple types of grants this
            will vary related to their different security properties. For example, the Implicit Grant might only allow
            read-only scopes but the Authorization Grant also allow writes. [default=[]]
        :param redirect_uri: These are the absolute URIs that a client may use to redirect to after authorization. You
            should never allow a client to redirect to a URI that has not previously been registered.
        :param active: True if client is active. False otherwise. [default=True]
        :param expiry_date: relation expiry date [default=365 days]. Set using a datetime object
        :param user: user id, uuid or name that you want to join with client. Set with 'Resource Owner Password
            Credentials Grant'. [optional]
        :return: Oauth2Client uuid
        :raise ApiManagerError:
        """
        params = {
            "name": name,
            "desc": desc,
            "grant_type": grant_type,
            "response_type": response_type,
            "redirect_uri": redirect_uri,
            "expiry_date": expiry_date,
        }

        # if expiry_date is not None:
        #    y, m, d = expiry_date.split('-')
        #    params['expiry_date'] = datetime(int(y), int(m), int(d))

        # check authorization
        self.check_authorization(Oauth2Client.objtype, Oauth2Client.objdef, None, "insert")

        if user is not None:
            user_id = self.get_user(user).oid
        else:
            # create client internal user
            user_name = "%s@local" % name
            user_desc = "Client %s user" % name
            user_uuid = self.add_user(
                name=user_name,
                storetype="DBUSER",
                active=True,
                password=None,
                desc=user_desc,
                expiry_date=expiry_date,
                base=True,
                system=False,
            )
            user_id = self.get_user(user_uuid).oid

        try:
            if grant_type == GrantType.JWT_BEARER:
                client_secret = None
                rsa_crypto = RasCrypto()
                private_key = rsa_crypto.generate_private_key()
                pubkey = rsa_crypto.get_public_key_pem(private_key)
                seckey = rsa_crypto.get_private_key_pem(private_key)
            else:
                client_secret = random_password(length=40)
                pubkey = None
                seckey = None

            params.update(
                {
                    "client_secret": client_secret,
                    "user_id": user_id,
                    "private_key": seckey,
                    "public_key": pubkey,
                }
            )
            objid = id_gen()
            client = self.manager.add_client(objid=objid, **params)

            # append scope to client
            for scope in scopes:
                try:
                    scope_obj = self.get_entity(Oauth2Scope, ModelOauth2Scope, scope)
                    client.scope.append(scope_obj.model)
                except:
                    self.logger.warning("Scope %s was not found" % scope)
            params["scopes"] = scopes
            params["expiry_date"] = expiry_date

            # add object and permission
            Oauth2Client(self, oid=client.id).register_object([objid], desc=desc)

            self.logger.debug("Add new client: %s" % name)
            return client.uuid
        except TransactionError as ex:
            self.logger.error(ex, exc_info=True)
            raise ApiManagerError(ex, code=ex.code)
        except Exception as ex:
            self.logger.error(str(ex), exc_info=True)
            raise ApiManagerError(str(ex), code=400)

    #
    # client manipulation methods
    #
    @trace(entity="Oauth2AuthorizationCode", op="view")
    def get_authorization_code(self, oid):
        """Get single client.

        :param oid: client id, uuid or name [optional]
        :param uuid: client uuid [optional]
        :param name: client name [optional]
        :return: Oauth2Client
        :raise ApiManagerError:
        """
        return self.get_entity(Oauth2AuthorizationCode, ModelOauth2AuthorizationCode, oid)

    @trace(entity="Oauth2AuthorizationCode", op="view")
    def get_authorization_codes(self, *args, **kvargs):
        """Get clients or single client.

        :param code: authorization code [optional]
        :param expire: expire time [optional]
        :param client: client id [optional]
        :param valid: if True get only code not expired [optional]
        :param user: user id [optional]
        :param page: users list page to show [default=0]
        :param size: number of users to show in list per page [default=0]
        :param order: sort order [default=DESC]
        :param field: sort field [default=id]
        :return: list of Oauth2Client
        :raise ApiManagerError:
        """
        user = kvargs.pop("user", None)
        client = kvargs.pop("client", None)
        if user is not None:
            kvargs["user_id"] = self.get_user(user).oid
        if client is not None:
            kvargs["client_id"] = self.get_client(client).oid

        # check authorization
        if operation.authorize is True:
            self.check_authorization(
                Oauth2AuthorizationCode.objtype,
                Oauth2AuthorizationCode.objdef,
                "*",
                "view",
            )

        codes, total = self.manager.get_authorization_codes(*args, **kvargs)
        res = []
        for code in codes:
            res.append(
                Oauth2AuthorizationCode(
                    self,
                    oid=code.id,
                    objid=None,
                    name=None,
                    active=None,
                    desc=None,
                    model=code,
                )
            )

        return res, total

    @trace(entity="Oauth2AuthorizationCode", op="delete")
    def delete_authorization_code(self, code):
        """Get clients or single client.

        :param code: authorization code
        :return: list of Oauth2Client
        :raise ApiManagerError:
        """
        # check authorization
        self.check_authorization(
            Oauth2AuthorizationCode.objtype,
            Oauth2AuthorizationCode.objdef,
            "*",
            "delete",
        )
        self.manager.remove_authorization_code(code)
        return None

    #
    # user sessions
    #
    def get_user_sessions(self, sid=None):
        """Get user sessions

        :param sid: session id [optional]
        :return: list of flask session
        :raise ApiManagerError:
        """
        self.check_authorization(User.objtype, User.objdef, "*", "use")

        redis = self.app.session_interface.redis
        key_prefix = self.app.session_interface.key_prefix
        serializer = self.app.session_interface.serializer

        sessions = []
        if sid is not None:
            keys = ["%s%s" % (key_prefix, sid)]
        else:
            keys = redis.keys("%s*" % key_prefix)

        for key in keys:
            val = redis.get(key)
            if val is not None:
                try:
                    data = serializer.loads(val)
                except:
                    data = val
            else:
                raise ApiManagerError("Session not found", code=404)
            data["ttl"] = redis.ttl(key)
            data["sid"] = key[len(key_prefix) :]
            sessions.append(data)
        self.logger.debug("Get user sessions: %s" % truncate(sessions))
        return sessions

    def delete_user_session(self, sid):
        """Delete a user session

        :param sid: session id
        :return: None
        :raise ApiManagerError:
        """
        redis = self.app.session_interface.redis
        key_prefix = self.app.session_interface.key_prefix
        redis.delete(key_prefix + sid)
