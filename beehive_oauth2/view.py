# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2022 CSI-Piemonte

from flask import request
from beecell.simple import get_remote_ip
import ujson as json
from flask import redirect
from flask import Response
from flask import session
from beecell.flask.render import render_template
from beecell.perf import watch
from flask.helpers import url_for
from beehive.common.apimanager import ApiView, SwaggerApiView,\
    GetApiObjectRequestSchema, ApiObjectResponseSchema, PaginatedResponseSchema,\
    PaginatedRequestQuerySchema, CrudApiObjectResponseSchema, ApiManagerError
from beehive.common.data import operation
from marshmallow import fields, Schema
from marshmallow.validate import OneOf
from marshmallow.decorators import validates
from marshmallow.exceptions import ValidationError
from beecell.swagger import SwaggerHelper
from beehive.module.auth.views.auhtorization import BaseCreateRequestSchema,\
    BaseCreateExtendedParamRequestSchema, BaseUpdateRequestSchema
from six.moves.urllib.parse import urlencode


class Oauth2ApiView(SwaggerApiView):
    """Oauth2 base view
    """
    def authorize_error(self, redirect_uri, error, state,
                        error_description=None, error_uri=None):
        """Return error from authorize request.

        For example, the authorization server redirects the user-agent by
        sending the following HTTP response:

        HTTP/1.1 302 Found Location:
            https://client.example.com/cb?error=access_denied&state=xyz

        :param error: A single error code from the following:
            invalid_request - The request is missing a required
                              parameter, includes an invalid parameter
                              value, or is otherwise malformed.
            unauthorized_client - The client is not authorized to
                                  request an authorization code using
                                  this method.
            access_denied - The resource owner or authorization server
                            denied the request.
            unsupported_response_type - The authorization server does
                                        not support obtaining an
                                        authorization code using this
                                        method.
            invalid_scope - The requested scope is invalid, unknown, or
                            malformed.
            server_error - The authorization server encountered an
                           unexpected condition which prevented it from
                           fulfilling the request.
            temporarily_unavailable - The authorization server is
                                      currently unable to handle the
                                      request due to a temporary
                                      overloading or maintenance of the
                                      server.
        :param error_description: [OPTIONAL]  A human-readable UTF-8 encoded
            text providing  additional information, used to assist the client
            developer in understanding the error that occurred.
        :param error_uri: [OPTIONAL] A URI identifying a human-readable web page
            with  information about the error, used to provide the client
            developer with additional information about the error.
        :param state: if a "state" parameter was present in the client
            authorization request. The exact value received from the client.
        """
        # params = urlencode({'error_description':error_description})
        resp = redirect('%s' % (redirect_uri))
        return resp

    @watch
    def get_error(self, exception, code, error, module=None):
        """Return error

        **Parameters:**

            * **exception** (:py:class:`str`):
            * **code** (:py:class:`str`):
            * **error** (:py:class:`str`):

        **Returns:**

            entity instance

        **Raise:** :class:`ApiManagerError`
        """
        self.logger.error('Code: %s, Error: %s' % (code, exception),
                          exc_info=True)
        if code == 420:
            # resp = self.authorize_error(error.in_uri(error.redirect_uri),
            #                            error.error, state,
            #                            error.description)
            resp = redirect('%s' % (error.redirect_uri))
        elif code == 421:
            resp = render_template('error.html', errors=error)
        else:
            headers = {'Cache-Control': 'no-store', 'Pragma': 'no-cache',
                       'remote-server': module.api_manager.server_name}
            body = {'error': error, 'error_description': error}
            data = json.dumps(body)
            resp = Response(data,
                            mimetype='application/json;charset=UTF-8',
                            status=code,
                            headers=headers)
            self.logger.error(data)
        return resp

    def check_login(self, controller, format_json=False):
        # check login
        user = controller.check_login(session)
        if user is None and format_json is False:
            # redirect to login page
            self.response_mime = 'text/html'
            resp = redirect('/%s/oauth2/login?code=authorization_code' %
                            (controller.version))
            return resp, resp.status_code
        if user is None and json is True:
            return self.get_error(ApiManagerError, 400, 'User is not logged')
        return True


#
# authorization
#
class GetAuthorizationRequestSchema(Schema):
    response_type = fields.String(required=True, example='code', context='query', description='must be code')
    client_id = fields.String(required=True, example='37sys6hd', context='query', description='client id')
    redirect_uri = fields.String(required=True, example='http://localhost/auth',
                                 context='query', description='redirection uri')
    scope = fields.String(required=True, example='auth', context='query', description='authorization scopes')
    state = fields.String(required=True, example='12345', context='query', description='authorization state')

    @validates('response_type')
    def validate_response_type(self, value):
        if value != 'code':
            raise ValidationError('response_type must be code')


class GetAuthorization(Oauth2ApiView):
    tags = ['oauth2']
    definitions = {
    }
    parameters = SwaggerHelper().get_parameters(GetAuthorizationRequestSchema)
    parameters_schema = GetAuthorizationRequestSchema
    responses = {
        302: {
            'description': 'redirect to */oauth2/login/?state=..* if credentials '\
            'or login are wrong else redirect to */oauth2/authorize/scope?state=..* '\
            'or create authorization token and redirect to client redirection uri'
        }
    }

    def get(self, controller, data, *args, **kwargs):
        """
        Authorization uri
        The client initiates the flow by directing the resource owner's user-agent to the authorization endpoint.
        The client includes its client identifier, requested scope, local state, and a redirection URI to which the
        authorization server will send the user-agent back once access is granted (or denied).
        <ul>
        <li>redirect to */oauth2/login/?state=..* if credentials or login are wrong</li>
        <li>redirect to */oauth2/authorize/scope?state=..* if user must accept scopes</li>
        <li>create authorization token if all is ok</li>
        </ul>
        """
        # authenticate client
        uri = request.path
        http_method = request.method
        body = request.args.to_dict()
        headers = request.headers

        # validate input params
        state = body.get('state', None)

        # check login
        check = self.check_login(controller)
        if check is not True:
            # save request body for later redirection
            session['redirect_body'] = urlencode(body)
            return check

        # check client credentials
        try:
            credentials = controller.authenticate_client(
                uri, http_method, body, headers)
        except ApiManagerError as ex:
            return self.get_error(ApiManagerError, ex.code, ex.value)

        # check valid authorization_code already present
        # TODO
        '''
        # return authorization token
        body, status, headers = controller.create_authorization(
            uri, http_method, body, headers, user_scope,
            session_credentials)

        return Response(body, status=status, headers=headers), status
        '''

        # save credentials in session
        controller.save_credentials(session, credentials)

        # redirect to authorization scope page
        self.response_mime = 'text/html'
        resp = redirect('/%s/oauth2/authorize/scope?state=%s' % (controller.version, state))
        return resp, resp.status_code


class GetAuthorizationScope(Oauth2ApiView):
    tags = ['oauth2']
    definitions = {
    }
    responses = {
        200: {
            'description': 'return html select scopes page'
        }
    }

    def get(self, controller, data, *args, **kwargs):
        """
        Scopes list page
        Return html select scopes page
        """
        # check login
        check = self.check_login(controller)
        if check is not True:
            return check

        # set content type
        self.response_mime = 'text/html'
        # get client scope
        msg, client_id, scope = controller.get_client_scopes(session)
        return render_template(
            'scope.html',
            msg=msg,
            client=client_id,
            scope=scope,
            scope_uri='/%s/oauth2/authorize/scope' % controller.version), 200


class SetAuthorizationScopeRequestSchema(Schema):
    scope = fields.String(required=True, example='auth', context='query', description='scopes list')


class SetAuthorizationScope(Oauth2ApiView):
    tags = ['oauth2']
    definitions = {
    }
    parameters = SwaggerHelper().get_parameters(SetAuthorizationScopeRequestSchema)
    parameters_schema = SetAuthorizationScopeRequestSchema
    responses = {
        302: {
            'description': 'redirect to /oauth2/authorize?.. if user authorize'\
            'access to scopes liost'
        }
    }

    def post(self, controller, data, *args, **kwargs):
        """
        Set user scopes
        Set scopes in session after user authorize access to scopes list and redirect to */oauth2/authorize?..* to
        create authorization code
        """
        # check login
        check = self.check_login(controller, format_json=True)
        if check is not True:
            return check

        # get scope
        body = request.form.to_dict()
        scopes = body.get('scope').split(',')

        # get credentials in session
        session_credentials = controller.get_credentials(session)
        # get client scope
        client_scopes = session_credentials['scope']

        # check scopes
        if scopes != client_scopes:
            return self.get_error(ApiManagerError, 400, 'Client scopes and user scopes does not match')

        # create authorization token
        uri = '%s/oauth2/authorize' % controller.version
        headers = request.headers
        body = request.form.to_dict()
        self.logger.warn(body)
        self.logger.warn(headers)
        http_method = 'get'

        body, status, headers = controller.create_authorization(uri, http_method, body, headers, scopes,
                                                                session_credentials)
        return Response(body, status=status, headers=headers), status


class CreateAccessTokenResponseSchema(Schema):
    token_type = fields.String(required=True, example='Bearer', description='token type')
    state = fields.String(required=True, example='UF0P0TjqKykwL3sHoAXRaOeSJKSafH', description='request state')
    refresh_token = fields.String(required=True, example='91KwQ7bLMoJA5lg5vQiYk91hllFJD8',
                                  description='refresh token')
    access_token = fields.String(required=True, example='uX9HCdbP0hBbKiv1p5wajbeKYM0gmh', description='access token')
    scope = fields.List(fields.String(example='photos'), required=True, description='scopes list')
    expires_in = fields.Integer(required=True, example=3600, description='expires in ..second')
    expires_at = fields.Float(required=True, example=1471546820.270866, description='expires at')


class CreateAccessTokenErrorResponseSchema(Schema):
    error = fields.Dict(required=False, example='', description='error')


class CreateAccessTokenRequestSchema(Schema):
    code = fields.String(required=False, example='bUCrCB2IMuIowKMt7fllpMh35H2aIY', context='query',
                         description='code')
    client_secret = fields.String(required=False, context='query', example='exh7ez922so3eeQjbsJLgiSR3fW3AVc1dsmQiBIi',
                                  description='client secret')
    grant_type = fields.String(required=True, example='authorization_code', context='query',
                               description='authorization code')
    client_id = fields.String(required=True, example='8a994dd1-e96b-4092-8a14-ede3f77d8a2c', context='query',
                              description='client id')
    redirect_uri = fields.String(required=False, context='query', example='https://localhost:7443/authorize',
                                 description='redirection uri')
    username = fields.String(required=False, context='query', example='prova@local', description='username')
    password = fields.String(required=False, context='query', example='xxxx', description='password')
    assertion = fields.String(required=False, context='query', example='serfss', description='jwt assertion')
    scope = fields.String(required=False, context='query', example='beehive', description='oauth2 scope')


class CreateAccessToken(Oauth2ApiView):
    tags = ['oauth2']
    definitions = {
        'CreateAccessTokenResponseSchema': CreateAccessTokenResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(CreateAccessTokenRequestSchema)
    parameters_schema = CreateAccessTokenRequestSchema
    responses = {
        200: {
            'description': 'redirect to /oauth2/authorize/scope if login end '\
            'with success else redirect also to /oauth2/login',
            'schema': CreateAccessTokenResponseSchema
        },
        400: {
            'description': 'return error {"error":"invalid_request"}',
        }
    }

    def post(self, controller, data, *args, **kwargs):
        """
        Token api
        Use this api to obtain a valid access token
        """
        # authenticate client
        uri = request.path
        http_method = request.method
        body = request.form.to_dict()
        headers = request.headers
        login_ip = get_remote_ip(request)
        body, status, headers = controller.create_token(
            uri, http_method, body, headers, session, login_ip)
        return Response(body, status=status, headers=headers)


#
# login, logout
#
class LoginRequestSchema(Schema):
    username = fields.String(required=True, example='user', context='query', description='login user')
    domain = fields.String(required=True, example='local', context='query', description='login domain')
    password = fields.String(required=True, example='user@local', context='query', description='login password')
    login_ip = fields.String(required=False, example='user@local', context='query', description='login ip address')
    code = fields.String(required=True, example='authorization_code', allow_none=True, context='query',
                         description='code')


class Login(SwaggerApiView):
    tags = ['oauth2']
    definitions = {
    }
    parameters = SwaggerHelper().get_parameters(LoginRequestSchema)
    parameters_schema = LoginRequestSchema
    responses = {
        302: {
            'description': 'redirect to /oauth2/authorize/scope if login end '\
            'with success else redirect also to /oauth2/login'
        }
    }

    def post(self, controller, data, *args, **kwargs):
        """
        Login api
        Call this api to login user
        """
        name = data.get('username', None)
        domain = data.get('domain', None)
        password = data.get('password', None)
        login_ip = data.get('login_ip', None)
        if login_ip is None:
            login_ip = get_remote_ip(request)
        code = data.get('code', None)

        innerperms = [
            (1, 1, 'auth', 'objects', 'ObjectContainer', '*', 1, '*'),
            (1, 1, 'auth', 'role', 'RoleContainer', '*', 1, '*'),
            (1, 1, 'auth', 'user', 'UserContainer', '*', 1, '*')]
        operation.perms = innerperms
        try:
            res = controller.login(session, name, domain, password, login_ip)
        except ApiManagerError as ex:
            res = False
            session['msg'] = ex.value

        # set content type
        self.response_mime = 'text/html'
        if res is True and code == 'authorization_code':
            session.pop('msg', None)
            # get previous request body
            body = session['redirect_body']
            resp = redirect('/%s/oauth2/authorize?%s' % (controller.version, body))
        elif res is True:
            session.pop('msg', None)
            resp = redirect('/%s/oauth2/user' % controller.version)
        else:
            resp = redirect('/%s/oauth2/login' % controller.version)
        return resp


class LoginPage(SwaggerApiView):
    tags = ['oauth2']
    definitions = {
    }
    responses = {
        200: {
            'description': 'return html login page'
        }
    }

    def get(self, controller, data, *args, **kwargs):
        """
        Open Login Page
        Open Login Page
        """
        msg = session.get('msg', None)
        redirect_uri = request.args.get('redirect-uri', None)
        code = request.args.get('code', None)
        style = 'css/style.%s.css' % request.args.get('style', 'blue')
        # get login page
        domains, redirect_uri = controller.login_page(redirect_uri)

        # check login
        user = controller.check_login(session)

        # set content type
        self.response_mime = 'text/html'
        # if user already logged redirect to other page
        if user is not None and code == 'authorization_code':
            session.pop('msg', None)
            resp = redirect('/%s/oauth2/authorize' % controller.version)
        elif user is not None:
            session.pop('msg', None)
            resp = redirect('/%s/oauth2/user' % controller.version)
        # user not already logged
        else:
            resp = render_template(
                'login.html',
                msg=msg,
                domains=domains,
                redirect_uri=redirect_uri,
                code=code,
                login_uri='/%s/oauth2/login' % controller.version,
                style=url_for('static', filename=style)), 200

        return resp


class Logout(SwaggerApiView):
    tags = ['oauth2']
    definitions = {
    }
    responses = {
        200: {
            'description': 'return html logout page'
        }
    }

    def get(self, controller, data, *args, **kwargs):
        """
        Logout user
        Logout user
        """
        user = controller.logout(session)
        style = 'css/style.%s.css' % request.args.get('style', 'blue')
        # set content type
        self.response_mime = 'text/html'
        resp = render_template(
            'logout.html',
            user=user,
            style=url_for('static', filename=style)), 200
        return resp


class UserPage(SwaggerApiView):
    tags = ['oauth2']
    definitions = {
    }
    responses = {
        200: {
            'description': 'return html user page'
        }
    }

    def get(self, controller, data, *args, **kwargs):
        """
        Open User Page
        Open User Page
        """
        # check login
        user = controller.check_login(session)
        if user is None:
            # redirect to login page
            self.response_mime = 'text/html'
            resp = redirect('/%s/oauth2/login' % (controller.version))
            return resp, resp.status_code

        style = 'css/style.%s.css' % request.args.get('style', 'blue')
        # set content type
        self.response_mime = 'text/html'
        return render_template(
            'user.html',
            logout_uri='/%s/oauth2/logout' % (controller.version),
            user=session['oauth2_user'],
            login_uri='/%s/oauth2/user' % controller.version,
            style=url_for('static', filename=style)), 200


#
# client
#
class ListClientsRequestSchema(PaginatedRequestQuerySchema):
    expiry_date = fields.String(default='2099-12-31', example='2099-12-31', context='query',
                                description='expiration date')


class ListClientsParamsResponseSchema(ApiObjectResponseSchema):
    grant_type = fields.String(example='authorization_code', required=True, context='query',
                               description='grant type')
    response_type = fields.String(example='code', required=True, description='response type')
    scopes = fields.String(example='beehive', required=True, description='comma separated list of scopes')


class ListClientsResponseSchema(PaginatedResponseSchema):
    clients = fields.Nested(ListClientsParamsResponseSchema, many=True, required=True, allow_none=True)


class ListClients(SwaggerApiView):
    tags = ['oauth2']
    definitions = {
        'ListClientsResponseSchema': ListClientsResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ListClientsRequestSchema)
    parameters_schema = ListClientsRequestSchema
    responses = SwaggerApiView.setResponses({
        200: {
            'description': 'success',
            'schema': ListClientsResponseSchema
        }
    })

    def get(self, controller, data, *args, **kwargs):
        """
        List clients
        Call this api to list clients
        """
        objs, total = controller.get_clients(**data)
        res = [r.info() for r in objs]

        return self.format_paginated_response(res, 'clients', total, **data)


class ClientScopeResponseSchema(Schema):
    name = fields.String(required=True, example='prova', description='scope name')
    uuid = fields.String(required=True, default='4cdf0ea4-159a-45aa-96f2-708e461130e1',
                         example='4cdf0ea4-159a-45aa-96f2-708e461130e1', description='scope uuid')


class GetClientParamsResponseSchema(ApiObjectResponseSchema):
    grant_type = fields.String(example='authorization_code', description='grant type')
    response_type = fields.String(example='code', description='response type')
    client_secret = fields.String(example='Vuh8tJlnhOA8taV2LSwYSgtP3IJpofWbBSjHmFM', allow_none=True,
                                  description='client secret')
    client_email = fields.String(example='client1@local', description='client email')
    redirect_uri = fields.String(example='https://localhost:7443/authorize', description='redirect uri')
    private_key = fields.String(example='_hdue48sisiemcc...', allow_none=True, description='private key')
    public_key = fields.String(example='e7SU-2ndw9cn9..', allow_none=True, description='public key')
    scopes = fields.String(example='beehive', required=True, description='comma separated list of scopes')
    auth_uri = fields.String(example='https://localhost/v1.0/authorize', description='auth uri')
    token_uri = fields.String(example='https://localhost/v1.0/token', description='token uri')


class GetClientResponseSchema(Schema):
    client = fields.Nested(GetClientParamsResponseSchema, required=True, allow_none=True)


class GetClient(SwaggerApiView):
    tags = ['oauth2']
    definitions = {
        'GetClientResponseSchema': GetClientResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(GetApiObjectRequestSchema)
    responses = SwaggerApiView.setResponses({
        200: {
            'description': 'success',
            'schema': GetClientResponseSchema
        }
    })

    def get(self, controller, data, oid, *args, **kwargs):
        """
        Get client
        Call this api to get client by id, uuid or name
        """
        obj = controller.get_client(oid)
        resp = {'client':obj.detail()}
        return resp


class CreateClientParamRequestSchema(BaseCreateRequestSchema, BaseCreateExtendedParamRequestSchema):
    scopes = fields.String(required=True, example='beehive,auth', description='comma separated list of scopes')
    grant_type = fields.String(required=True, example='authorization_code',
                               description='grant type. Select from: authorization_code, implicit, resource_owner_'
                                           'password_credentials, client_credentials, '
                                           'urn:ietf:params:oauth:grant-type:jwt-bearer',
                               validate=OneOf(['authorization_code', 'implicit', 'password', 'client_credentials',
                                               'urn:ietf:params:oauth:grant-type:jwt-bearer']))
    redirect_uri = fields.String(required=True, example='beehive,auth', description='redirect uri')
    response_type = fields.String(required=True, example='code',
                                  description='response type. Use code for grant-type=authorization_code')
    user = fields.String(required=False, example='admin@local',
                         description='id, uuid or name of the user to link to client. Use with Resource Owner '
                                     'Password Credentials Grant')


class CreateClientRequestSchema(Schema):
    client = fields.Nested(CreateClientParamRequestSchema)


class CreateClientBodyRequestSchema(Schema):
    body = fields.Nested(CreateClientRequestSchema, context='body')


class CreateClient(SwaggerApiView):
    tags = ['oauth2']
    definitions = {
        'CreateClientRequestSchema': CreateClientRequestSchema,
        'CrudApiObjectResponseSchema':CrudApiObjectResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(CreateClientBodyRequestSchema)
    parameters_schema = CreateClientRequestSchema
    responses = SwaggerApiView.setResponses({
        201: {
            'description': 'success',
            'schema': CrudApiObjectResponseSchema
        }
    })

    def post(self, controller, data, *args, **kwargs):
        """
        Create a client
        Call this api to create a client
        """
        data = data.get('client')
        data['scopes'] = data['scopes'].split(',')
        resp = controller.add_client(**data)
        return ({'uuid': resp}, 201)


class UpdateClientParamRequestSchema(BaseUpdateRequestSchema, BaseCreateExtendedParamRequestSchema):
    pass


class UpdateClientRequestSchema(Schema):
    client = fields.Nested(UpdateClientParamRequestSchema)


class UpdateClientBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(UpdateClientRequestSchema, context='body')


class UpdateClient(SwaggerApiView):
    tags = ['oauth2']
    definitions = {
        'UpdateClientRequestSchema': UpdateClientRequestSchema,
        'CrudApiObjectResponseSchema': CrudApiObjectResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(UpdateClientBodyRequestSchema)
    parameters_schema = UpdateClientRequestSchema
    responses = SwaggerApiView.setResponses({
        200: {
            'description': 'success',
            'schema': CrudApiObjectResponseSchema
        }
    })

    def put(self, controller, data, oid, *args, **kwargs):
        """
        Update client
        Call this api to update a client
        """
        obj = controller.get_client(oid)
        resp = obj.update(**data.get('client'))
        return {'uuid': resp}


class DeleteClient(SwaggerApiView):
    tags = ['oauth2']
    definitions = {}
    parameters = SwaggerHelper().get_parameters(GetApiObjectRequestSchema)
    responses = SwaggerApiView.setResponses({
        204: {
            'description': 'no response'
        }
    })

    def delete(self, controller, data, oid, *args, **kwargs):
        """
        Delete client
        Call this api to delete a client
        """
        client = controller.get_client(oid)
        resp = client.delete()
        return (resp, 204)

#
# scope
#
class ListScopesRequestSchema(PaginatedRequestQuerySchema):
    expiry_date = fields.String(default='2099-12-31', example='2099-12-31', context='query',
                                description='expiration date')


class ListScopesResponseSchema(PaginatedResponseSchema):
    scopes = fields.Nested(ApiObjectResponseSchema, many=True, required=True, allow_none=True)


class ListScopes(SwaggerApiView):
    tags = ['oauth2']
    definitions = {
        'ListScopesResponseSchema': ListScopesResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ListScopesRequestSchema)
    parameters_schema = ListScopesRequestSchema
    responses = SwaggerApiView.setResponses({
        200: {
            'description': 'success',
            'schema': ListScopesResponseSchema
        }
    })

    def get(self, controller, data, *args, **kwargs):
        """
        List scopes
        Call this api to list scopes
        """
        objs, total = controller.get_scopes(**data)
        res = [r.info() for r in objs]

        return self.format_paginated_response(res, 'scopes', total, **data)


class GetScopeParamsResponseSchema(ApiObjectResponseSchema):
    pass


class GetScopeResponseSchema(Schema):
    scope = fields.Nested(GetScopeParamsResponseSchema, required=True, allow_none=True)


class GetScope(SwaggerApiView):
    tags = ['oauth2']
    definitions = {
        'GetScopeResponseSchema': GetScopeResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(GetApiObjectRequestSchema)
    responses = SwaggerApiView.setResponses({
        200: {
            'description': 'success',
            'schema': GetScopeResponseSchema
        }
    })

    def get(self, controller, data, oid, *args, **kwargs):
        """
        Get scope
        Call this api to get scope by id, uuid or name
        """
        obj = controller.get_scope(oid)
        resp = {'scope': obj.detail()}
        return resp


class CreateScopeParamRequestSchema(BaseCreateRequestSchema):
    pass


class CreateScopeRequestSchema(Schema):
    scope = fields.Nested(CreateScopeParamRequestSchema)


class CreateScopeBodyRequestSchema(Schema):
    body = fields.Nested(CreateScopeRequestSchema, context='body')


class CreateScope(SwaggerApiView):
    tags = ['oauth2']
    definitions = {
        'CreateScopeRequestSchema': CreateScopeRequestSchema,
        'CrudApiObjectResponseSchema':CrudApiObjectResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(CreateScopeBodyRequestSchema)
    parameters_schema = CreateScopeRequestSchema
    responses = SwaggerApiView.setResponses({
        201: {
            'description': 'success',
            'schema': CrudApiObjectResponseSchema
        }
    })

    def post(self, controller, data, *args, **kwargs):
        """
        Create a scope
        Call this api to create a scope
        """
        resp = controller.add_scope(**data.get('scope'))
        return ({'uuid':resp}, 201)


class UpdateScopeParamRequestSchema(BaseUpdateRequestSchema, BaseCreateExtendedParamRequestSchema):
    pass


class UpdateScopeRequestSchema(Schema):
    scope = fields.Nested(UpdateScopeParamRequestSchema)


class UpdateScopeBodyRequestSchema(GetApiObjectRequestSchema):
    body = fields.Nested(UpdateScopeRequestSchema, context='body')


class UpdateScope(SwaggerApiView):
    tags = ['oauth2']
    definitions = {
        'UpdateScopeRequestSchema':UpdateScopeRequestSchema,
        'CrudApiObjectResponseSchema':CrudApiObjectResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(UpdateScopeBodyRequestSchema)
    parameters_schema = UpdateScopeRequestSchema
    responses = SwaggerApiView.setResponses({
        200: {
            'description': 'success',
            'schema': CrudApiObjectResponseSchema
        }
    })

    def put(self, controller, data, oid, *args, **kwargs):
        """
        Update scope
        Call this api to update a scope
        """
        obj = controller.get_scope(oid)
        resp = obj.update(**data.get('scope'))
        return {'uuid': resp}


class DeleteScope(SwaggerApiView):
    tags = ['oauth2']
    definitions = {}
    parameters = SwaggerHelper().get_parameters(GetApiObjectRequestSchema)
    responses = SwaggerApiView.setResponses({
        204: {
            'description': 'no response'
        }
    })

    def delete(self, controller, data, oid, *args, **kwargs):
        """
        Delete scope
        Call this api to delete a scope
        """
        scope = controller.get_scope(oid)
        resp = scope.delete()
        return (resp, 204)


#
# authorization_code
#
class ListAuthorizationCodesRequestSchema(PaginatedRequestQuerySchema):
    expire = fields.String(required=False, example='2099-12-31', context='query', description='expire time')
    client = fields.String(required=False, example=2, context='query', description='client id, uuid or name')
    valid = fields.Boolean(required=False, example=True, context='query',
                           description='if True get only code not expired')
    user = fields.String(required=False, example=2, context='query', description='user id, uuid or name')
    valid = fields.Boolean(required=False, example=False, context='query', description='if True list expired codes')


class AuthorizationCodeResponseSchema(Schema):
    id = fields.Integer(required=True, example=2, description='code id')
    client = fields.UUID(required=True, example=2, description='client uuid')
    user = fields.UUID(required=True, example=2, description='user uuid')
    scope = fields.List(fields.String(example='dje3d8whjdis'), required=True, description='scopes')
    state = fields.String(required=True, example='dje3d8whjdis', description='generation state')
    code = fields.String(required=True, example=2, description='code')
    redirect_uri = fields.String(required=True, example=2, description='redirect uri')
    expires_at = fields.String(required=True, example='2099-12-31', description='expiration date')
    expired = fields.Boolean(required=True, example=True, description='tell if code is expired')


class ListAuthorizationCodesResponseSchema(PaginatedResponseSchema):
    authorization_codes = fields.Nested(AuthorizationCodeResponseSchema, many=True, required=True, allow_none=True)


class ListAuthorizationCodes(SwaggerApiView):
    tags = ['oauth2']
    definitions = {
        'ListAuthorizationCodesResponseSchema': ListAuthorizationCodesResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ListAuthorizationCodesRequestSchema)
    parameters_schema = ListAuthorizationCodesRequestSchema
    responses = SwaggerApiView.setResponses({
        200: {
            'description': 'success',
            'schema': ListAuthorizationCodesResponseSchema
        }
    })

    def get(self, controller, data, *args, **kwargs):
        """
        List authorization_codes
        Call this api to list authorization_codes
        """
        objs, total = controller.get_authorization_codes(**data)
        res = [r.info() for r in objs]

        return self.format_paginated_response(res, 'authorization_codes', total, **data)


class DeleteAuthorizationCode(SwaggerApiView):
    tags = ['oauth2']
    definitions = {}
    parameters = SwaggerHelper().get_parameters(GetApiObjectRequestSchema)
    responses = SwaggerApiView.setResponses({
        204: {
            'description': 'no response'
        }
    })

    def delete(self, controller, data, oid, *args, **kwargs):
        """
        Delete authorization_code
        Call this api to delete a authorization_code
        """
        controller.delete_authorization_code(oid)
        return (None, 204)


#
# user_session
#
class ListUserSessionsRequestSchema(Schema):
    pass


class ListUserSessionsResponseSchema(Schema):
    user_sessions = fields.List(fields.Dict(example={}), required=True, description='List of user sessions')
    count = fields.Integer(required=True, example=1, description='User sessions count')


class ListUserSessions(SwaggerApiView):
    tags = ['oauth2']
    definitions = {
        'ListUserSessionsResponseSchema': ListUserSessionsResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ListUserSessionsRequestSchema)
    parameters_schema = ListUserSessionsRequestSchema
    responses = SwaggerApiView.setResponses({
        200: {
            'description': 'success',
            'schema': ListUserSessionsResponseSchema
        }
    })

    def get(self, controller, data, *args, **kwargs):
        """
        List user_sessions
        Call this api to list user_sessions
        """
        user_sessions = controller.get_user_sessions()
        return {
            'user_sessions': user_sessions,
            'count': len(user_sessions)
        }


class GetUserSessionResponseSchema(Schema):
    user_session = fields.Dict(example={}, required=True, description='User sessions')


class GetUserSession(SwaggerApiView):
    tags = ['oauth2']
    definitions = {
        'GetUserSessionResponseSchema': GetUserSessionResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(GetApiObjectRequestSchema)
    responses = SwaggerApiView.setResponses({
        200: {
            'description': 'success',
            'schema': GetUserSessionResponseSchema
        }
    })

    def get(self, controller, data, oid, *args, **kwargs):
        """
        Get user_session
        Call this api to get user_session by id, uuid or name
        """
        user_session = controller.get_user_sessions(sid=oid)[0]
        resp = {'user_session': user_session}
        return resp


class DeleteUserSession(SwaggerApiView):
    tags = ['oauth2']
    definitions = {}
    parameters = SwaggerHelper().get_parameters(GetApiObjectRequestSchema)
    responses = SwaggerApiView.setResponses({
        204: {
            'description': 'no response'
        }
    })

    def delete(self, controller, data, oid, *args, **kwargs):
        """
        Delete user_session
        Call this api to delete a user_session
        """
        controller.delete_user_session(oid)
        return (None, 204)


class Oauth2Api(ApiView):
    """Asymmetric key authentication API
    """
    @staticmethod
    def register_api(module, **kwargs):
        base = 'oauth2'
        old_rules = [
            ('%s/login' % base, 'POST', Login, {'secure': False}),
            ('%s/login' % base, 'GET', LoginPage, {'secure': False}),
            ('%s/logout' % base, 'GET', Logout, {'secure': False}),
            ('%s/user' % base, 'GET', UserPage, {'secure': False}),

            # required oauth2 routes
            ('%s/authorize' % base, 'GET', GetAuthorization, {'secure': False}),
            # ('%s/authorize' % base, 'POST', CreateAuthorization, {'secure': False}),
            ('%s/authorize/scope' % base, 'GET', GetAuthorizationScope, {'secure': False}),
            ('%s/authorize/scope' % base, 'POST', SetAuthorizationScope, {'secure': False}),
            ('%s/token' % base, 'POST', CreateAccessToken, {'secure': False}),

            # additional routes
            # ('%s/tokens' % base, 'GET', ListTokens, {}),
            # ('%s/tokens/<oid>' % base, 'DELETE', DeleteToken, {}),

            # ('%s/authorization-codes' % base, 'GET', ListAuthorizationCodes, {}),
            # ('%s/authorization-codes/<oid>' % base, 'DELETE', DeleteAuthorizationCode, {}),

            ('%s/clients' % base, 'GET', ListClients, {}),
            ('%s/clients/<oid>' % base, 'GET', GetClient, {}),
            ('%s/clients' % base, 'POST', CreateClient, {}),
            ('%s/clients/<oid>' % base, 'PUT', UpdateClient, {}),
            ('%s/clients/<oid>' % base, 'DELETE', DeleteClient, {}),

            ('%s/scopes' % base, 'GET', ListScopes, {}),
            ('%s/scopes/<oid>' % base, 'GET', GetScope, {}),
            ('%s/scopes' % base, 'POST', CreateScope, {}),
            ('%s/scopes/<oid>' % base, 'PUT', UpdateScope, {}),
            ('%s/scopes/<oid>' % base, 'DELETE', DeleteScope, {}),

            ('%s/authorization_codes' % base, 'GET', ListAuthorizationCodes, {}),
            # ('%s/authorization_codes/<oid>' % base, 'GET', GetAuthorizationCode, {}),
            ('%s/authorization_codes/<oid>' % base, 'DELETE', DeleteAuthorizationCode, {}),

            ('%s/user_sessions' % base, 'GET', ListUserSessions, {}),
            ('%s/user_sessions/<oid>' % base, 'GET', GetUserSession, {}),
            ('%s/user_sessions/<oid>' % base, 'DELETE', DeleteUserSession, {}),
        ]

        base = 'nas/oauth2'
        rules = [
            ('%s/login' % base, 'POST', Login, {'secure': False}),
            ('%s/login' % base, 'GET', LoginPage, {'secure': False}),
            ('%s/logout' % base, 'GET', Logout, {'secure': False}),
            ('%s/user' % base, 'GET', UserPage, {'secure': False}),

            # required oauth2 routes
            ('%s/authorize' % base, 'GET', GetAuthorization, {'secure': False}),
            # ('%s/authorize' % base, 'POST', CreateAuthorization, {'secure': False}),
            ('%s/authorize/scope' % base, 'GET', GetAuthorizationScope, {'secure': False}),
            ('%s/authorize/scope' % base, 'POST', SetAuthorizationScope, {'secure': False}),
            ('%s/token' % base, 'POST', CreateAccessToken, {'secure': False}),

            # additional routes
            # ('%s/tokens' % base, 'GET', ListTokens, {}),
            # ('%s/tokens/<oid>' % base, 'DELETE', DeleteToken, {}),

            # ('%s/authorization-codes' % base, 'GET', ListAuthorizationCodes, {}),
            # ('%s/authorization-codes/<oid>' % base, 'DELETE', DeleteAuthorizationCode, {}),

            ('%s/clients' % base, 'GET', ListClients, {}),
            ('%s/clients/<oid>' % base, 'GET', GetClient, {}),
            ('%s/clients' % base, 'POST', CreateClient, {}),
            ('%s/clients/<oid>' % base, 'PUT', UpdateClient, {}),
            ('%s/clients/<oid>' % base, 'DELETE', DeleteClient, {}),

            ('%s/scopes' % base, 'GET', ListScopes, {}),
            ('%s/scopes/<oid>' % base, 'GET', GetScope, {}),
            ('%s/scopes' % base, 'POST', CreateScope, {}),
            ('%s/scopes/<oid>' % base, 'PUT', UpdateScope, {}),
            ('%s/scopes/<oid>' % base, 'DELETE', DeleteScope, {}),

            ('%s/authorization_codes' % base, 'GET', ListAuthorizationCodes, {}),
            # ('%s/authorization_codes/<oid>' % base, 'GET', GetAuthorizationCode, {}),
            ('%s/authorization_codes/<oid>' % base, 'DELETE', DeleteAuthorizationCode, {}),

            ('%s/user_sessions' % base, 'GET', ListUserSessions, {}),
            ('%s/user_sessions/<oid>' % base, 'GET', GetUserSession, {}),
            ('%s/user_sessions/<oid>' % base, 'DELETE', DeleteUserSession, {}),
        ]
        rules.extend(old_rules)

        ApiView.register_api(module, rules, **kwargs)
