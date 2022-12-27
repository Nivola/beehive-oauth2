# -*- coding: utf-8 -*-
# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2022 CSI-Piemonte

import logging
# import pandas as pd
from datetime import datetime, timedelta
from sqlalchemy import Column, Integer, String, Boolean, Table, ForeignKey, DateTime
from sqlalchemy.orm import relationship, backref
from sqlalchemy import create_engine, exc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import func
from sqlalchemy.sql import text
from beecell.perf import watch
from beecell.simple import truncate, id_gen
from uuid import uuid4
from beecell.db import ModelError
from beehive.common.data import query, transaction, operation
from beehive.common.model import AbstractDbManager, BaseEntity
from beehive.common.model.authorization import User, AuthDbManager

# Base = declarative_base()

from beehive.common.model.authorization import Base
from beecell.auth.model import AbstractAuthDbManager
from sqlalchemy.dialects import mysql

logger = logging.getLogger(__name__)

# Many-to-Many Relationship
consumer_scope = Table('oauth2_client_scope', Base.metadata,
    Column('id', Integer, primary_key=True),
    Column('consumer_id', Integer(), ForeignKey('oauth2_client.id')),
    Column('scope_id', Integer(), ForeignKey('oauth2_scope.id')))

authorization_scope = Table('oauth2_authorization_scope', Base.metadata,
    Column('id', Integer, primary_key=True),
    Column('authorization_id', Integer(), ForeignKey('oauth2_authorization_code.id')),
    Column('scope_id', Integer(), ForeignKey('oauth2_scope.id')))


# Oauth2 Scope
class Oauth2Scope(Base, BaseEntity):
    __tablename__ = 'oauth2_scope'

    def __init__(self, objid, name, desc):
        BaseEntity.__init__(self, objid, name, desc, True)


# Oauth2 Consumer
class Oauth2Client(Base, BaseEntity):
    """Create new client
    
    :param objid: entity objid
    :param name: entity name
    :param client_secret: client secret used for all grant type except JWT
    :param user_id: user id associated to client
    :param desc: client desc. [default='']
    :param private_key: private key used by Jwt grant type. [optional]
    :param public_key: public key used by Jwt grant type. [optional]
    :param grant_type: The grant type the client may utilize. This should only be one per client as each grant type 
        has different security properties and it is best to keep them separate to avoid mistakes.
    :param response_type: If using a grant type with an associated response type (eg. Authorization Code Grant) or 
        using a grant which only utilizes response types (eg. Implicit Grant). [default=code]
    :param scope: The list of scopes the client may request access to. If you allow multiple types of grants this 
        will vary related to their different security properties. For example, the Implicit Grant might only allow 
        read-only scopes but the Authorization Grant also allow writes. [default=[]]
    :param redirect_uri: These are the absolute URIs that a client may use to redirect to after authorization. You 
        should never allow a client to redirect to a URI that has not previously been registered.
    :param active: True if client is active. False otherwise. [default=True]
    :param expiry_date: relation expiry date [default=365 days]. Set using a datetime object                          
    :return: client instance
    """    
    __tablename__ = 'oauth2_client'
        
    client_secret = Column(String(200), unique=True)
    private_key = Column(String(4096))
    public_key = Column(String(4096))
    user_id = Column(Integer(), ForeignKey('user.id'))
    user = relationship('User')
    grant_type = Column(String(50))
    response_type = Column(String(10))
    scope = relationship('Oauth2Scope', secondary=consumer_scope, backref=backref('oauth2_client', lazy='dynamic'))
    redirect_uri = Column(String(256))

    def __init__(self, objid, name, client_secret, user_id, grant_type, redirect_uri, response_type='code', scope=[], 
                 desc='', active=True, private_key=None, public_key=None, expiry_date=None):
        BaseEntity.__init__(self, objid, name, desc, active)
        
        self.client_secret = client_secret
        self.user_id = user_id
        self.grant_type = grant_type
        self.response_type = response_type
        self.redirect_uri = redirect_uri
        self.active = active
        self.private_key = private_key
        self.public_key = public_key
        self.scope = scope

        if expiry_date is None:
            expiry_date = datetime.datetime.today()+datetime.timedelta(days=365)
        self.expiry_date = expiry_date


# Oauth2 authorization code
class Oauth2AuthorizationCode(Base):
    """This is specific to the Authorization Code grant and represent the temporary credential granted to the client 
    upon successful authorization. It will later be exchanged for an access token, when that is done it should 
    cease to exist. It should have a limited life time, less than ten minutes. This model is similar to the Bearer 
    Token as it mainly acts a temporary storage of properties to later be transferred to the token.

    :param client: Association with the client to whom the token was given.
    :param user: Association with the user to which protected resources this token grants access.
    :param code: An unguessable unique string of characters.
    :param expire: Exact time of expiration. Commonly this is one hour after creation.
    :param redirect_uri: These are the absolute URIs that a client may use to redirect to after authorization. You 
        should never allow a client to redirect to a URI that has not previously been registered.                             
    :return: authorization code instance
    """
    __tablename__ = 'oauth2_authorization_code'
    __table_args__ = {'mysql_engine': 'InnoDB'}
        
    id = Column(Integer(), primary_key=True)
    client_id = Column(Integer(), ForeignKey('oauth2_client.id'))
    client = relationship('Oauth2Client')
    user_id = Column(Integer(), ForeignKey('user.id'))
    user = relationship('User')
    scope = relationship('Oauth2Scope', secondary=authorization_scope,
                         backref=backref('oauth2_authorization_code', lazy='dynamic'))
    code = Column(String(100), unique=True)
    expires_at = Column(DateTime())
    redirect_uri = Column(String(256))

    def __init__(self, client, user, code, redirect_uri):
        self.client = client
        self.user = user
        self.code = code
        self.redirect_uri = redirect_uri
        self.expires_at = datetime.today() + timedelta(minutes=60)
        
    def __repr__(self):
        return '<Oauth2AuthorizationCode id=%s client_id=%s user_id=%s scope=%s redirect_uri=%s)>' % \
               (self.id, self.client_id, self.user_id, self.scope, self.redirect_uri)        


class GrantType(object):
    AUTHORIZATION_CODE = 'authorization_code'
    IMPLICIT = 'implicit'
    RESOURCE_OWNER_PASSWORD_CREDENTIAL = 'password'
    CLIENT_CRDENTIAL = 'client_credentials'
    JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer'    


class Oauth2DbManager(AuthDbManager):
    """
    According to http://tools.ietf.org/html/rfc6749
    
    Authorization Grant

    An authorization grant is a credential representing the resource
    owner's authorization (to access its protected resources) used by the
    client to obtain an access token.  This specification defines four
    grant types: authorization code, implicit, resource owner password
    credentials, and client credentials, as well as an extensibility
    mechanism for defining additional types.    
    """
    @staticmethod
    def create_table(db_uri):
        """Create all tables in the engine. This is equivalent to "Create Table" statements in raw SQL."""
        try:
            engine = create_engine(db_uri)
            engine.execute('SET FOREIGN_KEY_CHECKS=1;')
            Base.metadata.create_all(engine)
            logger.info('Create tables on : %s' % db_uri)
            del engine
        except exc.DBAPIError as e:
            raise Exception(e)
    
    @staticmethod
    def remove_table(db_uri):
        """ Remove all tables in the engine. This is equivalent to "Drop Table" statements in raw SQL."""
        try:
            engine = create_engine(db_uri)
            engine.execute('SET FOREIGN_KEY_CHECKS=0;')
            Base.metadata.drop_all(engine)
            logger.info('Remove tables from : %s' % db_uri)
            del engine
        except exc.DBAPIError as e:
            raise Exception(e)
    
    #
    # scope
    #

    def count_scopes(self):
        """Get scopes count.
        
        :return: count of Oauth2Scope instances
            
        :raise QueryError:           
        """
        return self.count_entites(Oauth2Scope)

    def get_scopes(self, *args, **kvargs):
        """Get scopes
        
        :param page: entities list page to show [default=0]
        :param size: number of entities to show in list per page [default=0]
        :param order: sort order [default=DESC]
        :param field: sort field [default=id]        
        :return: list of Oauth2Scope instances            
        :raise QueryError:
        """
        filters = []
        res, total = self.get_paginated_entities(Oauth2Scope, filters=filters, *args, **kvargs)     
        
        return res, total

    def add_scope(self, objid, name, desc):
        """Add a scope. Extend :function:`add_entity`

        :param objid: scope objid
        :param name: scope name
        :param desc: scope desc    
        :return: Oauth2Client instance
        :raise TransactionError:                
        """
        res = self.add_entity(Oauth2Scope, objid, name, desc)
        return res

    def update_scope(self, *args, **kvargs):
        """Update scope. Extend :function:`update_entity`

        :param int oid: entity id. [optional]
        :param str objid: entity authorization id. [optional]
        :param str uuid: entity uuid. [optional]
        :param str name: entity name. [optional]
        :param str desc: entity desc. [optional]
        :return: update response
        :raise TransactionError:
        """        
        res = self.update_entity(Oauth2Scope, *args, **kvargs)
        return res

    def remove_scope(self, *args, **kvargs):
        """Remove scope.

        :param int oid: entity id. [optional]
        :param str objid: entity authorization id. [optional]
        :param str uuid: entity uuid. [optional]
        :param str name: entity name. [optional]
        :return:
        :raise TransactionError:     
        """
        res = self.remove_entity(Oauth2Scope, *args, **kvargs)
        return res

    #
    # client
    #

    def count_clients(self):
        """Get clients count.
        
        :return: count of Oauth2Client instances
        :raise QueryError:           
        """
        return self.count_entites(Oauth2Client)
    
    def get_clients(self, *args, **kvargs):
        """Get clients

        :param page: entities list page to show [default=0]
        :param size: number of entities to show in list per page [default=0]
        :param order: sort order [default=DESC]
        :param field: sort field [default=id]
        :return: list of Oauth2Client instances
        :raise QueryError:          
        """
        filters = []
        res, total = self.get_paginated_entities(Oauth2Client, filters=filters, *args, **kvargs)
        
        return res, total

    def add_client(self, objid, name, client_secret, user_id, grant_type, redirect_uri, response_type='code', scope=[],
                   desc='', active=True, private_key=None, public_key=None, expiry_date=None):
        """Add a client. Extend :function:`add_entity`
        
        :param objid: client objid
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
        :param scope: The list of scopes the client may request access to. If you allow multiple types of grants this
            will vary related to their different security properties. For example, the Implicit Grant might only allow
            read-only scopes but the Authorization Grant also allow writes. [default=[]]
        :param redirect_uri: These are the absolute URIs that a client may use to redirect to after authorization. You
            should never allow a client to redirect to a URI that has not previously been registered.
        :param active: True if client is active. False otherwise. [default=True]
        :param expiry_date: relation expiry date [default=365 days]. Set using a datetime object
        :return: Oauth2Client instance
        :raise TransactionError:                
        """
        res = self.add_entity(Oauth2Client, objid, name, client_secret, user_id, grant_type, redirect_uri,
                              response_type=response_type, scope=scope, desc=desc, active=active,
                              private_key=private_key, public_key=public_key, expiry_date=expiry_date)
        return res
    
    def update_client(self, *args, **kvargs):
        """Update client. Extend :function:`update_entity`

        :param int oid: entity id. [optional]
        :param str objid: entity authorization id. [optional]
        :param str uuid: entity uuid. [optional]
        :param name: client name [optional]
        :param client_secret: client secret used for all grant type except JWT. [optional]
        :param user_id: user id associated to client. [optional]
        :param desc: client desc. [optional]
        :param private_key: private key used by Jwt grant type. [optional]
        :param public_key: public key used by Jwt grant type. [optional]
        :param grant_type: The grant type the client may utilize. This should only be one per client as each grant type
            has different security properties and it is best to keep them separate to avoid mistakes. [optional]
        :param response_type: If using a grant type with an associated response type (eg. Authorization Code Grant) or
            using a grant which only utilizes response types (eg. Implicit Grant). [optional]
        :param scope: The list of scopes the client may request access to. If you allow multiple types of grants this
            will vary related to their different security properties. For example, the Implicit Grant might
            only allow read-only scopes but the Authorization Grant also allow writes. [optional]
        :param redirect_uri: These are the absolute URIs that a client may use to redirect to after authorization. You
            should never allow a client to redirect to a URI that has not previously been registered. [optional]
        :param active: True if client is active. False otherwise. [optional]
        :param expiry_date: relation expiry date. Set using a datetime object. [optional]
        :return: update response
        :raise TransactionError:      
        """        
        res = self.update_entity(Oauth2Client, *args, **kvargs)
        return res  

    def remove_client(self, *args, **kvargs):
        """Remove client.

        :param int oid: entity id. [optional]
        :param str objid: entity authorization id. [optional]
        :param str uuid: entity uuid. [optional]
        :param str name: entity name. [optional]
        :return:
        :raise TransactionError:    
        """
        res = self.remove_entity(Oauth2Client, *args, **kvargs)
        return res
    
    #
    # authorization_code
    #
    def count_authorization_codes(self):
        """Get authorization_codes count.
        """
        return self.count_entites(Oauth2AuthorizationCode)
    
    def get_authorization_codes(self, expire=None, client_id=None, valid=True, user_id=None, page=0, size=10,
                                order='DESC', field='id', code=None):
        """Get authorization_codes

        :param code: authorization code [optional]
        :param expire: expire time [optional]
        :param client_id: client id [optional]
        :param valid: if True get only code not expired [optional]
        :param user_id: user id [optional]
        :param page: entities list page to show [default=0]
        :param size: number of entities to show in list per page [default=0]
        :param order: sort order [default=DESC]
        :param field: sort field [default=id]
        :return: authorization codes
        :raise QueryError:
        """
        session = self.get_session()
        
        # get entity
        query = session.query(Oauth2AuthorizationCode)
          
        if code is not None:
            query = query.filter(Oauth2AuthorizationCode.code.like('%'+code+'%'))
        if expire is not None:
            query = query.filter_by(expires_at=expire)
        if user_id is not None:
            query = query.filter_by(user_id=user_id)
        if client_id is not None:
            query = query.filter_by(client_id=client_id)
        if valid is True:
            today = datetime.today()
            query = query.filter(Oauth2AuthorizationCode.expires_at > today)
        self.logger.warn('stmp: %s' % query.statement.compile(dialect=mysql.dialect()))
        res = query.limit(size).offset(page*size).all()
        total = query.count()
        
        self.logger.debug('Get get_authorization_codes: %s' % truncate(res))
        return res, total
    
    @transaction
    def remove_authorization_code(self, code):
        """Remove authorization code.
        
        :param code: authorization code
        :return: authorization code id
        :raise TransactionError:  
        """
        session = self.get_session()

        # get entity
        query = session.query(Oauth2AuthorizationCode).filter(Oauth2AuthorizationCode.code.like('%'+code+'%'))

        entity = query.first()
        if entity is None:
            msg = 'No %s found' % Oauth2AuthorizationCode.__name__
            self.logger.error(msg)
            raise ModelError(msg, code=404)
        
        # expire code
        for e in query.all():
            e.expires_at = datetime.today()
        
        self.logger.debug('Expire %s %s' % (Oauth2AuthorizationCode.__name__, entity.id))
        return None
