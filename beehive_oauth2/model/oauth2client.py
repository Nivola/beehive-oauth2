# -*- coding: utf-8 -*-
# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2024 CSI-Piemonte

from datetime import datetime, timedelta
from sqlalchemy import Column, Integer, String, Boolean, Table, ForeignKey, DateTime
from sqlalchemy.orm import relationship, backref
from beehive.common.model import BaseEntity

# Base = declarative_base()

from beehive.common.model.authorization import Base


# Many-to-Many Relationship
consumer_scope = Table(
    "oauth2_client_scope",
    Base.metadata,
    Column("id", Integer, primary_key=True),
    Column("consumer_id", Integer(), ForeignKey("oauth2_client.id")),
    Column("scope_id", Integer(), ForeignKey("oauth2_scope.id")),
)


# Oauth2 Consumer
class Oauth2Client(Base, BaseEntity):
    """Oauth2 Client"""

    __tablename__ = "oauth2_client"

    client_secret = Column(String(200), unique=True)
    private_key = Column(String(4096))
    public_key = Column(String(4096))
    user_id = Column(Integer(), ForeignKey("user.id"))
    user = relationship("User")
    grant_type = Column(String(50))
    response_type = Column(String(10))
    scope = relationship(
        "Oauth2Scope",
        secondary=consumer_scope,
        backref=backref("oauth2_client", lazy="dynamic"),
    )
    redirect_uri = Column(String(256))

    def __init__(
        self,
        objid,
        name,
        client_secret,
        user_id,
        grant_type,
        redirect_uri,
        response_type="code",
        scope=[],
        desc="",
        active=True,
        private_key=None,
        public_key=None,
        expiry_date=None,
    ):
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
            expiry_date = datetime.datetime.today() + datetime.timedelta(days=365)
        self.expiry_date = expiry_date
