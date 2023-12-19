# -*- coding: utf-8 -*-
# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2023 CSI-Piemonte

from datetime import datetime, timedelta
from sqlalchemy import Column, Integer, String, Boolean, Table, ForeignKey, DateTime
from sqlalchemy.orm import relationship, backref
from beehive.common.model.authorization import Base


# Many-to-Many Relationship
authorization_scope = Table(
    "oauth2_authorization_scope",
    Base.metadata,
    Column("id", Integer, primary_key=True),
    Column("authorization_id", Integer(), ForeignKey("oauth2_authorization_code.id")),
    Column("scope_id", Integer(), ForeignKey("oauth2_scope.id")),
)


# Oauth2 authorization code
class Oauth2AuthorizationCode(Base):
    """
    This is specific to the Authorization Code grant and represent the
    temporary credential granted to the client upon successful authorization.

    It will later be exchanged for an access token, when that is done it
    should cease to exist. It should have a limited life time, less than
    ten minutes.
    This model is similar to the Bearer Token as it mainly acts a temporary
    storage of properties to later be transferred to the token.

    :param client: Association with the client to whom the token was given.
    :param user: Association with the user to which protected resources this token grants access.
    :param code: An unguessable unique string of characters.
    :param expire: Exact time of expiration. Commonly this is one hour after creation.
    :param redirect_uri: These are the absolute URIs that a client may use to redirect to after authorization. You
        should never allow a client to redirect to a URI that has not previously been registered.
    :return: authorization code instance
    """

    __tablename__ = "oauth2_authorization_code"
    __table_args__ = {"mysql_engine": "InnoDB"}

    id = Column(Integer(), primary_key=True)
    client_id = Column(Integer(), ForeignKey("oauth2_client.id"))
    client = relationship("Oauth2Client")
    user_id = Column(Integer(), ForeignKey("user.id"))
    user = relationship("User")
    scope = relationship(
        "Oauth2Scope",
        secondary=authorization_scope,
        backref=backref("oauth2_authorization_code", lazy="dynamic"),
    )
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
        return "<Oauth2AuthorizationCode id=%s client_id=%s user_id=%s scope=%s redirect_uri=%s)>" % (
            self.id,
            self.client_id,
            self.user_id,
            self.scope,
            self.redirect_uri,
        )
