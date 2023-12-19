# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2023 CSI-Piemonte

import ujson as json
from beecell.simple import (
    id_gen,
    truncate,
    get_value,
    random_password,
    token_gen,
    format_date,
)
import os
from inspect import getfile
from datetime import datetime
from flask import request, session
from beecell.flask.render import render_template
from flask.helpers import url_for
from copy import deepcopy
from oauthlib.oauth2 import (
    WebApplicationServer,
    MobileApplicationServer,
    LegacyApplicationServer,
    BackendApplicationServer,
)
from oauthlib.oauth2 import FatalClientError, OAuth2Error
import logging
from beehive.common.model.authorization import AuthDbManager


from .oauth2object import Oauth2Object


class Oauth2AuthorizationCode(Oauth2Object):
    objdef = "Oauth2AuthorizationCode"
    objdesc = "Oauth2 Authorization Code"
    objuri = "nas/oauth2/authorization_codes"

    def __init__(
        self,
        controller,
        oid=None,
        objid=None,
        name=None,
        desc=None,
        active=None,
        model=None,
    ):
        self.logger = logging.getLogger(self.__class__.__module__ + "." + self.__class__.__name__)

        self.controller = controller
        self.model = model  # db model if exist
        self.oid = oid  # object internal db id
        self.objid = "*"

        # object uri
        self.objuri = "/%s/%s/%s" % (self.controller.version, self.objuri, self.oid)

        self.child_classes = []
        self.auth_db_manager = AuthDbManager()

        self.delete_object = self.manager.remove_authorization_code

    def info(self):
        """Get infos.

        :return: dict with infos
        :raise ApiManagerError:
        """
        expired = False
        if self.model.expires_at <= datetime.today():
            expired = True
        code = json.loads(self.model.code)
        info = {
            "id": self.model.id,
            "client": self.model.client.uuid,
            "user": self.model.user.uuid,
            "scope": [s.name for s in self.model.scope],
            "code": code["code"],
            "state": code["state"],
            "expires_at": format_date(self.model.expires_at),
            "expired": expired,
            "redirect_uri": self.model.redirect_uri,
        }
        return info

    def detail(self):
        """Get details.

        :return: dict with details
        :raise ApiManagerError:
        """
        info = self.info()
        return info
