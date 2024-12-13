# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2024 CSI-Piemonte

from beehive.common.apimanager import ApiModule
from beehive_oauth2.view import Oauth2Api
from beehive_oauth2.controller import Oauth2Controller
from beehive.common.controller.authorization import AuthenticationManager


class Oauth2Module(ApiModule):
    """Oauth2 Beehive Module"""

    def __init__(self, api_manger):
        self.name = "Oauth2Module"

        ApiModule.__init__(self, api_manger, self.name)

        self.apis = [Oauth2Api]
        self.authentication_manager = AuthenticationManager(api_manger.auth_providers)
        self.controller = Oauth2Controller(self)

    def get_controller(self):
        return self.controller

    def set_authentication_providers(self, auth_providers):
        self.authentication_manager.auth_providers = auth_providers
