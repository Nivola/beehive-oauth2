# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2024 CSI-Piemonte

from beehive.module.auth.controller import AuthObject


class Oauth2Object(AuthObject):
    objtype = "oauth2"
    objdef = "abstract"
    objdesc = "Oauth2 abstract object"

    @property
    def manager(self):
        return self.controller.manager
