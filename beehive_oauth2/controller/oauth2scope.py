# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2024 CSI-Piemonte

from .oauth2object import Oauth2Object


class Oauth2Scope(Oauth2Object):
    objdef = "Oauth2Scope"
    objdesc = "Oauth2 Scope"
    objuri = "nas/oauth2/scope"

    def __init__(self, *args, **kvargs):
        Oauth2Object.__init__(self, *args, **kvargs)

        self.update_object = self.manager.update_scope
        self.delete_object = self.manager.remove_scope
        self.register = True
