# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2024 CSI-Piemonte

from flask import request, session
from beecell.auth.base import SystemUser as BaseSystemUser


class SystemUser(BaseSystemUser):
    @staticmethod
    def load_user(userid):
        """Function to use with @self.login_manager.user_loader"""
        suser = None

        # load user only for dynamic request
        if request.path.find("static") < 0:
            # Return an instance of the User model
            user = session.get("user_obj")

            # create SystemUser instance
            suser = SystemUser.create(user)

        return suser
