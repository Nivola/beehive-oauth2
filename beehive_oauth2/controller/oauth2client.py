# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2024 CSI-Piemonte

from beehive.common.apimanager import ApiManagerError
from beecell.db import TransactionError
from beehive.common.data import trace


from .oauth2object import Oauth2Object


class Oauth2Client(Oauth2Object):
    objdef = "Oauth2Client"
    objdesc = "Oauth2 Client"
    objuri = "nas/oauth2/clients"

    def __init__(self, *args, **kvargs):
        Oauth2Object.__init__(self, *args, **kvargs)

        self.update_object = self.manager.update_client
        self.delete_object = self.manager.remove_client
        self.register = True

    def info(self):
        """Get infos.

        :return: dict with infos
        :raise ApiManagerError:
        """
        info = Oauth2Object.info(self)
        info.update(
            {
                "grant_type": self.model.grant_type,
                "response_type": self.model.response_type,
                "scopes": ",".join([i.name for i in self.model.scope]),
            }
        )
        return info

    def detail(self):
        """Get details.

        :return: dict with details
        :raise ApiManagerError:
        """
        info = self.info()
        info.update(
            {
                "client_secret": self.model.client_secret,
                "client_email": self.model.user.name,
                "redirect_uri": self.model.redirect_uri,
                "private_key": self.model.private_key,
                "public_key": self.model.public_key,
                "auth_uri": self.controller.auth_uri,
                "token_uri": self.controller.token_uri,
            }
        )
        return info

    @trace(op="delete")
    def delete(self, soft=False, **kvargs):
        """Delete entity.

        :param kvargs: custom params
        :param authorize: if True check permissions for authorization
        :param soft: if True make a soft delete
        :return: None
        :raise ApiManagerError:
        """
        if self.delete_object is None:
            raise ApiManagerError("Delete is not supported for %s:%s" % (self.objtype, self.objdef))

        # verify permissions
        self.verify_permisssions("delete")

        # custom action
        if self.pre_delete is not None:
            kvargs = self.pre_delete(**kvargs)

        try:
            if soft is False:
                # delete client
                self.delete_object(oid=self.oid)
                if self.register is True:
                    # remove object and permissions
                    self.deregister_object(self.objid.split("//"))

                user_name = "%s@local" % self.name
                if self.controller.exist_user(user_name) is True:
                    # delete client internal user
                    user = self.controller.get_user(user_name)
                    user.delete()

                self.logger.debug("Delete %s: %s" % (self.objdef, self.oid))
            else:
                self.delete_object(self.model)
                self.logger.debug("Soft delete %s: %s" % (self.objdef, self.oid))
            return None
        except TransactionError as ex:
            self.logger.error(ex.desc, exc_info=True)
            raise ApiManagerError(ex, code=ex.code)
