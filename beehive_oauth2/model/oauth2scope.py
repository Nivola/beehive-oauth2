# -*- coding: utf-8 -*-
# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2024 CSI-Piemonte

# import pandas as pd
from beehive.common.model import BaseEntity
from beehive.common.model.authorization import Base


# Oauth2 Scope
class Oauth2Scope(Base, BaseEntity):
    __tablename__ = "oauth2_scope"

    def __init__(self, objid, name, desc):
        BaseEntity.__init__(self, objid, name, desc, True)
