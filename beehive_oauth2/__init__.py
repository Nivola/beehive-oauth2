# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2026 CSI-Piemonte

with open(f"{__file__.replace('__init__.py', '')}VERSION") as f:
    __version__ = f.read()
print("__version__ " + __version__)

__git_last_commit__ = ""
try:
    import os

    LAST_COMMIT_PATH = os.getenv("LAST_COMMIT_BEEHIVE_OAUTH2")
    if LAST_COMMIT_PATH is not None:
        with open(LAST_COMMIT_PATH, encoding='utf-8') as f:
            __git_last_commit__ = f.read()
except Exception as ex:
    print(ex)
