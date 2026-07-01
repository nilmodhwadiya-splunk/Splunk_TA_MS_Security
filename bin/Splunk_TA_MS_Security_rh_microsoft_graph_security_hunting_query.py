## new file
##
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
##
##

import import_declare_test  # noqa: F401 isort: skip
import splunk_ta_ms_security_constants  # isort: skip
import logging
from typing import Any

from Splunk_TA_MS_Security_account_validation import account_validation
from splunktaucclib.rest_handler import admin_external, util
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler
from splunktaucclib.rest_handler.endpoint import (
    DataInputModel,
    RestModel,
    field,
    validator,
)

LOG_FILE_NAME = "microsoft_graph_security_hunting_query.log"

util.remove_http_proxy_env_vars()


fields = [
    field.RestField(
        "interval",
        required=True,
        encrypted=False,
        default=300,
        validator=validator.Number(
            max_val=31536000,
            min_val=1,
            is_int=True,
        ),
    ),
    field.RestField(
        "index",
        required=True,
        encrypted=False,
        default="default",
        validator=validator.String(
            max_len=80,
            min_len=1,
        ),
    ),
    field.RestField(
        "azure_app_account",
        required=True,
        encrypted=False,
        default=None,
        validator=None,
    ),
    field.RestField(
        "tenant_id",
        required=False,
        encrypted=False,
        default="",
        validator=validator.String(
            max_len=8192,
            min_len=0,
        ),
    ),
    field.RestField(
        "query",
        required=True,
        encrypted=False,
        default=None,
        validator=validator.String(
            max_len=8192,
            min_len=1,
        ),
    ),
    field.RestField(
        "environment",
        required=False,
        encrypted=False,
        default="commercial-graph-api",
        validator=None,
    ),
    field.RestField("disabled", required=False, validator=None),
]

model = RestModel(fields, name=None)

endpoint = DataInputModel(
    "microsoft_graph_security_hunting_query",
    model,
)


class MSSecurityAccountExternalHandler(AdminExternalHandler):
    def __init__(self, *args, **kwargs):
        AdminExternalHandler.__init__(self, *args, **kwargs)

    def handleEdit(self, confInfo: Any) -> None:
        if not self.payload.get("disabled"):
            account_validation(
                self.payload,
                self.getSessionKey(),
            )
        AdminExternalHandler.handleEdit(self, confInfo)

    def handleCreate(self, confInfo: Any) -> None:
        account_validation(
            self.payload,
            self.getSessionKey(),
        )
        AdminExternalHandler.handleCreate(self, confInfo)


if __name__ == "__main__":
    logging.getLogger().addHandler(logging.NullHandler())
    admin_external.handle(
        endpoint,
        handler=MSSecurityAccountExternalHandler,
    )