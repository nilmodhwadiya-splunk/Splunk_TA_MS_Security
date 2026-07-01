##
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
##
##

import import_declare_test  # isort: skip
import splunk_ta_ms_security_constants  # isort: skip

import json
import logging
from typing import Any

import splunk.rest as rest
from solnlib import conf_manager, log
from splunktaucclib.rest_handler import admin_external, util
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler
from splunktaucclib.rest_handler.endpoint import (
    RestModel,
    SingleModel,
    field,
    validator,
)
from splunktaucclib.rest_handler.error import RestError

APP_NAME = import_declare_test.ta_name
LOG_FILE_NAME = splunk_ta_ms_security_constants.ACCOUNT_VALIDATION_LOG_FILE_NAME
SETTINGS_CONF_NAME = splunk_ta_ms_security_constants.SETTINGS_CONF_NAME
util.remove_http_proxy_env_vars()


fields = [
    field.RestField(
        "username",
        required=True,
        encrypted=False,
        default=None,
        validator=validator.String(
            max_len=200,
            min_len=1,
        ),
    ),
    field.RestField(
        "password",
        required=True,
        encrypted=True,
        default=None,
        validator=validator.String(
            max_len=8192,
            min_len=1,
        ),
    ),
    field.RestField(
        "tenant_id",
        required=True,
        encrypted=False,
        default=None,
        validator=validator.String(
            max_len=200,
            min_len=1,
        ),
    ),
    field.RestField(
        "use_delegated_permissions",
        required=False,
        encrypted=False,
        default=None
    ),
    field.RestField(
        "delegated_acc_name",
        required=False,
        encrypted=False,
        default=None
    ),
]
model = RestModel(fields, name=None)


endpoint = SingleModel("splunk_ta_ms_security_account", model, config_name="account")


class MSSecurityAccountExternalHandler(AdminExternalHandler):
    def __init__(self, *args, **kwargs):
        AdminExternalHandler.__init__(self, *args, **kwargs)

    def handleRemove(self, confInfo: Any) -> None:
        session_key = self.getSessionKey()
        server_name = self.callerArgs.id
        logger = log.Logs().get_logger(LOG_FILE_NAME)
        log_level = conf_manager.get_log_level(
            logger=logger,
            session_key=session_key,
            app_name=APP_NAME,
            conf_name=SETTINGS_CONF_NAME,
        )
        logger.info(f"log level set is : {log_level}")
        logger.setLevel(log_level)
        try:
            response_status, response_content = rest.simpleRequest(
                "/servicesNS/nobody/" + str(APP_NAME) + "/configs/conf-inputs/",
                sessionKey=session_key,
                getargs={"output_mode": "json"},
                raiseAllErrors=True,
            )
            res = json.loads(response_content)
            if "entry" in res:
                for inputs in res["entry"]:
                    if "name" in inputs:
                        input_name = inputs["name"]
                        if (
                            "app" in inputs.get("acl", "")
                            and inputs["acl"].get("app", "") == APP_NAME
                        ):
                            if (
                                "content" in inputs
                                and "azure_app_account" in inputs["content"]
                            ):
                                account_name = inputs["content"]["azure_app_account"]
                                if account_name == server_name:
                                    raise RestError(
                                        409,
                                        f"Cannot delete the account as it is already been used in {input_name.split('//')[1]}.",
                                    )
        except Exception as e:  # noqa: F841
            logger.error(  # nosemgrep
                f"Cannot delete the account as it is already been used in {input_name.split('//')[1]}."
            )
            raise RestError(
                409,
                f"Cannot delete the account as it is already been used in {input_name.split('//')[1]}.",
            )
        AdminExternalHandler.handleRemove(self, confInfo)


if __name__ == "__main__":
    logging.getLogger().addHandler(logging.NullHandler())
    admin_external.handle(
        endpoint,
        handler=MSSecurityAccountExternalHandler,
    )
