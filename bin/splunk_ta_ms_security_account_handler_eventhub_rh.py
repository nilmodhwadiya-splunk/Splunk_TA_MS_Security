##
# SPDX-FileCopyrightText: 2023 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
##
##

import import_declare_test  # noqa: 401
import splunk_ta_ms_security_constants  # noqa: 401
from typing import Any

from ms_security_utils import delete_checkpoint
from eventhub_helper import event_hub_consumer_validation
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler

LOG_FILE_NAME = splunk_ta_ms_security_constants.EVENT_HUB_LOG_FILE_NAME


class MSSecurityAccountExternalHandler(AdminExternalHandler):
    def __init__(self, *args, **kwargs):
        AdminExternalHandler.__init__(self, *args, **kwargs)

    def handleEdit(self, confInfo: Any) -> None:
        """
        This function calls event_hub_consumer_validation to validate the account details on Edit Input.
        """
        if not self.payload.get("disabled"):
            event_hub_consumer_validation(
                self.payload, self.getSessionKey(), LOG_FILE_NAME
            )
        AdminExternalHandler.handleEdit(self, confInfo)

    def handleCreate(self, confInfo: Any) -> None:
        """
        This function calls event_hub_consumer_validation to validate the account_details on Create Input.
        """
        event_hub_consumer_validation(self.payload, self.getSessionKey(), LOG_FILE_NAME)
        AdminExternalHandler.handleCreate(self, confInfo)

    def handleRemove(self, confInfo: Any) -> None:
        session_key = self.getSessionKey()
        input_name = self.callerArgs.id
        input_type = self.handler.get_endpoint().input_type
        delete_checkpoint(session_key, input_name, input_type, LOG_FILE_NAME)
        AdminExternalHandler.handleRemove(self, confInfo)
