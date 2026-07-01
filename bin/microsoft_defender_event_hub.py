##
# SPDX-FileCopyrightText: 2023 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
##
##

import sys
import time
import traceback
from typing import Optional, Any
import import_declare_test  # noqa: F401
import splunk_ta_ms_security_constants  # noqa: F401

from solnlib import log
from splunklib import modularinput as smi
from azure.eventhub import exceptions as azure_exceptions

from ms_security_utils import (
    get_account_details,
    use_log_level_from_config,
    get_proxy_dict_for_eventhub,
)
from eventhub_helper import EventHubConsumerHandler, create_event_hub_consumer_client

LOG_FILE_NAME = splunk_ta_ms_security_constants.EVENT_HUB_LOG_FILE_NAME
APP_NAME = import_declare_test.ta_name
EH_FAILED_TO_CREATE_MSG = splunk_ta_ms_security_constants.EH_FAILED_TO_CREATE_MSG


class MICROSOFT_DEFENDER_EVENT_HUB(smi.Script):
    def __init__(self):
        super().__init__()

    def get_scheme(self) -> Optional[smi.Scheme]:
        """
        Method overloads method from parent class. @see splunklib.modularinput.script.get_schema
        """
        scheme = smi.Scheme("microsoft_defender_event_hub")
        scheme.description = "Microsoft Defender Event Hub"
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(
            smi.Argument(
                "name", title="Name", description="Name", required_on_create=True
            )
        )

        scheme.add_argument(
            smi.Argument(
                "azure_app_account",
                required_on_create=True,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "event_hub_namespace",
                required_on_create=True,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "event_hub_name",
                required_on_create=True,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "consumer_group",
                required_on_create=True,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "streaming_event_types",
                required_on_create=False,
            )
        )

        return scheme

    def validate_input(self, definition: Any) -> None:
        """
        Method overloads method from parent class. @see splunklib.modularinput.script.validate_input
        """
        return

    def stream_events(self, inputs: smi.InputDefinition, ew: smi.EventWriter) -> None:
        """
        Main entry point to start the data ingest for each modinput
        :param inputs: inputs configured via the UI in the inputs.conf
        :param event_writer: EventWriter object to ingest data to Splunk
        :return: None
        """
        session_key = inputs.metadata["session_key"]

        logger = log.Logs().get_logger(LOG_FILE_NAME)
        use_log_level_from_config(logger, session_key)

        for input_name, input_item in inputs.inputs.items():
            input_name = input_name.split("//")[1]
            input_item["name"] = input_name
            global_account = get_account_details(
                logger, session_key, input_item["azure_app_account"]
            )
            proxies = get_proxy_dict_for_eventhub(logger, session_key)

            try:
                consumer = create_event_hub_consumer_client(
                    logger, global_account, input_item, proxies, session_key
                )
            except azure_exceptions.EventHubError as exc:
                logger.error(vars(exc))
                logger.error(EH_FAILED_TO_CREATE_MSG.format(traceback.format_exc()))
                sys.exit(1)
            except Exception:
                logger.error(EH_FAILED_TO_CREATE_MSG.format(traceback.format_exc()))
                sys.exit(1)

            with EventHubConsumerHandler(consumer, ew, input_item, logger) as handler:
                while handler.is_alive():
                    time.sleep(1.0)
            return 0


if __name__ == "__main__":
    exit_code = MICROSOFT_DEFENDER_EVENT_HUB().run(sys.argv)
    sys.exit(exit_code)
