import import_declare_test  # isort: skip
import splunk_ta_ms_security_constants  # isort: skip
from typing import Any, Optional

import datetime
import json
import sys
import traceback

from Splunk_TA_MS_Security.api_specific_content import ApiSpecificContent
from Splunk_TA_MS_Security.environment_specific_urls import EnvironmentSpecificUrls
from ms_security_utils import (
    checkpoint_handler,
    get_access_token,
    get_account_details,
    get_atp_alerts_odata,
    get_current_addon_version,
    get_start_date,
    use_log_level_from_config,
    required,
)
from ta_execution_exception import TaExecutionException

from solnlib import conf_manager, log
from splunklib import modularinput as smi

LOG_FILE_NAME = splunk_ta_ms_security_constants.MACHINES_LOG_FILE_NAME
APP_NAME = import_declare_test.ta_name
SETTINGS_CONF_NAME = splunk_ta_ms_security_constants.SETTINGS_CONF_NAME


class MICROSOFT_DEFENDER_ENDPOINT_MACHINES(smi.Script):
    def __init__(self):
        super().__init__()

    def get_scheme(self):
        scheme = smi.Scheme("microsoft_defender_endpoint_machines")
        scheme.description = "Microsoft Defender Machines"
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
                "tenant_id",
                required_on_create=False,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "location",
                required_on_create=True,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "start_date",
                required_on_create=False,
            )
        )

        return scheme

    def validate_input(self, definition: Any) -> None:
        start_date = definition.parameters.get("start_date")
        today = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        if start_date:
            if start_date > today:
                raise ValueError(
                    f"Start date - {start_date} is a future date. It should be less than current time"
                )
            try:
                datetime.datetime.strptime(start_date, "%Y-%m-%dT%H:%M:%SZ")
            except ValueError:  # noqa: F841
                raise ValueError(
                    f"Invalid date format specified for 'Start Date': {start_date}"
                )
            except Exception as e:
                raise Exception(f"Unknown exception occurred - {e}")

    def stream_events(self, inputs: smi.InputDefinition, ew: smi.EventWriter) -> None:
        """
        Main entry point to start the data ingest for each modinput
        :param inputs: inputs configured via the UI in the inputs.conf
        :param event_writer: EventWriter object to ingest data to Splunk
        :return: None
        """
        access_token = None
        session_key = inputs.metadata["session_key"]

        logger = log.Logs().get_logger(LOG_FILE_NAME)
        use_log_level_from_config(logger, session_key)

        for input_name, input_item in inputs.inputs.items():
            input_stanza_name = input_name
            input_name = input_name.split("//")[1]
            input_item["name"] = input_name
            check_point_key = f"machines_lastUpdateTime_{input_name}"
            global_account = get_account_details(
                logger, session_key, input_item["azure_app_account"]
            )
            # setting a higher precedence of tenant_id fetched from inputs over accounts
            input_item["tenant_id"] = input_item.get("tenant_id") or global_account.get(
                "tenant_id"
            )
            
            # As per MS docs, we update the location before starting the data collection via "General" location.
            if input_item["location"] == "api.securitycenter.windows.com":
                input_item["location"] = "api.securitycenter.microsoft.com"
            
            urls = EnvironmentSpecificUrls.get_urls_by_location(
                input_item["location"], input_item["tenant_id"]
            )

            try:
                logger.debug(f"Trying to get access token for input={input_name}")
                access_token = get_access_token(
                    global_account["username"],
                    global_account["password"],
                    urls,
                    logger,
                    session_key,
                    global_account["use_delegated_permissions"],
                    global_account["delegated_acc_name"],
                    environment=None,
                    add_default=True
                )
            except Exception:
                logger.error(f"Failed to get access token : {traceback.format_exc()}")

            try:
                logger.debug("Trying to get current addon version")
                current_version = get_current_addon_version(logger, session_key)
                logger.info(
                    splunk_ta_ms_security_constants.CURRENT_TA_VERSION.format(
                        version=current_version
                    )
                )
            except Exception:
                logger.error("Failed to get current addon version")

            if access_token:
                logger.info(splunk_ta_ms_security_constants.TOKEN_SUCCESS_PROCEED)

                query_date = get_start_date(
                    logger, session_key, check_point_key, input_item, input_stanza_name
                )
                
                machines_url = urls.machines + ApiSpecificContent.get_machines_filter(
                    urls.api, query_date
                )
                logger.debug(f"Machines URL : {machines_url}")
                max_machine_date = query_date
                
                machines = get_atp_alerts_odata(
                    logger,
                    session_key,
                    access_token,
                    machines_url,
                    user_agent=f"MdePartner-Splunk-MicrosoftSecurityAddOn/{current_version}",
                )

                machines_ingested = 0
                for machine in machines:
                    # Graph API uses lastUpdateDateTime and Microsoft 365 API uses lastUpdateTime
                    lastUpdateTime = (
                        machine.get("lastUpdateDateTime")
                        or machine.get("lastSeen")
                        or ""
                    )
                    required(
                        lastUpdateTime,
                        "Field denoting last update not found in the API response",
                    )
                    if lastUpdateTime > max_machine_date:
                        max_machine_date = lastUpdateTime

                    event = smi.Event(
                        data=json.dumps(machine, ensure_ascii=False),
                        index=input_item["index"],
                        source="microsoft_defender_endpoint_machines",
                        sourcetype="ms:defender:machines",
                    )
                    ew.write_event(event)
                    machines_ingested = machines_ingested + 1
                logger.info(
                    f"Total Machines ingested - machines_count={machines_ingested}"
                )
                checkpoint_handler(
                    logger,
                    session_key,
                    max_machine_date,
                    check_point_key,
                    input_stanza_name,
                )

            else:
                logger.error(splunk_ta_ms_security_constants.TOKEN_FAILURE_EXIT)
                raise RuntimeError(
                    "Unable to obtain access token. Please check the Application ID, Client Secret, and Tenant ID"
                )


# This script is running as an input. Input definitions will be
# passed on stdin as XML, and the script will write events on
# stdout and log entries on stderr.
if __name__ == "__main__":
    exit_code = MICROSOFT_DEFENDER_ENDPOINT_MACHINES().run(sys.argv)
    sys.exit(exit_code)