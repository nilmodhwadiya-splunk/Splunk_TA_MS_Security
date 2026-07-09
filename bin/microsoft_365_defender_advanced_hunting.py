##
# SPDX-FileCopyrightText: 2026 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
##
##

import import_declare_test  # isort: skip
import splunk_ta_ms_security_constants  # isort: skip
from typing import Any

import json
import sys
import traceback

import requests
from requests import HTTPError
from solnlib import log
from splunklib import modularinput as smi

from Splunk_TA_MS_Security.environment_specific_urls import EnvironmentSpecificUrls
from ms_security_utils import (
    get_access_token,
    get_account_details,
    get_current_addon_version,
    get_proxy,
    raise_error_from_http_error,
    required,
    use_log_level_from_config,
)

LOG_FILE_NAME = splunk_ta_ms_security_constants.ADVANCED_HUNTING_INPUT_LOG_FILE_NAME


class MICROSOFT_365_DEFENDER_ADVANCED_HUNTING(smi.Script):
    def __init__(self):
        super().__init__()

    def get_scheme(self):
        scheme = smi.Scheme("microsoft_365_defender_advanced_hunting")
        scheme.description = "Microsoft 365 Defender Advanced Hunting"
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
                "environment",
                required_on_create=True,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "query",
                required_on_create=True,
            )
        )

        return scheme

    def validate_input(self, definition: Any) -> None:
        required(
            definition.parameters.get("query"),
            "Required input parameter 'query' missing",
        )

    def stream_events(self, inputs: smi.InputDefinition, ew: smi.EventWriter) -> None:
        access_token = None
        session_key = inputs.metadata["session_key"]

        logger = log.Logs().get_logger(LOG_FILE_NAME)
        use_log_level_from_config(logger, session_key)

        for input_name, input_item in inputs.inputs.items():
            input_name = input_name.split("//")[1]
            input_item["name"] = input_name
            global_account = get_account_details(
                logger, session_key, input_item["azure_app_account"]
            )
            input_item["tenant_id"] = input_item.get("tenant_id") or global_account.get(
                "tenant_id"
            )
            tenant_id = required(
                input_item.get("tenant_id"),
                "Required input parameter 'tenant_id' missing",
            )
            environment = required(
                input_item.get("environment"),
                "Required input parameter 'environment' missing",
            )
            query = required(
                input_item.get("query"),
                "Required input parameter 'query' missing",
            )

            urls = EnvironmentSpecificUrls.get_urls_by_environment(
                environment, tenant_id
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
                    environment,
                    add_default=True,
                )
            except Exception:
                logger.error(
                    f"Failed to get access token, reason={traceback.format_exc()}"
                )

            try:
                current_version = get_current_addon_version(logger, session_key)
            except Exception:
                logger.error("Failed to get current addon version")
                current_version = "unknown"

            if not access_token:
                logger.error(splunk_ta_ms_security_constants.TOKEN_FAILURE_EXIT)
                raise RuntimeError(
                    "Unable to obtain access token. Please check the delegated sign-in status, Application ID, Client Secret, and Tenant ID"
                )

            logger.info(splunk_ta_ms_security_constants.TOKEN_SUCCESS_PROCEED)
            results = self._hunt_by_query(
                logger,
                session_key,
                query,
                access_token,
                urls,
                current_version,
                environment,
            )

            events_ingested = 0
            for result in results:
                event = smi.Event(
                    data=json.dumps(result, ensure_ascii=False),
                    index=input_item["index"],
                    source=f"microsoft_365_defender_advanced_hunting:{tenant_id}",
                    sourcetype=input_item["sourcetype"],
                )
                ew.write_event(event)
                events_ingested = events_ingested + 1

            logger.info(
                f"Advanced hunting results ingested - advanced_hunting_count={events_ingested}"
            )

    def _hunt_by_query(
        self, logger, session_key, query, access_token, urls, current_version, environment
    ):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {access_token}",
            "User-Agent": f"M365DPartner-Splunk-MicrosoftSecurityAddOn/{current_version}",
        }
        proxies = get_proxy(logger, session_key)

        try:
            resp = requests.post(
                urls.advanced_hunting,
                headers=headers,
                data=json.dumps({"Query": query}),
                proxies=proxies,
                timeout=60,
            )
            resp.raise_for_status()
            response = json.loads(resp.content)
            if environment.endswith(splunk_ta_ms_security_constants.GRAPH_API):
                return response.get("results", [])
            return response.get("Results", [])
        except HTTPError as e:
            raise_error_from_http_error(logger, e)


if __name__ == "__main__":
    exit_code = MICROSOFT_365_DEFENDER_ADVANCED_HUNTING().run(sys.argv)
    sys.exit(exit_code)