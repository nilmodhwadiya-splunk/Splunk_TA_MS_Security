# new file
import import_declare_test  # isort: skip
import splunk_ta_ms_security_constants  # isort: skip

from typing import Any
import json
import sys
import traceback
import urllib.request
import urllib.error

from Splunk_TA_MS_Security.environment_specific_urls import EnvironmentSpecificUrls
from ms_security_utils import (
    get_access_token,
    get_account_details,
    get_current_addon_version,
    use_log_level_from_config,
)
from solnlib import log
from splunklib import modularinput as smi


LOG_FILE_NAME = "microsoft_graph_security_hunting_query.log"


class MICROSOFT_GRAPH_SECURITY_HUNTING_QUERY(smi.Script):
    def __init__(self):
        super().__init__()

    def get_scheme(self):
        scheme = smi.Scheme("microsoft_graph_security_hunting_query")
        scheme.description = "Microsoft Graph Security Hunting Query"
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(smi.Argument("name", title="Name", required_on_create=True))
        scheme.add_argument(smi.Argument("azure_app_account", required_on_create=True))
        scheme.add_argument(smi.Argument("tenant_id", required_on_create=False))
        scheme.add_argument(smi.Argument("query", required_on_create=True))
        scheme.add_argument(smi.Argument("environment", required_on_create=False))

        return scheme

    def validate_input(self, definition: Any) -> None:
        query = definition.parameters.get("query")

        if not query or len(query.strip()) == 0:
            raise ValueError("Query is required and cannot be empty.")

    def _get_graph_base_url(self, environment: str) -> str:
        if not environment:
            return "https://graph.microsoft.com"

        environment = environment.lower()

        if environment in ("commercial", "commercial-graph-api"):
            return "https://graph.microsoft.com"

        if environment in ("gov", "gcc", "gcc-high", "usgov", "us-government"):
            return "https://graph.microsoft.us"

        if environment in ("dod", "usgov-dod"):
            return "https://dod-graph.microsoft.us"

        return "https://graph.microsoft.com"

    def _run_hunting_query(self, logger, access_token: str, graph_url: str, query: str):
        url = f"{graph_url}/v1.0/security/runHuntingQuery"

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        payload = json.dumps({"query": query}).encode("utf-8")

        request = urllib.request.Request(
            url=url,
            data=payload,
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                response_body = response.read().decode("utf-8")
                return json.loads(response_body)

        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8")
            logger.error(
                f"Microsoft Graph runHuntingQuery failed. "
                f"status={e.code}, response={error_body}"
            )
            raise

        except Exception:
            logger.error(
                f"Unexpected error while calling runHuntingQuery: "
                f"{traceback.format_exc()}"
            )
            raise

    def stream_events(self, inputs: smi.InputDefinition, ew: smi.EventWriter) -> None:
        session_key = inputs.metadata["session_key"]

        logger = log.Logs().get_logger(LOG_FILE_NAME)
        use_log_level_from_config(logger, session_key)

        for input_name, input_item in inputs.inputs.items():
            short_input_name = input_name.split("//")[1]
            input_item["name"] = short_input_name

            logger.info(
                f"Starting Microsoft Graph Security Hunting Query input={short_input_name}"
            )

            global_account = get_account_details(
                logger,
                session_key,
                input_item["azure_app_account"],
            )

            input_item["tenant_id"] = input_item.get("tenant_id") or global_account.get(
                "tenant_id"
            )

            query = input_item.get("query")
            environment = input_item.get("environment") or "commercial-graph-api"
            graph_url = self._get_graph_base_url(environment)

            # IMPORTANT:
            # This input must use delegated permissions.
            # Application permissions are not allowed in this customer environment.
            use_delegated_permissions = global_account.get("use_delegated_permissions")
            delegated_acc_name = global_account.get("delegated_acc_name")

            if not use_delegated_permissions:
                raise RuntimeError(
                    "This input requires delegated permissions. "
                    "Please enable delegated permissions in the Azure app account configuration."
                )

            if not delegated_acc_name:
                raise RuntimeError(
                    "Delegated account name is missing. "
                    "Please complete the delegated OAuth login flow first."
                )

            try:
                current_version = get_current_addon_version(logger, session_key)
                logger.info(f"Current TA version={current_version}")
            except Exception:
                logger.error("Failed to get current addon version")

            try:
                urls = EnvironmentSpecificUrls.get_urls_by_environment(
                    environment,
                    input_item["tenant_id"],
                )
            except Exception:
                urls = None
                logger.warning(
                    "Could not get environment-specific URLs. "
                    "Token helper will use environment fallback."
                )

            try:
                logger.debug(
                    f"Trying to get delegated Microsoft Graph access token "
                    f"for input={short_input_name}"
                )

                access_token = get_access_token(
                    global_account["username"],
                    global_account["password"],
                    urls,
                    logger,
                    session_key,
                    True,  # force delegated permission flow
                    delegated_acc_name,
                    environment=environment,
                    add_default=True,
                )

            except Exception:
                logger.error(f"Failed to get access token: {traceback.format_exc()}")
                raise RuntimeError(
                    "Unable to obtain delegated Microsoft Graph access token. "
                    "Please check delegated login, tenant ID, and Graph permissions."
                )

            if not access_token:
                raise RuntimeError("Access token is empty.")

            logger.info("Delegated access token obtained successfully.")

            response = self._run_hunting_query(
                logger,
                access_token,
                graph_url,
                query,
            )

            results = response.get("results") or []

            events_ingested = 0

            for result in results:
                event = smi.Event(
                    data=json.dumps(result, ensure_ascii=False),
                    index=input_item["index"],
                    source="microsoft_graph_security_hunting_query",
                    sourcetype="ms:defender:hunting:query",
                )
                ew.write_event(event)
                events_ingested += 1

            logger.info(
                f"Microsoft Graph Security Hunting Query completed. "
                f"input={short_input_name}, events_ingested={events_ingested}"
            )


if __name__ == "__main__":
    exit_code = MICROSOFT_GRAPH_SECURITY_HUNTING_QUERY().run(sys.argv)
    sys.exit(exit_code)