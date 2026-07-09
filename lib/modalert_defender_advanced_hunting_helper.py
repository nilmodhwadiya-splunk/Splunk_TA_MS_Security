#  SPDX-FileCopyrightText: 2023 Splunk, Inc. <sales@splunk.com>
#  SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#

import json
import logging
from functools import lru_cache
from typing import Union, List

import requests
from requests import HTTPError

import splunk_ta_ms_security_constants
from Splunk_TA_MS_Security.environment_specific_urls import EnvironmentSpecificUrls
from alert_actions_base import ModularAlertBase
from ms_security_utils import (
    get_access_token,
    get_account_details,
    get_credentials,
    required,
    get_current_addon_version,
    get_proxy,
    get_hostname_from_socket,
    raise_error_from_http_error,
)
from ta_execution_exception import TaExecutionException

ACCOUNT_CONF_NAME = splunk_ta_ms_security_constants.ACCOUNT_CONF_NAME


def process_event(invoker: ModularAlertBase):
    logger = invoker.logger
    logger.info("_Splunk_ Alert action defender_advanced_hunting started.")
    try:
        return AdvancedHuntingHelper(invoker).process_events(
            logger, invoker.get_events()
        )
    except Exception as e:
        logger.error(f"_Splunk_ Exception occurred during defender get_events() : {e}")
        raise TaExecutionException(e, 1)


class AdvancedHuntingHelper:
    def __init__(self, invoker: ModularAlertBase):
        self.session_key = required(invoker.session_key, "session_key")
        self.logger = invoker.logger

        self.query = required(
            invoker.get_param("query"),
            "No 'query' parameter specified. Please enter query parameter",
        )

        self.tenant_id_from_input = invoker.get_param("tenant_id")
        self.acc_tenant_id = ""
        self.account_name = invoker.get_param("account_name")
        self.environment = invoker.get_param("environment") or "default"
        self.accessTokens = {}
        self.use_delegated_permissions = False
        self.delegated_acc_name = None

        self.client_id, self.client_secret, self.acc_tenant_id = get_credentials(
            invoker, self.session_key, self.logger
        )
        if self.account_name:
            account = get_account_details(
                self.logger, self.session_key, self.account_name
            )
            self.use_delegated_permissions = account.get(
                "use_delegated_permissions", False
            )
            self.delegated_acc_name = account.get("delegated_acc_name")

        self.index = "main"
        self.source = "_advanced_hunting"
        self.sourcetype = "m365:defender:incident:advanced_hunting"

        self.addevent = invoker.addevent
        self.writeevents = invoker.writeevents

    def process_events(self, logger: logging.Logger, events: List[dict]) -> int:

        tenant_id = self.tenant_id_from_input
        query = self.query
        host = None
        index = None
        for event in events:

            # Override values if they are present in the event
            source = event.get("source", "") + self.source
            index = event.get("index") or index
            query = event.get("query") or query
            # sequence: first use 'host' from event > fetch 'host' using socket lib > host value from previous loop
            host = event.get("host") or get_hostname_from_socket(logger) or host

            tenant_id = event.get("tenant_id") or tenant_id or self.acc_tenant_id
            required(tenant_id, "_Splunk_ tenant_id not found.")

            urls = EnvironmentSpecificUrls.get_urls_by_environment(
                self.environment, tenant_id
            )

            access_token = self.get_access_token(logger, urls, tenant_id)

            try:
                logger.debug("Trying to get events using query specified")
                results = self.hunt_by_query(logger, query, access_token, urls)
                logger.info("Creating events")
                for result in results:
                    # Note: Invoking method from parent class of class invoking this code!
                    self.addevent(
                        json.dumps(result), sourcetype=self.sourcetype, cam_header=True
                    )

            except Exception as e:
                logger.error(f"_Splunk_ Exception occurred during query execution: {e}")
                raise TaExecutionException(e, 1) from e

            logger.debug(
                f"Writing events with index={index}, source={source}, host={host}"
            )
            logger.info("Writing events to Splunk...")
            # Note: Invoking method from parent class of class invoking this code!
            # add a specific file extension for writing hunt query results
            self.writeevents(
                index=index, source=source, host=host, fext="ms_advance_hunt"
            )

        return 0

    @lru_cache(maxsize=8)
    def get_access_token(self, logger, urls, tenant_id):

        required(tenant_id, "Parameter is used as a cache key")
        try:
            logger.info("Trying to get access token using client_id, client_secret")

            return get_access_token(
                self.client_id,
                self.client_secret,
                urls,
                logger,
                self.session_key,
                self.use_delegated_permissions,
                self.delegated_acc_name,
                self.environment,
                add_default=True,
            )
        except Exception as e:
            logger.error(
                f"_Splunk_ Exception occurred while retrieving access token: {e}"
            )
            raise TaExecutionException(e, 1) from e

    def hunt_by_query(self, logger, query, access_token, urls):
        """
        Hunts the events by the query specified while configuring alert action

        Args:
            logger: logger object
            query: query specified in alert action
            access_token: access token to keep in header for getting events
            urls: urls to be used in API calls
        """
        hunting_url = urls.advanced_hunting
        current_version = get_current_addon_version(logger, self.session_key)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {access_token}",
            "User-Agent": f"M365DPartner-Splunk-MicrosoftSecurityAddOn/{current_version}",
        }

        proxies = self.get_proxies(logger)
        logger.debug("action=fetch_hunt_query, Requesting using hunting query")
        try:
            resp = requests.post(
                hunting_url,
                headers=headers,
                data=json.dumps({"Query": query}),
                proxies=proxies,
                timeout=60,
            )
            resp.raise_for_status()
            res = json.loads(resp.content)
            if self.environment.endswith(splunk_ta_ms_security_constants.GRAPH_API):
                # MS Graph API returns query result in 'results'
                results = res.get("results", [])
            else:
                # MS 365 API returns query result in 'Results'
                results = res.get("Results", [])
            logger.info(f"Number of results, hunt_query_result={len(results)}")

            return results
        except HTTPError as e:  # noqa: F841
            raise_error_from_http_error(logger, e)

    @lru_cache(maxsize=8)
    def get_proxies(self, logger) -> Union[dict, None]:
        return get_proxy(logger, self.session_key)
