#  SPDX-FileCopyrightText: 2023 Splunk, Inc. <sales@splunk.com>
#  SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
import json
import logging
from functools import lru_cache

import requests
from requests import HTTPError

import import_declare_test
import splunk_ta_ms_security_constants
from Splunk_TA_MS_Security.environment_specific_urls import (
    EnvironmentSpecificUrls,
    api_urls,
)
from defender_update_incident import AlertActionWorkerdefender_update_incident
from ms_security_utils import (
    get_access_token,
    get_credentials,
    required,
    get_hostname_from_socket,
    get_current_addon_version,
    get_proxy,
    raise_error_from_http_error,
)
from ta_execution_exception import TaExecutionException

APP_NAME = import_declare_test.ta_name
SETTINGS_CONF_NAME = splunk_ta_ms_security_constants.SETTINGS_CONF_NAME
ACCOUNT_CONF_NAME = splunk_ta_ms_security_constants.ACCOUNT_CONF_NAME


def process_event(self: AlertActionWorkerdefender_update_incident):
    """
    Method called by AlertActionWorkerdefender_update_incident
    """
    logger = self.logger
    logger.info("_Splunk_ Alert action defender_update_incident started.")
    try:
        logger.debug("Getting events for incident update")
        return UpdateIncidentHelper(self).process_events(logger, self.get_events())
    except Exception as e:
        logger.error(f"_Splunk_ Exception occurred during defender get_events() : {e}")
        raise TaExecutionException(e, 1) from e


def get_update_incident_data(invoker: AlertActionWorkerdefender_update_incident):
    status = invoker.get_param("status")
    assigned_to = invoker.get_param("assigned_to")
    classification = invoker.get_param("classification")
    determination = invoker.get_param("determination")
    tags = invoker.get_param("tags")
    # for MS Graph API, we need to send customTags and not tags
    customTags = invoker.get_param("customTags")

    data = {}
    if status:
        data["status"] = status

    if assigned_to:
        data["assignedTo"] = assigned_to

    if classification:
        data["classification"] = classification

    if determination:
        data["determination"] = determination

    if tags:
        data["tags"] = [tags]

    if customTags:
        data["customTags"] = [customTags]

    return data


class UpdateIncidentHelper:
    def __init__(self, invoker: AlertActionWorkerdefender_update_incident):
        self.session_key = invoker.session_key
        self.incident_id = invoker.get_param("incident_id")
        self.environment = invoker.get_param("environment") or "default"
        self.tenant_id = invoker.get_param("tenant_id")
        self.client_id, self.client_secret, self.acc_tenant_id = get_credentials(
            invoker, self.session_key, invoker.logger
        )

        self.data = get_update_incident_data(invoker)

        self.addevent = invoker.addevent
        self.writeevents = invoker.writeevents

    def process_events(self, logger: logging.Logger, events: [dict]) -> int:

        tenant_id = None
        index = "main"
        incidents_to_be_updated = 0
        incidents_not_updated = 0
        host = None

        for event in events:

            incident_id = event.get("incidentId") or self.incident_id
            tenant_id = event.get("tenant_id") or self.tenant_id or self.acc_tenant_id
            index = event.get("index") or index
            host = event.get("host") or host

            required(tenant_id, "_Splunk_ tenant_id not found.")

            urls = EnvironmentSpecificUrls.get_urls_by_environment(
                self.environment, tenant_id
            )

            logger.info("Trying to get access token using client_id, client_secret")
            access_token = self.get_access_token(logger, urls, tenant_id)

            # check if we have got incident_id from search result event or user input
            # if no incident_id found, then don't hit the API and log error message and continue
            if incident_id:
                try:
                    self.update_incident(  # noqa: F841
                        access_token,
                        logger,
                        urls.incidents + "/" + str(incident_id),
                    )
                    incidents_to_be_updated = incidents_to_be_updated + 1
                except Exception as e:
                    logger.error(
                        f"_Splunk_ Exception occurred during update execution: {e}"
                    )
                    raise TaExecutionException(e, 1)
            else:
                incidents_not_updated = incidents_not_updated + 1
                logger.error("Incident Id not found from event as well as user input.")
                continue

        logger.debug(f"Number of Incidents updated : {incidents_to_be_updated}")
        logger.debug(f"Number of Incidents not updated : {incidents_not_updated}")
        if incidents_to_be_updated != 0:
            host = host or get_hostname_from_socket(logger)

            source = f"microsoft_365_defender_endpoint_incidents:{tenant_id}"
            logger.debug(
                f"Writing events with index={index}, source={source}, host={host}"
            )
            logger.info("Writing events to Splunk...")
            # add a specific file extension for writing incident and associated alert response
            self.writeevents(
                index=index, source=source, host=host, fext="ms_update_incident"
            )
        else:
            logger.info("No Incidents updated...")

        return 0

    @lru_cache(maxsize=8)
    def get_access_token(self, logger, urls: api_urls, tenant_id):

        required(tenant_id, "Parameter is used as a cache key")
        try:
            logger.info("Trying to get access token using client_id, client_secret")

            return get_access_token(
                self.client_id,
                self.client_secret,
                urls,
                logger,
                self.session_key,
            )
        except Exception as e:
            logger.error(
                f"_Splunk_ Exception occurred while retrieving access token: {e}"
            )
            raise TaExecutionException(e, 1) from e

    def update_incident(self, access_token, logger, incident_url):
        """
        Updates the incident via alert action

        Args:
            access_token: Access token to be used in headers
            logger: logger object
            incident_url: environment-specific url to update the incident
        Raises:
            Exception: if any failure occurs while updating incident
        """
        current_version = get_current_addon_version(logger, self.session_key)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {access_token}",
            "User-Agent": f"M365DPartner-Splunk-MicrosoftSecurityAddOn/{current_version}",
        }

        proxies = get_proxy(logger, self.session_key)

        try:
            logger.debug("Requesting to update incident")
            resp = requests.patch(
                incident_url,
                headers=headers,
                json=self.data,
                proxies=proxies,
                timeout=60,
            )
            resp.raise_for_status()
            updated_incident = json.loads(resp.content)
            if updated_incident.get("alerts"):
                for alert in updated_incident["alerts"]:
                    self.addevent(json.dumps(alert), "ms365:defender:incident:alerts")
                del updated_incident["alerts"]
            self.addevent(json.dumps(updated_incident), "ms365:defender:incident")
        except HTTPError as e:  # noqa: F841
            raise_error_from_http_error(logger, e)
