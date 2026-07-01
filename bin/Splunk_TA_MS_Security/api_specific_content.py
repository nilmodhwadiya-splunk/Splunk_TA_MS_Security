# SPDX-FileCopyrightText: 2022 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
from typing import Dict, Optional, Any
import import_declare_test  # isort: skip
from splunk_ta_ms_security_constants import API_365, GRAPH_API
from ta_execution_exception import TaExecutionException


class ApiSpecificContent:
    """
    Utility class to provide various objects that are specific for given API
    """

    supported_api = (API_365, GRAPH_API)

    @staticmethod
    def get_login_payload(
        api: str, client_id: str, resource_url: str, client_secret: str
    ) -> Dict[str, Any]:
        ApiSpecificContent._check_api(api)
        return (
            {
                "resource": resource_url,
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            }
            if api == API_365
            else {
                "scope": resource_url,
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            }
        )

    @staticmethod
    def get_incidents_filter(api: str, query_date: str) -> str:
        ApiSpecificContent._check_api(api)
        return (
            f"?$filter=lastUpdateTime+gt+{query_date}"
            if api == API_365
            else f"?$expand=alerts&$filter=lastUpdateDateTime+gt+{query_date}"
        )

    @staticmethod
    def get_alerts_filter(api: str, query_date: str) -> str:
        ApiSpecificContent._check_api(api)
        return (
            f"?$expand=evidence&$filter=lastUpdateTime+gt+{query_date}"
            if api == API_365
            else f"?$filter=lastUpdateDateTime+gt+{query_date}"
        )

    @staticmethod
    def get_machines_filter(api: str, query_date: str) -> str:
        ApiSpecificContent._check_api(api)
        return (
            f"?$filter=lastSeen+gt+{query_date}"
            if api == API_365
            else f"?$filter=lastUpdateDateTime+gt+{query_date}"
        )
    
    @staticmethod
    def _check_api(api: str) -> None:
        if api not in ApiSpecificContent.supported_api:
            raise NotImplementedError("Unknown API: " + str(api))

    @staticmethod
    def get_simulations_filter(
        api: str, query_date: str, end_date: str
    ) -> Optional[str]:
        ApiSpecificContent._check_api(api)
        if api == GRAPH_API:
            return f"?$filter=completionDateTime+gt+{query_date} and completionDateTime+lt+{end_date}"
        raise TaExecutionException("Unsupported API")
