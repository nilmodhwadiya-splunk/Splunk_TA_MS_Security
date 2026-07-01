#  SPDX-FileCopyrightText: 2023 Splunk, Inc. <sales@splunk.com>
#  SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
import import_declare_test  # isort: skip
from typing import Optional

from ms_security_utils import required, api_urls
from splunk_ta_ms_security_constants import API_365, GRAPH_API

API_ADVANCED_HUNTING = "/api/advancedhunting/run"
API_ALERTS = "/api/alerts"
API_INCIDENTS = "/api/incidents"
API_GCC_SECURITY = "https://api-gcc.security.microsoft.us"
API_GCC_SECURITYCENTER = "https://api-gcc.securitycenter.microsoft.us"
API_GOV_SECURITY = "https://api-gov.security.microsoft.us"
API_GOV_SECURITYCENTER = "https://api-gov.securitycenter.microsoft.us"
API_SECURITY = "https://api.security.microsoft.com"
API_SECURITYCENTER = "https://api.securitycenter.microsoft.com"
API_SECURITYCENTER_EU = "https://api-eu.securitycenter.microsoft.com"
API_SECURITYCENTER_UK = "https://api-uk.securitycenter.microsoft.com"
API_SECURITYCENTER_US = "https://api-us.securitycenter.microsoft.com"
API_MACHINES = "/api/machines"

GRAPH_ADVANCED_HUNTING = "/v1.0/security/runHuntingQuery"  # POST
GRAPH_ALERTS_V2 = "/v1.0/security/alerts_v2"
GRAPH_INCIDENTS = "/v1.0/security/incidents"
GRAPH_MICROSOFT_COM = "https://graph.microsoft.com"
GRAPH_MICROSOFT_US = "https://graph.microsoft.us"
GRAPH_SIMULATIONS = "/v1.0/security/attackSimulation/simulations"
GRAPH_SIMULATION_REPORT_OVERVIEW = (
    "/v1.0/security/attackSimulation/simulations/{}/report/overview"
)


class EnvironmentSpecificUrls:
    def __init__(self):
        required(
            import_declare_test.ta_name,
            "import_declare_test must be imported first since it sets environment",
        )

    urls_by_environment = {
        "default": api_urls(
            "https://login.windows.net/{}/oauth2/token",
            f"{API_SECURITY}",
            f"{API_SECURITY}{API_ALERTS}",
            f"{API_SECURITY}{API_INCIDENTS}",
            f"{API_SECURITY}{API_ADVANCED_HUNTING}",
            f"{API_SECURITY}{API_MACHINES}",
            "",
            "",
            API_365,
        ),
        "commercial": api_urls(
            "https://login.microsoftonline.com/{}/oauth2/token",
            f"{API_SECURITY}",
            f"{API_SECURITY}{API_ALERTS}",
            f"{API_SECURITY}{API_INCIDENTS}",
            f"{API_SECURITY}{API_ADVANCED_HUNTING}",
            f"{API_SECURITY}{API_MACHINES}",
            "",
            "",
            API_365,
        ),
        "gcc": api_urls(
            "https://login.microsoftonline.com/{}/oauth2/token",
            f"{API_GCC_SECURITY}",
            f"{API_GCC_SECURITY}{API_ALERTS}",
            f"{API_GCC_SECURITY}{API_INCIDENTS}",
            f"{API_GCC_SECURITY}{API_ADVANCED_HUNTING}",
            f"{API_GCC_SECURITY}{API_MACHINES}",
            "",
            "",
            API_365,
        ),
        "gcc-high": api_urls(
            "https://login.microsoftonline.us/{}/oauth2/token",
            f"{API_GOV_SECURITY}",
            f"{API_GOV_SECURITY}{API_ALERTS}",
            f"{API_GOV_SECURITY}{API_INCIDENTS}",
            f"{API_GOV_SECURITY}{API_ADVANCED_HUNTING}",
            f"{API_GOV_SECURITY}{API_MACHINES}",
            "",
            "",
            API_365,
        ),
        "commercial-graph-api": api_urls(  # To be precise: commercial and GCC use the same endpoint
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            f"{GRAPH_MICROSOFT_COM}/.default",
            f"{GRAPH_MICROSOFT_COM}{GRAPH_ALERTS_V2}",
            f"{GRAPH_MICROSOFT_COM}{GRAPH_INCIDENTS}",
            f"{GRAPH_MICROSOFT_COM}{GRAPH_ADVANCED_HUNTING}",
            f"{GRAPH_MICROSOFT_COM}{API_MACHINES}",
            f"{GRAPH_MICROSOFT_COM}{GRAPH_SIMULATIONS}",
            f"{GRAPH_MICROSOFT_COM}{GRAPH_SIMULATION_REPORT_OVERVIEW}",
            GRAPH_API,
        ),
        "gcc-high-graph-api": api_urls(
            "https://login.microsoftonline.us/{}/oauth2/v2.0/token",
            f"{GRAPH_MICROSOFT_US}/.default",
            f"{GRAPH_MICROSOFT_US}{GRAPH_ALERTS_V2}",
            f"{GRAPH_MICROSOFT_US}{GRAPH_INCIDENTS}",
            f"{GRAPH_MICROSOFT_US}{GRAPH_ADVANCED_HUNTING}",
            f"{GRAPH_MICROSOFT_US}{API_MACHINES}",
            f"{GRAPH_MICROSOFT_US}{GRAPH_SIMULATIONS}",
            f"{GRAPH_MICROSOFT_US}{GRAPH_SIMULATION_REPORT_OVERVIEW}",
            GRAPH_API,
        ),
    }
    urls_by_location = {
        "api.securitycenter.microsoft.com": api_urls(
            "https://login.microsoftonline.com/{}/oauth2/token",
            f"{API_SECURITYCENTER}",
            f"{API_SECURITYCENTER}{API_ALERTS}",
            f"{API_SECURITY}{API_INCIDENTS}",
            f"{API_SECURITY}{API_ADVANCED_HUNTING}",
            f"{API_SECURITY}{API_MACHINES}",
            "",
            "",
            API_365,
        ),
        "api-us.securitycenter.microsoft.com": api_urls(
            "https://login.microsoftonline.com/{}/oauth2/token",
            f"{API_SECURITYCENTER}",
            f"{API_SECURITYCENTER_US}{API_ALERTS}",
            f"{API_SECURITY}{API_INCIDENTS}",
            f"{API_SECURITY}{API_ADVANCED_HUNTING}",
            f"{API_SECURITY}{API_MACHINES}",
            "",
            "",
            API_365,
        ),
        "api-eu.securitycenter.microsoft.com": api_urls(
            "https://login.microsoftonline.com/{}/oauth2/token",
            f"{API_SECURITYCENTER}",
            f"{API_SECURITYCENTER_EU}{API_ALERTS}",
            f"{API_SECURITY}{API_INCIDENTS}",
            f"{API_SECURITY}{API_ADVANCED_HUNTING}",
            f"{API_SECURITY}{API_MACHINES}",
            "",
            "",
            API_365,
        ),
        "api-uk.securitycenter.microsoft.com": api_urls(
            "https://login.microsoftonline.com/{}/oauth2/token",
            f"{API_SECURITYCENTER}",
            f"{API_SECURITYCENTER_UK}{API_ALERTS}",
            f"{API_SECURITY}{API_INCIDENTS}",  # NOT VERIFIED
            f"{API_SECURITY}{API_ADVANCED_HUNTING}",
            f"{API_SECURITY}{API_MACHINES}",
            "",
            "",
            API_365,
        ),
        "api-gov.securitycenter.microsoft.us": api_urls(
            "https://login.microsoftonline.us/{}/oauth2/token",
            f"{API_GOV_SECURITYCENTER}",
            f"{API_GOV_SECURITYCENTER}{API_ALERTS}",
            f"{API_SECURITY}{API_INCIDENTS}",
            f"{API_SECURITY}{API_ADVANCED_HUNTING}",
            f"{API_SECURITY}{API_MACHINES}",
            "",
            "",
            API_365,
        ),
        "api-gcc.securitycenter.microsoft.us": api_urls(
            "https://login.microsoftonline.com/{}/oauth2/token",
            f"{API_GCC_SECURITYCENTER}",
            f"{API_GCC_SECURITYCENTER }{API_ALERTS}",
            f"{API_SECURITY}{API_INCIDENTS}",
            f"{API_SECURITY}{API_ADVANCED_HUNTING}",
            f"{API_SECURITY}{API_MACHINES}",
            "",
            "",
            API_365,
        ),
        "commercial-graph-api": urls_by_environment["commercial-graph-api"],
        "gcc-high-graph-api": urls_by_environment["gcc-high-graph-api"],
    }

    @classmethod
    def get_urls_by_environment(cls, environment, tenant_id) -> api_urls:
        required(environment, "environment param is missing")
        required(tenant_id, "tenant_id is missing")

        env_api_urls = cls.urls_by_environment.get(environment)

        required(env_api_urls, f"Login URL not found for environment '{environment}'")
        return cls._inject_tenant_id(env_api_urls, tenant_id)

    @classmethod
    def _inject_tenant_id(cls, urls, tenant_id) -> api_urls:
        return api_urls(
            urls.authorization.format(tenant_id),
            urls.resource,
            urls.alerts,
            urls.incidents,
            urls.advanced_hunting,
            urls.machines,
            urls.simulations,
            urls.simulation_report,
            urls.api,
        )

    @classmethod
    def get_urls_by_location(cls, location, tenant_id) -> Optional[api_urls]:
        required(location, name="location")
        required(tenant_id, name="tenant_id")

        loc_api_urls = cls.urls_by_location.get(location)
        required(loc_api_urls, f"Login URL not found for the location {location}")
        return cls._inject_tenant_id(loc_api_urls, tenant_id)
