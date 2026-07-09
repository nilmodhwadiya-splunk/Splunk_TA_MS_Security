#
# SPDX-FileCopyrightText: 2022 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

"""
This module validates account being saved by the user
"""
import import_declare_test  # noqa: F401 isort: skip
import splunk_ta_ms_security_constants  # isort: skip
from typing import Optional, Dict, Any
import json

import requests

# isort: off
from solnlib import conf_manager, log
from splunktaucclib.rest_handler.error import RestError

from Splunk_TA_MS_Security.api_specific_content import ApiSpecificContent
from Splunk_TA_MS_Security.environment_specific_urls import EnvironmentSpecificUrls
from ms_security_utils import (
    get_current_addon_version,
    get_proxy,
    required,
    use_log_level_from_config,
)
from ta_execution_exception import TaExecutionException

LOG_FILE_NAME = splunk_ta_ms_security_constants.ACCOUNT_VALIDATION_LOG_FILE_NAME
APP_NAME = import_declare_test.ta_name
SETTINGS_CONF_NAME = splunk_ta_ms_security_constants.SETTINGS_CONF_NAME
ACCOUNT_CONF_NAME = splunk_ta_ms_security_constants.ACCOUNT_CONF_NAME

logger = log.Logs().get_logger(LOG_FILE_NAME)


def account_validation(payload: json, session_key: str) -> None:
    """
    This function validates the account used for an input
    Raises RestError if any of the tenant_id, client_id or client_secret is invalid/incorrect
    :param payload: payload from the user input
    :paramsession_key: a session key
    :raises RestError: if any of the tenant_id, client_id or client_secret is invalid/incorrect
    """
    try:
        logger.debug(f"Validating input: {json.dumps(payload)}")
        AccountValidator(payload, session_key).validate()
    except TaExecutionException as validationError:
        raise RestError(400, str(validationError)) from validationError


class AccountValidator:
    def __init__(self, payload: dict, session_key: str):
        self.session_key = required(session_key, name="session_key")
        use_log_level_from_config(logger, session_key)

        self._validate_payload(payload)
        self.global_account = payload.get("azure_app_account")
        self.tenant_id = payload.get("tenant_id")
        self.use_delegated_permissions = False

        self.environment = payload.get("environment")
        self.location = payload.get("location")
        self.is_get_alert_script = self.location is not None

    def validate(self) -> None:
        # TODO: merge with security_utils, note that error handling is much better in this class
        try:
            client_id, client_secret, tenant_id = self._get_user_credentials()
            # fallback to account config's tenant_id when not provided in input form
            self.tenant_id = self.tenant_id or tenant_id
            urls = self._get_microsoft_urls()
        except (TaExecutionException, ValueError) as execution_exception:
            raise execution_exception

        if self.use_delegated_permissions:
            logger.info(
                "Skipping client-credentials validation because the selected account uses delegated permissions"
            )
            return

        proxies = self._get_proxies(urls.authorization)
        header = {"User-Agent": self._get_user_agent()}

        payload = ApiSpecificContent.get_login_payload(
            urls.api, client_id, urls.resource, client_secret
        )

        try:
            logger.debug(
                f"Requesting connection using url '{urls.authorization}', client_id {client_id} and clinet secret starting with {client_secret[0:1]}"
            )
            resp = requests.post(  # nosemgrep
                urls.authorization,
                data=payload,
                proxies=proxies,
                headers=header,
                timeout=60,
            ).json()

            if resp.get("error_codes"):
                self._raise_on_error_code(resp)
            else:
                logger.info("Account credentials successfully validated")
                return
        except RestError as rest_error:
            raise rest_error
        except Exception as e:
            logger.error(f"Failure making post request. Exception occurred - {e}")
            raise RestError(
                503, "Unable to connect to server. Please check logs for more details"
            )

    def _get_microsoft_urls(self) -> None:
        if self.environment:
            return EnvironmentSpecificUrls.get_urls_by_environment(
                self.environment, self.tenant_id
            )
        if self.location:
            return EnvironmentSpecificUrls.get_urls_by_location(
                self.location, self.tenant_id
            )
        raise ValueError("Environment or location must be provided. Both are missing")

    def _get_user_agent(self) -> str:
        current_version = get_current_addon_version(logger, self.session_key)

        user_agent_string = (
            f"MdePartner-Splunk-MicrosoftSecurityAddOn/{current_version}"
            if self.is_get_alert_script
            else f"M365DPartner-Splunk-MicrosoftSecurityAddOn/{current_version}"
        )
        return user_agent_string

    @staticmethod
    def _validate_payload(payload: dict) -> None:
        logger.debug("Validating Tenant ID, Client ID and Client Secret...")
        environment = payload.get("environment")
        location = payload.get("location")
        if environment and location:
            raise ValueError(
                "Configuration error: one of 'environment' or 'location' is expected, not both"
            )

        required(
            payload.get("azure_app_account"),
            "Configuration error: azure_app_account is required",
        )

    def _get_user_credentials(self) -> tuple:
        try:
            cfm = conf_manager.ConfManager(
                self.session_key,
                APP_NAME,
                realm=f"__REST_CREDENTIAL__#{APP_NAME}#configs/conf-{ACCOUNT_CONF_NAME}",
            )
            account_conf_file = cfm.get_conf(ACCOUNT_CONF_NAME)
            logger.debug(
                f"Reading username, password from splunk_ta_ms_security_account.conf for account name {self.global_account}"
            )
            try:
                client_id = account_conf_file.get(self.global_account).get("username")
            except Exception as e:
                logger.error(
                    f"Failed to get client_id from account configured. Exception - {e}"
                )
                raise TaExecutionException(e) from e

            try:
                client_secret = account_conf_file.get(self.global_account).get(
                    "password"
                )
            except Exception as e:
                logger.error(
                    f"Failed to get client_secret from account configured. Exception - {e}"
                )
                raise TaExecutionException(e) from e
            # simply return the tenant_id from the account configs
            tenant_id = account_conf_file.get(self.global_account).get("tenant_id")
            self.use_delegated_permissions = (
                account_conf_file.get(self.global_account).get(
                    "use_delegated_permissions"
                )
                == "1"
            )
        except Exception as e:
            logger.error(
                f"Failed to get account details from splunk_ta_ms_security_account.conf file for the account: {self.global_account}"
            )
            logger.error(f"Exception message - {e}")
            raise TaExecutionException(e) from e

        return client_id, client_secret, tenant_id

    def _get_proxies(self, authorization_server_url: str) -> Optional[Dict[Any, str]]:
        proxies = None
        try:
            logger.info("Trying to get proxy")
            proxies = get_proxy(logger, self.session_key)
        except Exception as e:
            logger.error(f"Failure getting proxy : {e}")

        if proxies:
            try:
                logger.info(
                    f"Trying to connect url - {authorization_server_url} via proxy"
                )
                _ = requests.get(  # nosemgrep
                    authorization_server_url, proxies=proxies, timeout=60
                )
            except Exception as e:
                logger.error(f"Failure connecting to proxy : {e}")  # nosemgrep
                raise RestError(400, "Failure connecting via proxy")

        return proxies

    def _raise_on_error_code(self, resp: dict) -> None:
        error_code = resp.get("error_codes")[0]
        error_description = resp.get("error_description", "None")
        global_account = self.global_account

        logger.error(f"Error Code: {error_code}. Description: {error_description}")

        if error_code in (90002, 900023):
            logger.error("Incorrect Tenant ID")  # nosemgrep
            raise RestError(400, "Invalid Tenant ID")

        if error_code == 7000215:
            logger.error(  # nosemgrep
                "Incorrect Client Secret of the Azure App Account used to configure this Input"
            )
            raise RestError(
                400,
                "Incorrect Client Secret of the Azure App Account used to configure this Input",
            )

        if error_code == 700016:
            logger.error(  # nosemgrep
                "Incorrect Client ID of the Azure App Account used to configure this Input"
            )
            raise RestError(
                400,
                "Incorrect Client ID of the Azure App Account used to configure this Input",
            )

        if error_code == 90038:
            logger.error(  # nosemgrep
                f"Account '{global_account}' is unauthorised for National Cloud"
            )
            raise RestError(
                400,
                f"Account '{global_account}' is unauthorised for National Cloud",
            )

        if error_code == 500011:
            logger.error(  # nosemgrep
                f"Account '{global_account}' is unauthorised for GCC environment"
            )
            raise RestError(
                400,
                f"Account '{global_account}' is unauthorised for GCC environment",
            )

        if error_code:
            logger.error(  # nosemgrep
                f"Failed to connect with account : {global_account}, receiving error code : {error_code}"
            )
            raise RestError(
                400,
                f"Failed to connect with account : {global_account}, receiving error code : {error_code}",
            )
