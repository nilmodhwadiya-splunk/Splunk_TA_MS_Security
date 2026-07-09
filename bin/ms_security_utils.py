##
# SPDX-FileCopyrightText: 2022 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
##
##
import datetime
import json
import logging
import socket
import sys
import traceback
from base64 import b64decode
from collections import namedtuple
from functools import lru_cache
from json.decoder import JSONDecodeError
from typing import Optional, Tuple, TypeVar, Union, Dict, Any
import import_declare_test  # isort: skip
import requests
import splunk.rest as rest
import splunklib.client as client
from requests import HTTPError, RequestException
from solnlib import conf_manager, log, utils
from solnlib.modular_input import checkpointer
from Splunk_TA_MS_Security.api_specific_content import ApiSpecificContent
from ta_execution_exception import TaExecutionException
import splunk_ta_ms_security_constants
import msal

APP_NAME = import_declare_test.ta_name
CHECKPOINTER = splunk_ta_ms_security_constants.CHECKPOINTER
SETTINGS_CONF_NAME = splunk_ta_ms_security_constants.SETTINGS_CONF_NAME
ALERTS_INPUT_TYPE = splunk_ta_ms_security_constants.ALERTS_INPUT_TYPE
MACHINES_INPUT_TYPE = splunk_ta_ms_security_constants.MACHINES_INPUT_TYPE
INCIDENTS_INPUT_TYPE = splunk_ta_ms_security_constants.INCIDENTS_INPUT_TYPE
SIMULATIONS_INPUT_TYPE = splunk_ta_ms_security_constants.SIMULATIONS_INPUT_TYPE
ACCOUNT_CONF_NAME = splunk_ta_ms_security_constants.ACCOUNT_CONF_NAME

# FIXME: remove sys.exit(): none of the utility functions may decide to close the program

api_urls = namedtuple(
    "api_urls",
    "authorization, resource, alerts, incidents, advanced_hunting, machines, simulations, simulation_report, api",
)


def get_account_details(
    logger: logging.Logger, session_key: str, account_name: str
) -> Optional[Dict[str, str]]:
    """
    Returns username and password of the account configured
    :param logger: a logger object
    :param session_key: a session key
    :param account_name: name of the account of which username and password are fetched
    :returns dict: dictionary containing username, password and tenant_id(if provided) of the account
    """
    try:
        cfm = conf_manager.ConfManager(
            session_key,
            APP_NAME,
            realm=f"__REST_CREDENTIAL__#{APP_NAME}#configs/conf-{ACCOUNT_CONF_NAME}",
        )
        account_conf_file = cfm.get_conf(ACCOUNT_CONF_NAME)
        logger.debug(
            f"Reading username, password from splunk_ta_ms_security_account.conf for account_name={account_name}"
        )
        return {
            "username": account_conf_file.get(account_name).get("username"),
            "password": account_conf_file.get(account_name).get("password"),
            "tenant_id": account_conf_file.get(account_name).get("tenant_id"),
            "use_delegated_permissions": account_conf_file.get(account_name).get("use_delegated_permissions") == '1',
            "delegated_acc_name": account_conf_file.get(account_name).get("delegated_acc_name"),
        }
    except Exception as e:
        logger.error(
            f"Failed to fetch the account details from splunk_ta_ms_security_account.conf "
            f"file for the AccountName={account_name}. Reason={e}"
        )
        sys.exit("Error while fetching account details. Terminating modular input.")


def get_start_date(
    logger: logging.Logger,
    session_key: str,
    check_point_key: str,
    input_item: dict,
    input_stanza_name: str,
) -> str:
    """
    Gets the start date of the modinput configured
    :param logger: a logger object
    :param session_key: a session key
    :param check_point_key: checkpoint object
    :param input_item: an input item
    :param input_stanza_name: stanza name from which start_date is fetched
    :returns str: start date as a JSON string
    """
    logger.debug(f"Trying to get date from checkpoint. InputName={check_point_key}")
    checkpoint_collection = checkpointer.KVStoreCheckpointer(
        CHECKPOINTER, session_key, APP_NAME
    )
    date_from_checkpoint = checkpoint_collection.get(check_point_key)
    if date_from_checkpoint:
        logger.info(
            f"action=date_from_ckpt, Start date found from checkpoint : ckpt_date={date_from_checkpoint}"
        )
        return date_from_checkpoint
    else:
        logger.info(
            "action=date_from_config, Start date not found from checkpoint, trying to get from the input configuration"
        )
        start_date = input_item.get("start_date")
        if start_date not in [None, ""]:
            if not start_date.endswith("Z"):
                start_date = f"{start_date}Z"
            return start_date
        else:
            logger.info(
                f'action=date_use_default, No start_date specified in InputName={input_item.get("name")}, setting default start_date'
            )
            cfm = conf_manager.ConfManager(session_key, APP_NAME)
            conf = cfm.get_conf("inputs")
            default_start_date = (
                datetime.datetime.utcnow() - datetime.timedelta(days=30)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            conf.update(input_stanza_name, {"start_date": default_start_date})
            logger.debug("Setting default start_date (30 days ago) in inputs.conf")
            return default_start_date

def get_secrets(name, session_key, logger):
    logger.info(f"Fetching passwords from secrets storage")
    url = f'/servicesNS/nobody/Splunk_TA_MS_Security/storage/passwords/credential:mssecuritydelegatedaccess:{name}:'
    status , resp = rest.simpleRequest(
        url,
        sessionKey=session_key,
        method="GET",
        getargs={"output_mode": "json"},
        raiseAllErrors=True,
    )

    if status.status == 200:
        return json.loads(resp)['entry'][0]['content']['clear_password']

    logger.error(f"Could not fetch cached token for delegated user with account {name}")

def get_access_token(
    client_id: str,
    client_secret: str,
    urls: api_urls,
    logger: logging.Logger,
    session_key: str,
    use_delegated_permissions: bool = None, 
    delegated_acc_name: str = None,
    environment: str = None,
    add_default: bool = False
) -> str:
    """
    Gets access token
    :param client_id: client id of the account configured
    :param client_secret: client secret of the account configured
    :param ulrs: urls to be used to communicate with microsoft API
    :param logger: logger object
    :param session_key: a session key
    :raises Exception: if access token is not obtained
    :returns: access token
    """

    if (use_delegated_permissions):
        delegated_token_cache = get_secrets(delegated_acc_name + "-token_cache",session_key,logger)
        index = urls.authorization.find("oauth2")
        msal_app = msal.ConfidentialClientApplication(
            client_id=client_id,
            authority=urls.authorization[:index-1],
            client_credential=client_secret,
            token_cache=msal.SerializableTokenCache(),
        )
        msal_app.token_cache.deserialize(json.loads(delegated_token_cache))
        accounts = msal_app.get_accounts()
        if accounts:
            logger.info(f"Account found for delegated access")
            res = urls.resource
            if environment and 'graph' not in environment: 
                res = res + "/Incident.Read"
            if add_default and not res.endswith("/.default"):
                res = res + "/.default"
            token_result = msal_app.acquire_token_silent([res], account=accounts[0])
            if not token_result:
                logger.error(f"Could not fetch token for delegated user with account {delegated_acc_name}")
                raise ValueError
            return token_result["access_token"]

    payload = ApiSpecificContent.get_login_payload(
        urls.api, client_id, urls.resource, client_secret
    )
    try:
        proxies = get_proxy(logger, session_key)
        response = requests.post(  # nosemgrep
            urls.authorization, data=payload, proxies=proxies, timeout=60
        ).json()
        if response.get("error_description"):
            logger.error(
                f'action=fetch_token_failure, reason={response["error_description"]}'
            )
            sys.exit(1)
        # INFO is 20, so we don't want to decode the access token redundantly unless the DEBUG logs are enabled
        if logger.level < logging.INFO:
            logger.debug(
                splunk_ta_ms_security_constants.TOKEN_ROLES_MESSAGE.format(
                    roles=decode_access_token(response["access_token"], logger=logger)
                )
            )
        return response["access_token"]
    except Exception as e:
        logger.error(
            f"Splunk Exception occurred while retrieving access token, reason={e}"
        )
        raise e


@lru_cache(maxsize=8)
def get_proxy(logger: logging.Logger, session_key: str) -> Optional[Dict[str, str]]:
    """
    Gets the proxy setting if proxy is configured
    :param logger: a logger object
    :param session_key: a session key
    :returns None: if proxy is disabled
    :returns dict: dictionary with proxy parameter details
    """
    proxies = None
    logger.debug("Getting proxy server.")
    try:
        cfm = conf_manager.ConfManager(
            session_key,
            APP_NAME,
            realm=f"__REST_CREDENTIAL__#{APP_NAME}#configs/conf-{SETTINGS_CONF_NAME}",
        )

        proxy = cfm.get_conf(SETTINGS_CONF_NAME).get("proxy")
    except Exception:
        logger.error(
            f"Failed to fetch proxy details from configuration. Traceback={traceback.format_exc()}"
        )
        sys.exit(1)

    if proxy:
        if utils.is_false(proxy.get("proxy_enabled", 0)):
            logger.info("Proxy is not enabled.")
        else:
            proxy_address = f"{proxy.get('proxy_url')}:{proxy.get('proxy_port')}"

            logger.debug(f"Proxy is enabled: proxy_address={proxy_address}")

            if proxy.get("proxy_username") and proxy.get("proxy_password"):
                proxy_url = f"http://{requests.compat.quote_plus(proxy.get('proxy_username'))}:{requests.compat.quote_plus(proxy.get('proxy_password'))}@{proxy_address}"
            else:
                proxy_url = f"http://{proxy_address}"

            proxies = {"http": proxy_url, "https": proxy_url}
    return proxies


def get_atp_alerts_odata(
    logger: logging, session_key: str, access_token: str, url: str, user_agent=None
) -> Optional[Dict[str, str]]:
    """
    Gets the events
    :param logger: a logger object
    :param session_key: a session key
    :param access_token: access token for header
    :param url: url on which we request to get data
    :param user_agent: user-agent for header. Defaults to None
    :raises ValueError: if url is not HTTPS
    :raises Exception e: if request call failed
    :returns dict: dictionary with events data
    """
    alerts = []
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-type": "application/json",
    }
    if user_agent:
        headers["User-Agent"] = user_agent
    proxies = get_proxy(logger, session_key)

    try:
        logger.debug(f"action=collect_data, Getting data using url={url}")
        r = requests.get(url, headers=headers, proxies=proxies, timeout=60)
        r.raise_for_status()
        response_json = r.json()

        alerts += response_json["value"]

        if "odata.nextLink" in response_json:
            next_atp_url = response_json["odata.nextLink"]

            # This should never happen, but just in case...
            if not is_https(next_atp_url):
                logger.error("nextLink scheme is not HTTPS")  # nosemgrep
                raise ValueError(
                    f"nextLink scheme is not HTTPS. nextLink_URL={next_atp_url}"
                )

            logger.debug(f"action=continue_call, next_URL={next_atp_url}")
            get_atp_alerts_odata(logger, session_key, access_token, next_atp_url)
    except HTTPError as http_error:
        logger.exception(http_error.response.json())
        raise http_error
    except Exception as e:
        logger.error(  # nosemgrep
            f"Exception occurred while getting data using access token : {e}"
        )
        raise e

    logger.debug(f"action=complete_call, Successfully got the results")
    return alerts


def is_https(url: str) -> bool:
    """
    Check if the url is HTTPS or not
    :param url: a url to be checked
    :returns boolean: True if url is HTTPS else False
    """
    return url.startswith("https://")


def checkpoint_handler(
    logger: logging.Logger,
    session_key: str,
    max_date: str,
    check_point_key: str,
    input_stanza_name: str,
) -> None:
    """
    Handles checkpoint update
    """
    try:
        checkpoint_collection = checkpointer.KVStoreCheckpointer(
            CHECKPOINTER, session_key, APP_NAME
        )
        logger.debug(f"Trying to get checkpoint for the InputName={input_stanza_name}")
        _ = checkpoint_collection.get(check_point_key)
    except Exception:
        logger.error(f"Error in Checkpoint handling, reason={traceback.format_exc()}")
    else:
        try:
            logger.info(f"Updating {max_date} as checkpoint date")
            checkpoint_collection.update(check_point_key, max_date)
        except Exception as e:
            logger.error(
                f"action=ckpt_update_failure, Updating checkpoint failed. Exception occurred, reason={e}"
            )


def get_config(session_key: str, logger: logging.Logger) -> Any:
    try:
        logger.debug("Connect to Splunk client")
        service = client.connect(token=session_key)

        logger.debug(f"Getting conf_file={ACCOUNT_CONF_NAME}")
        return service.confs[ACCOUNT_CONF_NAME]
    except Exception as e:
        logger.error(f"Splunk Error getting splunk_ta_ms_security_account, reason={e}")
        raise TaExecutionException(e, 1) from e


def get_credentials(
    self, session_key: str, logger: logging.Logger
) -> Tuple[str, str, Optional[str]]:
    conf = get_config(session_key, logger)
    # we check whether the account name is provided for
    # either Update Incident(account) or Advanced Hunting(account_name)
    account_name = self.get_param("account") or self.get_param("account_name")
    credentials_tuple: tuple
    if account_name:
        logger.info(f"Splunk Defender AccountName={account_name}")

        credentials_tuple = get_credentials_with_account_name(
            self, logger, conf, session_key
        )
    else:
        logger.info("Splunk No defender account name given")
        credentials_tuple = get_credentials_without_account_name(
            logger, conf, session_key
        )
    if len(credentials_tuple) == 3:
        return credentials_tuple
    if len(credentials_tuple) == 2:
        return credentials_tuple[0], credentials_tuple[1], None
    raise TaExecutionException(
        f"Unexpected number of credentials returned: {len(credentials_tuple)}"
    )


def get_credentials_with_account_name(
    self, logger: logging.Logger, conf, session_key: str
) -> tuple:
    """
    Gets the client_id and client_secret
    :param: logger: logger object
    :param conf: conf file object
    :param session_key: a session key
    :returns: tuple: client_id and client_secret
    """
    client_id = client_secret = tenant_id = ""  # nosemgrep
    account = None

    # For Update Incident, parameter name is 'account'
    # For Advanced Hunting, parameter name is 'account_name'
    if self.get_param("account"):
        global_account_name = self.get_param("account")
    else:
        global_account_name = self.get_param("account_name")
    logger.info(
        f"action=cred_with_account, Retrieving credentials with AccountName={global_account_name}"
    )
    stanza = None
    for stanza in conf:
        if stanza.name == global_account_name:
            for key, value in stanza.content.items():
                # If there's a username in the key, that will be the client ID
                if key == "username":
                    try:
                        account = get_account_details(logger, session_key, stanza.name)
                        client_id = account.get("username", "")
                        client_secret = account.get("password", "")
                        tenant_id = account.get("tenant_id", "")
                        break
                    except Exception as e:  # noqa: F841
                        logger.error(
                            "get_credentials_with_account_name() - Type 3 - Exception occurred during accessing conf file values."
                        )

            if client_id != "" and client_secret != "":
                # Found the client id and secret. No need to iterate anymore.
                break

    if not account:
        stanza_name = stanza.name if stanza else "<no stanza in config>"
        logger.error(
            f"get_credentials_with_account_name() - Type 3 - The stanza name {global_account_name} specified is not in the global account "
            f"configuration. Tested with stanza name : {stanza_name}. Retrying ..."
        )
    if client_id == "" or client_secret == "":  # nosemgrep
        logger.error(
            "get_credentials_with_account_name() - Type 3 - Exception occurred. The global account name specified has not been configured. Please re-configure them or re-enter the right stanza name."  # noqa: E501
        )
        sys.exit(1)
    else:
        return client_id, client_secret, tenant_id


def get_credentials_without_account_name(
    logger: logging.Logger, conf, session_key: str
) -> tuple:
    """
    Gets the client_id and client_secret
    :param: logger: logger object
    :param conf: conf file object
    :param session_key: a session key
    :returns: tuple: client_id and client_secret
    """
    client_id = ""
    client_secret = ""  # nosemgrep
    logger.info(
        "action=cred_without_account, Retrieving credentials without account name"
    )

    for stanza in conf:
        for key, value in stanza.content.items():
            # If there's a username in the key, that will be the client ID
            if key == "username":
                try:
                    account = get_account_details(logger, session_key, stanza.name)
                    client_id = account.get("username")
                    client_secret = account.get("password")
                    break
                except Exception as e:  # noqa: F841
                    logger.error(
                        "get_credentials_without_account_name() - Type 3 - "
                        "Exception occurred during accessing conf file values."
                    )

        if client_id != "" and client_secret != "":
            # Found the client id and secret. No need to iterate anymore.
            break

    if client_id == "" or client_secret == "":  # nosemgrep
        logger.error(
            "get_credentials_without_account_name() - Type 3 - Exception occurred. "
            "The global account name specified has not been configured. Please re-configure "
            "them or re-enter the right stanza name."
        )
        sys.exit(1)
    else:
        return client_id, client_secret


def delete_checkpoint(
    session_key: str, input_name: str, input_type: str, LOG_FILE_NAME: str
) -> None:
    """
    Deleted the checkpoint when user deletes the input
    :param session_key: a session key
    :param input_name: input name which is to be deleted
    :param input_type: type of the input to be deleted
    :param LOG_FILE_NAME: log file name
    """
    logger = log.Logs().get_logger(LOG_FILE_NAME)
    use_log_level_from_config(logger, session_key)

    if input_type == ALERTS_INPUT_TYPE:
        checkpoint_name = f"atp_lastUpdateTime_{input_name}"
    elif input_type == INCIDENTS_INPUT_TYPE:
        checkpoint_name = f"m365_incident_lastUpdateTime_{input_name}"
    elif input_type == SIMULATIONS_INPUT_TYPE:
        checkpoint_name = f"simulation_lastUpdateTime_{input_name}"
    elif input_type == MACHINES_INPUT_TYPE:
        checkpoint_name = f"machines_lastUpdateTime_{input_name}"
    else:
        checkpoint_name = f"event_hub_lastUpdate_{input_name}"

    try:
        checkpoint_collection = checkpointer.KVStoreCheckpointer(
            CHECKPOINTER, session_key, APP_NAME
        )
        logger.debug(f"Trying to get checkpoint for the input : InputName={input_name}")
        checkpoint_dict = checkpoint_collection.get(checkpoint_name)
        if not checkpoint_dict:
            logger.info(
                f"Checkpoint not yet set for the InputName={input_name}, deleting the input directly"
            )
            return
    except Exception as e:
        logger.error(f"Error in Checkpoint handling, reason={e}")
        sys.exit(1)

    try:
        rest_url = f"/servicesNS/nobody/{APP_NAME}/storage/collections/data/{CHECKPOINTER}/{checkpoint_name}"

        _, _ = rest.simpleRequest(
            rest_url,
            sessionKey=session_key,
            method="DELETE",
            getargs={"output_mode": "json"},
            raiseAllErrors=True,
        )

        logger.info(f"Deleted checkpoint for InputName={input_name}")

    except Exception as e:
        logger.error(f"Error deleting checkpoint, reason={e}")
        sys.exit(1)


@lru_cache(maxsize=8)
def get_current_addon_version(
    logger: logging.Logger, session_key: str
) -> Optional[str]:
    """
    Gets current addon version from app.conf
    :param logger: logger object
    :param session_key: a session key
    :returns string: current addon version from app.conf
    """
    try:
        cfm = conf_manager.ConfManager(
            session_key,
            APP_NAME,
            realm=f"__REST_CREDENTIAL__#{APP_NAME}#configs/conf-app",
        )
        current_version = cfm.get_conf("app").get("launcher").get("version")
        logger.debug(f"Found TA Version from app.conf - version={current_version}")
        return current_version
    except Exception as e:
        logger.error(f"Failed to get details from app.conf with exception, reason={e}")


@lru_cache(maxsize=8)
def use_log_level_from_config(logger: logging.Logger, session_key: str):
    log_level = conf_manager.get_log_level(
        logger=logger,
        session_key=session_key,
        app_name=APP_NAME,
        conf_name=SETTINGS_CONF_NAME,
    )
    logger.info(f"log level set is log_level={log_level}")
    logger.setLevel(log_level)


@lru_cache(maxsize=2)
def get_hostname_from_socket(logger):
    logger.debug("Getting hostname from socket")
    try:
        host = socket.gethostname()
    except Exception:
        logger.error("Error getting host from socket, setting host to None")
        host = None
    logger.debug(f"Host value successfully obtained HostName={host}")
    return host


def raise_error_from_http_error(logger, e: RequestException):
    error_message = f"Failure occurred while loading error response: {e}"
    detailed_error_message = None
    try:
        error_dict = (
            json.loads(e.response.content)
            if e.response is not None and e.response.content
            else None
        )

        detailed_error_message = (
            f"Failure occurred. Received error message: {error_dict['error']['message']}"
            if error_dict
            and error_dict.get("error")
            and error_dict["error"].get("message")
            else None
        )

    except (KeyError, JSONDecodeError, TypeError) as inner_ex:
        logger.debug(f"Exception while processing error message: {inner_ex}")

    logger.error(detailed_error_message or error_message)
    raise TaExecutionException(e, 1) from e


#  Define Generic for the method below
T_ = TypeVar("T_")


def required(obj: T_, error_msg="required value is not set", name: str = "") -> T_:
    # updated the condition to accept all built-in data type's False values
    if not obj:
        prefix = (name + ": ") if name else ""
        raise ValueError(prefix + error_msg)
    return obj


def decode_access_token(access_token: str, logger: logging) -> str:
    """
    Decodes the access token and returns the roles from the token details
    """
    try:
        access_token_claims = access_token.split(".")[1]
        # we fix the padding of "=" if it is incorrect for `base64` library
        access_token_claims += "=" * (-len(access_token_claims) % 4)
        byte_token = b64decode(access_token_claims)
        decoded_access_token: dict = json.loads(byte_token)
    except JSONDecodeError:
        logger.debug(f"action=token_decode_failed, reason={traceback.format_exc()}")
        # two types of quotes are used for the correct auto KV extraction for token roles
        return '"Invalid JSON found, unable to decode the access token"'
    except Exception:
        logger.debug(f"action=token_parse_failed, reason={traceback.format_exc()}")
        # two types of quotes are used for the correct auto KV extraction for token roles
        return '"Unable to parse the access token"'
    else:
        logger.debug(
            f"action=token_parse_success, Successfully parsed the access token"
        )
        return decoded_access_token.get(
            "roles", "<roles not found in the decoded token>"
        )


def get_simulation_report(
    logger: logging.Logger,
    session_key: str,
    access_token: str,
    url: str,
    user_agent=None,
) -> Optional[Dict[Any, Any]]:
    """
    Gets the simulation report
    :param logger: logger object
    :param session_key: a session key
    :param access_token: access token used for header
    :param url: url on which we request to get data
    :param user_agent: user-agent for header. Defaults to None
    :raises ValueError: if url is not HTTPS
    :raises Exception e: if request call failed
    :returns Dict: simulation event data
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-type": "application/json",
    }
    if user_agent:
        headers["User-Agent"] = user_agent
    proxies = get_proxy(logger, session_key)

    try:
        logger.debug(f"Getting data using url {url}")
        r = requests.get(url, headers=headers, proxies=proxies, timeout=60)
        r.raise_for_status()
        simulation_report = r.json()

    except HTTPError as http_error:
        logger.exception(http_error.response.json())
        raise http_error
    except Exception as e:
        logger.error(  # nosemgrep
            f"Exception occurred while getting data using access token : {e}"
        )
        raise e

    return simulation_report


@lru_cache(maxsize=8)
def get_proxy_dict_for_eventhub(
    logger: logging.Logger, session_key: str
) -> Optional[Dict[str, str]]:
    """
    Gets the proxy setting if proxy is configured
    :param logger: logger object
    :param session_key: a session key
    :raises Exception: raises excepotion if unable to fetch proxy details
    :returns None: if proxy is disabled
    :returns dict: dictionary with proxy parameter details
    """
    proxies = None
    logger.debug("Getting proxy server.")
    try:
        cfm = conf_manager.ConfManager(
            session_key,
            APP_NAME,
            realm=f"__REST_CREDENTIAL__#{APP_NAME}#configs/conf-{SETTINGS_CONF_NAME}",
        )

        proxy = cfm.get_conf(SETTINGS_CONF_NAME).get("proxy")
    except Exception:
        logger.error(
            f"Failed to fetch proxy details from configuration. Traceback={traceback.format_exc()}"
        )
        sys.exit(1)

    if proxy:
        if utils.is_false(proxy.get("proxy_enabled", 0)):
            logger.info("Proxy is not enabled.")
        else:
            proxies = {
                "proxy_hostname": proxy.get("proxy_url"),
                "proxy_port": int(proxy.get("proxy_port")),
            }
            logger.debug(f"Proxy is enabled: proxies={proxies}")

            if proxy.get("proxy_username") and proxy.get("proxy_password"):
                proxies = {
                    "proxy_hostname": proxy.get("proxy_url"),
                    "proxy_port": int(proxy.get("proxy_port")),
                    "username": proxy.get("proxy_username"),
                    "password": proxy.get("proxy_password"),
                }
    return proxies
