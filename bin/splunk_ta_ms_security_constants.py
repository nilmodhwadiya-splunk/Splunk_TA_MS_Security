##
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
##
##

CHECKPOINTER = "Splunk_TA_MS_Security_checkpointer"

ACCOUNT_VALIDATION_LOG_FILE_NAME = "Splunk_TA_MS_Security_account_validation"
CRED_HANDLER_LOG_FILE_NAME = "Splunk_TA_MS_Security_encrypt_creds"
ADVANCED_HUNTING_LOG_FILE_NAME = "Splunk_TA_MS_Security_Advanced_Hunting_Alert_Action"
UPDATE_INCIDENT_LOG_FILE_NAME = "Splunk_TA_MS_Security_Update_Incident_Alert_Action"

INCIDENTS_LOG_FILE_NAME = "Splunk_TA_MS_Security_Incidents"
ALERTS_LOG_FILE_NAME = "Splunk_TA_MS_Security_ATP_Alerts"
SIMULATIONS_LOG_FILE_NAME = "Splunk_TA_MS_Security_ATP_Simulations"
EVENT_HUB_LOG_FILE_NAME = "Splunk_TA_MS_Security_Event_Hub"
MACHINES_LOG_FILE_NAME = "Splunk_TA_MS_Security_Machines"

INCIDENTS_INPUT_TYPE = "microsoft_365_defender_endpoint_incidents"
ALERTS_INPUT_TYPE = "microsoft_defender_endpoint_atp_alerts"
SIMULATIONS_INPUT_TYPE = "microsoft_defender_endpoint_simulations"
EVENT_HUB_INPUT_TYPE = "microsoft_defender_event_hub"
MACHINES_INPUT_TYPE = "microsoft_defender_endpoint_machines"

SETTINGS_CONF_NAME = "splunk_ta_ms_security_settings"
ACCOUNT_CONF_NAME = "splunk_ta_ms_security_account"
ACCOUNT_CONF_ENDPOINT = "Splunk_TA_MS_Security_account"

# Supported API types
GRAPH_API = "graph-api"
API_365 = "365-api"

CURRENT_TA_VERSION = "Current Add-on version={version}"

TOKEN_SUCCESS_PROCEED = (
    "action=fetch_access_token, status=success, proceeding with data collection."
)
TOKEN_FAILURE_EXIT = (
    "action=fetch_access_token, status=failure, Unable to fetch access token"
)
TOKEN_ROLES_MESSAGE = (
    "action=token_decode, Found the following roles for the token, token_roles={roles}"
)

CURR_EVENT_BATCH_STATS = (
    "Received Event batch. partition_id={} current_partition_batch_count={}"
)
TOTAL_EVENT_BATCH_STATS = "Finished collecting events. total_received_batch_count={} skipped_events={} ingested_events={} end_time={}"

EH_NAMESPACE_ERROR = "Failed to initiate the connection due to exception: failed to resolve broker hostname."
EH_NAME_ERROR = "CBS Token authentication failed."
EH_FAILED_TO_CREATE_MSG = "Failed to create an event hub consumer due to reason={}"
EH_ERROR_SPECIFIC_MSG = "Azure Eventhub {} with err_msg={} Verify that {} value is correct. Check {}.log file for more details."
EH_ERROR_GENERAL_MSG = (
    "Azure Eventhub {} with err_msg={} Check {}.log file for more details."
)
