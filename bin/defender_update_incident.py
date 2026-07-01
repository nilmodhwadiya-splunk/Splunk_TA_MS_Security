##
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
##
##
import import_declare_test  # noqa: F401 isort: skip

import logging
import sys

import modalert_defender_update_incident_helper
import splunk_ta_ms_security_constants
from alert_actions_base import ModularAlertBase
from solnlib.log import Logs
from ta_execution_exception import TaExecutionException


class AlertActionWorkerdefender_update_incident(ModularAlertBase):
    # TODO: Duplicated Code: defender_advanced_hunting & defender_update_incident
    def __init__(self, logger: logging.Logger, al_name: str, settings):
        super().__init__(logger, al_name, settings)

    def process_event(self):
        try:
            return modalert_defender_update_incident_helper.process_event(self)
        except (AttributeError, TypeError) as ae:
            msg = (
                "Error: {}. Please double check spelling and also verify that a compatible version of "
                "Splunk_SA_CIM is installed.".format(str(ae))
            )  # noqa: E501
            self.log_error(msg)
            raise TaExecutionException(msg, 4)
        except Exception as ex:
            self.log_error(str(ex))
            raise TaExecutionException(ex, 5)


if __name__ == "__main__":
    exitcode = 0
    alert_name = "defender_update_incident"
    try:
        config = str(sys.stdin.read())
        exitcode = AlertActionWorkerdefender_update_incident(
            Logs().get_logger(
                splunk_ta_ms_security_constants.UPDATE_INCIDENT_LOG_FILE_NAME
            ),
            alert_name,
            config,
        ).run(sys.argv)
    except TaExecutionException as e:
        exitcode = e.exit_code
    sys.exit(exitcode)
