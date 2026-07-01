##
# SPDX-FileCopyrightText: 2022 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
##
##
import import_declare_test  # noqa: F401 isort: skip

import sys

import modalert_defender_advanced_hunting_helper
import splunk_ta_ms_security_constants
from alert_actions_base import ModularAlertBase
from solnlib.log import Logs
from ta_execution_exception import TaExecutionException


class AlertActionWorkerdefender_advanced_hunting(ModularAlertBase):
    def __init__(self, logger, alert_name, settings):
        super().__init__(logger, alert_name, settings)

    def process_event(self):
        try:
            return modalert_defender_advanced_hunting_helper.process_event(self)
        except (AttributeError, TypeError) as ae:
            msg = (
                "Error: {}. Please double check spelling and also verify that a compatible version of "
                "Splunk_SA_CIM is installed.".format(str(ae))
            )  # noqa: E501
            self.log_error(msg)
            raise TaExecutionException(msg, 4) from ae
        except Exception as ex:
            self.log_error(str(ex))
            raise TaExecutionException(ex, 5) from ex


if __name__ == "__main__":
    try:
        action_name = "defender_advanced_hunting"
        config = str(sys.stdin.read())
        logger = Logs().get_logger(
            splunk_ta_ms_security_constants.ADVANCED_HUNTING_LOG_FILE_NAME
        )
        exitcode = AlertActionWorkerdefender_advanced_hunting(
            logger, action_name, config
        ).run(sys.argv)
    except TaExecutionException as e:
        exitcode = e.exit_code
    sys.exit(exitcode)
