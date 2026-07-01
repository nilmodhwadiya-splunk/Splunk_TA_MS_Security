#
# SPDX-FileCopyrightText: 2022 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
import csv
import gzip
import logging
import sys
from logging import DEBUG, ERROR, INFO, WARN
from typing import Iterable

from splunktaucclib.cim_actions import ModularAction
from splunktaucclib.splunk_aoblib.setup_util import Setup_Util
from ta_execution_exception import TaExecutionException


class ModularAlertBase(ModularAction):
    """
    Base class for API operations. It reads settings dictionary and passes to base class,
    Override method process_event, inside overloaded method you may use get_events method

    @param logger - logger to be used
    @param alert_name - used in logger name, stored in parent class unless config contains this param, but not used
    @param config -  "A modular action payload in JSON format" - description from parent class
    """

    def __init__(self, logger: logging.Logger, alert_name: str, config: str):
        super().__init__(config, logger, alert_name)
        self.setup_util = Setup_Util(
            self.settings.get("server_uri"), self.session_key, self.logger
        )

    def log_error(self, msg):
        self.message(msg, "failure", level=ERROR)

    def log_info(self, msg):
        self.message(msg, "success", level=INFO)

    def log_debug(self, msg):
        self.message(msg, None, level=DEBUG)

    def log_warn(self, msg):
        self.message(msg, None, level=WARN)

    def set_log_level(self, level):
        self.logger.setLevel(level)

    def get_param(self, param_name):
        return self.configuration.get(param_name)

    @property
    def proxy(self):
        return self.get_proxy()

    def get_proxy(self):
        """if the proxy setting is set. return a dict like
        {
        proxy_url: ... ,
        proxy_port: ... ,
        proxy_username: ... ,
        proxy_password: ... ,
        proxy_type: ... ,
        proxy_rdns: ...
        }
        """
        return self.setup_util.get_proxy_settings()

    def process_event(self) -> int:
        """
        Abstract method to process the events.
        Value returned will be script's exit code
        """
        raise NotImplemented()  # pylint: disable=E0711, E1102  # noqa: F901

    def pre_handle(self, num: int, result: dict):
        result.setdefault("rid", str(num))
        self.update(result)
        return result

    def get_events(self) -> Iterable[dict]:
        try:
            # as we are iterating over return object, we need to create a file object
            self.result_handle = gzip.open(self.results_file, "rt")
            return (
                self.pre_handle(num, result)
                for num, result in enumerate(csv.DictReader(self.result_handle))
            )
        except IOError:
            self.log_error("Error: No search result. Cannot send alert action.")
            sys.exit(2)

    def prepare_meta_for_cam(self):
        """
        I have no idea what is the purpose of this method
        It opens gzip file, reads first line, adds 0 to it and breaks the loop
        get_events does the same, but for all rows and does not call invoke() - that is empty method in parent class
        """
        with gzip.open(self.results_file, "rt") as rf:
            for num, result in enumerate(csv.DictReader(rf)):
                result.setdefault("rid", str(num))
                self.update(result)
                self.invoke()
                break

    def run(self, argv) -> int:
        self._validate_input_params(argv)
        self._read_log_level_from_config_and_set()

        try:
            # prepare meta first for permission lack error handling: TAB-2455
            self.prepare_meta_for_cam()
            status = self.process_event()
        except OSError as ioe:
            msg = "Error: No search result. Cannot send alert action."
            self.log_error(msg)
            raise TaExecutionException(msg, 2) from ioe
        except Exception as e:
            self.log_error(str(e))
            raise TaExecutionException(e, 2) from e

        return status

    def _read_log_level_from_config_and_set(self):
        try:
            self.logger.setLevel(self.setup_util.get_log_level())
        except Exception as e:
            self.log_error(str(e))
            raise TaExecutionException(e, 2) from e

    @staticmethod
    def _validate_input_params(argv):
        """
        Validate if the script was opened for execution - as described in
        https://dev.splunk.com/enterprise/docs/devtools/python/sdk-python/howtousesplunkpython/howtocreatemodpy/
        """
        if len(argv) < 2 or argv[1] != "--execute":
            msg = f'Error: argv="{argv}", expected="--execute"'
            print(msg, file=sys.stderr)
            raise TaExecutionException(msg, 1)
