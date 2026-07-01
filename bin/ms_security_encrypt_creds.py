#
# SPDX-FileCopyrightText: 2023 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import import_declare_test  # isort: skip # noqa: F401
import sys
from traceback import format_exc

from solnlib import log
from solnlib.splunkenv import get_splunkd_uri
from splunk_ta_ms_security_constants import (
    ACCOUNT_CONF_ENDPOINT,
    CRED_HANDLER_LOG_FILE_NAME,
)
from splunktalib.rest import code_to_msg, splunkd_request

_LOGGER = log.Logs().get_logger(CRED_HANDLER_LOG_FILE_NAME)
log.Logs().set_level("INFO")


class MaskCredentials:
    """
    This class is used to migrate the existing filter parameter in inputs.conf file.
    """

    @staticmethod
    def get_session_key() -> str:
        """
        This function is used to get the session key.
        :return: This function returns the session_key value.
        """
        session_key = sys.stdin.readline().strip()
        return session_key

    def encrypt_sensitive_information(self) -> None:
        """
        This function encrypts the credentials that are meant to be encrypted.
        """
        session_key = MaskCredentials().get_session_key()
        splunkd_uri = get_splunkd_uri()
        account_endpoint = f"{splunkd_uri}/servicesNS/-/{import_declare_test.ta_name}/{ACCOUNT_CONF_ENDPOINT}"
        try:
            resp = splunkd_request(
                splunkd_uri=account_endpoint, session_key=session_key, method="GET"
            )
        except Exception:
            _LOGGER.error(
                "Failed to make the endpoint API call. The credentials may not have been encrypted "
                f"in the splunk_ta_ms_security_account.conf file. Reason={format_exc()}"
            )
        else:
            if resp is None or resp.status_code != 200:
                _LOGGER.error(
                    f'Fail to load endpoint "{account_endpoint}" - {code_to_msg(resp)}'
                )
            else:
                _LOGGER.info(
                    "Successfully encrypted the sensitive information in the MS Security TA."
                )


if __name__ == "__main__":
    mask_credentials = MaskCredentials()
    mask_credentials.encrypt_sensitive_information()
