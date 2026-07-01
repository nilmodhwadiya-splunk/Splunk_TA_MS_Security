#
# SPDX-FileCopyrightText: 2022 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
from typing import Union


class TaExecutionException(Exception):
    """
    Use this exception to finish the processing. Catch at the end of the script and display information provided
    msg - message to be displayed at the end of the processing
    exit_code - (optional) script shall exit with provided exit code, zero if omitted
    """

    def __init__(self, msg: Union[str, Exception], exit_code: int = 0):
        self.exit_code = exit_code
        self.msg = msg

    def __str__(self):
        return str(self.msg)
