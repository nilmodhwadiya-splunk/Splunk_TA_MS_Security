##
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
##
##

import datetime

from splunktaucclib.rest_handler.endpoint.validator import Validator


class StartDateValidation(Validator):
    """
    Start date Validation
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def validate(self, value, data):
        start_date = data.get("start_date")
        today = datetime.datetime.utcnow()
        if start_date:
            try:
                start_date = datetime.datetime.strptime(
                    start_date, "%Y-%m-%dT%H:%M:%SZ"
                )
            except ValueError:
                errorMsg = (
                    f"Invalid date format specified for 'Start Date': {start_date}"
                )
                self.put_msg(errorMsg)
                return False
            else:
                if start_date > today:
                    errorMsg = "Start date cannot be in future"
                    self.put_msg(errorMsg)
                    return False
                return True
        # In scenario where start_date isn't given,
        # TA would update inputs.conf runtime with value of 30 days ago.
        return True
