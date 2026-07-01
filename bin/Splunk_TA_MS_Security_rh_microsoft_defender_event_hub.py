
import import_declare_test

from splunktaucclib.rest_handler.endpoint import (
    field,
    validator,
    RestModel,
    DataInputModel,
)
from splunktaucclib.rest_handler import admin_external, util
from splunk_ta_ms_security_account_handler_eventhub_rh import MSSecurityAccountExternalHandler
import logging

util.remove_http_proxy_env_vars()


fields = [
    field.RestField(
        'azure_app_account',
        required=True,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'event_hub_namespace',
        required=True,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'event_hub_name',
        required=True,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'consumer_group',
        required=True,
        encrypted=False,
        default='$Default',
        validator=None
    ), 
    field.RestField(
        'streaming_event_types',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'index',
        required=True,
        encrypted=False,
        default='default',
        validator=validator.String(
            max_len=80, 
            min_len=1, 
        )
    ), 

    field.RestField(
        'disabled',
        required=False,
        validator=None
    )

]
model = RestModel(fields, name=None)



endpoint = DataInputModel(
    'microsoft_defender_event_hub',
    model,
)


if __name__ == '__main__':
    logging.getLogger().addHandler(logging.NullHandler())
    admin_external.handle(
        endpoint,
        handler=MSSecurityAccountExternalHandler,
    )
