[microsoft_365_defender_endpoint_incidents://<name>]
azure_app_account = account created in configuration page using client_id and client_secret
tenant_id = tenant_id of azure account
start_date = date from where user wants to collect data, in a specific format
environment = endpoint to collect data from

[microsoft_defender_endpoint_simulations://<name>]
azure_app_account = account created in configuration page using client_id and client_secret
start_date = date from where user wants to collect data, in a specific format
environment = endpoint to collect data from

[microsoft_defender_endpoint_atp_alerts://<name>]
azure_app_account = account created in configuration page using client_id and client_secret
tenant_id = tenant_id of azure account
location = localtion of server close to user's geolocation
start_date = date from where user wants to collect data, in a specific format

[microsoft_defender_event_hub://<name>]
azure_app_account = account created in configuration page using client_id and client_secret
event_hub_namespace = namespace of event hub (FQDN)
event_hub_name = name of the event hub
consumer_group = consumer group of event hub
streaming_event_types = event types supported by streaming api

[microsoft_defender_endpoint_machines://<name>]
azure_app_account = account created in configuration page using client_id and client_secret
tenant_id = tenant_id of azure account
location = localtion of server close to user's geolocation
start_date = date from where user wants to collect data, in a specific format

### NEW - Microsoft Graph Security Advanced Hunting input
### Endpoint:
### POST https://graph.microsoft.com/v1.0/security/runHuntingQuery
### This API runs KQL advanced hunting queries in Microsoft 365 Defender.
[microsoft_graph_security_hunting_query://<name>]
azure_app_account = account created in configuration page using client_id and client_secret
tenant_id = tenant_id of azure account
query = KQL hunting query to run against Microsoft 365 Defender advanced hunting data
start_date = date from where user wants to collect data, in a specific format
environment = Microsoft Graph endpoint/environment to collect data from

[microsoft_365_defender_endpoint_incidents]
python.version = {default|python3}

[microsoft_defender_endpoint_simulations]
python.version = {default|python3}

[microsoft_defender_endpoint_atp_alerts]
python.version = {default|python3}

[microsoft_defender_event_hub]
python.version = {default|python3}

[microsoft_defender_endpoint_machines]
python.version = {default|python3}

### NEW - Python version for Microsoft Graph Security Advanced Hunting input
[microsoft_graph_security_hunting_query]
python.version = {default|python3}