import os
import json
import sys
import splunk.rest as rest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import msal

realm = "mssecuritydelegatedaccess"

API_ADVANCED_HUNTING = "/api/advancedhunting/run"
API_ALERTS = "/api/alerts"
API_INCIDENTS = "/api/incidents"
API_GCC_SECURITY = "https://api-gcc.security.microsoft.us"
API_GCC_SECURITYCENTER = "https://api-gcc.securitycenter.microsoft.us"
API_GOV_SECURITY = "https://api-gov.security.microsoft.us"
API_GOV_SECURITYCENTER = "https://api-gov.securitycenter.microsoft.us"
API_SECURITY = "https://api.security.microsoft.com"
API_SECURITYCENTER = "https://api.securitycenter.microsoft.com"
API_SECURITYCENTER_EU = "https://api-eu.securitycenter.microsoft.com"
API_SECURITYCENTER_UK = "https://api-uk.securitycenter.microsoft.com"
API_SECURITYCENTER_US = "https://api-us.securitycenter.microsoft.com"


GRAPH_ADVANCED_HUNTING = "/v1.0/security/runHuntingQuery"  # POST
GRAPH_ALERTS_V2 = "/v1.0/security/alerts_v2"
GRAPH_INCIDENTS = "/v1.0/security/incidents"
GRAPH_MICROSOFT_COM = "https://graph.microsoft.com"
GRAPH_MICROSOFT_US = "https://graph.microsoft.us"
GRAPH_SIMULATIONS = "/v1.0/security/attackSimulation/simulations"
GRAPH_SIMULATION_REPORT_OVERVIEW = (
    "/v1.0/security/attackSimulation/simulations/{}/report/overview"
)
TOKEN_CACHE_PATH = "token_cache.json"
INCIDENT_ENVS = {
    "default": {
        'authority': "https://login.windows.net/{}",
        'scope': f"{API_SECURITY}/Incident.Read",
    },
    "commercial":{ 
        'authority': "https://login.microsoftonline.com/{}",
        'scope': f"{API_SECURITY}/Incident.Read"
    },
    "gcc": {
        'authority': "https://login.microsoftonline.com/{}",
        'scope': f"{API_GCC_SECURITY}",
    },
    "gcc-high": {
        'authority': "https://login.microsoftonline.us/{}",
        'scope': f"{API_GOV_SECURITY}",
    },
    "commercial-graph-api": {
        'authority': "https://login.microsoftonline.com/{}",
        'scope': f"{GRAPH_MICROSOFT_COM}/.default",
    },
    "gcc-high-graph-api": {
        'authority': "https://login.microsoftonline.us/{}",
        'scope': f"{GRAPH_MICROSOFT_US}/.default",
    }
}
    
REDIRECT_URI = "/en-US/app/splunk-tams-security-delegated-access/handleRedirect"

class DelegatedAuthToken(rest.BaseRestHandler):
    def handle_GET(self):
        try:
            sessionKey = self.sessionKey
            name = self.request['query']['name']
            client_id = self.request['query']['client_id']
            tenant_id = self.request['query']['tenant_id']
            environment = self.request['query']['environment']
            location = self.request['query']['location']
            auth_code = self.request['query']['auth_code']
            url = f'/servicesNS/nobody/Splunk_TA_MS_Security/storage/passwords/credential:mssecuritydelegatedaccess:{name}:'
            scopes = [f"{INCIDENT_ENVS[environment]['scope']}"]
            status , resp = rest.simpleRequest(
                url,
                sessionKey=sessionKey,
                method="GET",
                getargs={"output_mode": "json"},
                raiseAllErrors=True,
            )
            redirect_uri_for_client = f"{location}{REDIRECT_URI}"

            if status.status == 200:
                msal_app = msal.ConfidentialClientApplication(
                    client_id=client_id,
                    authority=INCIDENT_ENVS[environment]['authority'].format(tenant_id),
                    client_credential=json.loads(resp)['entry'][0]['content']['clear_password'],
                    token_cache=msal.SerializableTokenCache(),
                )

                token_result = msal_app.acquire_token_by_authorization_code(
                    auth_code, scopes, redirect_uri=redirect_uri_for_client
                )
                if "access_token" in token_result:
                    self.updateConf(name)
                    response = {
                        'result': "Token received!",
                    }
                    st = self.save_token_cache(msal_app,name)
                    response['st'] = json.dumps(st)
                    self.response.write(json.dumps(response))
                else:
                    self.response.write(json.dumps(token_result))
            else:
                response = {
                    'error': str(status)
                }
                self.response.write(json.dumps(response))

        except Exception as e:
            response = {
                'error': str(e)
            }
            self.response.write(json.dumps(response))

    def updateConf(self, name):
        sessionKey = self.sessionKey
   
        url = f"/servicesNS/nobody/Splunk_TA_MS_Security/properties/delegated_settings/{name}"
        args = {}
        args['verification_status'] = True
        _ , _ = rest.simpleRequest(
            url,
            sessionKey=sessionKey,
            method="POST",
            postargs=args,
            raiseAllErrors=True,
        )

    
    def save_token_cache(self, msal_app, name):
        token_cache = json.dumps(msal_app.token_cache.serialize())
        url = f'/servicesNS/nobody/Splunk_TA_MS_Security/storage/passwords'
        args = {
            'name': f"{name}-token_cache",
            'password':token_cache,
            'realm': 'mssecuritydelegatedaccess'
        }
        status , resp = rest.simpleRequest(
            url,
            sessionKey=self.sessionKey,
            method="POST",
            postargs=args,
            raiseAllErrors=True,
        )

        return status