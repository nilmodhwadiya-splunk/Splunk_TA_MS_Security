/**
 *
 * SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
 * SPDX-License-Identifier: LicenseRef-Splunk-8-2021
 *
 */
class Hook {
  constructor(globalConfig, serviceName, state, mode, util) {
    this.globalConfig = globalConfig
    this.serviceName = serviceName
    this.state = state
    this.mode = mode
    this.util = util
    this.saveOnce = false
  }

  areStreamingTypesEqual(existing_input_event_types, current_input_event_types) {
    const existing_list = existing_input_event_types.split(',').sort();
    const current_list = current_input_event_types.split(',').sort();

    if (existing_list.length !== current_list.length) {
      return false;
    }

    return existing_list.every((value, index) => value === current_list[index]);
  }

  checkForDuplicateInput(input_list, current_input, input_type) {
    if (input_type == "microsoft_defender_event_hub") {
      return input_list.find((input) => (
        !input.content.disabled &&
        input.name != current_input.name && // so that it doesn't check duplicate with itself while editing input
        input.content.azure_app_account == current_input.azure_app_account &&
        input.content.event_hub_namespace == current_input.event_hub_namespace &&
        input.content.event_hub_name == current_input.event_hub_name &&
        input.content.consumer_group == current_input.consumer_group &&
        this.areStreamingTypesEqual(input.content.streaming_event_types, current_input.streaming_event_types)
      ));
    }

    return input_list.find((input) => (
      !input.content.disabled &&
      input.name != current_input.name && // so that it doesn't check duplicate with itself while editing input
      input.content.azure_app_account == current_input.azure_app_account &&
      input.content.tenant_id == current_input.tenant_id &&
      input.content.environment == current_input.environment &&
      input.content.location == current_input.location
    ));
  }

  onSave(dataDict) {
    if (this.serviceName == "microsoft_defender_event_hub" && !dataDict["streaming_event_types"]) {
      const allStreamingEventTypes = "AlertInfo,AlertEvidence,DeviceInfo,DeviceNetworkInfo,DeviceProcessEvents,DeviceNetworkEvents,DeviceFileEvents,DeviceRegistryEvents,DeviceLogonEvents,DeviceImageLoadEvents,DeviceEvents,DeviceFileCertificateInfo,EmailAttachmentInfo,EmailEvents,EmailPostDeliveryEvents,EmailUrlInfo,IdentityLogonEvents,IdentityQueryEvents,IdentityDirectoryEvents,CloudAppEvents";
      dataDict["streaming_event_types"] = allStreamingEventTypes;
      this.util.setState((prevState) => {
        const data = { ...prevState.data };
        data.streaming_event_types.value = allStreamingEventTypes;
        return { data };
      });
    }

    if (!this.saveOnce) {
      const warning_msg = "This input is duplicate of an existing input and can cause data duplication. Review the details entered or click on Save again to proceed.";
      const service_endpoint = this.globalConfig.meta.name + "_" + this.serviceName;
      const conf_endpoint = "splunkd/__raw/servicesNS/-/" + this.globalConfig.meta.name + "/" + service_endpoint + "?output_mode=json&count=-1";
      const input_url = window.location.href.replace("app/Splunk_TA_MS_Security/inputs", conf_endpoint);
      const apiRequest = new XMLHttpRequest();

      apiRequest.open('GET', input_url, false); // `false` makes the request synchronous
      apiRequest.send(null);
      if (apiRequest.status === 200) {
        const inputs_list = JSON.parse(apiRequest.responseText).entry;
        const hasDuplications = this.checkForDuplicateInput(inputs_list, dataDict, this.serviceName);
        if (hasDuplications) {
          this.util.setState((previousState) => ({
            ...previousState,
            warningMsg: warning_msg
          }));
          this.saveOnce = true;
          return false;
        }
        else {
          this.util.clearAllErrorMsg();
          this.saveOnce = false;
          return true;
        }
      }
      else {
        this.util.setErrorMsg("Failed to fetch inputs. Please refresh the page and try again.");
        return false;
      }
    }
    // we switch the flag on/off as per the clicks on the "Save" button.
    this.saveOnce = !this.saveOnce;
    return true;
  }
}
export default Hook
