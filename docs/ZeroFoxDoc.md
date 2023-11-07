## About the connector

ZeroFox Platform combines advanced AI-driven analysis to detect complex threats on the surface, deep and dark web, fully managed services with threat analysts that become an extension of your team, and automated remediation to effectively disrupt threats.
<p>This document provides information about the ZeroFox Connector, which facilitates automated interactions, with a ZeroFox server using FortiSOAR&trade; playbooks. Add the ZeroFox Connector as a step in FortiSOAR&trade; playbooks and perform automated operations with ZeroFox.</p>

### Version information

Connector Version: 1.0.0


Authored By: Fortinet

Certified: No

## Installing the connector

<p>Use the <strong>Content Hub</strong> to install the connector. For the detailed procedure to install a connector, click <a href="https://docs.fortinet.com/document/fortisoar/0.0.0/installing-a-connector/1/installing-a-connector" target="_top">here</a>.</p><p>You can also use the <code>yum</code> command as a root user to install the connector:</p>
<pre>yum install cyops-connector-zerofox</pre>

## Prerequisites to configuring the connector

- You must have the credentials of ZeroFox server to which you will connect and perform automated operations.
- The FortiSOAR&trade; server should have outbound connectivity to port 443 on the ZeroFox server.

## Minimum Permissions Required

- Not applicable

## Configuring the connector

For the procedure to configure a connector, click [here](https://docs.fortinet.com/document/fortisoar/0.0.0/configuring-a-connector/1/configuring-a-connector)

### Configuration parameters

<p>In FortiSOAR&trade;, on the Connectors page, click the <strong>ZeroFox</strong> connector row (if you are in the <strong>Grid</strong> view on the Connectors page) and in the <strong>Configurations</strong> tab enter the required configuration details:</p>
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Server URL</td><td>Specify the URL of the ZeroFox server to connect and perform automated operations.
</td>
</tr><tr><td>Username</td><td>Specify the username to access the ZeroFox server to connect and perform automated operations.
</td>
</tr><tr><td>Password</td><td>Specify the password to access the ZeroFox server to connect and perform automated operations.
</td>
</tr><tr><td>Verify SSL</td><td>Specifies whether the SSL certificate for the server is to be verified or not. <br/>By default, this option is set to True.</td></tr>
</tbody></table>

## Actions supported by the connector

The following automated operations can be included in playbooks and you can also use the annotations to access operations from FortiSOAR&trade; release 4.10.0 and onwards:
<table border=1><thead><tr><th>Function</th><th>Description</th><th>Annotation and Category</th></tr></thead><tbody><tr><td>Get IP Lookup</td><td>Retrieves a report from ZeroFox for the IP address submitted to determine if it is malicious or not.</td><td>get_ip_lookup <br/>Investigation</td></tr>
<tr><td>Get Domain Lookup</td><td>Retrieves a report from ZeroFox for the domain submitted to determine if it is suspicious or not.</td><td>get_domain_lookup <br/>Investigation</td></tr>
<tr><td>Get Email Lookup</td><td>Retrieves a report from ZeroFox for the email address submitted to determine if it is suspicious or not.</td><td>get_email_lookup <br/>Investigation</td></tr>
<tr><td>Get FileHash Lookup</td><td>Retrieves a report from ZeroFox for the hash submitted to determine if it is suspicious or not.</td><td>get_filehash_lookup <br/>Investigation</td></tr>
<tr><td>Get Exploits Lookup</td><td>Retrieves a registered exploits from ZeroFox based on the created after you have specified.</td><td>get_exploits_lookup <br/>Investigation</td></tr>
<tr><td>Get Alerts List</td><td>Retrieves a list of all alerts from ZeroFox based on the input parameters you have specified.</td><td>get_alerts_list <br/>Investigation</td></tr>
<tr><td>Get Alert Details</td><td>Retrieves a specific alert details from ZeroFox.</td><td>get_alert_details <br/>Investigation</td></tr>
<tr><td>Assign Alert to User</td><td>Assigns a alert ID to a specific user in ZeroFox.</td><td>assign_alert_to_user <br/>Investigation</td></tr>
<tr><td>Open Alert</td><td>Opens an specific alert in ZeroFox.</td><td>open_alert <br/>Investigation</td></tr>
<tr><td>Close Alert</td><td>Closed an specific alert in ZeroFox.</td><td>close_alert <br/>Investigation</td></tr>
<tr><td>Request Alert Takedown</td><td>Requests a takedown for specified alert ID in ZeroFox.</td><td>alert_request_takedown <br/>Investigation</td></tr>
<tr><td>Cancel Alert Takedown</td><td>Cancels a takedown for specified alert ID in ZeroFox.</td><td>alert_cancel_takedown <br/>Investigation</td></tr>
<tr><td>Modify Alert Tags</td><td>Adds tags to and or removes tags from a specified alert in ZeroFox based on the alert ID, action, and tags you have specified.</td><td>modify_alert_tags <br/>Investigation</td></tr>
<tr><td>Modify Alert Notes</td><td>Modify the notes of specified alert ID in ZeroFox.</td><td>modify_alert_notes <br/>Investigation</td></tr>
<tr><td>Create Entity</td><td>Creates a new entity associated with the company of the authorized user in ZeroFox based on the entity name and other input parameters you have specified.</td><td>create_entity <br/>Investigation</td></tr>
<tr><td>Get Entity List</td><td>Retrieves a list of all entities associated with the company of the authorized user from ZeroFox based on the input parameters you have specified.</td><td>get_entity_list <br/>Investigation</td></tr>
<tr><td>Get Entity Types List</td><td>Retrieves the list of all entity types from ZeroFox.</td><td>get_entity_types <br/>Investigation</td></tr>
<tr><td>Get Policy Types List</td><td>Retrieves the list of all policy types from ZeroFox.</td><td>get_policy_types <br/>Investigation</td></tr>
<tr><td>Submit Threat</td><td>Submit threats into the alert registry for disruption in ZeroFox based on the entity ID, content, content type, infringement type, and notes you have specified.</td><td>submit_threat <br/>Investigation</td></tr>
</tbody></table>

### operation: Get IP Lookup

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>IP Address</td><td>Specify the IP address based on which you want to retrieve details from ZeroFox.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Get Domain Lookup

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Domain Name</td><td>Specify the domain based on which you want to retrieve details from ZeroFox.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Get Email Lookup

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Email Address</td><td>Specify the email address based on which you want to retrieve details from ZeroFox.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Get FileHash Lookup

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>File Hash</td><td>Specify the value of the file hash based on which you want to retrieve details from ZeroFox.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Get Exploits Lookup

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Created After</td><td>Select the DateTime using which you want to filter the result set to only include only those items that have been created after the specified timestamp.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Get Alerts List

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Account Number</td><td>Specify the account number of the social network based on which you want to retrieve alerts from ZeroFox.
</td></tr><tr><td>Alert Type</td><td>Select the type of the alert based on which you want to retrieve alerts from ZeroFox. Possible values are Account Information, Entity Discovery Content, Entity Discovery Profile, Impersonating Account, etc.
</td></tr><tr><td>Assignee Name</td><td>Specify the name of the user assigned to an alert based on which you want to retrieve alerts from ZeroFox.
</td></tr><tr><td>Entity ID</td><td>Specify the ID of the entity based on which you want to retrieve alerts from ZeroFox.
</td></tr><tr><td>Term ID of Entity</td><td>Specify the term ID of the entity based on which you want to retrieve alerts from ZeroFox.
</td></tr><tr><td>Created After</td><td>Select the DateTime using which you want to filter the result set to only include only those items that have been created after the specified timestamp.
</td></tr><tr><td>Created Before</td><td>Select the DateTime using which you want to filter the result set to only include only those items that have been created before the specified timestamp.
</td></tr><tr><td>Last Modified</td><td>Specify the amount of time (in seconds) since an alert was last modified based on which you want to retrieve alerts from ZeroFox.
</td></tr><tr><td>Network Names</td><td>Specify the names of the network based on which you want to retrieve alerts from ZeroFox.
</td></tr><tr><td>Risk Rating</td><td>Select the risk rating of the alert based on which you want to retrieve alerts from ZeroFox. Possible values are Info, Low, Medium, High, or Critical.
</td></tr><tr><td>Sort Direction</td><td>Select the sort direction to sort alerts retrieved from ZeroFox. Possible values are Ascending or Descending.
</td></tr><tr><td>Sort Field</td><td>Select the sort field based on which you want to sort alerts from ZeroFox. Possible values are Alert ID, Alert Status, Alert Type, Assigned User, etc.
</td></tr><tr><td>Alert Status</td><td>Select the status of the alert based on which you want to retrieve alerts from ZeroFox. Possible values are Open, Closed, Takedown Accepted, Takedown Denied, Takedown Requested, or White Listed.
</td></tr><tr><td>Escalated</td><td>If true, returns only escalated alerts from ZeroFox. By default, it set as True.
</td></tr><tr><td>Limit</td><td>Specify the maximum count of records that you want this operation to fetch from ZeroFox. By default, this option is set to 10, and you can set a maximum value of 100.
</td></tr><tr><td>Offset</td><td>Index of the first item to be returned by this operation. This parameter is useful for pagination and for getting a subset of items. By default, this is set as 0.
</td></tr><tr><td>Additional Fields</td><td>Additional fields, in the JSON format, based on which you want to retrieve a alerts from ZeroFox.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Get Alert Details

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Alert ID</td><td>Specify the ID of the alert based on which you want to retrieve details from ZeroFox.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Assign Alert to User

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Alert ID</td><td>Specify the ID of the alert which you want to assign to specific user in ZeroFox.
</td></tr><tr><td>User Name</td><td>Specify the name of the user which you want to assign to the alert in ZeroFox.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Open Alert

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Alert ID</td><td>Specify the ID of the alert which you want to open in ZeroFox.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Close Alert

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Alert ID</td><td>Specify the ID of the alert which you want to close in ZeroFox.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Request Alert Takedown

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Alert ID</td><td>Specify the alert ID for which you want to request a takedown.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Cancel Alert Takedown

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Alert ID</td><td>Specify the alert ID for which you want to cancel a takedown.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Modify Alert Tags

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Alert ID</td><td>Specify the ID of the alert based on which you want to modify the alert tags in ZeroFox.
</td></tr><tr><td>Action</td><td>Select one of the action based on which you want to add or remove the alert tags in ZeroFox.
</td></tr><tr><td>Tags</td><td>Specify the tags which you want to modify in ZeroFox.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Modify Alert Notes

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Alert ID</td><td>Specify the ID of the alert based on which you want to modify the alert notes in ZeroFox.
</td></tr><tr><td>Notes</td><td>Specify the notes you wish to include while updating the alert notes.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Create Entity

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Entity Name</td><td>Specify the entity name based on which you want to create entity in ZeroFox.
</td></tr><tr><td>Policy ID</td><td>Specify the ID of the policy based on which you want to create entity in ZeroFox.
</td></tr><tr><td>Strict Name Matching</td><td>Specifies the type of string matching used for comparing entity names to impersonator names. You can set it to true or false.
</td></tr><tr><td>Tags</td><td>Specify the comma-separated list of string tags based on which you want to create entity in ZeroFox.
</td></tr><tr><td>Organization Name</td><td>Specify the name of the organization associated with the entity based on which you want to create entity in ZeroFox.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Get Entity List

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Email Address</td><td>Specify the email address based on which you want to retrieve entity from ZeroFox.
</td></tr><tr><td>Group ID</td><td>Specify the ID of the entity group based on which you want to retrieve entity from ZeroFox.
</td></tr><tr><td>Label ID</td><td>Specify the ID of the entity label based on which you want to retrieve entity from ZeroFox.
</td></tr><tr><td>Network ID</td><td>Specify the ID of the network based on which you want to retrieve entity from ZeroFox.
</td></tr><tr><td>Network Name</td><td>Specify the name of the network based on which you want to retrieve entity from ZeroFox.
</td></tr><tr><td>Policy ID</td><td>Specify the ID of the entity policy based on which you want to retrieve entity from ZeroFox.
</td></tr><tr><td>Type ID</td><td>Specify the ID of the entity type based on which you want to retrieve entity from ZeroFox.
</td></tr><tr><td>Page Number</td><td>Specify the page from which you want this operation to return results.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Get Entity Types List

#### Input parameters

None.

#### Output

 The output contains a non-dictionary value.

### operation: Get Policy Types List

#### Input parameters

None.

#### Output

 The output contains a non-dictionary value.

### operation: Submit Threat

#### Input parameters

<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Entity ID</td><td>Specify the ID of the entity based on which you want to submit threat in ZeroFox.
</td></tr><tr><td>Content</td><td>Specify the specific content you wish to report as a threat in ZeroFox.
</td></tr><tr><td>Content Type</td><td>Specify the type of the content acting as a threat based on which you want to submit threat in ZeroFox. Possible values are Email, IP, Domain, URL, etc.
</td></tr><tr><td>Infringement Type</td><td>Specify the type of the infringement the submitted threat represents based on which you want to submit threat in ZeroFox. Possible values are Phishing, Malware, Rogue App, Impersonation, etc.
</td></tr><tr><td>Notes</td><td>Specify the notes you want to include in the submission for reporting a threat in ZeroFox.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

## Included playbooks

The `Sample - zerofox - 1.0.0` playbook collection comes bundled with the ZeroFox connector. These playbooks contain steps using which you can perform all supported actions. You can see bundled playbooks in the **Automation** > **Playbooks** section in FortiSOAR&trade; after importing the ZeroFox connector.

- Assign Alert to User
- Cancel Alert Takedown
- Close Alert
- Create Entity
- Get Alert Details
- Get Alerts List
- Get Domain Lookup
- Get Email Lookup
- Get Entity List
- Get Entity Types List
- Get Exploits Lookup
- Get FileHash Lookup
- Get IP Lookup
- Get Policy Types List
- Modify Alert Notes
- Modify Alert Tags
- Open Alert
- Request Alert Takedown
- Submit Threat

**Note**: If you are planning to use any of the sample playbooks in your environment, ensure that you clone those playbooks and move them to a different collection since the sample playbook collection gets deleted during connector upgrade and delete.
