"""
Copyright start
MIT License
Copyright (c) 2023 Fortinet Inc
Copyright end
"""

ALERT_TYPES = {
    "Email": "email",
    "IP": "ip",
    "Domain": "domain",
    "URL": "url",
    "Phone": "phone",
    "Mail Exchange": "mail_exchange",
    "Page Content": "page_content",
    "Account": "account",
    "Account Information": "account_information",
    "Entity Discovery Content": "entity_discovery_content",
    "Entity Discovery Profile": "entity_discovery_profile",
    "Impersonating Account": "impersonating_account",
    "Impersonating Comment": "impersonating_comment",
    "Impersonating Post": "impersonating_post",
    "Incoming Comment": "incoming_comment",
    "Incoming Post": "incoming_post",
    "Incoming Private Message": "incoming_private_message",
    "Outgoing Private Message": "outgoing_private_message",
    "Self Comment": "self_comment",
    "Self Post": "self_post",
    "Search Query": "search_query",
    "Location": "location"
}

VIOLATION = {
    "Phishing": "phishing",
    "Malware": "malware",
    "Rogue App": "rogue_app",
    "Impersonation": "impersonation",
    "Trademark": "trademark",
    "Copyright": "copyright",
    "Private Data": "private_data",
    "Fraud": "fraud",
    "Other": "other"
}

SORT_DIRECTION = {
    "Ascending": "asc",
    "Descending": "desc"
}

SORT_FIELD = {
    "Alert ID": "alert_id",
    "Alert Status": "alert_status",
    "Alert Type": "alert_type",
    "Assigned User": "assigned_user",
    "Perpetrator": "perpetrator",
    "Protected Entity": "protected_entity",
    "Protected Social Object": "protected_social_object",
    "Rule": "rule",
    "Severity": "severity",
    "Social Network": "social_network",
    "Timestamp": "timestamp",
    "Escalated": "escalated"
}

STATUS = {
    "Open": "open",
    "Closed": "closed",
    "Takedown Accepted": "takedown_accepted",
    "Takedown Denied": "takedown_denied",
    "Takedown Requested": "takedown_requested",
    "White Listed": "whitelisted"
}

RISK_RATING = {
    "Info": 1,
    "Low": 2,
    "Medium": 3,
    "High": 4,
    "Critical": 5
}
