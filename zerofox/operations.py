"""
Copyright start
MIT License
Copyright (c) 2023 Fortinet Inc
Copyright end
"""

import requests, json
from .constants import *
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('zerofox')


class ZeroFox(object):
    def __init__(self, config, *args, **kwargs):
        self.username = config.get('username')
        self.password = config.get('password')
        url = config.get('server_url').strip('/')
        if not url.startswith('https://') and not url.startswith('http://'):
            self.url = 'https://{0}'.format(url)
        else:
            self.url = url
        self.verify_ssl = config.get('verify_ssl')

    def make_rest_call(self, url, method='GET', data=None, params=None, cti=None):
        try:
            url = self.url + url
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            if cti:
                cti_token = get_cti_authorization_token(self.url, self.username, self.password)
                headers.update({"Authorization": f"Bearer {cti_token}"})
            else:
                token = get_authorization_token(self.url, self.username, self.password)
                headers.update({"Authorization": f"Token {token}"})
            logger.debug("Endpoint {0}".format(url))
            response = requests.request(method, url, data=data, params=params, headers=headers, verify=self.verify_ssl)
            logger.debug("response_content {0}:{1}".format(response.status_code, response.content))
            if response.ok or response.status_code == 204:
                logger.info('Successfully got response for url {0}'.format(url))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response
            else:
                logger.error("{0}".format(response.status_code))
                raise ConnectorError("{0}:{1}".format(response.status_code, response.text))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid Credentials')
        except Exception as err:
            raise ConnectorError(str(err))


def get_authorization_token(url, username, password):
    endpoint = url + '/1.0/api-token-auth/'
    data = {
        "username": username,
        "password": password
    }
    response = requests.request(method='POST', url=endpoint, data=data)
    return response.get("token", "")


def get_cti_authorization_token(url, username, password):
    endpoint = url + '/auth/token/'
    data = {
        "username": username,
        "password": password
    }
    response = requests.request(method='POST', url=endpoint, data=data)
    return response.get("access", "")


def get_cti_phishing(config, params):
    zf = ZeroFox(config)
    endpoint = '/cti/phishing'
    params = {'host_ip': params.get('ip')} if params.get('ip') else {'domain': params.get('domain')}
    response = zf.make_rest_call(endpoint, params=params, cti=True)
    return response


def get_cti_ip_botnet(config, params):
    zf = ZeroFox(config)
    endpoint = '/cti/botnet'
    response = zf.make_rest_call(endpoint, params=params, cti=True)
    return response


def get_ip_lookup(config, params):
    try:
        cti_botnet = get_cti_ip_botnet(config, params)
        cti_phishing = get_cti_phishing(config, params)
        return {
            "cti_ip_botnet": cti_botnet,
            "cti_ip_phishing": cti_phishing
        }
    except Exception as err:
        raise ConnectorError(str(err))


def get_cti_domain_botnet(config, params):
    zf = ZeroFox(config)
    endpoint = '/cti/c2-domains'
    response = zf.make_rest_call(endpoint, params=params, cti=True)
    return response


def get_domain_lookup(config, params):
    try:
        cti_botnet = get_cti_domain_botnet(config, params)
        cti_phishing = get_cti_phishing(config, params)
        return {
            "cti_domain_botnet": cti_botnet,
            "cti_domain_phishing": cti_phishing
        }
    except Exception as err:
        raise ConnectorError(str(err))


def get_cti_email_addresses(config, params, endpoint):
    zf = ZeroFox(config)
    response = zf.make_rest_call(endpoint, params=params, cti=True)
    return response


def get_email_lookup(config, params):
    try:
        cti_email = get_cti_email_addresses(config, params, endpoint='/cti/email-addresses')
        cti_compromised = get_cti_email_addresses(config, params, endpoint='/cti/compromised-credentials')
        cti_botnet_compromised = get_cti_email_addresses(config, params, endpoint='/cti/botnet-compromised-credentials')
        return {
            "cti_email_addresses": cti_email,
            "cti_compromised_credentials": cti_compromised,
            "cti_botnet_compromised_credentials": cti_botnet_compromised
        }
    except Exception as err:
        raise ConnectorError(str(err))


def get_hash_type(hash_value):
    length = len(hash_value)
    if length == 32:
        return 'md5'
    if length == 40:
        return 'sha1'
    if length == 64 and ":" in hash_value:
        return 'ssdeep'
    elif length == 64:
        return 'sha256'
    if length == 128:
        return 'sha512'
    return ''


def get_filehash_lookup(config, params):
    try:
        zf = ZeroFox(config)
        endpoint = "/cti/malware"
        hash_value = params.get('hash')
        hash_type = get_hash_type(hash_value)
        params = {
            hash_type: hash_value
        }
        response = zf.make_rest_call(endpoint, params=params, cti=True)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_exploits_lookup(config, params):
    try:
        zf = ZeroFox(config)
        endpoint = "/cti/exploits"
        params = {
            'created_after': params.get('created_after')
        }
        response = zf.make_rest_call(endpoint, params=params, cti=True)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_alerts_list(config, params):
    try:
        zf = ZeroFox(config)
        endpoint = "/alerts"
        data = {
            "account": params.get('account'),
            "alert_type": ALERT_TYPES.get(params.get('alert_type')) if params.get('alert_type') else '',
            "assignee": params.get('assignee'),
            "entity": params.get('entity'),
            "entity_term": params.get('entity_term'),
            "last_modified": params.get('last_modified'),
            "limit": params.get('limit'),
            "max_timestamp": params.get('max_timestamp'),
            "min_timestamp": params.get('min_timestamp'),
            "network": params.get('network'),
            "offset": params.get('offset'),
            "severity": RISK_RATING.get(params.get('risk_rating')),
            "sort_direction": SORT_DIRECTION.get(params.get('sort_direction')) if params.get('sort_direction') else '',
            "sort_field": SORT_FIELD.get(params.get('sort_field')),
            "status": STATUS.get(params.get('status')) if params.get('status') else '',
            "escalated": params.get('escalated')
        }
        additional_fields = params.get('additional_fields')
        if additional_fields:
            data.update(additional_fields)
        data = {k: v for k, v in data.items() if v is not None and v != ''}
        response = zf.make_rest_call(endpoint, 'POST', data=json.dumps(data))
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_alert_details(config, params):
    try:
        zf = ZeroFox(config)
        endpoint = "/alerts/{0}".format(params.get('alert_id'))
        response = zf.make_rest_call(endpoint)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def assign_alert_to_user(config, params):
    try:
        zf = ZeroFox(config)
        endpoint = "/alerts/{0}/assign".format(params.get('alert_id'))
        data = {
            "subject": params.get('username')
        }
        response = zf.make_rest_call(endpoint, 'POST', data=json.dumps(data))
        if response:
            alert_details = get_alert_details(config, params)
            return alert_details
    except Exception as err:
        raise ConnectorError(str(err))


def open_alert(config, params):
    try:
        zf = ZeroFox(config)
        endpoint = "/alerts/{0}/open".format(params.get('alert_id'))
        response = zf.make_rest_call(endpoint, 'POST')
        if response:
            alert_details = get_alert_details(config, params)
            return alert_details
    except Exception as err:
        raise ConnectorError(str(err))


def close_alert(config, params):
    try:
        zf = ZeroFox(config)
        endpoint = "/alerts/{0}/close".format(params.get('alert_id'))
        response = zf.make_rest_call(endpoint, 'POST')
        if response:
            alert_details = get_alert_details(config, params)
            return alert_details
    except Exception as err:
        raise ConnectorError(str(err))


def alert_request_takedown(config, params):
    try:
        zf = ZeroFox(config)
        endpoint = "/alerts/{0}/request_takedown".format(params.get('alert_id'))
        response = zf.make_rest_call(endpoint, 'POST')
        if response:
            alert_details = get_alert_details(config, params)
            return alert_details
    except Exception as err:
        raise ConnectorError(str(err))


def alert_cancel_takedown(config, params):
    try:
        zf = ZeroFox(config)
        endpoint = "/alerts/{0}/cancel_takedown".format(params.get('alert_id'))
        response = zf.make_rest_call(endpoint, 'POST')
        if response:
            alert_details = get_alert_details(config, params)
            return alert_details
    except Exception as err:
        raise ConnectorError(str(err))


def modify_alert_tags(config, params):
    try:
        zf = ZeroFox(config)
        endpoint = "/alerttagchangeset"
        action = params.get('action').lower()
        data = {
            "changes": [
                {
                    f"{action}": ",".split(params.get('tags_list')),
                    "alert": params.get('alert_id'),
                },
            ]
        }
        response = zf.make_rest_call(endpoint, 'POST', data=json.dumps(data))
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def modify_alert_notes(config, params):
    try:
        zf = ZeroFox(config)
        endpoint = "/alerts/{0}".format(params.get('alert_id'))
        data = {
            'notes': params.get('notes')
        }
        response = zf.make_rest_call(endpoint, 'POST', data=json.dumps(data))
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def create_entity(config, params):
    try:
        zf = ZeroFox(config)
        endpoint = "/entities"
        data = {
            "name": params.get('name'),
            "strict_name_matching": params.get('strict_name_matching'),
            "labels": ",".split(params.get('tags')) if params.get('tags') else '',
            "policy": params.get('policy'),
            "policy_id": params.get('policy'),
            "organization": params.get('organization')
        }
        data = {k: v for k, v in data.items() if v is not None and v != ''}
        response = zf.make_rest_call(endpoint, 'POST', data=json.dumps(data))
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_entity_list(config, params):
    try:
        zf = ZeroFox(config)
        endpoint = "/entities"
        data = {
            "email_address": params.get('email_address'),
            "group": params.get('group'),
            "label": params.get('label'),
            "network": params.get('network'),
            "networks": params.get('networks'),
            "page": params.get('page'),
            "policy": params.get('policy'),
            "type": params.get('type')
        }
        data = {k: v for k, v in data.items() if v is not None and v != ''}
        response = zf.make_rest_call(endpoint, params=data)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_entity_types(config, params):
    try:
        zf = ZeroFox(config)
        endpoint = "/entities/types"
        response = zf.make_rest_call(endpoint)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_policy_types(config, params):
    try:
        zf = ZeroFox(config)
        endpoint = "/policies"
        response = zf.make_rest_call(endpoint)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def submit_threat(config, params):
    try:
        zf = ZeroFox(config)
        endpoint = "/2.0/threat_submit"
        data = {
            "source": params.get('source'),
            "alert_type": ALERT_TYPES.get(params.get('alert_type')),
            "violation": VIOLATION.get(params.get('violation')),
            "entity_id": params.get('entity_id'),
            "notes": params.get('notes')
        }
        response = zf.make_rest_call(endpoint, 'POST', data=json.dumps(data))
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def check_health(config):
    try:
        response = get_alerts_list(config, params={})
        if response:
            return True
    except Exception as err:
        logger.info(str(err))
        raise ConnectorError(str(err))


operations = {
    'get_ip_lookup': get_ip_lookup,
    'get_domain_lookup': get_domain_lookup,
    'get_email_lookup': get_email_lookup,
    'get_filehash_lookup': get_filehash_lookup,
    'get_exploits_lookup': get_exploits_lookup,
    'get_alerts_list': get_alerts_list,
    'get_alert_details': get_alert_details,
    'assign_alert_to_user': assign_alert_to_user,
    'open_alert': open_alert,
    'close_alert': close_alert,
    'alert_request_takedown': alert_request_takedown,
    'alert_cancel_takedown': alert_cancel_takedown,
    'modify_alert_tags': modify_alert_tags,
    'modify_alert_notes': modify_alert_notes,
    'create_entity': create_entity,
    'get_entity_list': get_entity_list,
    'get_entity_types': get_entity_types,
    'get_policy_types': get_policy_types,
    'submit_threat': submit_threat
}
