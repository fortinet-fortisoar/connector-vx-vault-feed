"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

import requests
from connectors.core.connector import get_logger, ConnectorError
from bs4 import BeautifulSoup

try:
    from integrations.crudhub import trigger_ingest_playbook
except:
    # ignore. lower FSR version
    pass

logger = get_logger('vx-vault-feed')


class VXVaultFeed(object):
    def __init__(self, config, *args, **kwargs):
        self.url = config.get('server_url').strip('/')
        self.verify_ssl = config.get('verify_ssl')

    def make_rest_call(self, method='GET', data=None, params=None):
        try:
            url = self.url
            response = requests.request(method, url, data=data, params=params, verify=self.verify_ssl,
                                        timeout=60)
            if response.ok:
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


def get_indicators(config, params, **kwargs):
    try:
        vx = VXVaultFeed(config)
        query_parameter = {
            's': 0,
            'm': params.get('limit')
        }
        query_parameter = {k: v for k, v in query_parameter.items() if v is not None and v != ''}
        response = vx.make_rest_call(params=query_parameter)
        if response:
            soup = BeautifulSoup(response.content, 'html.parser')  # Parse the HTML content using BeautifulSoup
            tables = soup.find_all('table')   # Find all <table> tags in the HTML
            tables_dict = {}  # Initialize an empty dictionary to store tables as dictionaries
            for idx, table in enumerate(tables, start=1):
                table_data = []  # Initialize an empty list to store table rows as dictionaries
                headers = [th.text.strip() for th in table.find_all('th')]    # Process table header
                for row in table.find_all('tr'):   # Process table rows
                    if not row.find_all('th'):     # Skip the header row
                        row_data = {}
                        cells = row.find_all('td')
                        for i, cell in enumerate(cells):
                            row_data[headers[i]] = cell.text.strip()
                        table_data.append(row_data)
                tables_dict[f"table_{idx}"] = table_data   # Add table data to tables_dict with a key based on table index
            filtered_indicators = tables_dict.get('table_1')
        else:
            filtered_indicators = [{}]
        mode = params.get('output_mode')
        if mode == 'Create as Feed Records in FortiSOAR':
            create_pb_id = params.get("create_pb_id")
            confidence = params.get('confidence')
            reputation = params.get('reputation')
            tlp = params.get('tlp')
            playbook_params = {"confidence": confidence, "reputation": reputation, "tlp": tlp}
            trigger_ingest_playbook(filtered_indicators, create_pb_id, parent_env=kwargs.get('env', {}),
                                    batch_size=1000, pb_params=playbook_params)
            return "Successfully triggered playbooks to create feed records."
        else:
            return filtered_indicators
    except Exception as err:
        raise ConnectorError(str(err))


def check_health(config, **kwargs):
    try:
        response = get_indicators(config, params={}, **kwargs)
        if response:
            return True
    except Exception as err:
        logger.info(str(err))
        raise ConnectorError(str(err))


operations = {
    'get_indicators': get_indicators
}
