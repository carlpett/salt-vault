# -*- coding: utf-8 -*-
'''
:maintainer:    Calle Pettersson <cpettsson@gmail.com>
:maturity:      new
:depends:       python-requests
:platform:      all

Interact with Hashicorp Vault
'''

import logging
import json
import requests

import salt.crypt
import salt.exceptions

log = logging.getLogger(__name__)
logging.getLogger("requests").setLevel(logging.WARNING)

def read_secret(path, key=None):
  '''
  Return the value of key at path in vault, or entire secret

  Jinja Example:

  .. code-block:: jinja

      my-secret: {{ salt['vault'].secret('secret/my/secret', 'some-key') }}

  .. code-block:: jinja

      {% set supersecret = salt['vault'].secret('secret/my/secret') %}
      secrets:
        first: {{ supersecret.first }}
        second: {{ supersecret.second }}
  '''
  try:
    minion_id = __opts__['id']
    pki_dir = __opts__['pki_dir']
    signature = salt.crypt.sign_message('{0}/minion.pem'.format(pki_dir), minion_id)

    result = __salt__['publish.runner']('vault.generate_token', arg=[minion_id, signature])
    if not isinstance(result, dict) or result.has_key('error'):
      log.error('Failed to get token from master: {0}'.format(result))
      raise salt.exceptions.CommandExecutionError(result)

    data = _call_vault(result['url'], path, result['token'])

    # TODO: Maybe it would be clearer, both here and in usages, to have separate read-all and read-specific?
    if key is not None:
      return data[key]
    return data
  except Exception as e:
    raise salt.exceptions.CommandExecutionError(e)

def _call_vault(vault_url, path, token):
  url = "%s/v1/%s" % (vault_url, path)
  headers = {'X-Vault-Token': token}
  response = requests.get(url, headers=headers)
  if response.status_code != 200:
    response.raise_for_status()
  
  data = response.json()['data']
  return data