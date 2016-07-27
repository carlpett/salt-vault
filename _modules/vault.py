# -*- coding: utf-8 -*-
'''
:maintainer:    Calle Pettersson <cpettsson@gmail.com>
:maturity:      new
:depends:       python-requests
:platform:      all

Interact with Hashicorp Vault
'''
import logging

import salt.crypt
import salt.exceptions

log = logging.getLogger(__name__)

def read_secret(path, key=None):
  '''
  Return the value of key at path in vault, or entire secret

  Jinja Example:

  .. code-block:: jinja

      my-secret: {{ salt['vault'].read_secret('secret/my/secret', 'some-key') }}

  .. code-block:: jinja

      {% set supersecret = salt['vault'].read_secret('secret/my/secret') %}
      secrets:
        first: {{ supersecret.first }}
        second: {{ supersecret.second }}
  '''
  log.debug('Reading Vault secret for {0} at {1}'.format(__grains__['id'], path))
  try:
    url = 'v1/{0}'.format(path)
    response = __utils__['vault.make_request']('GET', url)
    if response.status_code != 200:
      response.raise_for_status()
    data = response.json()['data']

    # TODO: Maybe it would be clearer, both here and in usages, to have separate read-all and read-specific?
    if key is not None:
      return data[key]
    return data
  except Exception as e:
    log.error('Failed to read secret! {0}: {1}'.format(type(e).__name__, e))
    raise salt.exceptions.CommandExecutionError(e)
