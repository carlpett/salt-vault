# -*- coding: utf-8 -*-
'''
:maintainer:    Calle Pettersson <cpettsson@gmail.com>
:maturity:      new
:depends:       python-requests
:platform:      all

Interact with Hashicorp Vault
'''

import logging
import requests

import salt.crypt
import salt.exceptions

log = logging.getLogger(__name__)

def generate_token(minion_id, signature, impersonated_by_master=False):
  log.debug('Token generation request for {0} (impersonated by master: {1})'.format(minion_id, impersonated_by_master))
  _validate_signature(minion_id, signature, impersonated_by_master)

  try:
    config = __opts__['vault']

    url = '{0}/v1/auth/token/create'.format(config['url'])
    headers = {'X-Vault-Token': config['auth']['token']}
    audit_data = {
      'saltstack-jid': globals().get('__jid__', '<no jid set>'),
      'saltstack-minion': minion_id,
      'saltstack-user': globals().get('__user__', '<no user set>')
    }
    payload = { 'policies': _get_policies(minion_id, config), 'num_uses': 1, 'metadata': audit_data }

    log.trace('Sending token creation request to Vault')
    response = requests.post(url, headers=headers, json=payload)

    if response.status_code != 200:
      return { 'error': response.reason }

    authData = response.json()['auth']
    return { 'token': authData['client_token'], 'url': config['url'] }
  except Exception as e:
    return { 'error': str(e) }

def show_policies(minion_id):
  config = __opts__['vault']
  return _get_policies(minion_id, config)

def _validate_signature(minion_id, signature, impersonated_by_master):
  pki_dir = __opts__['pki_dir']
  if impersonated_by_master:
    public_key = '{0}/master.pub'.format(pki_dir)
  else:
    public_key = '{0}/minions/{1}'.format(pki_dir, minion_id)

  log.trace('Validating signature for {0}'.format(minion_id))
  if not salt.crypt.verify_signature(public_key, minion_id, signature):
    raise salt.exceptions.AuthenticationError('Could not validate token request from {0}'.format(minion_id))
  log.trace('Signature ok')

def _get_policies(minion_id, config):
  policyPatterns = config.get('policies', ['saltstack/minion/{minion}', 'saltstack/minions'])

  # Allowing pillars in the policy template creates infinite recursion if there
  # are pillars with secrets as values. Removed until that can be solved.
  #minion_pillar = __salt__['pillar.show_pillar'](minion_id)
  #mappings = { 'minion': minion_id, 'grains': __grains__, 'pillar': minion_pillar }
  mappings = { 'minion': minion_id, 'grains': __grains__ }

  policies = []
  for pattern in policyPatterns:
    policies.append(pattern.format(**mappings))

  log.debug('{0} policies: {1}'.format(minion_id, policies))
  return policies
