import json
import logging
import requests

import salt.crypt
import salt.exceptions

log = logging.getLogger(__name__)

def generate_token(minion_id, signature):
  _validate_minion(minion_id, signature)

  try:
    config = __opts__['vault']

    url = '{0}/v1/auth/token/create'.format(config['url'])
    headers = {'X-Vault-Token': config['auth']['token']}
    audit_data = {
      'saltstack-jid': __jid__,
      'saltstack-minion': minion_id,
      'saltstack-user': __user__
    }
    payload = { 'policies': _get_policies(minion_id, config), 'num_uses': 1, 'metadata': audit_data }

    response = requests.post(url, headers=headers, data=json.dumps(payload))

    if response.status_code != 200:
      return { 'error': response.reason }

    authData = response.json()['auth']
    return { 'token': authData['client_token'], 'url': config['url'] }
  except Exception as e:
    return {'error': e}

def _validate_minion(minion_id, signature):
  pki_dir = __opts__['pki_dir']
  public_key = '{0}/minions/{1}'.format(pki_dir, minion_id)
  if not salt.crypt.verify_signature(public_key, minion_id, signature):
    raise salt.exceptions.AuthenticationError('Could not validate token request')


def _get_policies(minion_id, config):
  policyPatterns = config.get('policies', ['saltstack/minion/{minion}', 'saltstack/minions'])

  minion_pillar = __salt__['pillar.show_pillar'](minion_id)
  mappings = { 'minion': minion_id, 'grains': __grains__, 'pillar': minion_pillar }

  policies = []
  for pattern in policyPatterns:
      policies.append(pattern.format(**mappings))

  return policies
