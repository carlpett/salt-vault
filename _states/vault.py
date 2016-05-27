import json
import logging
import requests
import difflib

import salt.exceptions

log = logging.getLogger(__name__)

def policy_present(name, rules):
  token, vault_url = _get_token_and_url()

  url = "{0}/v1/sys/policy/{1}".format(vault_url, name)
  headers = {'X-Vault-Token': token }
  response = requests.get(url, headers=headers)

  try:
    if response.status_code == 200:
      return _handle_existing_policy(name, rules, response.json()['rules'])
    elif response.status_code == 404:
      return _create_new_policy(name, rules)
    else:
      response.raise_for_reason()
  except Exception as e:
    return {
      'name': name,
      'changes': None,
      'result': False,
      'comment': 'Failed to get policy: {0}'.format(e)
    }

def _create_new_policy(name, rules):
  if __opts__['test']:
    return {
      'name': name,
      'changes': { name: {'old': '', 'new': rules} },
      'result': None,
      'comment': 'Policy would be created'
    }

  payload = json.dumps({'rules': rules})
  token, vault_url = _get_token_and_url()
  url = "{0}/v1/sys/policy/{1}".format(vault_url, name)
  headers = {'X-Vault-Token': token, 'Content-Type': 'application/json' }
  response = requests.put(url, headers=headers, data=payload)
  if response.status_code != 204:
    return {
      'name': name,
      'changes': None,
      'result': False,
      'comment': 'Failed to create policy: {0}'.format(response.reason)
    }

  return {
    'name': name,
    'result': True,
    'changes': { name: {'old': None, 'new': rules} },
    'comment': 'Policy was created'
  }

def _handle_existing_policy(name, new_rules, existing_rules):
  ret = { 'name': name }
  if new_rules == existing_rules:
    ret['result'] = True
    ret['changes'] = None
    ret['comment'] = 'Policy exists, and has the correct content'
    return ret

  change = ''.join(difflib.unified_diff(existing_rules.splitlines(True), new_rules.splitlines(True)))
  if __opts__['test']:
    ret['result'] = None
    ret['changes'] = { name: {'change': change} }
    ret['comment'] = 'Policy would be changed'
    return ret

  payload = json.dumps({'rules': new_rules})

  token, vault_url = _get_token_and_url()
  url = "{0}/v1/sys/policy/{1}".format(vault_url, name)
  headers = {'X-Vault-Token': token, 'Content-Type': 'application/json' }
  response = requests.put(url, headers=headers, data=payload)
  if response.status_code != 204:
    return {
      'name': name,
      'changes': None,
      'result': False,
      'comment': 'Failed to change policy: {0}'.format(response.reason)
    }

  ret['result'] = True
  ret['changes'] = { name: {'change': change} }
  ret['comment'] = 'Policy was updated'

  return ret

def _get_token_and_url():
  minion_id = __opts__['id']
  pki_dir = __opts__['pki_dir']
  signature = salt.crypt.sign_message('{0}/minion.pem'.format(pki_dir), minion_id)

  result = __salt__['publish.runner']('vault.generate_token', arg=[minion_id, signature])
  if not isinstance(result, dict) or result.has_key('error'):
    log.error('Failed to get token from master: {0}'.format(result))
    raise salt.exceptions.CommandExecutionError(result)

  return result['token'], result['url']
