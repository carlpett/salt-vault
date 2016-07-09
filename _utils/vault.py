import logging
import requests

import salt.crypt
import salt.exceptions

log = logging.getLogger(__name__)
logging.getLogger("requests").setLevel(logging.WARNING)

__salt__ = None
def __virtual__():
  try:
    global __salt__
    if not __salt__:
      __salt__ = salt.loader.minion_mods(__opts__)
    return True
  except Exception as e:
    log.error("Could not load __salt__: {0}".format(e))
    return False

def _get_token_and_url_from_master():
  minion_id = __opts__['id']
  pki_dir = __opts__['pki_dir']
  signature = salt.crypt.sign_message('{0}/minion.pem'.format(pki_dir), minion_id)

  result = __salt__['publish.runner']('vault.generate_token', arg=[minion_id, signature])
  if not result:
    log.error('Failed to get token from master! No result returned - is the peer publish configuration correct?')
    raise salt.exceptions.CommandExecutionError(result)
  if not isinstance(result, dict):
    log.error('Failed to get token from master! Response is not a dict: {0}'.format(result))
    raise salt.exceptions.CommandExecutionError(result)
  if result.has_key('error'):
    log.error('Failed to get token from master! An error was returned: {0}'.format(result['error']))
    raise salt.exceptions.CommandExecutionError(result)
  return {
    'url': result['url'],
    'token': result['token']
  }

def get_vault_connection():
  if __opts__.has_key('vault'):
    try:
      return {
        'url': __opts__['vault']['url'],
        'token': __opts__['vault']['auth']['token']
      }
    except KeyError as err:
      errmsg = 'Minion has "vault" config section, but could not find key "{0}" within'.format(err.message)
      raise salt.exceptions.CommandExecutionError(errmsg)
  else:
    return _get_token_and_url_from_master()

def make_request(method, resource, **args):
  connection = get_vault_connection()
  token, vault_url = connection['token'], connection['url']

  url = "{0}/{1}".format(vault_url, resource)
  headers = { 'X-Vault-Token': token, 'Content-Type': 'application/json' }
  response = requests.request(method, url, headers=headers, **args)

  return response