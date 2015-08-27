# salt-vault
Get secrets from a Hashicorp Vault installation

## Usage
Fetch a specific key:
`my-secret: {{ salt['vault'].secret('secret/my/secret', 'some-key') }}`

Fetch the entire secret:
```
{% set supersecret = salt['vault'].secret('secret/my/secret') %}
secrets:
  first: {{ supersecret.first }}
  second: {{ supersecret.second }}
```

## Requirements
Salt master config supports the following values:
```
vault:
  # Url to the Vault. Default: https://localhost:8200/v1
  url: https://vault.mydomain.com:8200/v1
  # A token with root access
  master_token: a427786c-d90a-40a2-a089-ef7af1849138
  # Policies that are applied to tokens used for rendering on minions. Shown are defaults
  policies:
    - saltstack/minion/{minion}
    - saltstack/minions
```