# salt-vault
Manage and use a [Hashicorp Vault](https://www.vaultproject.io) installation 
within Saltstack.

## Usages
salt-vault contains both an execution module and a state module (and internally
uses a runner module). The execution module lets you read secrets from Vault, 
and the state module can manage Vault policies.

### Reading secrets
Fetch a specific sub-key:

```
run-stuff:
  cmd.run:
    - name: executable --user foo --password {{ salt['vault'].read_secret('secret/my/secret', 'password') }}
```

Fetch the entire secret as an object:
```
{% set supersecret = salt['vault'].read_secret('secret/my/secret') %}
secrets:
  first: {{ supersecret.first }}
  second: {{ supersecret.second }}
```

### Managing policies
The state `vault.policy_present` takes two parameters, `name` and `rules`. 
`rules` must be given as in-line HCL:

```
demo-policy:
  vault.policy_present:
    - name: foo
    - rules: |
        path "secret/top-secret/*" {
          policy = "deny"
        }
        path "secret/not-very-secret/*" {
          policy = "write"
        }
```

## Configuration
The salt-master must be configured to allow peer-runner configuration, as well
as configuration for the module.

### Module configuration
Add this segment to the master configuration file, or `/etc/salt/master.d/vault.conf`:

```
vault:
  url: https://vault.service.domain:8200
  auth:
    method: token
    token: 11111111-2222-3333-4444-555555555555
  policies:
    - saltstack/minions
    - saltstack/minion/{minion}
    .. more policies
```

* `url`
  Url to your Vault installation. Required.
* `auth`
  Currently only token auth is supported. The token must be able to create 
  tokens with the policies that should be assigned to minions. Required.
* `policies`
  Policies that are assigned to minions when requesting a token. These can
  either be static, eg `saltstack/minions`, or templated, eg 
  `saltstack/minion/{minion}`. `{minion}` is shorthand for `grains[id]`.
  Both grains and pillar are available, for example these are both valid:
  `my-policies/{grains[os]}`, `{pillar[system]}/{grains[fqdn]}`

  Optional, if `policies` is not configured, `saltstack/minions` and 
  `saltstack/{minion}` are used as defaults.


### Peer-run
Add this segment to the master configuration file, or `/etc/salt/master.d/peer_run.conf`:

```
peer_run:
  .*:
    - vault.generate_token
```


## Masterless
In a masterless setup, the minion can be configured to contact Vault directly.
Example `/etc/salt/minion.d/vault.conf`:

```
vault:
  url: https://vault.service.domain:8200
  auth:
    token: 11111111-2222-3333-4444-555555555555
```

The minion will use the token as-is, without (potentially) downgrading to other
policies as in the master scenario.

Note that this means distributing a token to each minion, stored in clear text
on the file system. Carefully consider the implications of this and plan for
how to revoke the tokens. Also note that non-root tokens expire unless renewed
periodically.
