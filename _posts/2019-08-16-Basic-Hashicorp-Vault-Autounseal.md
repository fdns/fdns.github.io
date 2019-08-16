---
title: HashiCorp Vault Auto Unseal for On-Premise Servers
author: Felipe
layout: post
---

# Vault Seal
HashiCorp Vault default startup state is sealed, meaning that any interruption of the services will mean the Vault will be sealed until manual intervention, inserting the seal keys on the system for it to unlock and start running again.

This is more prominent with on-premise servers, where the auto-unseal features are not as available compared to the clod services, and when the Enterprise features are not available.

In this post, I will show you how to setup a easy auto-unseal using basic http requests, and an example using docker-compose for a full running setup. This setup is **NOT** recommended if you have high security requirements, but will work at a start if you can't use any other method to unseal the vault.

Note: You can also use the PGP method to auto-unseal the vault, but the security will be similar to using the raw tokens, and you will gain more if you distribute more keys in different servers (or raspberries at your office).

## Setup

This setup will docker and docker-compose to build the services. The vault backend will be consul, and I recommend to setup automatic backup of it if you can't have it distributed between multiple servers/locations.

If you are able to, you should distribute the software in multiple servers, to prevent downtime if one server fails.

{::nomarkdown}
<div class="mermaid">
graph LR
A[Network]
B[Vault]
C[Consul]
D[unsealer]
E["Backup (TODO)"]
F[Firewall]
F --> A
A --> B
B --> C
D --> B
E --> C

style F fill:turquoise,stroke:#333,stroke-width:4px
</div>
{:/}


### Variables

To make this run on your services, you will have to replace the following variables:
* **\{\{ consul_token \}\}**: Token used by the vault service to authenticate to the consul backend, can be generated with *uuidgen*.
* **\{\{ vault_token \}\}**: Token used to unseal vault after initializing it.

### Configuration files

In consul, we will use the following configuration, which setup a single client/server instance. We have to replace *\{\{ consul_token \}\}* with the random token.

#### consul.json
{% raw %}
```json
{
    "datacenter": "dc1",
    "server": true,
    "ui": true,
    "bind_addr": "0.0.0.0",
    "client_addr": "0.0.0.0",
    "bootstrap_expect": 1,
    "acl": {
        "enabled": true,
        "default_policy": "deny",
        "enable_token_persistence": true,
        "tokens": {
            "master": "{{ consul_token }}"
        }
    }
}
```
{% endraw %}

For vault, we will replace the *\{\{ consul_token \}\}* with the one configured previously. This configuration will enable the ui and **disable TLS**, which you should look to enable.
#### vault.json
{% raw %}
```json
{
  "ui": true,
  "storage":
  {
    "consul":
    {
      "address": "consul:8500",
      "path": "vault/",
      "token": "{{ consul_token }}"
    }
  },
  "listener":
  {
    "tcp":
    {
      "address": "0.0.0.0:8200",
      "tls_disable": 1
    }
  }
}
```
{% endraw %}

We will setup the automatic unseal as a small shell script that will run in parallel of the services, querying to check if the service is sealed or not. Note that the \{\{ vault_token \}\} hasn't be generated yet, but we can update it later. The script will check every 10 seconds the seal status of vault and try to unlock it if it sees that the vault is locked.

#### unseal.sh
```sh
#!/usr/bin/env sh

KEY={{ vault_token }}
URL=http://vault:8200

echo "Starting unsealer"
while true
do
    status=$(curl -s $URL/v1/sys/seal-status | jq '.sealed')
    if [ true = "$status" ]
    then
        echo "Unsealing"
        curl -s --request PUT --data "{\"key\": \"$KEY\"}" $URL/v1/sys/unseal
    fi
    sleep 10
done
```

To start this service, you can use the following docker-compose configuration file, and run it doing a *docker-compose up*. This will expose vault to the internet if done on a public facing server, so make sure to **firewall the port (8200)** so only you can access.

#### docker-compose.yml
{% raw %}
```yml
---
version: "3"

services:
  consul:
    image: consul:1.5.3
    command: agent -server -bind=0.0.0.0 -client 0.0.0.0 -bootstrap-expect=1 -ui
    environment: []
    volumes:
      - ./consul.json:/consul/config/config.json:ro
      - ./data/consul:/consul/data
  vault:
    image: vault:1.2.1
    command: server
    ports:
      - 8200:8200
    volumes:
      - ./vault.json:/vault/config/vault.json:ro
    cap_add:
      - IPC_LOCK
    environment:
      - VAULT_ADDR=http://localhost:8200
  unsealer:
    image: alpine:3.9.2
    command: sh -c "apk add curl jq  && chmod +x /root/unseal.sh && /root/unseal.sh"
    volumes:
      - ./unseal.sh:/root/unseal.sh:ro
```
{% endraw %}

## Vault Configuration
After starting the service, you can navigate to http://\<ip\>:8200/, and it will redirect you to the ui to setup Vault. In our example, we will use only 1 shard for the key, but you can use more if able (have more than one server, and TLS enabled) for more security.

After you get the unseal key, you have to replace in the file *unseal.sh* the \{\{ vault_token \}\} and restart the service by running *docker-compose restart*. By restarting all services, you can check if the unsealer is setup correctly and vault is unsealed automatically.

## Wrapping up
This is a simple setup for automatically unsealing HashiCorp Vault. It is recommended to enable TLS to the Vault service and setup [automatic backup of consul](https://www.consul.io/docs/commands/snapshot.html) to an external storage, to prevent missing data and the difficulty of bootstrapping this service and all issued tokens again.

This by no means is the best setup for Vault, but will work when you start working on secret management and don't have access to cloud resources or the enterprise version of Vault.

Best!
