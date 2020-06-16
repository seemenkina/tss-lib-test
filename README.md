# Multi-Party TSS-based Attestor for SPIRE

This repository contains agent and server plugins for [SPIRE](https://github.com/spiffe/spire) to allow [Multi-Party TSS](https://github.com/binance-chain/tss-lib) based node attestation.

## Quick Start

Before starting, create a running SPIRE deployment and add the following configuration to the agent and server:

### Configuring the server plugin

https://github.com/spiffe/spire/blob/master/conf/server/server.conf

The server plugin configuration template is as below:

```hcl
plugins {
    NodeAttestor "tssNodeattestor" {
        plugin_cmd = "/path/to/plugin_cmd"
        plugin_checksum = "sha256 of the plugin binary"
        plugin_data {
            ca_bundle_path = "/path/to/trusted/CA/bundle"
        }
    }
...
```

| key | type | required | description | example |
|:----|:-----|:---------|:------------|:--------|
| ca_bundle_path | string | ✓ | The path to the trusted CA bundle on disk. |  |


### Configuring the agent plugin

https://github.com/spiffe/spire/blob/master/conf/agent/agent.conf

The agent plugin configuration template is as below:

```hcl
plugins {
    NodeAttestor "tssNodeattestor" {
        plugin_cmd = "/path/to/plugin_cmd"
        plugin_checksum = "sha256 of the plugin binary"
        plugin_data {
            certificate_path = "/path/to/certificate"
            intermediates_path = "/path/to/trusted/CA/bundle"
        }
    }
...
```

| key | type | required | description | example |
|:----|:-----|:---------|:------------|:--------|
| certificate_path | string | ✓ | The path to the certificate on disk. |  |
| intermediates_path | string |  | Optional. The path to a chain of intermediate certificates on disk. |  |


## Building 

To build agent or server plugin on MacOS or Unix-system, run `go build .` in corresponding directory. 

## Generate new certificate 

To generate new certificates, delete the old ones in `/tss-lib-test/data/...` and then generate a new chain.

Then copy the received certificates to the required directories for the SPIRE Agent or Server config. Don't delete generate data from `/tss-lib-test/data/...` after copy!

```
rm ../data/agent_.../*
rm ../data/keyLib/key.json
go run certs/main.go      
```