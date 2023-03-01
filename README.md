# Relay Monitor Builder/Relay Fuzzer

## 🚧 WIP 🚧

Mini "fuzzer" to simulate invalid bids / payloads(TODO) that a [relay monitor](https://github.com/ralexstokes/relay-monitor) then is supposed to catch.

Implements just two endpoints:
1. `getHeader()` -> returns a signed builder bid (refer to `builder-specs` for structure)
2. `getStatus()` -> returns the status of the builder/relay

Behavior is configurable via a config, e.g. `config.example.yaml`

```
---
network:
  name: "sepolia"
  genesis_fork_version: "0x90000069"
consensus:
  endpoint: "http://localhost:5052"
api:
  host: "localhost"
  port: 8088
builder:
  secret_key: "0x0f79a1807a8da8fc978ae1122db7611e752487e014a8784e0277f8d5f371bc86"
fuzzer:
  builder_bid_fault:
    public_key:
      enabled: false
      rate: 50
    signature:
      enabled: false
      rate: 50
    parent_hash:
      enabled: false
      rate: 50
    randao:
      enabled: false
      rate: 20
    block_number:
      enabled: false
      rate: 50
    gas_limit:
      enabled: false
      rate: 50
    timestamp:
      enabled: false
      rate: 50
    basefee:
      enabled: false
      rate: 10

```

For each option
- `enabled` toggles on/off
- `rate` adjusts the probability of that fault being deliberately included in a signed builder bid
