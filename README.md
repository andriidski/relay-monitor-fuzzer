# Relay Monitor Relay/Builder Fuzzer

Mini "fuzzer" service to simulate invalid bids / payloads to test data collection by a [relay monitor](https://github.com/ralexstokes/relay-monitor).

The service pretends to be a relay and implements just two endpoints:

1. `getHeader()` -> returns a signed builder bid (refer to `builder-specs` for structure)
2. `getStatus()` -> returns the status of the relay/builder

The specific faulty behavior is configurable under the `builder_bid_fault` field in the [fuzzer config](./config.example.yaml), for example:

```yaml
---
...
fuzzer:
  builder_bid_fault:
    public_key:
      enabled: false
      probability: 0.5
    signature:
      enabled: false
      probability: 0.5
    parent_hash:
      enabled: false
      probability: 0.5
    randao:
      enabled: false
      probability: 0.5
    block_number:
      enabled: false
      probability: 0.5
    gas_limit:
      enabled: false
      probability: 0.5
    timestamp:
      enabled: true
      probability: 0.5
    basefee:
      enabled: false
      probability: 0.5


```

For each option
- `enabled` toggles on/off
- `probability` adjusts the probability of that fault being deliberately included in a signed builder bid
