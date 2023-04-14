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
