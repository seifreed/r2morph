# Adversarial shard balance

## Scope

The 16-shard campaign was measured against the 162 executable fixtures
discovered in `fixtures/dataset`. The comparison uses total fixture bytes as a
deterministic cost proxy; it does not claim that byte size equals analyzer
runtime.

## Measurement

| Sharding | Smallest shard | Largest shard | Spread |
|---|---:|---:|---:|
| Round-robin | 40,712 bytes | 72,432 bytes | 31,720 bytes |
| Size-balanced | 52,728 bytes | 55,144 bytes | 2,416 bytes |

The size-balanced assignment reduces the static shard spread by 92.4% while
preserving deterministic, disjoint fixture selection. Analyzer wall time must
be confirmed by the next remote campaign; file size remains a coarse proxy.
