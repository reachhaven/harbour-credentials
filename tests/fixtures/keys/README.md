# Test Key Fixtures

P-256 key pairs for each role in the trust chain.
did:ethr addresses are derived from P-256 public keys via
`keccak256(uncompressed_point[1:])[-20:]` for self-contained test fixtures.

**DO NOT use these keys in production.**

| Role | File | did:ethr | did:key |
|------|------|---------|---------|
| trust-anchor | `trust-anchor.p256.json` | `did:ethr:0x14a34:0x4d6246a7d1e60caa44b75e3af9b37ac8d6442774` | `did:key:zDnaeotFceWszHurnw1CQuhqVsBCsX6s...` |
| haven | `haven.p256.json` | `did:ethr:0x14a34:0x31f1ca3dc5da9f83f360d805662d11a418950202` | `did:key:zDnaefrde2MxCJfVoE1Z6RW6Zk6S91ot...` |
| company | `company.p256.json` | `did:ethr:0x14a34:0xa682b9044de0a1ad3429e8c6a0be0ed45d01da93` | `did:key:zDnaeXyPKbKzPn6vR73hsPF8T12hexnm...` |
| employee | `employee.p256.json` | `did:ethr:0x14a34:0x272c04206c826047add586cbf7f4ffc4386da129` | `did:key:zDnaeupW53s139booGLf5QepJbWnvc9e...` |
| ascs | `ascs.p256.json` | `did:ethr:0x14a34:0x26bac51329c3c13230a77e8524bfbb62e1a8e2d3` | `did:key:zDnaebg1BPCQvqzPWHD53VtVvbFjKwWV...` |

## Chain ID

`0x14a34` = Base testnet (84532 decimal)

## Derivation

```python
from harbour.keys import p256_public_key_to_did_ethr

did = p256_public_key_to_did_ethr(public_key)  # did:ethr:0x14a34:0x<addr>
```
