## Title  
Missing Asset Transfer Sender Validation in NttManager (_HIGH-1_)

## Summary 
The NttManager contract enforces correct asset ID, receiver, and amount for incoming ASA transfers, but fails to validate that the asset transfer’s `sender` matches the application call’s `Txn.sender`. An attacker who holds delegated asset authority—via a LogicSig delegation—can burn tokens from a victim’s account and receive cross-chain minted tokens, even though the victim never initiated the bridge transfer.

## Description
In Algorand, atomic transaction groups may include multiple transactions signed by different parties. NttManager’s `_transfer_entry_point()` inspects only the asset ID, asset receiver, and transfer amount in the grouped `AssetTransferTxn` (referred to as `send_token`), but never checks `send_token.sender`. As a result, an attacker can submit:

1. A payment transaction signed by the attacker (to pay bridge fees)  
2. An asset transfer transaction whose `sender` is the victim’s address (signed by a LogicSig that the victim delegated)  
3. An application call signed by the attacker  

Because the contract does not verify that the asset transfer’s `sender` equals the application call’s `Txn.sender`, it treats the victim-signed asset transfer as legitimate and proceeds to burn the victim’s tokens on Algorand while minting destination tokens for the attacker.


## Impact & Risk 
- **Unauthorized Burns**: Victims lose delegated tokens without intending to bridge.  
- **Cross-Chain Forgery**: Attacker receives minted tokens on destination chain.  
- **Trust Violation**: Victim’s intent to delegate for DeFi use is subverted.  
- **Wide Reach**: Any user who has ever delegated asset authority to a protocol could be exploited.

**Suggested Mitigation**  
Update `_transfer_entry_point()` to enforce sender consistency:

```python
# After existing asset ID/receiver/amount checks:
assert send_token.sender == Txn.sender, err.ASSET_SENDER_UNAUTHORIZED
```

Add to `errors.py`:

```python
ASSET_SENDER_UNAUTHORIZED = "Asset sender must be transaction initiator"
```

This binds the ASA transfer’s `sender` to the application call’s `Txn.sender`, closing the delegation-based burn attack.



## Setup

To install all required packages, run:

```bash
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
```

```bash
npm install
```

## Compilation

To generate the TEAL code, ARC56 specs and TS clients for the contracts, run the command:

```bash
npm run build
```

## Testing

Start an Algorand localnet with AlgoKit and Docker using:

```bash
algokit localnet start
```

Make sure to run the compilation commands before testing.

## RUN POC

```bash
npx jest tests/ntt_manager/NttManager.test.ts
```

# POC Location

The test case `"POC: Missing Asset Transfer Sender Validation - [HIGH-1] from Security Audit"` is located in:

- **File:** NttManager.test.ts
- **Describe block:** `describe("transfer", ... )`
- **Test name:** `test("POC: Missing Asset Transfer Sender Validation - [HIGH-1] from Security Audit", async () => { ... })`

**How to find it:**  
Search for the string  
```
POC: Missing Asset Transfer Sender Validation - [HIGH-1]
```
inside the `describe("transfer", ...)` block in the NttManager.test.ts file. It is the last test in that describe block.
