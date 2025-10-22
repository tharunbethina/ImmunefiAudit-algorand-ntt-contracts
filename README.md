# FINDING 1
Missing Asset Transfer Sender Validation in NttManager (_HIGH-1_)

## Summary 
The NttManager contract enforces correct asset ID, receiver, and amount for incoming ASA transfers, but fails to validate that the asset transfer’s `sender` matches the application call’s `Txn.sender`. An attacker who holds delegated asset authority—via a LogicSig delegation—can burn tokens from a victim’s account and receive cross-chain minted tokens, even though the victim never initiated the bridge transfer.

## Vulnerability location
**Location:** `ntt_contracts/ntt_manager/NttManager.py:318-323`  
**Function:** `_transfer_entry_point()` 

```python
assert send_token.xfer_asset.id == self.asset_id.value, err.ASSET_UNKNOWN
assert send_token.asset_receiver == ntt_token_address, err.ASSET_RECEIVER_UNKNOWN
assert send_token.asset_amount == amount, err.ASSET_AMOUNT_INCORRECT

# MISSING:
# assert send_token.sender == Txn.sender, "Sender must be transaction initiator"
```

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

## POC Location

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



# 
#
# FINDING 2
Instant Threshold Changes Enable Race Attacks

## Summary 
The attestation threshold for message approval can be changed instantly with no timelock or delay mechanism. An admin can decrease the threshold after a user sends a cross-chain message but before it executes, allowing the message to execute with fewer attestations than originally required. This retroactively weakens the security model for in-flight messages, enabling governance attacks and signature requirements bypass.

## Vulnerability location
**Location:** `ntt_contracts/transceiver/MessageHandler.py:114-130`  
**Function:** `_set_threshold()` 

```python
@subroutine
def _set_threshold(self, new_threshold: UInt64) -> None:
    assert new_threshold, err.ZERO_THRESHOLD
    self.threshold.value = new_threshold  # ← INSTANT CHANGE, NO TIMELOCK!
    emit(ThresholdUpdated(ARC4UInt64(new_threshold)))

```
Checking Logic (MessageHandler.py:70-80):
```python
@abimethod(readonly=True)
def is_message_approved(self, message_digest: MessageDigest) -> Bool:
    message_attestations, txn = abi_call(
        ITransceiverManager.message_attestations,
        message_digest,
        app_id=self.transceiver_manager.value,
        fee=0,
    )
    
    return Bool(message_attestations > 0 and message_attestations >= self.threshold.value)

```

## Description
The threshold is checked **at message execution time**, not locked **at message send time**. This creates a Time-of-Check Time-of-Use (TOCTOU) vulnerability where:

1. User sends a cross-chain message expecting `threshold=3` attestations required (3 out of 4 transceivers)
2. Only 1 transceiver attests to the message (insufficient under original threshold)
3. Message is correctly blocked (cannot execute with only 1 attestation)
4. Compromised/malicious admin calls `_set_threshold(1)` with **no delay or timelock**
5. Same message now **passes** the approval check with only 1 attestation
6. Message executes with drastically reduced security compared to user expectations



## Impact & Risk 
- **Retroactive Security Degradation**: In-flight messages execute with fewer attestations than originally required
- **Governance Attack Vector**: Compromised admin can weaken bridge security retroactively
- **Consensus Bypass**: Users lose multi-signature protection they were relying on
- **Financial Risk**: High-value transfers may execute with insufficient validation
- **No User Control**: Users cannot prevent threshold changes affecting their messages
- **No Transparency**: No advance notice or timelock before security parameters change


**Suggested Mitigation**  
**Option 1: Prevent Threshold Decreases (Simplest)**
**Option 2: Implement Timelock for Decreases (Recommended)**


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
npx jest tests/transceiver/MessageHandler.test.ts 
```

## POC Location

The test case `"POC: Instant Threshold Changes Enable Race Attacks - [HIGH-3] from Security Audit"` is located in:

- **File:** NttManager.test.ts
- **Describe block:** `describe("POC: Instant Threshold Changes Enable Race Attacks - [HIGH-3]", () => { ... })`
- **Test name:** `test("POC: Admin lowers threshold enabling execution with insufficient attestations", async () => { ... })`, ` test("POC: Real-world attack scenario - Bridge with 4 transceivers", async () => { ... })`

**How to find it:**  
Search for the string  
```
POC: Instant Threshold Changes Enable Race Attacks - [HIGH-3]
```
in the MessageHandler.test.ts file. The describe block contains two comprehensive test cases demonstrating:

1. **Basic attack**: Threshold 2→1, showing message blocked then executed
2. **Real-world scenario**: 4 transceivers, $1M transfer, threshold 3→2 showing financial impact

Both tests include step-by-step console output clearly showing the TOCTOU vulnerability progression and attack success.
