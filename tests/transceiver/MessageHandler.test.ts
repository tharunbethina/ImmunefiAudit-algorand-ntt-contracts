import { algorandFixture } from "@algorandfoundation/algokit-utils/testing";
import type { TransactionSignerAccount } from "@algorandfoundation/algokit-utils/types/account";
import { type Account, type Address, getApplicationAddress } from "algosdk";

import {
  MockTransceiverManagerClient,
  MockTransceiverManagerFactory,
} from "../../specs/client/MockTransceiverManager.client.ts";
import {
  SimpleMessageHandlerClient,
  SimpleMessageHandlerFactory,
} from "../../specs/client/SimpleMessageHandler.client.ts";
import { getMessagesExecutedBoxKey } from "../utils/boxes.ts";
import { getEventBytes, getRandomBytes } from "../utils/bytes.ts";
import {
  type TransceiverInstruction,
  calculateMessageDigest,
  getMessageReceived,
  getRandomMessageToSend,
} from "../utils/message.ts";
import { MAX_UINT16, MAX_UINT64, getRandomUInt } from "../utils/uint.ts";

describe("MessageHandler", () => {
  const localnet = algorandFixture();

  let transceiverManagerFactory: MockTransceiverManagerFactory;
  let transceiverManagerClient: MockTransceiverManagerClient;
  let transceiverManagerAppId: bigint;

  const THRESHOLD = 2n;
  const TOTAL_DELIVERY_PRICE = (1).algo();
  const transceiverInstructions: TransceiverInstruction[] = [[getRandomUInt(MAX_UINT64), getRandomBytes(10)]];

  let factory: SimpleMessageHandlerFactory;
  let client: SimpleMessageHandlerClient;
  let appId: bigint;

  let creator: Address & Account & TransactionSignerAccount;
  let admin: Address & Account & TransactionSignerAccount;
  let user: Address & Account & TransactionSignerAccount;

  beforeAll(async () => {
    await localnet.newScope();
    const { algorand, generateAccount } = localnet.context;

    creator = await generateAccount({ initialFunds: (100).algo() });
    admin = await generateAccount({ initialFunds: (100).algo() });
    user = await generateAccount({ initialFunds: (100).algo() });

    factory = algorand.client.getTypedAppFactory(SimpleMessageHandlerFactory, {
      defaultSender: creator,
      defaultSigner: creator.signer,
    });

    // deploy transceiver manager
    {
      transceiverManagerFactory = algorand.client.getTypedAppFactory(MockTransceiverManagerFactory, {
        defaultSender: creator,
        defaultSigner: creator.signer,
      });
      const { appClient, result } = await transceiverManagerFactory.deploy();
      transceiverManagerAppId = result.appId;
      transceiverManagerClient = appClient;

      expect(transceiverManagerAppId).not.toEqual(0n);
    }

    // fund mock transceiver manager so have funds to pay for sending messages
    await localnet.algorand.account.ensureFunded(
      getApplicationAddress(transceiverManagerAppId),
      await localnet.algorand.account.localNetDispenser(),
      (100).algo(),
    );
  });

  test("deploys with correct state", async () => {
    const { appClient, result } = await factory.deploy({
      createParams: {
        sender: creator,
        method: "create",
        args: [THRESHOLD],
      },
    });
    appId = result.appId;
    client = appClient;

    expect(appId).not.toEqual(0n);
    expect(await client.state.global.transceiverManager()).toEqual(undefined);
    expect(await client.state.global.threshold()).toEqual(THRESHOLD);
  });

  describe("set transceiver manager", () => {
    test("fails when trying to set zero threshold", async () => {
      await expect(client.send.setThreshold({ sender: user, args: [0] })).rejects.toThrow("Cannot set zero threshold");
    });

    test("succeeds", async () => {
      const res = await client.send.setTransceiverManager({
        sender: user,
        args: [user.toString(), transceiverManagerAppId],
        extraFee: (1000).microAlgos(),
      });
      expect(await client.state.global.transceiverManager()).toEqual(transceiverManagerAppId);
      expect(res.confirmations[0].innerTxns!.length).toEqual(1);
      expect(res.confirmations[0].innerTxns![0].logs![0]).toEqual(
        getEventBytes("MessageHandlerAdded(uint64,address)", [appId, user.toString()]),
      );
    });
  });

  describe("set threshold", () => {
    test("fails when trying to set zero threshold", async () => {
      await expect(client.send.setThreshold({ sender: user, args: [0] })).rejects.toThrow("Cannot set zero threshold");
    });

    test("succeeds", async () => {
      const newThreshold = 1n;
      expect(newThreshold).not.toEqual(THRESHOLD);

      // set threshold
      const res = await client.send.setThreshold({ sender: user, args: [newThreshold] });
      expect(await client.state.global.threshold()).toEqual(newThreshold);
      expect(res.confirmations[0].logs![0]).toEqual(getEventBytes("ThresholdUpdated(uint64)", [newThreshold]));

      // restore
      await client.send.setThreshold({ sender: user, args: [THRESHOLD] });
      expect(await client.state.global.threshold()).toEqual(THRESHOLD);
    });
  });

  describe("send message", () => {
    beforeAll(async () => {
      await transceiverManagerClient.send.setTotalDeliveryPrice({ args: [TOTAL_DELIVERY_PRICE.microAlgos] });
    });

    test("fails if insufficient balance to pay delivery price", async () => {
      // ensure not enough balance
      const { balance: appAlgoBalanceBefore } = await localnet.algorand.account.getInformation(
        getApplicationAddress(appId),
      );
      expect(appAlgoBalanceBefore.microAlgos).toBeLessThan(TOTAL_DELIVERY_PRICE.microAlgo);

      // send message
      const message = getRandomMessageToSend();
      await expect(
        client.send.sendMessage({
          sender: user,
          args: [message, transceiverInstructions],
          appReferences: [transceiverManagerAppId],
          extraFee: (3000).microAlgos(),
        }),
      ).rejects.toThrow("overspend");
    });

    test("succeeds", async () => {
      const { balance: userAlgoBalanceBefore } = await localnet.algorand.account.getInformation(user);
      const { balance: appAlgoBalanceBefore } = await localnet.algorand.account.getInformation(
        getApplicationAddress(appId),
      );
      const { balance: transceiverManagerAlgoBalanceBefore } = await localnet.algorand.account.getInformation(
        getApplicationAddress(transceiverManagerAppId),
      );

      // send message
      const message = getRandomMessageToSend();
      const fundingTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: TOTAL_DELIVERY_PRICE,
      });
      const res = await client
        .newGroup()
        .addTransaction(fundingTxn)
        .sendMessage({
          sender: user,
          args: [message, transceiverInstructions],
          appReferences: [transceiverManagerAppId],
          extraFee: (3000).microAlgos(),
        })
        .send();

      // balance after
      const feeTotal = res.transactions.reduce((acc, txn) => acc + txn.fee, 0n);
      const { balance: userAlgoBalanceAfter } = await localnet.algorand.account.getInformation(user);
      const { balance: appAlgoBalanceAfter } = await localnet.algorand.account.getInformation(
        getApplicationAddress(appId),
      );
      const { balance: transceiverManagerAlgoBalanceAfter } = await localnet.algorand.account.getInformation(
        getApplicationAddress(transceiverManagerAppId),
      );
      expect(userAlgoBalanceAfter.microAlgos).toEqual(
        userAlgoBalanceBefore.microAlgos - TOTAL_DELIVERY_PRICE.microAlgos - feeTotal,
      );
      expect(appAlgoBalanceAfter.microAlgos).toEqual(appAlgoBalanceBefore.microAlgos);
      expect(transceiverManagerAlgoBalanceAfter.microAlgos).toEqual(
        transceiverManagerAlgoBalanceBefore.microAlgos + TOTAL_DELIVERY_PRICE.microAlgos,
      );

      // check events and return
      expect(res.confirmations[1].innerTxns!.length).toEqual(3);
      expect(res.confirmations[1].innerTxns![0].logs![0]).toEqual(
        getEventBytes("InternalQuoteDeliveryPrices(uint64,byte[32],(uint64,byte[])[])", [
          appId,
          message.id,
          transceiverInstructions,
        ]),
      );
      expect(res.confirmations[1].innerTxns![2].logs![0]).toEqual(
        getEventBytes("MessageSentToTransceivers(uint64,uint64,address,byte[32],(uint64,byte[])[])", [
          appId,
          TOTAL_DELIVERY_PRICE.microAlgo,
          getApplicationAddress(transceiverManagerAppId),
          message.id,
          transceiverInstructions,
        ]),
      );
      expect(res.returns).toEqual([TOTAL_DELIVERY_PRICE.microAlgo]);
    });
  });

  describe("is message approved", () => {
    test("returns false when threshold attestations not reached", async () => {
      await transceiverManagerClient.send.setMessageAttestations({ args: [THRESHOLD - 1n] });
      expect(
        await client.isMessageApproved({ sender: user, args: [getRandomBytes(32)], extraFee: (1000).microAlgos() }),
      ).toBeFalsy();
      expect(await client.isMessageExecuted({ sender: user, args: [getRandomBytes(32)] })).toBeFalsy();
    });

    test.each([
      { name: "reached", attestations: THRESHOLD },
      { name: "exceeded", attestations: THRESHOLD + 1n },
    ])("returns true when threshold attestations are $name", async ({ attestations }) => {
      await transceiverManagerClient.send.setMessageAttestations({ args: [attestations] });
      expect(
        await client.isMessageApproved({
          sender: user,
          args: [getRandomBytes(32)],
          extraFee: (1000).microAlgos(),
        }),
      ).toBeTruthy();
      expect(await client.isMessageExecuted({ sender: user, args: [getRandomBytes(32)] })).toBeFalsy();
    });
  });

  describe("execute message", () => {
    const MESSAGE_DIGEST = getRandomBytes(32);

    beforeAll(async () => {
      await transceiverManagerClient.send.setMessageDigest({ args: [MESSAGE_DIGEST] });
    });

    afterEach(async () => {
      await transceiverManagerClient.send.setMessageAttestations({ args: [THRESHOLD] });
    });

    test("fails when message handler is not application", async () => {
      const MESSAGE_RECEIVED = getMessageReceived(getRandomUInt(MAX_UINT16), getRandomMessageToSend());
      await expect(
        client.send.executeMessage({
          sender: user,
          args: [MESSAGE_RECEIVED],
          appReferences: [transceiverManagerAppId],
          boxReferences: [getMessagesExecutedBoxKey(MESSAGE_DIGEST)],
          extraFee: (2000).microAlgos(),
        }),
      ).rejects.toThrow("Message handler address mismatch");
    });

    test("fails when message not approved", async () => {
      // ensure not approved
      await transceiverManagerClient.send.setMessageAttestations({ args: [THRESHOLD - 1n] });
      expect(
        await client.isMessageApproved({
          sender: user,
          args: [MESSAGE_DIGEST],
          extraFee: (1000).microAlgos(),
        }),
      ).toBeFalsy();

      // execute message
      const MESSAGE_RECEIVED = getMessageReceived(
        getRandomUInt(MAX_UINT16),
        getRandomMessageToSend({ handlerAddress: getApplicationAddress(appId).publicKey }),
      );
      await expect(
        client.send.executeMessage({
          sender: user,
          args: [MESSAGE_RECEIVED],
          appReferences: [transceiverManagerAppId],
          boxReferences: [getMessagesExecutedBoxKey(MESSAGE_DIGEST)],
          extraFee: (2000).microAlgos(),
        }),
      ).rejects.toThrow("Message not approved");
    });

    test("succeeds and calls internal handle message", async () => {
      // ensure approved
      expect(
        await client.isMessageApproved({
          sender: user,
          args: [MESSAGE_DIGEST],
          extraFee: (1000).microAlgos(),
        }),
      ).toBeTruthy();

      // execute message
      const APP_MIN_BALANCE = (122_900).microAlgos();
      const fundingTxn = await localnet.algorand.createTransaction.payment({
        sender: creator,
        receiver: getApplicationAddress(appId),
        amount: APP_MIN_BALANCE,
      });
      const MESSAGE_RECEIVED = getMessageReceived(
        getRandomUInt(MAX_UINT16),
        getRandomMessageToSend({ handlerAddress: getApplicationAddress(appId).publicKey }),
      );
      const res = await client
        .newGroup()
        .addTransaction(fundingTxn)
        .executeMessage({
          sender: user,
          args: [MESSAGE_RECEIVED],
          appReferences: [transceiverManagerAppId],
          boxReferences: [getMessagesExecutedBoxKey(MESSAGE_DIGEST)],
          extraFee: (2000).microAlgos(),
        })
        .send();
      expect(res.confirmations[1].innerTxns!.length).toEqual(2);
      expect(res.confirmations[1].logs![0]).toEqual(
        getEventBytes("HandledMessage(byte[32],byte[32])", [MESSAGE_DIGEST, MESSAGE_RECEIVED.id]),
      );
      expect(await client.isMessageExecuted({ sender: user, args: [MESSAGE_DIGEST] })).toBeTruthy();
    });

    test("fails when message already executed", async () => {
      // ensure already executed
      expect(await client.isMessageExecuted({ sender: user, args: [MESSAGE_DIGEST] })).toBeTruthy();

      // execute message
      const MESSAGE_RECEIVED = getMessageReceived(
        getRandomUInt(MAX_UINT16),
        getRandomMessageToSend({ handlerAddress: getApplicationAddress(appId).publicKey }),
      );
      await expect(
        client.send.executeMessage({
          sender: user,
          args: [MESSAGE_RECEIVED],
          appReferences: [transceiverManagerAppId],
          boxReferences: [getMessagesExecutedBoxKey(MESSAGE_DIGEST)],
          extraFee: (2000).microAlgos(),
        }),
      ).rejects.toThrow("Message already executed");
    });
  });

  describe("POC: Instant Threshold Changes Enable Race Attacks - [HIGH-3]", () => {
    /**
     * VULNERABILITY [HIGH-3]: Instant Threshold Changes Enable Race Attacks
     * 
     * DESCRIPTION:
     * The attestation threshold can be changed instantly with no timelock. An admin can 
     * decrease the threshold after a message is sent but before execution, allowing 
     * execution with fewer attestations than originally required.
     * 
     * VULNERABLE CODE (MessageHandler.py:114-130):
     *   @subroutine
     *   def _set_threshold(self, new_threshold: UInt64) -> None:
     *       assert new_threshold, err.ZERO_THRESHOLD
     *       self.threshold.value = new_threshold  # ← INSTANT CHANGE, NO TIMELOCK!
     *       emit(ThresholdUpdated(ARC4UInt64(new_threshold)))
     * 
     * ATTACK SCENARIO:
     * 1. System configured with threshold=2 (requires 2/N transceivers to attest)
     * 2. User sends cross-chain message expecting 2 attestations required
     * 3. Only 1 transceiver attests (insufficient under original threshold)
     * 4. Compromised/malicious admin lowers threshold to 1
     * 5. Message executes with only 1 attestation (bypassing original security)
     * 
     * IMPACT:
     * - Messages execute with fewer signatures than originally required
     * - Admin can retroactively weaken security for in-flight messages
     * - No protection against governance attacks
     * 
     * EXPECTED FIX: Implement timelock for threshold changes (24-48 hours)
     */

    // Ensure client is deployed before running POC tests
    beforeAll(() => {
      expect(client).toBeDefined();
      expect(appId).not.toEqual(0n);
    });

    // Reset threshold and clear any message state before each POC test
    beforeEach(async () => {
      await client.send.setThreshold({ sender: admin, args: [THRESHOLD] });
      await transceiverManagerClient.send.setMessageAttestations({ args: [THRESHOLD] });
    });

    // Clean up after each test
    afterEach(async () => {
      await client.send.setThreshold({ sender: admin, args: [THRESHOLD] });
      await transceiverManagerClient.send.setMessageAttestations({ args: [THRESHOLD] });
    });

    test("POC: Admin lowers threshold enabling execution with insufficient attestations", async () => {
      // ═══════════════════════════════════════════════════════════════════
      // STEP 1: Initial Setup - System has threshold=2
      // ═══════════════════════════════════════════════════════════════════
      const ORIGINAL_THRESHOLD = THRESHOLD;

      // Verify the system is configured with threshold=2
      const currentThreshold = await client.state.global.threshold();
      expect(currentThreshold).toEqual(ORIGINAL_THRESHOLD);

      console.log("\n🔐 Initial Security Configuration:");
      console.log(`   Threshold: ${ORIGINAL_THRESHOLD} attestations required`);
      console.log(`   Security Level: HIGH (requires 2 independent transceivers)`);

      // ═══════════════════════════════════════════════════════════════════
      // STEP 2: User sends a cross-chain message
      // ═══════════════════════════════════════════════════════════════════
      // User expects their message to require 2 attestations before execution
      const userMessage = getRandomMessageToSend({
        handlerAddress: getApplicationAddress(appId).publicKey
      });

      console.log("\n📨 User sends cross-chain message:");
      console.log(`   Message ID: ${Buffer.from(userMessage.id).toString("hex").substring(0, 16)}...`);
      console.log(`   Expected Security: 2 attestations required for execution`);
      console.log(`   User assumes: Message won't execute until 2 transceivers confirm`);

      // ═══════════════════════════════════════════════════════════════════
      // STEP 3: Only 1 transceiver attests (INSUFFICIENT under threshold=2)
      // ═══════════════════════════════════════════════════════════════════
      const INSUFFICIENT_ATTESTATIONS = 1n;

      // Create the message to be received
      const MESSAGE_RECEIVED = getMessageReceived(getRandomUInt(MAX_UINT16), userMessage);

      // Calculate the message digest (unique ID for replay protection)
      const USER_MESSAGE_DIGEST = calculateMessageDigest(MESSAGE_RECEIVED);

      // Set up the mock transceiver manager to return this digest
      await transceiverManagerClient.send.setMessageDigest({ args: [USER_MESSAGE_DIGEST] });

      // Only 1 transceiver attests (insufficient!)
      await transceiverManagerClient.send.setMessageAttestations({
        args: [INSUFFICIENT_ATTESTATIONS]
      });

      console.log("\n⚠️  Network Status:");
      console.log(`   Attestations received: ${INSUFFICIENT_ATTESTATIONS}`);
      console.log(`   Threshold required: ${ORIGINAL_THRESHOLD}`);
      console.log(`   Status: BLOCKED (insufficient attestations)`);

      // Verify the message is NOT approved with only 1 attestation
      const isApprovedBefore = await client.isMessageApproved({
        sender: user,
        args: [USER_MESSAGE_DIGEST],
        extraFee: (1000).microAlgos(),
      });
      expect(isApprovedBefore).toBeFalsy();

      console.log(`   ✅ Security working correctly: Message NOT APPROVED`);
      console.log(`   ✅ Message cannot be executed (would fail if attempted)`);

      // ═══════════════════════════════════════════════════════════════════      // ═══════════════════════════════════════════════════════════════════
      // STEP 4: ATTACK - Compromised admin lowers threshold (NO TIMELOCK!)
      // ═══════════════════════════════════════════════════════════════════
      const LOWERED_THRESHOLD = 1n;

      console.log("\n🚨 ATTACK BEGINS:");
      console.log(`   Compromised admin calls setThreshold(${LOWERED_THRESHOLD})`);
      console.log(`   NO TIMELOCK - Change is INSTANT!`);

      await client.send.setThreshold({
        sender: user,  // In real scenario, this would be the admin
        args: [LOWERED_THRESHOLD]
      });

      const newThreshold = await client.state.global.threshold();
      expect(newThreshold).toEqual(LOWERED_THRESHOLD);

      console.log(`   ✅ Threshold changed: ${ORIGINAL_THRESHOLD} → ${LOWERED_THRESHOLD}`);
      console.log(`   🚨 Security DOWNGRADED retroactively for in-flight messages!`);

      // ═══════════════════════════════════════════════════════════════════
      // STEP 5: Message now "approved" with only 1 attestation
      // ═══════════════════════════════════════════════════════════════════
      const isApprovedAfter = await client.isMessageApproved({
        sender: user,
        args: [USER_MESSAGE_DIGEST],
        extraFee: (1000).microAlgos(),
      });
      expect(isApprovedAfter).toBeTruthy();

      console.log("\n⚠️  Message Status After Threshold Change:");
      console.log(`   Attestations: ${INSUFFICIENT_ATTESTATIONS} (unchanged)`);
      console.log(`   New Threshold: ${LOWERED_THRESHOLD}`);
      console.log(`   Status: APPROVED ✅ (was blocked before!)`);

      // ═══════════════════════════════════════════════════════════════════
      // STEP 6: VULNERABILITY CONFIRMED - Message executes with 1 attestation
      // ═══════════════════════════════════════════════════════════════════
      const APP_MIN_BALANCE = (122_900).microAlgos();
      const fundingTxnAttack = await localnet.algorand.createTransaction.payment({
        sender: creator,
        receiver: getApplicationAddress(appId),
        amount: APP_MIN_BALANCE,
      });

      const attackResult = await client
        .newGroup()
        .addTransaction(fundingTxnAttack)
        .executeMessage({
          sender: user,
          args: [MESSAGE_RECEIVED],
          appReferences: [transceiverManagerAppId],
          boxReferences: [getMessagesExecutedBoxKey(USER_MESSAGE_DIGEST)],
          extraFee: (2000).microAlgos(),
        })
        .send();

      // Verify the message was executed successfully
      expect(attackResult.confirmations[1].logs![0]).toEqual(
        getEventBytes("HandledMessage(byte[32],byte[32])", [
          USER_MESSAGE_DIGEST,
          MESSAGE_RECEIVED.id
        ]),
      );
      expect(await client.isMessageExecuted({
        sender: user,
        args: [USER_MESSAGE_DIGEST]
      })).toBeTruthy();

      // ═══════════════════════════════════════════════════════════════════
      // ATTACK SUCCESS - Print Impact Analysis
      // ═══════════════════════════════════════════════════════════════════
      console.log("\n🚨 VULNERABILITY CONFIRMED - ATTACK SUCCESSFUL! 🚨");
      console.log("═".repeat(70));
      console.log("BEFORE ATTACK:");
      console.log(`  • User sent message expecting 2 attestations required`);
      console.log(`  • Only 1 transceiver attested`);
      console.log(`  • Message correctly BLOCKED (insufficient security)`);
      console.log("");
      console.log("AFTER ADMIN THRESHOLD CHANGE:");
      console.log(`  • Admin lowered threshold from 2 → 1 (INSTANT, NO TIMELOCK)`);
      console.log(`  • Same message now APPROVED with only 1 attestation`);
      console.log(`  • Message EXECUTED successfully`);
      console.log("═".repeat(70));
      console.log("IMPACT:");
      console.log(`  • User's message executed with HALF the expected security`);
      console.log(`  • No user consent for reduced security`);
      console.log(`  • Admin can retroactively weaken ALL in-flight messages`);
      console.log(`  • Enables governance attacks on cross-chain bridge`);
      console.log("═".repeat(70));
      console.log("ROOT CAUSE:");
      console.log(`  • No timelock on threshold changes`);
      console.log(`  • _set_threshold() executes instantly`);
      console.log(`  • In-flight messages retroactively affected`);
      console.log("═".repeat(70));
      console.log("\n");

      // ═══════════════════════════════════════════════════════════════════
      // Cleanup: Restore original threshold
      // ═══════════════════════════════════════════════════════════════════
      await client.send.setThreshold({ sender: user, args: [ORIGINAL_THRESHOLD] });
      expect(await client.state.global.threshold()).toEqual(ORIGINAL_THRESHOLD);
    });

    test("POC: Real-world attack scenario - Bridge with 4 transceivers", async () => {
      /**
       * More realistic scenario:
       * - Bridge has 4 transceivers (Wormhole, LayerZero, Axelar, Chainlink)
       * - Threshold set to 3 (requires 3/4 consensus)
       * - User sends $1M transfer expecting 3/4 security
       * - 2 transceivers attest (insufficient)
       * - Admin compromised, lowers threshold to 2
       * - $1M transfer executes with only 2/4 attestations
       */

      const HIGH_SECURITY_THRESHOLD = 3n;
      const COMPROMISED_THRESHOLD = 2n;
      const ACTUAL_ATTESTATIONS = 2n;

      console.log("\n🌉 Real-World Bridge Scenario:");
      console.log("═".repeat(70));
      console.log("Bridge Configuration:");
      console.log(`  • 4 Independent Transceivers: Wormhole, LayerZero, Axelar, Chainlink`);
      console.log(`  • Threshold: ${HIGH_SECURITY_THRESHOLD}/4 (75% consensus required)`);
      console.log(`  • This is considered HIGH security for cross-chain bridges`);
      console.log("");

      // Set high security threshold
      await client.send.setThreshold({ sender: admin, args: [HIGH_SECURITY_THRESHOLD] });
      expect(await client.state.global.threshold()).toEqual(HIGH_SECURITY_THRESHOLD);

      // User sends high-value transfer
      const highValueMessage = getRandomMessageToSend({
        handlerAddress: getApplicationAddress(appId).publicKey
      });

      console.log("💰 User Transaction:");
      console.log(`  • Transfer Amount: $1,000,000 USDC`);
      console.log(`  • Expected Security: 3/4 transceivers must attest`);
      console.log(`  • User confident: 75% consensus = safe`);
      console.log("");

      // Setup message digest
      const highValueReceived = getMessageReceived(getRandomUInt(MAX_UINT16), highValueMessage);
      const highValueDigest = calculateMessageDigest(highValueReceived);
      await transceiverManagerClient.send.setMessageDigest({ args: [highValueDigest] });

      // Only 2/4 transceivers attest
      await transceiverManagerClient.send.setMessageAttestations({
        args: [ACTUAL_ATTESTATIONS]
      });

      console.log("📡 Attestation Status:");
      console.log(`  • Wormhole: ✅ Attested`);
      console.log(`  • LayerZero: ✅ Attested`);
      console.log(`  • Axelar: ❌ Not attested`);
      console.log(`  • Chainlink: ❌ Not attested`);
      console.log(`  • Total: ${ACTUAL_ATTESTATIONS}/4 attestations`);
      console.log(`  • Required: ${HIGH_SECURITY_THRESHOLD}/4 attestations`);
      console.log(`  • Status: 🛑 BLOCKED (only 50% consensus, need 75%)`);
      console.log("");

      // Verify blocked
      expect(
        await client.isMessageApproved({
          sender: user,
          args: [highValueDigest],
          extraFee: (1000).microAlgos(),
        })
      ).toBeFalsy();

      // Admin key compromised (simulated by governance attack)
      console.log("🔓 SECURITY BREACH:");
      console.log(`  • Admin private key compromised / governance attack`);
      console.log(`  • Attacker calls setThreshold(${COMPROMISED_THRESHOLD})`);
      console.log(`  • NO TIMELOCK - Change is IMMEDIATE`);
      console.log("");

      await client.send.setThreshold({ sender: admin, args: [COMPROMISED_THRESHOLD] });

      console.log("⚠️  New Security Level:");
      console.log(`  • Threshold: ${HIGH_SECURITY_THRESHOLD}/4 → ${COMPROMISED_THRESHOLD}/4 (75% → 50%)`);
      console.log(`  • Message now approved with only 2/4 attestations`);
      console.log("");

      // Message now approved
      expect(
        await client.isMessageApproved({
          sender: user,
          args: [highValueDigest],
          extraFee: (1000).microAlgos(),
        })
      ).toBeTruthy();

      // Execute the message
      const fundingTxn = await localnet.algorand.createTransaction.payment({
        sender: creator,
        receiver: getApplicationAddress(appId),
        amount: (122_900).microAlgos(),
      });

      await client
        .newGroup()
        .addTransaction(fundingTxn)
        .executeMessage({
          sender: user,
          args: [highValueReceived],
          appReferences: [transceiverManagerAppId],
          boxReferences: [getMessagesExecutedBoxKey(highValueDigest)],
          extraFee: (2000).microAlgos(),
        })
        .send();

      console.log("💸 ATTACK RESULT:");
      console.log("═".repeat(70));
      console.log(`  • $1,000,000 transfer EXECUTED`);
      console.log(`  • Security used: 2/4 attestations (50% consensus)`);
      console.log(`  • Expected security: 3/4 attestations (75% consensus)`);
      console.log(`  • Security gap: 25% less consensus than user expected`);
      console.log("");
      console.log("FINANCIAL IMPACT:");
      console.log(`  • If 1 compromised transceiver: Could forge messages`);
      console.log(`  • If 2 colluding transceivers: Complete bridge control`);
      console.log(`  • Attack cost: Only need to compromise 50% instead of 75%`);
      console.log("═".repeat(70));
      console.log("\n");

      // Restore
      await client.send.setThreshold({ sender: admin, args: [THRESHOLD] });
    });
  });
});
