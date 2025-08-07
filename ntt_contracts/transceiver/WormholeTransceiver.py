from algopy import Account, BoxMap, Bytes, GlobalState, Global, OnCompleteAction, Txn, UInt64, itxn, gtxn, op, subroutine
from algopy.arc4 import Address, Bool, Struct, UInt16, abi_call, abimethod, emit

from folks_contracts.library.extensions.InitialisableWithCreator import InitialisableWithCreator
from ..external.relayer.interfaces.IRelayer import IRelayer
from ..external.relayer.interfaces.ICustomWormholeReceiver import ICustomWormholeReceiver
from ..types import Bytes16, Bytes32, MessageReceived, MessageToSend
from .Transceiver import Transceiver


# Constants
WH_TRANSCEIVER_PAYLOAD_PREFIX = "9945FF10"


# Structs
class WormholeTransceiverInstruction(Struct):
    should_skip_relayer_send: Bool


# Events
class WormholePeerSet(Struct):
    peer_chain_id: UInt16
    peer_contract_address: Bytes32

class ReceivedMessage(Struct):
    vaa_digest: Bytes32
    message_id: Bytes32


class WormholeTransceiver(Transceiver, ICustomWormholeReceiver, InitialisableWithCreator):
    """Transceiver implementation for Wormhole.

    This contract is responsible for sending and receiving NTT messages that are authenticated through Wormhole Core.

    The messages can be delivered either manually or via a (custom) relayer. There is built in replay protection which
    prevents the same message from being delivered multiple times.
    """
    def __init__(self) -> None:
        Transceiver.__init__(self)
        InitialisableWithCreator.__init__(self)

        self.wormhole_core = GlobalState(UInt64)
        self.wormhole_relayer = GlobalState(UInt64)
        self.chain_id = GlobalState(UInt64)
        self.emitter_lsig = GlobalState(Address)
        self.relayer_default_gas_limit = GlobalState(UInt64)

        self.wormhole_peers = BoxMap(UInt16, Bytes32, key_prefix=b"wormhole_peer_")
        self.vaas_consumed = BoxMap(Bytes32, Bool, key_prefix=b"vaas_consumed_")

    @abimethod(create="require")
    def create( # type: ignore[override]
        self,
        transceiver_manager: UInt64,
        wormhole_core: UInt64,
        wormhole_relayer: UInt64,
        chain_id: UInt64,
        min_upgrade_delay: UInt64
    ) -> None:
        Transceiver.create(self, transceiver_manager, min_upgrade_delay)
        self.wormhole_core.value = wormhole_core
        self.wormhole_relayer.value = wormhole_relayer
        self.chain_id.value = chain_id
        self.emitter_lsig.value = self._calculate_emitter_lsig()

    @abimethod
    def initialise(self, admin: Address) -> None: # type: ignore[override]
        # check caller is contract creator
        InitialisableWithCreator.initialise(self)

        self._grant_role(self.default_admin_role(), admin)
        self._grant_role(self.upgradable_admin_role(), admin)
        self._grant_role(self.manager_role(), admin)

    @abimethod
    def set_wormhole_relayer(self, wormhole_relayer: UInt64) -> None:
        """Set the (custom) relayer to use.

         Args:
             wormhole_relayer: The new relayer application id
         """
        self._only_initialised()
        self._check_sender_role(self.manager_role())

        self.wormhole_relayer.value = wormhole_relayer

    @abimethod
    def set_relayer_default_gas_limit(self, gas_limit: UInt64) -> None:
        """Set the default gas limit to use for messages sent with the (custom) relayer.

         Args:
             gas_limit: The new default gas limit
         """
        self._only_initialised()
        self._check_sender_role(self.manager_role())

        self.relayer_default_gas_limit.value = gas_limit

    @abimethod
    def set_wormhole_peer(self, peer_chain_id: UInt16, peer_contract_address: Bytes32) -> None:
        """Set the WormholeTransceiver on a peer chain, overriding if needed.

         Args:
             peer_chain_id: The peer chain to set
             peer_contract_address: The peer contract address
         """
        self._only_initialised()
        self._check_sender_role(self.manager_role())

        # set peer (overriding if needed)
        self.wormhole_peers[peer_chain_id] = peer_contract_address.copy()
        emit(WormholePeerSet(peer_chain_id, peer_contract_address))

    @abimethod
    def receive_message(self, verify_vaa: gtxn.ApplicationCallTransaction) -> None:
        """Receive a Wormhole message directly with manual delivery.

        Args:
            verify_vaa: The call to Wormhole call to verify the VAA
        """
        self._only_initialised()

        # check message has been verified
        assert verify_vaa.app_id.id == self.wormhole_core.value, "Unknown wormhole core"
        assert verify_vaa.on_completion == OnCompleteAction.NoOp, "Incorrect app on completion"
        assert verify_vaa.app_args(0) == Bytes(b"verifyVAA"), "Incorrect method"

        # header
        index = UInt64(5) # skip version and guardian_set_index
        num_sigs = op.btoi(op.extract(verify_vaa.app_args(1), 5, 1))
        index += 1 + num_sigs * 66 # skip signatures

        # body
        vaa_digest = Bytes32.from_bytes(
            op.keccak256(op.keccak256(op.substring(verify_vaa.app_args(1), index, verify_vaa.app_args(1).length)))
        )
        index += 8 # skip timestamp and nonce
        emitter_chain_id = UInt16(op.extract_uint16(verify_vaa.app_args(1), index))
        index += 2
        emitter_address = Bytes32.from_bytes(op.extract(verify_vaa.app_args(1), index, 32))
        index += 41 # skip sequence and consistency_level
        payload = op.substring(verify_vaa.app_args(1), index, verify_vaa.app_args(1).length)

        # decode payload, check emitter is known, prevent replays and forward to handler
        self._receive_message(payload, emitter_chain_id, emitter_address, vaa_digest)

    @abimethod
    def receive_wormhole_message(
        self,
        payload: Bytes,
        emitter_chain_id: UInt16,
        emitter_address: Bytes32,
        vaa_digest: Bytes32,
    ) -> None:
        """Receive a Wormhole message from relayer with automatic delivery.

        Relies on the relayer for verifying the VAA is valid.

        Args:
            payload: The VAA payload
            emitter_chain_id: The chain where the VAA was emitted from
            emitter_address: The address where the VAA was emitted from
            vaa_digest: Unique identifier for VAA (also known as "delivery_hash")
        """
        self._only_initialised()
        self._only_relayer()

        # decode payload, check emitter is known, prevent replays and forward to handler
        self._receive_message(payload, emitter_chain_id, emitter_address, vaa_digest)

    @abimethod(readonly=True)
    def manager_role(self) -> Bytes16:
        return Bytes16.from_bytes(op.extract(op.keccak256(b"MANAGER"), 0, 16))

    @abimethod(readonly=True)
    def get_wormhole_peer(self, peer_chain_id: UInt16) -> Bytes32:
        """Get the address of the peer WormholeTransceiver set on a given chain.

        Args:
             peer_chain_id: The peer chain to get the address of
        """
        assert peer_chain_id in self.wormhole_peers, "Unknown peer chain"
        return self.wormhole_peers[peer_chain_id]

    @subroutine
    def _receive_message(
        self,
        payload: Bytes,
        emitter_chain_id: UInt16,
        emitter_address: Bytes32,
        vaa_digest: Bytes32,
    ) -> None:
        index = UInt64(0)
        assert Bytes.from_hex(WH_TRANSCEIVER_PAYLOAD_PREFIX) == op.extract(payload, index, 4), "Incorrect prefix"
        index += 4
        source_address = Bytes32.from_bytes(op.extract(payload, index, 32))
        index += 32
        handler_address = Bytes32.from_bytes(op.extract(payload, index, 32))
        index += 32
        handler_payload_length = op.extract_uint16(payload, index)
        index += 2
        handler_payload = op.substring(payload, index, index + handler_payload_length)
        # transceiver_payload_length and transceiver_payload are ignored

        # check message comes from peer
        assert emitter_address == self.get_wormhole_peer(emitter_chain_id), "Emitter address mismatch"

        # save the vaa digest in storage to protect against replay attacks
        self._set_vaa_consumed(vaa_digest)

        # parse handler payload
        index = UInt64(0)
        message_id = Bytes32.from_bytes(op.extract(handler_payload, index, 32))
        index += 32
        message_user_address = Bytes32.from_bytes(op.extract(handler_payload, index, 32))
        index += 32
        message_payload = op.substring(handler_payload, index, handler_payload.length)

        # deliver message to TransceiverManager
        # NEED TO VERIFY RECIPIENT CHAIN IN HANDLER
        self._deliver_message(MessageReceived(
            id=message_id,
            user_address=message_user_address,
            source_chain_id=emitter_chain_id,
            source_address=source_address,
            handler_address=handler_address,
            payload=message_payload,
        ))

        # emit event
        emit(ReceivedMessage(vaa_digest, message_id))

    @subroutine
    def _quote_delivery_price(self, message: MessageToSend, transceiver_instruction: Bytes) -> UInt64:
        # check whether peer chain is registered
        self.get_wormhole_peer(message.destination_chain_id)

        # quote comprised of core fee and relayer cost
        core_fee = self._get_wormhole_core_message_fee()

        # determine whether relayer fee is included
        we_ins = self._parse_transceiver_instruction(transceiver_instruction)
        if we_ins.should_skip_relayer_send:
            return core_fee
        else:
            relayer_fee, txn = abi_call(
                IRelayer.quote_delivery_price,
                message.destination_chain_id,
                0, # receiver value
                self.relayer_default_gas_limit.value,
                app_id=self.wormhole_relayer.value,
                fee=0,
            )
            return core_fee + relayer_fee.native_price_quote.native

    @subroutine
    def _send_message(self, total_fee: UInt64, message: MessageToSend, transceiver_instruction: Bytes) -> None:
        self._only_initialised()

        # check whether peer chain is registered
        peer_address = self.get_wormhole_peer(message.destination_chain_id)

        # transceiver_instruction is ignored, when automatic relayer is supported
        # it could be used to signal the relay approach (automatic/manual)
        handler_payload = message.id.bytes + message.user_address.bytes + message.payload
        payload = (
            Bytes.from_hex(WH_TRANSCEIVER_PAYLOAD_PREFIX) +
            message.source_address.bytes +
            message.handler_address.bytes +
            UInt16(handler_payload.length).bytes +
            handler_payload +
            UInt16(0).bytes # transceiver payload empty
        )

        # publish message
        wormhole_core_address, exists = op.AppParamsGet.app_address(self.wormhole_core.value)
        assert exists, "Wormhole Core address unknown"

        core_fee = self._get_wormhole_core_message_fee()
        payment = itxn.Payment(receiver=wormhole_core_address, amount=core_fee, fee=0)
        app_call = itxn.ApplicationCall(
            app_id=self.wormhole_core.value,
            app_args=(Bytes(b"publishMessage"), payload, op.itob(0)),
            accounts=(Account(self.emitter_lsig.value.bytes),),
            fee=0,
        )
        itxn.submit_txns(payment, app_call)

        # request message delivery if needed
        we_ins = self._parse_transceiver_instruction(transceiver_instruction)
        if not we_ins.should_skip_relayer_send:
            sequence = self._get_wormhole_emitter_sequence()
            payment = itxn.Payment(receiver=self._get_wormhole_relayer_address(), amount=total_fee - core_fee, fee=0)
            abi_call(
                IRelayer.request_delivery,
                payment,
                Address(Global.current_application_address),
                sequence,
                message.destination_chain_id,
                peer_address,
                0, # receiver value
                self.relayer_default_gas_limit.value,
                True, # pay in native token
                app_id=self.wormhole_relayer.value,
                fee=0,
            )

    @subroutine
    def _parse_transceiver_instruction(self, transceiver_instruction: Bytes) -> WormholeTransceiverInstruction:
        # default use relayer if empty instruction
        should_skip_relayer_send = (
            (transceiver_instruction.length > 0) and
            bool(op.btoi(op.extract(transceiver_instruction, 0, 1)))
        )
        return WormholeTransceiverInstruction(Bool(should_skip_relayer_send))

    @subroutine
    def _get_wormhole_core_message_fee(self) -> UInt64:
        message_fee, exists = op.AppGlobal.get_ex_uint64(self.wormhole_core.value, Bytes(b"MessageFee"))
        assert exists, "Wormhole message fee is unknown"
        return message_fee

    @subroutine
    def _get_wormhole_emitter_sequence(self) -> UInt64:
        sequence, exists = op.AppLocal.get_ex_bytes(
            Account(self.emitter_lsig.value.bytes),
            self.wormhole_core.value,
            Bytes.from_hex("00")
        )
        assert exists, "Sequence is unknown"
        return op.extract_uint64(sequence, 0)

    @subroutine
    def _get_wormhole_relayer_address(self) -> Account:
        wormhole_relayer_address, exists = op.AppParamsGet.app_address(self.wormhole_relayer.value)
        assert exists, "Wormhole Relayer address unknown"
        return wormhole_relayer_address

    @subroutine
    def _only_relayer(self) -> None:
        assert Txn.sender == self._get_wormhole_relayer_address(), "Caller must be relayer"

    @subroutine
    def _set_vaa_consumed(self, vaa_digest: Bytes32) -> None:
        assert not (Bool(vaa_digest in self.vaas_consumed) and self.vaas_consumed[vaa_digest]), "VAA already seen"
        self.vaas_consumed[vaa_digest] = Bool(True)

    @subroutine
    def _calculate_emitter_lsig(self) -> Address:
        wormhole_core_address, exists = op.AppParamsGet.app_address(self.wormhole_core.value)
        assert exists, "WormholeCore address unknown"

        return Address.from_bytes(op.sha512_256(
            Bytes(b"Program") +
            Bytes.from_hex("062001018100488020") +  # hardcoded TMPL_ADDR_IDX as 0, suffix 20 is length of below bytes
            Global.current_application_address.bytes +  # TMPL_EMITTER_ID
            Bytes.from_hex("483110810612443119221244311881") +
            self._encode_uvarint(self.wormhole_core.value) +  # TMPL_APP_ID
            Bytes.from_hex("124431208020") +  # suffix 20 is length of below bytes
            wormhole_core_address.bytes +  # TMPL_APP_ADDRESS
            Bytes.from_hex("124431018100124431093203124431153203124422")
        ))

    @subroutine
    def _encode_uvarint(self, val: UInt64) -> Bytes:
        return self._encode_uvarint_helper(val, Bytes(b""))

    @subroutine
    def _encode_uvarint_helper(self, val: UInt64, b: Bytes) -> Bytes:
        return b + (
            self._encode_uvarint_helper(
                val >> 7,
                op.extract(op.itob((val & 255) | 128), 7, 1)
            ) if val >= 128 else op.extract(op.itob(val & 255), 7, 1)
        )
