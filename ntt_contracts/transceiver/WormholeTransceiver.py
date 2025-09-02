from algopy import Account, BoxMap, Bytes, GlobalState, Global, OnCompleteAction, String, UInt64, itxn, gtxn, op, subroutine
from algopy.arc4 import Address, Bool, Struct, UInt16, abimethod, emit

from folks_contracts.library.extensions.InitialisableWithCreator import InitialisableWithCreator
from ..types import Bytes16, Bytes32, MessageReceived, MessageToSend
from .Transceiver import Transceiver


# Constants
WH_TRANSCEIVER_PAYLOAD_PREFIX = "9945FF10"


# Events
class WormholePeerSet(Struct):
    peer_chain_id: UInt16
    peer_contract_address: Bytes32

class ReceivedMessage(Struct):
    vaa_digest: Bytes32
    message_id: Bytes32


class WormholeTransceiver(Transceiver, InitialisableWithCreator):
    """Transceiver implementation for Wormhole.

    This contract is responsible for sending and receiving NTT messages that are authenticated through Wormhole Core.

    The messages can be delivered either manually or via a (custom) relayer. There is built in replay protection which
    prevents the same message from being delivered multiple times.
    """
    def __init__(self) -> None:
        Transceiver.__init__(self)
        InitialisableWithCreator.__init__(self)

        # wormhole source chain constants
        self.wormhole_core = GlobalState(UInt64)
        self.chain_id = GlobalState(UInt64)
        self.emitter_lsig = GlobalState(Address)

        # messaging
        self.wormhole_peers = BoxMap(UInt16, Bytes32, key_prefix=b"wormhole_peer_")
        self.vaas_consumed = BoxMap(Bytes32, Bool, key_prefix=b"vaas_consumed_")

    @abimethod(create="require")
    def create( # type: ignore[override]
        self,
        transceiver_manager: UInt64,
        wormhole_core: UInt64,
        chain_id: UInt64,
        min_upgrade_delay: UInt64
    ) -> None:
        Transceiver.create(self, transceiver_manager, min_upgrade_delay)

        self.wormhole_core.value = wormhole_core
        self.chain_id.value = chain_id
        self.emitter_lsig.value = self._calculate_emitter_lsig()

    @abimethod
    def initialise(self, admin: Address) -> None: # type: ignore[override]
        # check caller is contract creator
        InitialisableWithCreator.initialise(self)

        self._grant_role(self.default_admin_role(), admin)
        self._grant_role(self.upgradable_admin_role(), admin)
        self._grant_role(self.manager_role(), admin)

    @abimethod(readonly=True)
    def get_transceiver_type(self) -> String:
        return String("wormhole")

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
        # IMPORTANT: must verify the recipient chain in the concrete MessageHandler
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

        # quote comprised of only core fee
        return self._get_wormhole_core_message_fee()

    @subroutine
    def _send_message(self, total_fee: UInt64, message: MessageToSend, transceiver_instruction: Bytes) -> None:
        self._only_initialised()

        # check whether peer chain is registered
        self.get_wormhole_peer(message.destination_chain_id)

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
