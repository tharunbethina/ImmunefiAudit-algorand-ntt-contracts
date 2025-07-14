from algopy import BoxMap, Global, Txn, UInt64, gtxn, itxn, op, subroutine, uenumerate
from algopy.arc4 import Address, Bool, DynamicArray, DynamicBytes, Struct, UInt256, abi_call, abimethod, emit

from folks_contracts.library import UInt64SetLib
from folks_contracts.library.AccessControl import AccessControl
from ..library import MathLib
from ..types import ARC4UInt64, Bytes16, Bytes32, TransceiverInstructions, MessageToSend, MessageReceived
from .interfaces.ITransceiver import ITransceiver
from .interfaces.ITransceiverManager import (
    ITransceiverManager,
    MessageHandlerAdded,
    TransceiverAdded,
    TransceiverRemoved,
    MessageSent,
    AttestationReceived,
)


# Structs
class TransceiverAttestationKey(Struct):
    message_digest: Bytes32
    transceiver: ARC4UInt64 # app id


class TransceiverManager(ITransceiverManager, AccessControl):
    def __init__(self) -> None:
        AccessControl.__init__(self)

        self.max_transceivers = UInt64(32)

        # message handler -> configured transceivers
        self.handler_transceivers = BoxMap(UInt64, DynamicArray[ARC4UInt64], key_prefix=b"handler_transceivers_")

        # (message digest, transceiver) -> whether transceiver has attested to message
        self.transceiver_attestations = BoxMap(TransceiverAttestationKey, Bool, key_prefix=b"attestations_")
        # message digest -> number of attestations for message
        self.num_attestations = BoxMap(Bytes32, UInt64, key_prefix=b"num_attestations_")

    @abimethod
    def add_message_handler(self, message_handler_admin: Address) -> Bool:
        # check caller is new message handler
        message_handler = Global.caller_application_id
        assert message_handler, "Caller must be an application"

        # do nothing if already added
        if self.is_message_handler_known(message_handler):
            return Bool(False)

        # grant admin role and make itself its own admin
        role = self.message_handler_admin_role(message_handler)
        self._grant_role(role, message_handler_admin)
        self._set_role_admin(role, role.copy())

        # add message handler
        self.handler_transceivers[message_handler] = DynamicArray[ARC4UInt64]()
        emit(MessageHandlerAdded(ARC4UInt64(message_handler), message_handler_admin))
        return Bool(True)

    @abimethod
    def add_transceiver(self, message_handler: UInt64, transceiver: UInt64) -> None:
        self._check_message_handler_known(message_handler)
        self._check_sender_role(self.message_handler_admin_role(message_handler))

        # ensure not going above maximum
        old_transceivers = self.handler_transceivers[message_handler].copy()
        assert old_transceivers.length < self.max_transceivers, "Maximum transceivers exceeded"

        # ensure transceiver not already added
        was_added, new_transceivers = UInt64SetLib.add_item(transceiver, old_transceivers)
        assert was_added, "Transceiver was already added"

        # add transceiver
        self.handler_transceivers[message_handler] = new_transceivers.copy()
        emit(TransceiverAdded(ARC4UInt64(message_handler), ARC4UInt64(transceiver)))

    @abimethod
    def remove_transceiver(self, message_handler: UInt64, transceiver: UInt64) -> None:
        self._check_message_handler_known(message_handler)
        self._check_sender_role(self.message_handler_admin_role(message_handler))

        # ensure transceiver was added
        old_transceivers = self.handler_transceivers[message_handler].copy()
        was_removed, new_transceivers = UInt64SetLib.remove_item(transceiver, old_transceivers)
        assert was_removed, "Transceiver was not added"

        # remove transceiver
        self.handler_transceivers[message_handler] = new_transceivers.copy()
        emit(TransceiverRemoved(ARC4UInt64(message_handler), ARC4UInt64(transceiver)))

    @abimethod(readonly=True)
    def get_handler_transceivers(self, message_handler: UInt64) -> DynamicArray[ARC4UInt64]:
        self._check_message_handler_known(message_handler)
        return self.handler_transceivers[message_handler]

    @abimethod(readonly=True)
    def quote_delivery_prices(
        self,
        message_handler: UInt64,
        message: MessageToSend,
        transceiver_instructions: TransceiverInstructions,
    ) -> UInt64:
        self._check_message_handler_known(message_handler)

        # get total delivery quote without sending message
        return self._quote_and_maybe_send_message(message_handler, message, transceiver_instructions, Bool(False))

    @abimethod
    def send_message_to_transceivers(
        self,
        fee_payment: gtxn.PaymentTransaction,
        message: MessageToSend,
        transceiver_instructions: TransceiverInstructions,
    ) -> None:
        # check message handler caller
        message_handler = Global.caller_application_id
        assert message_handler, "Caller must be an application"
        self._check_message_handler_known(message_handler)

        # check message source address matches caller
        assert message.source_address == Bytes32.from_bytes(Txn.sender.bytes), "Unexpected message source address"

        # get total delivery quote and send message through each transceiver
        total_delivery_price = self._quote_and_maybe_send_message(
            message_handler,
            message,
            transceiver_instructions,
            Bool(True)
        )

        # check payment
        assert fee_payment.receiver == Global.current_application_address, "Unknown fee payment receiver"
        assert fee_payment.amount == total_delivery_price, "Incorrect fee payment"

    @abimethod
    def attestation_received(self, message: MessageReceived) -> None:
        # check caller is configured transceiver for message handler
        transceiver = Global.caller_application_id
        assert transceiver, "Caller must be an application"
        message_handler = MathLib.safe_cast_uint256_to_uint64(UInt256.from_bytes(message.handler_address.bytes))
        self._check_message_handler_known(message_handler)
        self._check_transceiver_configured(message_handler, transceiver)

        # calculate message digest and retrieve number of attestations
        message_digest = self.calculate_message_digest(message)
        num_attestations = self.message_attestations(message_digest)

        # protect against replay attacks
        assert not self.has_transceiver_attested(message_digest, transceiver), "Attestation already received"
        transceiver_attestation_key = self._transceiver_attestation_key(message_digest, transceiver)
        self.transceiver_attestations[transceiver_attestation_key] = Bool(True)

        # increment number of attestations received
        new_num_attestations = num_attestations + 1
        self.num_attestations[message_digest] = new_num_attestations
        emit(AttestationReceived(
            message.id,
            message.source_chain_id,
            message.source_address,
            ARC4UInt64(message_handler),
            message_digest,
            ARC4UInt64(new_num_attestations))
        )

    @abimethod(readonly=True)
    def message_attestations(self, message_digest: Bytes32) -> UInt64:
        return self.num_attestations[message_digest] if message_digest in self.num_attestations else UInt64(0)

    @abimethod(readonly=True)
    def has_transceiver_attested(self, message_digest: Bytes32, transceiver: UInt64) -> Bool:
        transceiver_attestation_key = self._transceiver_attestation_key(message_digest, transceiver)
        return Bool(transceiver_attestation_key in self.transceiver_attestations) and self.transceiver_attestations[transceiver_attestation_key]

    @abimethod(readonly=True)
    def calculate_message_digest(self, message: MessageReceived) -> Bytes32:
        return Bytes32.from_bytes(op.keccak256(
            message.id.bytes +
            message.user_address.bytes +
            message.source_chain_id.bytes +
            message.source_address.bytes +
            message.handler_address.bytes +
            message.payload
        ))

    @abimethod(readonly=True)
    def message_handler_admin_role(self, message_handler: UInt64) -> Bytes16:
        """Returns the role identifier for the given message handler's admin role

        Args:
            message_handler (UInt64): The message handler app id

        Returns:
            Role bytes of length 16
        """
        name = b"MESSAGE_HANDLER_ADMIN_" + op.itob(message_handler)
        return Bytes16.from_bytes(op.extract(op.keccak256(name), 0, 16))

    @abimethod(readonly=True)
    def is_message_handler_known(self, message_handler: UInt64) -> Bool:
        return Bool(message_handler in self.handler_transceivers)

    @abimethod(readonly=True)
    def is_transceiver_configured(self, message_handler: UInt64, transceiver: UInt64) -> Bool:
        self._check_message_handler_known(message_handler)
        return UInt64SetLib.has_item(transceiver, self.handler_transceivers[message_handler].copy())

    @subroutine
    def _transceiver_attestation_key(self, message_digest: Bytes32, transceiver: UInt64) -> TransceiverAttestationKey:
        return TransceiverAttestationKey(message_digest.copy(), ARC4UInt64(transceiver))

    @subroutine
    def _check_message_handler_known(self, message_handler: UInt64) -> None:
        assert self.is_message_handler_known(message_handler), "Message handler unknown"

    @subroutine
    def _check_transceiver_configured(self, message_handler: UInt64, transceiver: UInt64) -> None:
        assert self.is_transceiver_configured(message_handler, transceiver), "Transceiver not configured"

    @subroutine(inline=False)
    def _quote_and_maybe_send_message(
        self,
        message_handler: UInt64,
        message: MessageToSend,
        transceiver_instructions: TransceiverInstructions,
        should_send: Bool
    ) -> UInt64:
        total_delivery_price = UInt64(0)

        # must have at least 1 transceiver
        transceivers = self.handler_transceivers[message_handler].copy()
        assert transceivers.length, "Message handler has zero transceivers"

        # iterate through each transceiver, getting quote and possibly sending
        index_into_transceiver_instructions = UInt64(0)
        for idx, transceiver in uenumerate(transceivers):
            # the instructions passed need to be in same order as configured transceivers array
            instruction = DynamicBytes()
            if index_into_transceiver_instructions < transceiver_instructions.length:
                transceiver_instruction = transceiver_instructions[index_into_transceiver_instructions].copy()
                if transceiver_instruction.transceiver == transceiver:
                    instruction = transceiver_instruction.instruction.copy()
                    index_into_transceiver_instructions += 1

            # quote delivery price
            delivery_price, txn = abi_call(
                ITransceiver.quote_delivery_price,
                message,
                instruction,
                app_id=transceiver.native,
                fee=0,
            )
            total_delivery_price += delivery_price

            # if specified, send message
            if should_send:
                transceiver_address, exists = op.AppParamsGet.app_address(transceiver.native)
                assert exists, "Transceiver address unknown"
                abi_call(
                    ITransceiver.send_message,
                    itxn.Payment(amount=delivery_price, receiver=transceiver_address, fee=0),
                    message,
                    instruction,
                    app_id=transceiver.native,
                    fee=0,
                )
                emit(MessageSent(ARC4UInt64(message_handler), transceiver, message.id))

        # ensure entire transceiver instructions consumed
        assert index_into_transceiver_instructions == transceiver_instructions.length, "Incorrect order or unknown transceiver in instructions"

        return total_delivery_price
