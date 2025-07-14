from algopy import Bytes, Global, GlobalState, TransactionType, UInt64, gtxn, itxn
from algopy.arc4 import Address, Bool, Struct, UInt16, UInt256, abi_call, abimethod, emit

from ...external.relayer.interfaces.IRelayer import DeliveryQuote, IRelayer
from ...external.relayer.interfaces.ICustomWormholeReceiver import ICustomWormholeReceiver
from ...types import ARC4UInt16, ARC4UInt64, ARC4UInt256, Bytes32


# Events
class QuoteDeliveryPrice(Struct):
    target_chain_id: ARC4UInt16
    receiver_value: ARC4UInt256
    gas_limit: ARC4UInt256

class RequestDelivery(Struct):
    source_contract: Address
    sequence: ARC4UInt64
    target_chain_id: ARC4UInt16
    target_address: Bytes32
    receiver_value: ARC4UInt256
    gas_limit: ARC4UInt256
    paid_amount: ARC4UInt64
    paid_in_native_token: Bool


class MockRelayer(IRelayer):
    def __init__(self) -> None:
        self.folks_id = GlobalState(UInt64)
        self.native_price_quote = GlobalState(UInt64)
        self.token_price_quote = GlobalState(UInt64)

    @abimethod(create="require")
    def create(self, folks_id: UInt64, native_price_quote: UInt64, token_price_quote: UInt64) -> None:
        self.folks_id.value = folks_id
        self.native_price_quote.value = native_price_quote
        self.token_price_quote.value = token_price_quote

    @abimethod
    def opt_into_folks(self) -> None:
        itxn.AssetTransfer(
            xfer_asset=self.folks_id.value,
            asset_receiver=Global.current_application_address,
            asset_amount=0,
            fee=0,
        ).submit()

    @abimethod
    def quote_delivery_price(self, target_chain: UInt16, receiver_value: UInt256, gas_limit: UInt256) -> DeliveryQuote:
        emit(QuoteDeliveryPrice(target_chain, receiver_value, gas_limit))
        return DeliveryQuote(ARC4UInt64(self.native_price_quote.value), ARC4UInt64(self.token_price_quote.value))

    @abimethod
    def request_delivery(
        self,
        fee_payment: gtxn.Transaction,
        source_contract: Address,
        sequence: UInt64,
        target_chain: UInt16,
        target_address: Bytes32,
        receiver_value: UInt256,
        gas_limit: UInt256,
        pay_in_native_token: Bool,
    ) -> None:
        paid_amount = fee_payment.amount if fee_payment.type == TransactionType.Payment else fee_payment.asset_amount
        emit(RequestDelivery(
            source_contract,
            ARC4UInt64(sequence),
            target_chain,
            target_address,
            receiver_value,
            gas_limit,
            ARC4UInt64(paid_amount),
            pay_in_native_token
        ))

    @abimethod
    def deliver_message( # type: ignore[override]
        self,
        payload: Bytes,
        emitter_chain_id: UInt16,
        emitter_address: Bytes32,
        vaa_digest: Bytes32,
        target_app_id: UInt64
    ) -> None:
        abi_call(
            ICustomWormholeReceiver.receive_wormhole_message,
            payload,
            emitter_chain_id,
            emitter_address,
            vaa_digest,
            app_id=target_app_id,
            fee=0,
        )
