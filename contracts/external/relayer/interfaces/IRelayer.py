from abc import ABC, abstractmethod
from algopy import ARC4Contract, UInt64, gtxn
from algopy.arc4 import Address, Bool, Struct, UInt16, UInt256, abimethod

from ..types import ARC4UInt64, Bytes32


# Structs
class DeliveryQuote(Struct, frozen=True):
    native_price_quote: ARC4UInt64 # quote in ALGO
    token_price_quote: ARC4UInt64 # quote in token (e.g. Wormhole W)


class IRelayer(ARC4Contract, ABC):
    @abstractmethod
    @abimethod
    def quote_delivery_price(self, target_chain: UInt16, receiver_value: UInt256, gas_limit: UInt256) -> DeliveryQuote:
        pass

    @abstractmethod
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
        pass

    @abstractmethod
    @abimethod
    def deliver_message(self, verify_vaa: gtxn.ApplicationCallTransaction, target_app_id: UInt64) -> None:
        pass
