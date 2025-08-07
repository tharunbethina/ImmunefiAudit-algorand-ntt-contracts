from abc import ABC, abstractmethod
from algopy import ARC4Contract, Bytes
from algopy.arc4 import UInt16, abimethod

from ..types import Bytes32


class ICustomWormholeReceiver(ARC4Contract, ABC):
    @abstractmethod
    @abimethod
    def receive_wormhole_message(
        self,
        payload: Bytes,
        emitter_chain_id: UInt16,
        emitter_address: Bytes32,
        vaa_digest: Bytes32,
    ) -> None:
        """The method to override to receive a wormhole message.

        Args:
            payload: The VAA payload
            emitter_chain_id: The chain where the VAA was emitted from
            emitter_address: The address where the VAA was emitted from
            vaa_digest: Unique identifier for VAA (also known as "delivery_hash")
        """
        pass
