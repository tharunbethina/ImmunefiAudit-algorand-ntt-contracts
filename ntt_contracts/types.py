from algopy import Bytes, UInt64
from algopy.arc4 import (
    Byte,
    DynamicArray,
    DynamicBytes,
    StaticArray,
    Struct,
    UInt8 as ARC4UInt8,
    UInt16 as ARC4UInt16,
    UInt64 as ARC4UInt64,
    UInt256 as ARC4UInt256,
)
from typing import Literal, NamedTuple, TypeAlias

Bytes8: TypeAlias = StaticArray[Byte, Literal[8]]
Bytes16: TypeAlias = StaticArray[Byte, Literal[16]]
Bytes32: TypeAlias = StaticArray[Byte, Literal[32]]

class TrimmedAmount(Struct, frozen=True):
    amount: ARC4UInt64
    decimals: ARC4UInt8

class TransceiverInstruction(Struct, frozen=True):
    transceiver: ARC4UInt64
    instruction: DynamicBytes

TransceiverInstructions: TypeAlias = DynamicArray[TransceiverInstruction]

class MessageToSend(NamedTuple):
    id: Bytes32 # user defined so no guarantees - used to group messages from different transceivers
    user_address: Bytes32
    source_address: Bytes32
    destination_chain_id: ARC4UInt16
    handler_address: Bytes32
    payload: Bytes

class MessageReceived(NamedTuple):
    id: Bytes32 # user defined so no guarantees - used to group messages from different transceivers
    user_address: Bytes32
    source_chain_id: ARC4UInt16
    source_address: Bytes32
    handler_address: Bytes32
    payload: Bytes
