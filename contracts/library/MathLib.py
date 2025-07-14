from algopy import UInt64, op, subroutine
from algopy.arc4 import UInt8, UInt256

max_uint64_hex = 0xFFFFFFFFFFFFFFFF

@subroutine
def safe_cast_uint256_to_uint64(a: UInt256) -> UInt64:
    assert a <= UInt256(max_uint64_hex), "Cannot cast uint256 to uint64"
    return op.extract_uint64(a.native.bytes, 24)

@subroutine
def max_uint8(a: UInt8, b: UInt8) -> UInt8:
    return a if a > b else b

@subroutine
def min_uint8(a: UInt8, b: UInt8) -> UInt8:
    return a if a < b else b

@subroutine
def max_uint64(a: UInt64, b: UInt64) -> UInt64:
    return a if a > b else b

@subroutine
def min_uint64(a: UInt64, b: UInt64) -> UInt64:
    return a if a < b else b
