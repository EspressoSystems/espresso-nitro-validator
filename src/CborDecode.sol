// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {LibBytes} from "./LibBytes.sol";

type CborElement is uint256;

// Major types
uint8 constant TYPE_MAJOR_MASK = 0xe0; // first 3 bits
uint8 constant TYPE_UNSIGNED_INTEGER = 0x00;
uint8 constant TYPE_NEGATIVE_INTEGER = 0x20;
uint8 constant TYPE_BYTE_STRING = 0x40;
uint8 constant TYPE_TEXT_STRING = 0x60;
uint8 constant TYPE_ARRAY = 0x80;
uint8 constant TYPE_MAP = 0xa0;
uint8 constant TYPE_TAG = 0xc0;
uint8 constant TYPE_SIMPLE_OR_FLOAT = 0xe0;
// Signals parser that we don't expect a concrete type
uint8 constant TYPE_ANY = 0xff;

// Additional information
uint8 constant ADDITIONAL_INFO_MASK = 0x1f; // last 5 bits
uint8 constant ADDITIONAL_INFO_1BYTE = 0x18;
uint8 constant ADDITIONAL_INFO_2BYTES = 0x19;
uint8 constant ADDITIONAL_INFO_4BYTES = 0x1a;
uint8 constant ADDITIONAL_INFO_8BYTES = 0x1b;
uint8 constant ADDITIONAL_INFO_INDEFINITE = 0x1f;

library LibCborElement {
    // Cbor element type
    function cborType(CborElement self) internal pure returns (uint8) {
        return uint8(CborElement.unwrap(self));
    }

    // First byte index of the content
    function start(CborElement self) internal pure returns (uint256) {
        return uint80(CborElement.unwrap(self) >> 80);
    }

    // First byte index of the next element (exclusive end of content)
    function end(CborElement self) internal pure returns (uint256) {
        return start(self) + length(self);
    }

    // Content length (0 for non-string types)
    function length(CborElement self) internal pure returns (uint256) {
        uint8 _type = cborType(self);
        if (_type == TYPE_BYTE_STRING || _type == TYPE_TEXT_STRING) {
            // length is non-zero only for byte strings and text strings
            return value(self);
        }
        return 0;
    }

    // Value of the element (length for string/map/array types, value for others)
    function value(CborElement self) internal pure returns (uint64) {
        return uint64(CborElement.unwrap(self) >> 160);
    }

    // Returns true if the element is null
    function isNull(CborElement self) internal pure returns (bool) {
        uint8 _type = cborType(self);
        return _type == 0xf6 || _type == 0xf7; // null or undefined
    }

    // Pack 3 uint80s into a uint256
    function toCborElement(uint256 _type, uint256 _start, uint256 _length) internal pure returns (CborElement) {
        return CborElement.wrap(_type | _start << 80 | _length << 160);
    }
}

library CborDecode {
    using LibBytes for bytes;
    using LibCborElement for CborElement;

    // Calculate the keccak256 hash of the given cbor element
    function keccak(bytes memory cbor, CborElement ptr) internal pure returns (bytes32) {
        return cbor.keccak(ptr.start(), ptr.length());
    }

    // Take a slice of the given cbor element
    function slice(bytes memory cbor, CborElement ptr) internal pure returns (bytes memory) {
        return cbor.slice(ptr.start(), ptr.length());
    }

    function byteStringAt(bytes memory cbor, uint256 ix) internal pure returns (CborElement) {
        return elementAt(cbor, ix, TYPE_BYTE_STRING, true);
    }

    function nextByteString(bytes memory cbor, CborElement ptr) internal pure returns (CborElement) {
        return elementAt(cbor, ptr.end(), TYPE_BYTE_STRING, true);
    }

    function nextByteStringOrNull(bytes memory cbor, CborElement ptr) internal pure returns (CborElement) {
        return elementAt(cbor, ptr.end(), TYPE_BYTE_STRING, false);
    }

    function nextTextString(bytes memory cbor, CborElement ptr) internal pure returns (CborElement) {
        return elementAt(cbor, ptr.end(), TYPE_TEXT_STRING, true);
    }

    function nextPositiveInt(bytes memory cbor, CborElement ptr) internal pure returns (CborElement) {
        return elementAt(cbor, ptr.end(), TYPE_UNSIGNED_INTEGER, true);
    }

    function mapAt(bytes memory cbor, uint256 ix) internal pure returns (CborElement) {
        return elementAt(cbor, ix, TYPE_MAP, true);
    }

    function nextMap(bytes memory cbor, CborElement ptr) internal pure returns (CborElement) {
        return mapAt(cbor, ptr.end());
    }

    function nextArray(bytes memory cbor, CborElement ptr) internal pure returns (CborElement) {
        return elementAt(cbor, ptr.end(), TYPE_ARRAY, true);
    }

    function elementAt(bytes memory cbor, uint256 ix, uint8 expectedType, bool required)
        internal
        pure
        returns (CborElement)
    {
        uint8 _type = uint8(cbor[ix] & 0xe0);
        uint8 ai = uint8(cbor[ix] & 0x1f);

        if (_type == TYPE_SIMPLE_OR_FLOAT) {
            // The primitive type can encode a float, bool, null, undefined, etc.
            // We only need support for null (and we treat undefined as null).
            require(ai == 22 || ai == 23, "only null primitive values are supported");
            require(!required, "null value for required element");
            // retain the additional information:
            return LibCborElement.toCborElement(_type | ai, ix + 1, 0);
        }

        if (expectedType != TYPE_ANY) {
            require((_type == expectedType), "unexpected type");
        }

        require((ai <= ADDITIONAL_INFO_8BYTES || ai == ADDITIONAL_INFO_INDEFINITE), "unsupported type");

        if (ai == ADDITIONAL_INFO_1BYTE) {
            return LibCborElement.toCborElement(_type, ix + 2, uint8(cbor[ix + 1]));
        } else if (ai == ADDITIONAL_INFO_2BYTES) {
            return LibCborElement.toCborElement(_type, ix + 3, cbor.readUint16(ix + 1));
        } else if (ai == ADDITIONAL_INFO_4BYTES) {
            return LibCborElement.toCborElement(_type, ix + 5, cbor.readUint32(ix + 1));
        } else if (ai == ADDITIONAL_INFO_8BYTES) {
            return LibCborElement.toCborElement(_type, ix + 9, cbor.readUint64(ix + 1));
        } else if (ai == ADDITIONAL_INFO_INDEFINITE) {
            uint256 cursor = ix + 1;
            uint256 length = 0;
            uint256 nested_length = 0;
            while (cursor < cbor.length) {
                if (cbor[cursor] == 0xFF) {
                    if (_type == TYPE_MAP) {
                        return LibCborElement.toCborElement(_type, ix + 1, (length - nested_length) / 2);
                    } else {
                        return LibCborElement.toCborElement(_type, ix + 1, (length - nested_length));
                    }
                }
                CborElement el = elementAt(cbor, cursor, TYPE_ANY, false);

                length += 1;
                if (el.cborType() == TYPE_MAP) {
                    nested_length += el.value() * 2;
                } else if (el.cborType() == TYPE_ARRAY) {
                    nested_length += el.value();
                }

                cursor = el.end();
            }
            revert("couldn't find the end of indefinite length item");
        }
        return LibCborElement.toCborElement(_type, ix + 1, ai);
    }
}
