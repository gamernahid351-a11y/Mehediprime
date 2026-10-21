#!/usr/bin/env python3
import struct
from enum import IntEnum
from typing import Any, Dict, List, Union

class WireType(IntEnum):
    VARINT = 0
    FIXED64 = 1
    LENGTH_DELIMITED = 2
    FIXED32 = 5
    SIGNED_VARINT = 8

class ProtobufEncoder:
    @staticmethod
    def encode_varint(value: int) -> bytes:
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)

    @staticmethod
    def encode_fixed64(value: int) -> bytes:
        return struct.pack('<Q', value)

    @staticmethod
    def encode_fixed32(value: int) -> bytes:
        return struct.pack('<I', value)

    @staticmethod
    def encode_zigzag(value: int) -> bytes:
        zigzag = (value << 1) ^ (value >> 63)
        return ProtobufEncoder.encode_varint(zigzag & 0xFFFFFFFFFFFFFFFF)

    @staticmethod
    def encode_tag(field_num: int, wire_type: int) -> bytes:
        return ProtobufEncoder.encode_varint((field_num << 3) | wire_type)

    @classmethod
    def encode(cls, message: Dict[int, Any]) -> bytes:
        result = bytearray()
        for field_num, value in message.items():
            if isinstance(value, list):
                for item in value:
                    result.extend(cls.encode_field(field_num, item))
            else:
                result.extend(cls.encode_field(field_num, value))
        return bytes(result)

    @classmethod
    def encode_field(cls, field_num: int, value: Any) -> bytes:
        if isinstance(value, int):
            if value < 0:
                return cls.encode_tag(field_num, WireType.VARINT) + cls.encode_zigzag(value)
            else:
                return cls.encode_tag(field_num, WireType.VARINT) + cls.encode_varint(value)
        elif isinstance(value, str):
            encoded_str = value.encode('utf-8')
            return (cls.encode_tag(field_num, WireType.LENGTH_DELIMITED) + 
                    cls.encode_varint(len(encoded_str)) + encoded_str)
        elif isinstance(value, bytes):
            return (cls.encode_tag(field_num, WireType.LENGTH_DELIMITED) + 
                    cls.encode_varint(len(value)) + value)
        elif isinstance(value, dict):
            nested_data = cls.encode(value)
            return (cls.encode_tag(field_num, WireType.LENGTH_DELIMITED) + 
                    cls.encode_varint(len(nested_data)) + nested_data)
        elif isinstance(value, bool):
            return cls.encode_tag(field_num, WireType.VARINT) + cls.encode_varint(1 if value else 0)
        else:
            raise ValueError(f"Unsupported type: {type(value)}")

def fields_to_protobuf(fields: Dict[str, Any]) -> bytes:
    converted = {}
    for key, value in fields.items():
        field_num = int(key)
        converted[field_num] = value
    return ProtobufEncoder.encode(converted)

if __name__ == "__main__":
    fields = {
        "1": "lhob_rizakuu",
        "2": "ed004ee67d56af9815da5c751c05ee1c74dbdc55d31ab58d86dd61da1a73bb67",
        "3": "94d89970687371489d91821208d9acc8",
        "5": 102000007,
        "6": 4,
        "7": 1,
        "13": 1,
        "14": "\t\u0004T\n\t\b\u0000\u0000\u0006\b\u0007\u0003\u0005\u0001\u0005\u000f\tT\t\u0001\b\u0000\u0001\u0003\u0007\bT\tQSQ\b",
        "15": "en",
        "16": 1
    }
    
    encoded = fields_to_protobuf(fields)
    print(encoded.hex())