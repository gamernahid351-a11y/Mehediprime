#!/usr/bin/env python3
import json
import struct
from enum import IntEnum
from typing import Any, Dict, List, Tuple

class WireType(IntEnum):
    VARINT = 0
    FIXED64 = 1
    LENGTH_DELIMITED = 2
    FIXED32 = 5

class ProtoValue:
    def __init__(self, value: Any, wire_type: WireType, raw_bytes: bytes):
        self.value = value
        self.wire_type = wire_type
        self.raw_bytes = raw_bytes

class ProtoVarint(ProtoValue):
    def __init__(self, value: int, raw_bytes: bytes):
        super().__init__(value, WireType.VARINT, raw_bytes)

class ProtoFixed64(ProtoValue):
    def __init__(self, value: int, raw_bytes: bytes):
        super().__init__(value, WireType.FIXED64, raw_bytes)

class ProtoFixed32(ProtoValue):
    def __init__(self, value: int, raw_bytes: bytes):
        super().__init__(value, WireType.FIXED32, raw_bytes)

class ProtoBytes(ProtoValue):
    def __init__(self, value: bytes, raw_bytes: bytes):
        super().__init__(value, WireType.LENGTH_DELIMITED, raw_bytes)

class ProtoString(ProtoValue):
    def __init__(self, value: str, raw_bytes: bytes):
        super().__init__(value, WireType.LENGTH_DELIMITED, raw_bytes)

class ProtoMessage(ProtoValue):
    def __init__(self, value: Dict[int, List[ProtoValue]], raw_bytes: bytes):
        super().__init__(value, WireType.LENGTH_DELIMITED, raw_bytes)

class ProtobufDecoder:
    @staticmethod
    def decode_varint(buffer: bytes, offset: int) -> Tuple[int, int]:
        result = 0
        shift = 0
        while True:
            if offset >= len(buffer):
                raise ValueError("Unexpected end of buffer")
            byte = buffer[offset]
            result |= (byte & 0x7F) << shift
            offset += 1
            if not (byte & 0x80):
                break
            shift += 7
        return result, offset

    @staticmethod
    def decode_fixed64(buffer: bytes, offset: int) -> Tuple[int, int]:
        if offset + 8 > len(buffer):
            raise ValueError("Insufficient data")
        val = struct.unpack_from('<Q', buffer, offset)[0]
        return val, offset + 8

    @staticmethod
    def decode_fixed32(buffer: bytes, offset: int) -> Tuple[int, int]:
        if offset + 4 > len(buffer):
            raise ValueError("Insufficient data")
        val = struct.unpack_from('<I', buffer, offset)[0]
        return val, offset + 4

    @classmethod
    def decode(cls, data: bytes) -> Dict[int, List[ProtoValue]]:
        buffer = data
        offset = 0
        message: Dict[int, List[ProtoValue]] = {}
        length = len(buffer)

        while offset < length:
            field_start_offset = offset
            tag, offset = cls.decode_varint(buffer, offset)
            field_num = tag >> 3
            wire_type = tag & 0x7
            field_header_bytes = buffer[field_start_offset:offset]
            field_value_start = offset

            if wire_type == WireType.VARINT:
                value, offset = cls.decode_varint(buffer, offset)
                field_raw_bytes = field_header_bytes + buffer[field_value_start:offset]
                proto_value = ProtoVarint(value, field_raw_bytes)
            elif wire_type == WireType.FIXED64:
                value, offset = cls.decode_fixed64(buffer, offset)
                field_raw_bytes = field_header_bytes + buffer[field_value_start:offset]
                proto_value = ProtoFixed64(value, field_raw_bytes)
            elif wire_type == WireType.LENGTH_DELIMITED:
                size, offset = cls.decode_varint(buffer, offset)
                if offset + size > length:
                    raise ValueError("Length exceeds buffer")
                chunk = buffer[offset:offset + size]
                field_raw_bytes = field_header_bytes + buffer[field_value_start:offset + size]
                offset += size
                try:
                    nested = cls.decode(chunk)
                    proto_value = ProtoMessage(nested, field_raw_bytes)
                except Exception:
                    try:
                        string_value = chunk.decode('utf-8')
                        proto_value = ProtoString(string_value, field_raw_bytes)
                    except UnicodeDecodeError:
                        proto_value = ProtoBytes(chunk, field_raw_bytes)
            elif wire_type == WireType.FIXED32:
                value, offset = cls.decode_fixed32(buffer, offset)
                field_raw_bytes = field_header_bytes + buffer[field_value_start:offset]
                proto_value = ProtoFixed32(value, field_raw_bytes)
            else:
                raise ValueError(f"Unsupported wire type {wire_type}")

            if field_num not in message:
                message[field_num] = []
            message[field_num].append(proto_value)

        return message

def hex_to_json(hex_string: str) -> dict:
    hex_clean = hex_string.replace(" ", "").replace("\n", "")
    data = bytes.fromhex(hex_clean)
    decoded_message = ProtobufDecoder.decode(data)
    return message_to_json(decoded_message)

def message_to_json(message: Dict[int, List[ProtoValue]]) -> dict:
    json_obj = {}
    for field_num, values in message.items():
        if len(values) == 1:
            json_obj[str(field_num)] = proto_value_to_json(values[0])
        else:
            json_obj[str(field_num)] = [proto_value_to_json(v) for v in values]
    return json_obj

def proto_value_to_json(proto_value: ProtoValue) -> Any:
    if isinstance(proto_value, ProtoVarint):
        return proto_value.value
    elif isinstance(proto_value, ProtoFixed32):
        return proto_value.value
    elif isinstance(proto_value, ProtoFixed64):
        return proto_value.value
    elif isinstance(proto_value, ProtoString):
        return proto_value.value
    elif isinstance(proto_value, ProtoBytes):
        return proto_value.value.hex()
    elif isinstance(proto_value, ProtoMessage):
        return message_to_json(proto_value.value)
    else:
        return str(proto_value.value)

if __name__ == "__main__":
    packet_hex = "0a0c6c686f625f72697a616b75751240656430303465653637643536616639383135646135633735316330356565316337346462646335356433316162353864383664643631646131613733626236371a2039346438393937303638373337313438396439313832313230386439616363382887cbd13030043801680172200904540a09080000060807030501050f095409010800010307085409515351087a02656e800101"
    
    result = hex_to_json(packet_hex)
    print(json.dumps(result, indent=2, ensure_ascii=False))