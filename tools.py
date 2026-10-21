"""Packet builders and parsers for this bot.

Everything comes from files in this folder: ffcore for crypto and the two
start packets, protodecoder/protoencoder for the wire format. Nothing is
loaded from the parent directory, so the folder can be copied anywhere and
still run.
"""

import json
import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import config
import ffcore
from protodecoder import ProtoBytes, ProtobufDecoder, ProtoMessage, ProtoString
from protoencoder import ProtobufEncoder, fields_to_protobuf

create_protobuf_packet = ffcore.create_protobuf_packet
decrypt_api = ffcore.decrypt_api
decrypt_packet = ffcore.decrypt_packet
encrypt_api = ffcore.encrypt_api
encrypt_packet = ffcore.encrypt_packet
get_available_room = ffcore.get_available_room
live_client_version = ffcore.live_client_version
live_release_version = ffcore.live_release_version
GenSoloStartPacket = ffcore.GenSoloStartPacket
GenSoloCS43Packet = ffcore.GenSoloCS43Packet
GenSoloStopPacket = ffcore.GenSoloStopPacket
_with_header = ffcore._with_header
_to_room_shape = ffcore._to_room_shape


def live_server_url():
    try:
        import autoupdate
        return autoupdate.server_url()
    except Exception:
        return "https://loginbp.ppmainecoonghj.com"


def random_uuid():
    import uuid
    return str(uuid.uuid4())


def encode_payload(fields):
    return bytes.fromhex(encrypt_api(create_protobuf_packet(fields).hex()))


def field_text(decoded, number):
    entries = decoded.get(number)
    if not entries:
        return None
    value = entries[0].value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, str):
        return value
    raw = getattr(entries[0], "raw_bytes", None)
    if isinstance(raw, (bytes, bytearray)):
        try:
            return bytes(raw).decode("utf-8")
        except Exception:
            return None
    return None


def put_varint(value):
    out = bytearray()
    value = int(value)
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value & 0x7F)
    return bytes(out)


def pack_varints(values):
    out = bytearray()
    for value in values:
        out += put_varint(value)
    return bytes(out)


def read_varint(data, pos):
    value = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift > 63:
            break
    return value, pos


def build_purchase(item_id, quantity=1):
    out = bytearray()
    out += put_varint(0)
    out += put_varint(2)
    out += put_varint(item_id)
    out += put_varint(quantity)
    return bytes(out)


def build_switch_weapon(player_id, unique_id):
    out = bytearray()
    out += put_varint(player_id)
    out += put_varint(unique_id)
    return bytes(out)


def build_start_fire(player_id, weapon_unique, tick, state=1):
    out = bytearray()
    out += put_varint(player_id)
    out += put_varint(weapon_unique)
    out += put_varint(tick)
    out += put_varint(state)
    out += bytes(4)
    return bytes(out)


def build_stop_fire(player_id, weapon_unique, ammo, tick):
    out = bytearray()
    out += put_varint(player_id)
    out += put_varint(weapon_unique)
    out += put_varint(ammo)
    out += put_varint(tick)
    out += bytes(4)
    return bytes(out)


def parse_pickup(body):
    player_id, pos = read_varint(body, 0)
    unique_id, pos = read_varint(body, pos)
    item_id, pos = read_varint(body, pos)
    return player_id, unique_id, item_id


def build_use_skill(player_id, skill_id, tick=0):
    out = bytearray()
    out += put_varint(player_id)
    out += put_varint(skill_id)
    out += put_varint(tick)
    out += bytes(6)
    return bytes(out)


def parse_skill_state(body):
    player_id, pos = read_varint(body, 0)
    skill_id, pos = read_varint(body, pos)
    if pos >= len(body):
        return player_id, skill_id, 0, 0.0
    state = body[pos]
    pos += 1
    ready = 0.0
    while pos < len(body):
        try:
            raw, pos = read_varint(body, pos)
        except Exception:
            break
        if raw == 0:
            continue
        value = struct.unpack("<f", struct.pack("<I", raw & 0xFFFFFFFF))[0]
        if 0.0 < value < 100000.0:
            ready = value
        break
    return player_id, skill_id, state, ready


def build_personal_show(account_id):
    return encode_payload({1: int(account_id), 2: 9, 3: 1, 4: 1})


def _text_of(entry):
    """Read a length-delimited field as text.

    The decoder tries to parse every length-delimited chunk as a nested
    message *first* and only falls back to a string when that raises, so a
    ProtoMessage here is not proof the field really was a message. A short
    nickname can parse as one by accident: "Hi" is 0x48 0x69, which reads
    perfectly well as field 9, varint 105. Recovering the payload from the raw
    bytes is the only reading that is right in both cases.

    raw_bytes carries the tag and the length in front of the payload, so both
    varints have to be stepped over rather than decoded as text.
    """
    value = getattr(entry, "value", None)
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")

    raw = getattr(entry, "raw_bytes", None)
    if not isinstance(raw, (bytes, bytearray)):
        return None
    data = bytes(raw)
    pos = 0
    try:
        _, pos = read_varint(data, pos)      # tag
        size, pos = read_varint(data, pos)   # payload length
    except Exception:
        return None
    chunk = data[pos:pos + size]
    if not chunk:
        return None
    return chunk.decode("utf-8", "replace")


def read_personal_show(body):
    """Everything useful out of one GetPlayerPersonalShow reply.

    Field numbers, from a live capture of the response::

        1.1  account id      1.3  nickname     1.5  region
        1.6  level           1.7  xp

    Returns None when the reply cannot be decoded at all, and leaves
    individual keys as None when only that field is missing - a reply without
    a nickname should not also lose the xp reading beside it.
    """
    try:
        decoded = ProtobufDecoder.decode(body)
        info = decoded[1][0].value
    except Exception:
        return None
    if not isinstance(info, dict):
        return None

    def number(field):
        try:
            return int(info[field][0].value)
        except Exception:
            return None

    def text(field):
        try:
            out = _text_of(info[field][0])
        except Exception:
            return None
        return out or None

    return {
        "account_id": number(1),
        "nickname": text(3),
        "region": text(5),
        "level": number(6),
        "xp": number(7),
    }


def read_level(body):
    """Kept for callers that only want the level and should not have to know
    the shape of the rest of the reply."""
    show = read_personal_show(body)
    return show["level"] if show else None


def region_idc(region=None):
    """Matchmaking IDC from live GetLoginData. BD listed IDC3/IDC1/IDC2."""
    if region is None:
        region = config.LIVE.get_region()
    table = {"BD": "IDC3", "ME": "IDC2", "SG": "IDC1",
             "IND": "IDC2", "EUROPE": "IDC1", "US": "IDC1"}
    return table.get(str(region).upper(), "IDC3")


def clash_start_packet(key, iv, region=None, idc=None, version=None):
    if region is None:
        region = config.LIVE.get_region()
    if idc is None:
        idc = region_idc(region)
    if version is None:
        version = config.LIVE.client_version
    return GenSoloStartPacket(key, iv,
                              int(getattr(config, "Clash_Mode", 15)),
                              region,
                              version=version,
                              idc=idc)


def lone_wolf_packet(key, iv, region=None, idc=None, version=None):
    if region is None:
        region = config.LIVE.get_region()
    if idc is None:
        idc = region_idc(region)
    if version is None:
        version = config.LIVE.client_version
    return GenSoloCS43Packet(key, iv,
                             int(getattr(config, "LoneWolf_Mode", 43)),
                             region,
                             idc=idc,
                             version=version)


def solo_stop_packet(key, iv):
    return GenSoloStopPacket(key, iv)


def find_handshake_offset(content: bytes) -> int:
    """Locate the protobuf body inside a MajorLogin response.

    Live OB55 replies can carry a binary envelope before the protobuf.
    Parsing from offset 0 raises on that envelope even though fields 8/10
    are present a little further in. Prefer the handshake keys (16-byte
    field22/23 in MyMessage); fall back to the first offset whose field 8
    looks like a JWT.
    """
    if not content:
        return 0
    try:
        import my_message_pb2
        for off in range(0, min(len(content), 128)):
            try:
                message = my_message_pb2.MyMessage()
                message.ParseFromString(content[off:])
                if len(message.field22) == 16 and len(message.field23) == 16:
                    return off
            except Exception:
                continue
    except Exception:
        pass
    for off in range(0, min(len(content), 128)):
        try:
            decoded = ProtobufDecoder.decode(content[off:])
        except Exception:
            continue
        entries = decoded.get(8)
        if not entries:
            continue
        text = _shape_text(entries[0])
        if text.startswith("eyJ"):
            return off
    return 0


def _shape_text(entry) -> str:
    """Read a length-delimited field as text even when it nested-parsed.

    The decoder tries nested messages first, so a JWT or URL can show up as
    a ProtoMessage. Recover the payload from raw_bytes (tag + length + body)
    rather than trusting the nested shape.
    """
    value = getattr(entry, "value", None)
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    raw = getattr(entry, "raw_bytes", None)
    if not isinstance(raw, (bytes, bytearray)):
        return ""
    data = bytes(raw)
    pos = 0
    try:
        _, pos = read_varint(data, pos)
        size, pos = read_varint(data, pos)
    except Exception:
        return ""
    chunk = data[pos:pos + size]
    if not chunk:
        return ""
    return chunk.decode("utf-8", "replace")


def parse_major_login(content: bytes):
    """MajorLogin reply as a room-shape dict, after the binary envelope.

    Field 8 is the JWT, field 10 the client host URL. Same body bot.py
    decodes with get_available_room after find_handshake_offset. Text
    fields are recovered so a JWT that nested-parsed still comes back as
    the eyJ... string.
    """
    if not content:
        return None
    start = find_handshake_offset(content)
    try:
        decoded = ProtobufDecoder.decode(content[start:])
    except Exception:
        return None
    shape = {}
    for field_num, values in decoded.items():
        entry = values[0]
        text = ""
        if isinstance(entry, (ProtoMessage, ProtoString, ProtoBytes)):
            # JWT / host URL / short region codes can nested-parse; recover text.
            text = _shape_text(entry)
        looks_text = False
        if text:
            if text.startswith("eyJ") or "://" in text:
                looks_text = True
            elif 1 < len(text) <= 16 and text.isalpha():
                looks_text = True
        if looks_text:
            shape[str(field_num)] = {"wire_type": "string", "data": text}
        else:
            shape[str(field_num)] = _to_room_shape({field_num: values})[
                str(field_num)]
    return shape
