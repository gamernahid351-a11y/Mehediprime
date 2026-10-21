"""Crypto, packet framing and the matchmaking start packets.

Extracted from the project-wide tools.py so levelup_solo stands on its own.
Only what this bot actually calls is here: the AES layer, the protobuf packet
builder, the 0315 clash and lone-wolf start packets with their captured device
fingerprint blobs, and the version lookup. Everything else in the original -
squad packets, room helpers, sniffer plumbing - is unused here and would only
be dead weight that drifts out of sync with the parent copy.
"""

import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from protoencoder import ProtobufEncoder
from protodecoder import (ProtobufDecoder, ProtoBytes, ProtoFixed32,
                          ProtoFixed64, ProtoMessage, ProtoString, ProtoVarint)

_API_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69,
                  117, 104, 54, 37, 90, 99, 94, 56])
_API_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50,
                 69, 51, 121, 99, 104, 106, 77, 37])

_SOLO_CS_F12_1 = (
    "08FBA33CA27253B2021798056666000101F0000301EC01"
    "777A310EFC1303BBFC467625142201043067bfd446ca3ca4f96a68ee74"
    "0000004f32321a0bcacfa16d"
)

_SOLO_CS_F12_3 = (
    "v_YT\u0015\u0007\u0006L\u0005\u0002\u000f\tP\u0004\u0002\u0004"
    "\u0001\u0000\u0000\u0005P\u0006\t\u0001V\u0006\u0007SW\u0000SPSV"
    "\u0000WR\u0007\u0002T\u0013\u0001\u0003Ku[EEO\u001e\u0006\u001c"
    "\u0001\u001b\u0014\u0001\u0004I\u001aDf|\\WBsqXSHcuF\u001bY]O"
    "\u0005TBBlZga\r\u0011\u0006L\u001d\u0000^q\u0019d\u0001B{\u0002"
    "SaBct\u0019[UBGMGTf\u0001\u0007\u0002\u000b\u0013\u0001\u0001"
    "Kaq@hclq_`PmBB|_\u000eA~G\u0004\u0005neYlsc\u000b\u0015\bL]Oh"
    "\u000fzG\u000ft\u0004eaYQX\u0001pXF_\\JAzMe]F\f\u0015\u0004J|"
    "\\j|If]}\u0000\u0005^GU[M\u001foYA\u0003Dyr\u0004\u0002~}\u000b"
    "\u0016\bJC\u0000WbH}Syp\u0001UrE]\u0007spUxOa[yWRS\n\u0013"
    "\u0007\rMZ\u0002~yzfBg\u0002z\u0006T]WwrWD\\q\u0004BS\u0007a"
    "\u0000C\u000f\u0014\u0003Jv\u001ezP|H{}DZtirqWIuccXwtgssQ\r"
    "\u0013\u0006K\u0001z\u001ag]f|IEcx`]Wz{@\u001bC\u0000u\u0000o"
    "\u001ahY\u000b\u0015\u0002\u0000N\u0003b\u0006\rpcaqeCssdu{E"
    "\u0006wFb{M\u0004\\x\u000b\u0015\u0003LR\u0003xBUruE_gd\u0007"
    "uZeOY\u0001b@{sEg\u0007\u0005s\b"
)

_SOLO_CS_F12_11 = (
    "\u0003bbSQ64lTLlgIAdV2KyoVldmgm19UvPMGwNFUmtspezIzQqEfojlInZ17BNVtPu"
    "Fl8VHGMhePZppbOxt7/Xf0ITTsu6YK0ad1BTT6y1dHOIjwIMrFAJbCuhjQALX5w2+Fm"
    "HpBnvvLc1OKaKZ9N/Jy2TNtkAao23bC93WYfrmRNYH3asOfFuexExNGC3SsSr73tkeL"
    "I4Aq0bIqOfcuIQ7i8LCQ7iGocTbpKV7LnVG4CBPaQGabBJOVvKvWgatGqIb28lEaM9X"
    "GorFtp08oAZyhOpMP5uc6yzr4uu61yg7JgBkLYMqwywyVfdHfG5VtEFkhdeAtJj6pqd"
    "HX/K0FerijF6FQn138RSrsR6cbEAf50p8pC3+2e8QiEfe1IFXML2lsZwYyWKKEOKiXu"
    "nqX1/POWiTY0QLOPkW+P4wl+erkfSgIQiUdBznm+xd0JAmnI5ewjDefEifsMcp9Qj0l"
    "qwnas7WJFYPOqZdMgw57R086n7vDuxtCh+vBTx4a9CL9KDYY5wZ6Mr5pqjFSnyZuT/g"
    "nM4JnKbSob7K9Jwf4q7q71j1bIVE7SeHzI4oIiPncvQ8Nw1Y/Z2OfvGoBjzBuW6gDPh"
    "83XlLpS0sMlgGew5LjL7dnr2ZRs8lshClf5lg="
)

_CS43_F12_1 = (
    "088B8238A2425B8B020101000000000700140001000C0002A067394D0F00000046"
    "762514000000010000000000000000000000000000004f00000000cacfa16d"
)

_CS43_F12_7 = "\u0012ftvipV\t\u0012\u0011"

_CS43_F12_11 = (
    "\u0003bbSQ6/Du7Rd/AdV2KyoVlS1It2Mco+mRgJ/PabJ0r6PfwcscgJbKxfm5Wh9M9"
    "Bb5JuL/AVdLdhKafSW5ttO/ZP0JM3/cgq4J81yhESa692t5xc6Uy5KX/4okqAX1KsFU"
    "V3h7UhD8rC7trNuxDX8wMfz2rzyBCCHKCkHeQYEXSlN5l7WK5xna3Bgqc4/y5j+HfuL"
    "xZRizrBOKy9pb8+c5lERaLIdvm7bp7BdyaSi2soYhZ58p7jWBAAO9dRBnCjbeSrg3nV"
    "MUpvjBnus+UW9dVRH2w8+ThuM4LBjTfUKtwKJcNzhuRWxDVM+ALis3IwPDoXbeoo37W"
    "/dbET+vorL0tanIqPacJCmwUwe0Wi3uJixFp4TSKRt70vO26G5T8bC2PtVOWIWGH9bs"
    "lZm6zi5XfGK4smBVxubWOVi9HB7R+9aaq/NUs3Bc4RFRwUPgp6J3tEMywcWKrJpF1/X"
    "kNIfnKJqSHjVstam6uF6uWlpztXN/6/sn9Ar6j1mjMoPCoSu2njTLZSfVjik7786K/A"
    "9vN6o1ZxY/gvWFkfytC413dQIZqHWxICXw2ebunHmdoFuKx03t1VwfaDi6fVsofRzRn"
    "p4U8firAJ5JgGht"
)


def dec_to_hex(ask):
    result = hex(ask)[2:]
    if len(result) == 1:
        result = "0" + result
    return result


def _wire_name(v):
    if isinstance(v, ProtoVarint):
        return "varint"
    if isinstance(v, ProtoString):
        return "string"
    if isinstance(v, ProtoBytes):
        return "bytes"
    if isinstance(v, ProtoFixed32):
        return "fixed32"
    if isinstance(v, ProtoFixed64):
        return "fixed64"
    if isinstance(v, ProtoMessage):
        return "length_delimited"
    return "unknown"


def _to_room_shape(message):
    result = {}
    for field_num, values in message.items():
        v = values[0]
        field_data = {"wire_type": _wire_name(v)}
        if isinstance(v, ProtoMessage):
            field_data["data"] = _to_room_shape(v.value)
        elif isinstance(v, ProtoBytes):
            field_data["data"] = v.value.hex()
        else:
            field_data["data"] = v.value
        result[str(field_num)] = field_data
    return result


def live_client_version():
    """The version autoupdate is currently reporting.

    Imported lazily so this module works with or without the updater beside
    it, and falls back to a literal rather than raising.
    """
    try:
        import autoupdate
        return autoupdate.remote_version()
    except Exception:
        return "1.132.3"


def live_release_version():
    try:
        import autoupdate
        return autoupdate.release_version()
    except Exception:
        return "OB55"


def create_protobuf_packet(fields):
    return ProtobufEncoder.encode(fields)


def encrypt_api(plain_text):
    cipher = AES.new(_API_KEY, AES.MODE_CBC, _API_IV)
    return cipher.encrypt(pad(bytes.fromhex(plain_text),
                              AES.block_size)).hex()


def decrypt_api(cipher_text):
    cipher = AES.new(_API_KEY, AES.MODE_CBC, _API_IV)
    return unpad(cipher.decrypt(bytes.fromhex(cipher_text)),
                 AES.block_size).hex()


def encrypt_packet(plain_text, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(bytes.fromhex(plain_text),
                              AES.block_size)).hex()


def decrypt_packet(packet, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(bytes.fromhex(packet)),
                 AES.block_size).hex()


def _with_header(packet_hex, key, iv, prefix):
    encrypted = encrypt_packet(packet_hex, key, iv)
    length = dec_to_hex(len(encrypted) // 2)
    header = prefix + ("0" * (8 - len(length))) + length
    return bytes.fromhex(header + encrypted)


def get_available_room(input_text):
    try:
        data = bytes.fromhex(input_text.replace(" ", "").replace("\n", ""))
        return json.dumps(_to_room_shape(ProtobufDecoder.decode(data)))
    except Exception:
        return None


def GenSoloStartPacket(key, iv, game_mode=15, region="ME", ping=3000,
                       version=None, idc="IDC3"):
    if version is None:
        version = live_client_version()
    fields = {
        1: 1,
        2: {
            1: "\u0001",
            2: int(game_mode),
            7: {1: idc, 2: int(ping), 3: region},
            8: 1,
            9: "\u0001\u0007\t\n\u000b\u0012\u0019 \"'",
            11: 1,
            12: {
                1: _SOLO_CS_F12_1,
                2: 1487,
                3: _SOLO_CS_F12_3,
                4: "y_XP",
                6: 11,
                7: "\u0012Tsuddx\u0012\u0011",
                8: version,
                9: 3,
                10: 2,
                11: _SOLO_CS_F12_11,
            },
            20: "\b\u0015",
            21: "a_2342091806014554718",
        },
    }
    return _with_header(create_protobuf_packet(fields).hex(), key, iv, "0315")


def GenSoloCS43Packet(key, iv, game_mode=43, region="ME", idc="IDC2",
                      ping=89, version=None):
    if version is None:
        version = live_client_version()
    fields = {
        1: 1,
        2: {
            1: "\u000b",
            2: int(game_mode),
            7: {1: idc, 2: int(ping), 3: region},
            8: 1,
            9: "\u0001\u0007\t\n\u000b\u0012\u0019 \"'",
            11: 1,
            12: {
                1: _CS43_F12_1,
                2: 169,
                3: _SOLO_CS_F12_3,
                4: "y_XP",
                6: 11,
                7: _CS43_F12_7,
                8: version,
                9: 3,
                10: 2,
                11: _CS43_F12_11,
            },
            20: "\b\u0015",
            21: "a_2342091806014554718",
        },
    }
    return _with_header(create_protobuf_packet(fields).hex(), key, iv, "0315")


def GenSoloStopPacket(key, iv):
    return _with_header(create_protobuf_packet({1: 2}).hex(), key, iv, "0315")
