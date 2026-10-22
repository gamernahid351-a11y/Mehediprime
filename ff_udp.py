import socket
import struct
import random
import threading
import time
import zlib

try:
    from udp_message_ids import cmd_name
except ImportError:
    def cmd_name(cmd):
        return "CMD_%d" % cmd


MTU_LIMIT = 1300
UDP_HEAD_AND_ENCRY_SIZE = 40
MSG_KEY_MIN, MSG_KEY_MID, MSG_KEY_MAX = 90, 100, 110
HDR_UNRELIABLE, HDR_RELIABLE = 8, 10
F_SENDOPTION, F_CMD, F_ORDERID, F_FLAGS, F_LENGTH = 0, 1, 2, 3, 4
FIELD_SIZE = {0: 1, 1: 2, 2: 2, 3: 1, 4: 2}

CMD_HELLO = 1
CMD_ACK = 2
CMD_PING = 3

# ---------------------------------------------------------------------------
# Raw AES auth datagram (live capture). Separate from TEA/CRC7 framing below.
#
# The match UDP host can accept this plain packet first:
#   [cmd u8][region u8][account_id u64be][kts u32be][wm u32be?][len i32be][data]
# data = AES-128-CBC(login JWT) with the fixed key/IV from the capture.
# After this, the existing HELLO -> 447 -> 448 TEA session continues.
# ---------------------------------------------------------------------------

# Captured OB55 UDP auth key + IV (16 bytes each, AES-128-CBC).
AUTH_AES_KEY = bytes([
    0x19, 0x47, 0xB9, 0x74, 0xD9, 0x73, 0xF3, 0x7F,
    0x42, 0x06, 0x01, 0x38, 0x42, 0x00, 0x10, 0x30,
])
AUTH_AES_IV = bytes([
    0x28, 0x7F, 0xCA, 0x7A, 0xF9, 0x67, 0xF3, 0x7A,
    0x65, 0x02, 0x01, 0x10, 0x40, 0x40, 0x00, 0x30,
])

# cmds 0x65..0x96 carry account_id + kts in this format.
AUTH_CMD_MIN = 0x65
AUTH_CMD_WRAP = 0x31


def auth_cmd_has_identity(cmd):
    return ((cmd - AUTH_CMD_MIN) & 0xFF) <= AUTH_CMD_WRAP


def auth_aes_encrypt(data, key=None, iv=None):
    """AES-128-CBC + PKCS#7, matching the capture."""
    from Crypto.Cipher import AES
    key = AUTH_AES_KEY if key is None else key
    iv = AUTH_AES_IV if iv is None else iv
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pad = 16 - (len(data) % 16)
    return cipher.encrypt(data + bytes([pad]) * pad)


def auth_aes_decrypt(data, key=None, iv=None):
    from Crypto.Cipher import AES
    key = AUTH_AES_KEY if key is None else key
    iv = AUTH_AES_IV if iv is None else iv
    plain = AES.new(key, AES.MODE_CBC, iv).decrypt(data)
    if not plain:
        return b""
    pad = plain[-1]
    if 0 < pad <= 16:
        return plain[:-pad]
    return plain


def calc_init_watermark(addr, port, key=None):
    """crc32(ip4_be || port_be || key). 0 when the address is not IPv4."""
    try:
        ip4 = socket.inet_aton(addr)
    except OSError:
        return 0
    buf = bytearray(6)
    buf[0:4] = ip4[:4]
    buf[4] = (int(port) >> 8) & 0xFF
    buf[5] = int(port) & 0xFF
    if key:
        buf += str(key).encode("utf-8")
    return zlib.crc32(bytes(buf)) & 0xFFFFFFFF


def serialize_auth_packet(cmd, region, data, account_id, kts,
                          server_addr=None, server_port=0,
                          need_watermark=False, watermark_enabled=False,
                          watermark_key=None):
    """Build the raw auth datagram from the live capture layout."""
    out = bytearray()
    out.append(int(cmd) & 0xFF)
    out.append(int(region) & 0xFF)
    if auth_cmd_has_identity(cmd):
        out += struct.pack(">Q", int(account_id) & 0xFFFFFFFFFFFFFFFF)
        out += struct.pack(">I", int(kts) & 0xFFFFFFFF)
        if need_watermark and watermark_enabled:
            wm = 0
            if watermark_key and server_addr:
                wm = calc_init_watermark(server_addr, server_port,
                                         watermark_key)
            out += struct.pack(">I", wm)
    if data:
        out += struct.pack(">i", len(data))
        out += bytes(data)
    return bytes(out)


def build_auth_packet(token, account_id, server_addr, server_port,
                      cmd=None, region=None, kts=None,
                      need_watermark=None, watermark_enabled=None,
                      watermark_key=None):
    """Token -> encrypted auth datagram.

    Uses live config defaults when an argument is None. kts defaults to now
    so each match carries a fresh timestamp instead of a frozen capture one.
    """
    try:
        import config
    except ImportError:
        config = None

    def cfg(name, default):
        if config is None:
            return default
        return getattr(config, name, default)

    if cmd is None:
        cmd = cfg("Auth_Cmd", 0x65)
    if region is None:
        region = cfg("Auth_Region", 0x15)
    if kts is None:
        kts = int(time.time())
    if need_watermark is None:
        need_watermark = bool(cfg("Auth_Need_Watermark", False))
    if watermark_enabled is None:
        watermark_enabled = bool(cfg("Auth_Watermark_Enabled", False))
    if watermark_key is None:
        watermark_key = cfg("Auth_Watermark_Key", None)

    payload = token if isinstance(token, (bytes, bytearray)) else str(token).encode("utf-8")
    data = auth_aes_encrypt(payload)
    return serialize_auth_packet(
        cmd, region, data, account_id, kts,
        server_addr=server_addr, server_port=server_port,
        need_watermark=need_watermark,
        watermark_enabled=watermark_enabled,
        watermark_key=watermark_key)


def send_auth_packet(sock, addr, token, account_id,
                     cmd=None, region=None, kts=None,
                     need_watermark=None, watermark_enabled=None,
                     watermark_key=None):
    """Send the raw AES auth datagram to the match UDP host.

    Returns the packet bytes, or None when disabled / missing token.
    """
    try:
        import config
        if not getattr(config, "Use_Auth_Packet", False):
            return None
    except ImportError:
        pass
    if not token:
        return None
    ip, port = addr[0], int(addr[1])
    pkt = build_auth_packet(
        token, account_id, ip, port,
        cmd=cmd, region=region, kts=kts,
        need_watermark=need_watermark,
        watermark_enabled=watermark_enabled,
        watermark_key=watermark_key)
    try:
        sock.sendto(pkt, (ip, port))
    except Exception:
        return None
    return pkt


SENDOPTION_HELLO = 1
FLAG_ENCRYPTED = 1
PING_INTERVAL = 4  # seconds; must stay under DEFAULT_DEACTIVE_TIME (10)

DELTA, ROUNDS, SALT_LEN, ZERO_LEN = 0x9E3779B9, 16, 2, 7
M32 = 0xFFFFFFFF


def _crc7_table():
    t = []
    for b in range(256):
        c = 0
        for i in range(8):
            top = ((c >> 6) & 1) ^ ((b >> (7 - i)) & 1)
            c = (c << 1) & 0x7F
            if top:
                c ^= 0x09
        t.append(c)
    return t


CRC7 = _crc7_table()


def crc7_byte(crc, b):
    return CRC7[((crc << 1) ^ b) & 0xFF]


def crc7_u16(crc, v):
    return crc7_byte(crc7_byte(crc, v & 0xFF), (v >> 8) & 0xFF)


def crc7_buf(crc, data):
    for b in data:
        crc = CRC7[((crc << 1) ^ b) & 0xFF]
    return crc


def _tea_enc_block(blk, k):
    y, z = struct.unpack("<2I", blk)
    s = 0
    for _ in range(ROUNDS):
        s = (s + DELTA) & M32
        y = (y + ((((z << 4) & M32) + k[0]) ^ (z + s) ^ ((z >> 5) + k[1]))) & M32
        z = (z + ((((y << 4) & M32) + k[2]) ^ (y + s) ^ ((y >> 5) + k[3]))) & M32
    return struct.pack("<2I", y, z)


def _tea_dec_block(blk, k):
    y, z = struct.unpack("<2I", blk)
    s = (DELTA << 4) & M32
    for _ in range(ROUNDS):
        z = (z - ((((y << 4) & M32) + k[2]) ^ (y + s) ^ ((y >> 5) + k[3]))) & M32
        y = (y - ((((z << 4) & M32) + k[0]) ^ (z + s) ^ ((z >> 5) + k[1]))) & M32
        s = (s - DELTA) & M32
    return struct.pack("<2I", y, z)


def tea_encrypt_len(n):
    t = 1 + SALT_LEN + n + ZERO_LEN
    r = t % 8
    return t + (8 - r if r else 0)


def tea_encrypt(data, key):
    k = list(struct.unpack("<4I", key[:16]))
    n = tea_encrypt_len(len(data))
    pad = n - (1 + SALT_LEN + len(data) + ZERO_LEN)
    plain = bytearray(n)
    plain[0] = pad
    plain[1 + pad + SALT_LEN:1 + pad + SALT_LEN + len(data)] = data
    out = bytearray(n)
    iv_p = iv_c = bytes(8)
    for off in range(0, n, 8):
        blk = bytes(a ^ b for a, b in zip(plain[off:off + 8], iv_c))
        c = bytes(a ^ b for a, b in zip(_tea_enc_block(blk, k), iv_p))
        out[off:off + 8] = c
        iv_p, iv_c = blk, c
    return bytes(out)


def tea_decrypt(buf, key):
    if len(buf) < 16 or len(buf) % 8:
        return None
    k = list(struct.unpack("<4I", key[:16]))
    pad = _tea_dec_block(buf[0:8], k)[0] & 7
    out_len = len(buf) - pad - 1 - SALT_LEN - ZERO_LEN
    if out_len < 0:
        return None
    plain = bytearray(len(buf))
    iv_p = iv_c = bytes(8)
    for off in range(0, len(buf), 8):
        c = buf[off:off + 8]
        t = bytes(a ^ b for a, b in zip(c, iv_p))
        blk = _tea_dec_block(t, k)
        plain[off:off + 8] = bytes(a ^ b for a, b in zip(blk, iv_c))
        iv_p, iv_c = blk, c
    at = 1 + pad + SALT_LEN
    if bytes(plain[at + out_len:]) != bytes(ZERO_LEN):
        return None
    return bytes(plain[at:at + out_len])


def is_reliable(cmd, send_option):
    if cmd == CMD_ACK or not 1 <= send_option <= 5:
        return False
    return bool((0x13 >> (send_option - 1)) & 1)


def gen_msg_key(cmd, send_option):
    if is_reliable(cmd, send_option):
        return random.randrange(MSG_KEY_MIN, MSG_KEY_MID)
    return random.randrange(MSG_KEY_MID, MSG_KEY_MAX)


def encode_packet(cmd, send_option, order_id, flags, body, key, order):
    reliable = is_reliable(cmd, send_option)
    payload = tea_encrypt(body, key) if flags & FLAG_ENCRYPTED else body
    if UDP_HEAD_AND_ENCRY_SIZE + len(payload) > MTU_LIMIT:
        raise ValueError("payload exceeds MTU guard")
    k = key[0]
    kk = k | (k << 8)
    masked = {
        F_SENDOPTION: send_option ^ k,
        F_CMD: cmd ^ kk,
        F_ORDERID: order_id ^ kk,
        F_FLAGS: flags ^ k,
        F_LENGTH: len(payload) ^ kk,
    }
    out = bytearray([gen_msg_key(cmd, send_option), 0])
    crc = 0
    for fid in order:
        if fid == F_ORDERID and not reliable:
            continue
        v = masked[fid]
        if FIELD_SIZE[fid] == 1:
            crc = crc7_byte(crc, v)
            out.append(v)
        else:
            crc = crc7_u16(crc, v)
            out += struct.pack("<H", v)
    out += payload
    out[1] = crc7_buf(crc, payload)
    return bytes(out)


def decode_packet(pkt, key, order):
    if len(pkt) < HDR_UNRELIABLE:
        return None
    k = key[0]
    kk = k | (k << 8)
    msg_key, crc = pkt[0], pkt[1]
    if not MSG_KEY_MIN <= msg_key <= MSG_KEY_MAX:
        return None
    if crc7_buf(0, pkt[2:]) != crc:
        return None
    reliable = msg_key < MSG_KEY_MID
    hdr = HDR_RELIABLE if reliable else HDR_UNRELIABLE
    if len(pkt) < hdr:
        return None
    off, f = 2, {F_ORDERID: 0}
    for fid in order:
        if fid == F_ORDERID and not reliable:
            continue
        if FIELD_SIZE[fid] == 1:
            f[fid] = pkt[off] ^ k
        else:
            f[fid] = struct.unpack_from("<H", pkt, off)[0] ^ kk
        off += FIELD_SIZE[fid]
    payload = pkt[hdr:]
    if f[F_FLAGS] & FLAG_ENCRYPTED:
        body = tea_decrypt(payload, key)
    else:
        body = payload
    return {
        "MsgKey": msg_key,
        "Cmd": f[F_CMD],
        "OrderID": f.get(F_ORDERID, 0),
        "Flags": f[F_FLAGS],
        "SendOption": f[F_SENDOPTION],
        "Length": f[F_LENGTH],
        "reliable": reliable,
        "body": body,
    }


def parse_udp_mask(mask):
    if len(mask) != 5:
        return [0, 1, 2, 3, 4]
    order = [int(c) for c in mask]
    if sorted(order) != [0, 1, 2, 3, 4]:
        return [0, 1, 2, 3, 4]
    return order


def build_hello_body(account_id, suffix="0"):
    device_id = "%s_%s" % (account_id, suffix)
    raw = device_id.encode("utf-8")
    body = bytearray()
    body += struct.pack("<i", len(raw))
    body += raw
    body += bytes(9)
    return bytes(body)


def parse_hello_res(body):
    if body is None or len(body) < 4:
        return None
    p = 0
    n = struct.unpack_from("<i", body, p)[0]
    p += 4
    session_key = body[p:p + n].decode("utf-8", "replace")
    p += n
    if p + 4 > len(body):
        return {"SessionKey": session_key}
    order_id = struct.unpack_from("<H", body, p)[0]
    p += 2
    required_id = struct.unpack_from("<H", body, p)[0]
    p += 2
    addr = ""
    if p + 4 <= len(body):
        m = struct.unpack_from("<i", body, p)[0]
        p += 4
        addr = body[p:p + m].decode("utf-8", "replace")
    return {
        "SessionKey": session_key,
        "OrderID": order_id,
        "RequiredID": required_id,
        "Addr": addr,
    }


def handler_s2c(pkt, key, order, state):
    dec = decode_packet(pkt, key, order)
    if dec is None:
        print("[s2c] undecodable packet (%d bytes)" % len(pkt))
        return None
    cmd = dec["Cmd"]
    if cmd == CMD_HELLO:
        res = parse_hello_res(dec["body"])
        state["hello_res"] = res
        state["got_hello"] = True
        print("[s2c] HELLO_RES received:")
        if res:
            print("      SessionKey :", (res.get("SessionKey") or "")[:32])
            print("      OrderID    :", res.get("OrderID"))
            print("      RequiredID :", res.get("RequiredID"))
            print("      Addr       :", res.get("Addr"))
        return res
    if cmd == CMD_ACK:
        print("[s2c] ACK  OrderID=%d" % dec["OrderID"])
        return dec
    if cmd == CMD_PING:
        print("[s2c] PING")
        return dec
    print("[s2c] Cmd=%d reliable=%s len=%d" % (cmd, dec["reliable"], dec["Length"]))
    return dec


def handler_c2s(cmd, send_option, order_id, flags, body, key, order, sock, addr):
    pkt = encode_packet(cmd, send_option, order_id, flags, body, key, order)
    sock.sendto(pkt, addr)
    print("[c2s] sent Cmd=%d SendOption=%d OrderID=%d (%d bytes)"
          % (cmd, send_option, order_id, len(pkt)))
    return pkt


def handler_udp(ip, port, account_id, secret, udp_jwt, udp_mask,
                suffix="0", timeout=12.0):
    key = bytes.fromhex(secret)
    order = parse_udp_mask(udp_mask)
    addr = (ip, int(port))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    state = {"got_hello": False, "hello_res": None}

    print("=== handler_udp ===")
    print("target   :", "%s:%s" % (ip, port))
    print("key byte :", "0x%02x" % key[0], " mask:", udp_mask, "->", order)
    print("account  :", account_id)

    hello_body = build_hello_body(account_id, suffix)
    handler_c2s(CMD_HELLO, SENDOPTION_HELLO, 0, FLAG_ENCRYPTED,
                hello_body, key, order, sock, addr)

    deadline = time.time() + timeout
    resend_at = time.time() + 0.3
    while time.time() < deadline and not state["got_hello"]:
        try:
            data, _ = sock.recvfrom(4096)
            handler_s2c(data, key, order, state)
        except socket.timeout:
            if time.time() >= resend_at:
                handler_c2s(CMD_HELLO, SENDOPTION_HELLO, 0, FLAG_ENCRYPTED,
                            hello_body, key, order, sock, addr)
                resend_at = time.time() + 0.3

    if state["got_hello"]:
        print(">>> server SENT hello_res : YES")
    else:
        print(">>> server SENT hello_res : NO (timeout after %.0fs)" % timeout)
    sock.close()
    return state["hello_res"]


# ---------------------------------------------------------------------------
# ACK / join-match bodies and the full handshake sequence
# ---------------------------------------------------------------------------

CMD_JOIN_PREPARE = 447
CMD_JOIN_POST = 448
SENDOPTION_NONE = 0
SENDOPTION_RELIABLE = 2


def _zig(v):
    return (v << 1) ^ (v >> 63)


def _put_varint(out, v):
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)


def _put_zigvarint(out, v):
    _put_varint(out, _zig(v))


def _put_string(out, s):
    raw = s.encode("utf-8")
    _put_zigvarint(out, len(raw))
    out += raw


def build_start_rescue_body(target_player_id, server_time):
    """C2S_RUDP_StartRescure_Req { UInt32 TargetPlayerID, UInt64 StartRescureTime }

    The target is the FULL PlayerID, the same 0x0100000N form the roster and
    the join carry - not the short id that Cmd 2012 is keyed by.
    """
    body = bytearray()
    _put_varint(body, int(target_player_id))
    _put_varint(body, int(server_time))
    return bytes(body)


def build_stop_rescue_body(target_player_id):
    """C2S_RUDP_StopRescure_Req { UInt32 TargetPlayerID }"""
    body = bytearray()
    _put_varint(body, int(target_player_id))
    return bytes(body)


def build_ack_body(required_order_id, mask=b""):
    body = bytearray()
    body += struct.pack("<H", required_order_id)
    body += mask
    return bytes(body)


def _dg_size(token_len, reliable=True):
    zv = bytearray()
    _put_zigvarint(zv, token_len)
    body = len(zv) + token_len
    return (HDR_RELIABLE if reliable else HDR_UNRELIABLE) + tea_encrypt_len(body)


def split_token(token):
    raw = int(len(token) * 0.85)
    p1 = raw - (raw % 40)
    while UDP_HEAD_AND_ENCRY_SIZE + _dg_size(p1) > MTU_LIMIT and p1 > 40:
        p1 -= 40
    return token[:p1], token[p1:]


def build_join_prepare_body(token_part1):
    body = bytearray()
    _put_string(body, token_part1)
    return bytes(body)


# C2S_RUDP_JoinMatchPost_Req { JoinMatchReqInfo ReqInfo, string TokenPart2 }
# JoinMatchReqInfo (message.DBGNDLHOIEJ / ACLLIENGCIN), built field by field
# from a live C2S_448 capture. Order and widths must match the client exactly.
#
# Nested Workshop / empty lists flatten to a zero-length / zero-count prefix
# (same 0x00 as an empty string), so an all-default Workshop block is ten
# zeros plus RelationshipInfos + IsSpecialPool - twelve zeros, then the flags.


def _live_client_version():
    try:
        import autoupdate
        return autoupdate.remote_version()
    except Exception:
        return "1.132.7"


def _live_client_version_code():
    # Live JWT claim client_version_code for 1.132.7.
    return "2019121229"


def _live_client_url():
    """ClientUrl = semicolon-joined anticheat hosts from MajorLogin field 16."""
    try:
        import config
        hosts = config.LIVE.anticheat_hosts()
        if hosts:
            return ";".join(hosts)
    except Exception:
        pass
    return CLIENT_URL


def _live_country():
    try:
        import config
        country = config.LIVE.country
        if country:
            return str(country)
    except Exception:
        pass
    return "MA"


CLIENT_VERSION = _live_client_version()
CLIENT_VERSION_CODE = _live_client_version_code()
# Live capture ClientUrl (fallback when MajorLogin has not spoken yet).
CLIENT_URL = ("csoversea.stronghold.freefiremobile.com;0.0.0.0;"
              "34.126.76.45;34.87.177.14;34.87.170.230;35.185.183.57")


def build_join_info_head(account_id, game_mode=15, match_mode=1, map_id=1,
                         country=None, client_version=None,
                         client_version_code=None, client_url=None,
                         room_id=0, match_id=0,
                         drift_bottle_owner_id=0, drift_bottle_owner_name="",
                         enable_antihack_tick=1, friend_count=0,
                         client_ip="", client_fingerprint="",
                         session_tag=0, is_emulator=1):
    """JoinMatchReqInfo body (everything except TokenPart2).

    Values follow the live C2S_RUDP_JoinMatchPost_Req capture. Session-specific
    fields (RoomID, DriftBottle*, NEW_0xD8/E8/F0) are arguments so a join is
    never stamped with another match's ids.
    """
    if country is None:
        country = _live_country()
    if client_version is None:
        client_version = _live_client_version()
    if client_version_code is None:
        client_version_code = _live_client_version_code()
    if client_url is None:
        client_url = _live_client_url()

    room = int(match_id or room_id)
    b = bytearray()
    _put_varint(b, int(account_id))             # UserID
    # RoomID and ServiceRoomID both carry the match id (same 19-digit value).
    _put_varint(b, room)                        # RoomID
    b.append(1)                                 # RoomType
    b.append(int(game_mode) & 0xFF)             # GameMode (74 in the capture)
    _put_varint(b, room)                        # ServiceRoomID
    b.append(int(map_id) & 0xFF)                # MapID
    b.append(0)                                 # IsReconnect
    _put_varint(b, 0)                           # CustomRoomIndex
    _put_varint(b, 0)                           # GroupIcon
    b.append(0)                                 # IsPCClient
    b.append(int(is_emulator) & 0xFF)           # IsEmulator
    b.append(0)                                 # IsEmulatorPool
    b.append(1)                                 # SystemPlatform
    b.append(2)                                 # CPUType
    b.append(3)                                 # ChannelType
    # EnableFFANTIHACKTick: capture sends 1. Declaring 1 is a promise to keep
    # sending Cmd 431 anti-cheat ticks; 0 makes no such promise.
    b.append(int(enable_antihack_tick) & 0xFF)  # EnableFFANTIHACKTick
    b.append(1)                                 # ClientLanguage
    _put_string(b, country)                     # CountryCode
    _put_varint(b, 0)                           # Role
    b.append(1)                                 # BuildVariantType
    b.append(2)                                 # NewbieChoice
    b.append(0)                                 # FactionType
    b.append(1)                                 # RankMapCount
    b.append(0)                                 # IfHaveMapsBonus
    b.append(0)                                 # GSReplayEnabled
    b.append(4)                                 # AccountType
    _put_string(b, client_version)              # ClientVersion
    _put_string(b, client_version_code)         # ClientVersionCode
    _put_string(b, client_url)                  # ClientUrl
    b.append(0)                                 # NoPowerGun
    b.append(0)                                 # Gender
    _put_varint(b, int(friend_count))           # FriendCount
    b.append(0)                                 # IsCadet
    _put_varint(b, int(drift_bottle_owner_id))  # DriftBottleOwnerID
    _put_string(b, drift_bottle_owner_name or "")  # DriftBottleOwnerName
    b.append(1)                                 # MobileReplayEnabled
    # --- Workshop (flattened nested WorkshopInfo) ---
    _put_string(b, "")                          # WorkshopShareCode
    _put_string(b, "")                          # WorkshopMapName
    b.append(0)                                 # IsUnlimitedAmmo
    _put_varint(b, 0)                           # ModeSetting []
    _put_varint(b, 0)                           # ClientEventsWhiteList []
    b.append(0)                                 # IsUnlimitedBullet
    b.append(0)                                 # IsUnlimitedGloowall
    b.append(0)                                 # IsUnlimitedThrowables
    _put_varint(b, 0)                           # UGCCustomMissions []
    _put_string(b, "")                          # Workshop.NEW_0x50.NEW_0x18
    _put_varint(b, 0)                           # RelationshipInfos []
    b.append(0)                                 # IsSpecialPool
    b.append(1)                                 # IsTransferReport
    b.append(0)                                 # IsHalfWayJoin
    b.append(0)                                 # ShowDamageType
    _put_varint(b, 0)                           # WeaponProficiencyMaxItemID
    _put_varint(b, 0)                           # UGCGameDataMD5 []
    b.append(0)                                 # QuickMsgVocal
    b.append(1)                                 # IsBagShow
    _put_string(b, "")                          # SamoAIParam
    _put_varint(b, 0)                           # MapLayerID
    b.append(0)                                 # IsVoiceBeMuted
    b.append(0)                                 # IsReconnectWithoutParseToken
    b.append(0)                                 # GroupMode
    b.append(int(match_mode) & 0xFF)            # MatchMode
    b.append(0)                                 # IsAIChatOpen
    # NEW_* are IL2CPP offset names from the dump (not protobuf tags).
    _put_varint(b, int(session_tag))            # NEW_0xD8
    b.append(2)                                 # NEW_0xE0
    b.append(0)                                 # NEW_0xE1
    _put_string(b, client_ip or "")             # NEW_0xE8  (client IP)
    _put_string(b, client_fingerprint or "")    # NEW_0xF0  (sha256 hex)
    return bytes(b)


def build_join_post_body(account_id, token_part2, game_mode=15, match_mode=1,
                         map_id=1, room_id=0, match_id=0,
                         country=None, client_version=None,
                         client_version_code=None, client_url=None,
                         drift_bottle_owner_id=0, drift_bottle_owner_name="",
                         enable_antihack_tick=1, friend_count=0,
                         client_ip="", client_fingerprint="",
                         session_tag=0, is_emulator=1):
    """C2S_RUDP_JoinMatchPost_Req = ReqInfo || TokenPart2."""
    body = bytearray()
    body += build_join_info_head(
        account_id, game_mode=game_mode, match_mode=match_mode, map_id=map_id,
        room_id=room_id, match_id=match_id,
        country=country, client_version=client_version,
        client_version_code=client_version_code, client_url=client_url,
        drift_bottle_owner_id=drift_bottle_owner_id,
        drift_bottle_owner_name=drift_bottle_owner_name,
        enable_antihack_tick=enable_antihack_tick, friend_count=friend_count,
        client_ip=client_ip, client_fingerprint=client_fingerprint,
        session_tag=session_tag, is_emulator=is_emulator)
    _put_string(body, token_part2)
    return bytes(body)


def _print_reply(dec):
    if dec is None:
        print("cmd = <undecodable>")
        return
    print("cmd = %d (%s)" % (dec["Cmd"], cmd_name(dec["Cmd"])))
    print("send_option =", dec["SendOption"])
    body = dec["body"]
    if body is None:
        print("decrypted_payload = <decrypt failed>")
        return
    print("decrypted_payload =", body.hex())
    if dec["Cmd"] == CMD_PLAYER_STATE_SYNC:
        print_player_state(body)


def handler_full(ip, port, account_id, secret, udp_jwt, udp_mask,
                 suffix="0", timeout=15.0,
                 game_mode=15, map_id=1, match_mode=1, sleep_ms=0,
                 match_id=0):
    key = bytes.fromhex(secret)
    order = parse_udp_mask(udp_mask)
    addr = (ip, int(port))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    delay = sleep_ms / 1000.0

    print("=== handler_full ===")
    print("target :", "%s:%s" % (ip, port), " key byte 0x%02x  order %s" % (key[0], order))
    print("match  : game_mode=%d map_id=%d match_mode=%d sleep_ms=%d"
          % (game_mode, map_id, match_mode, sleep_ms))

    # --- step 1: HELLO ---
    hello_body = build_hello_body(account_id, suffix)
    handler_c2s(CMD_HELLO, SENDOPTION_HELLO, 0, FLAG_ENCRYPTED, hello_body, key, order, sock, addr)

    hello_res = None
    deadline = time.time() + timeout
    resend = time.time() + 0.3
    while time.time() < deadline and hello_res is None:
        try:
            data, _ = sock.recvfrom(4096)
            dec = decode_packet(data, key, order)
            if dec and dec["Cmd"] == CMD_HELLO:
                hello_res = parse_hello_res(dec["body"])
                print("[1] HELLO_RES: OrderID=%s RequiredID=%s Addr=%s"
                      % (hello_res.get("OrderID"), hello_res.get("RequiredID"), hello_res.get("Addr")))
        except socket.timeout:
            if time.time() >= resend:
                handler_c2s(CMD_HELLO, SENDOPTION_HELLO, 0, FLAG_ENCRYPTED, hello_body, key, order, sock, addr)
                resend = time.time() + 0.3
    if hello_res is None:
        print(">>> no HELLO_RES, aborting")
        sock.close()
        return

    # --- step 2: ACK the hello_res so the server stops resending ---
    required = (hello_res.get("OrderID", 0) + 1) & 0xFFFF
    ack_body = build_ack_body(required)
    handler_c2s(CMD_ACK, SENDOPTION_NONE, 0, FLAG_ENCRYPTED, ack_body, key, order, sock, addr)
    print("[2] sent ACK RequiredOrderID=%d" % required)

    # --- step 3: send Cmd 447 (JoinMatchPrepare) OrderID 0 ---
    part1, part2 = split_token(udp_jwt)
    body447 = build_join_prepare_body(part1)
    if delay > 0:
        time.sleep(delay)
    handler_c2s(CMD_JOIN_PREPARE, SENDOPTION_RELIABLE, 0, FLAG_ENCRYPTED, body447, key, order, sock, addr)
    print("[3] sent Cmd 447 OrderID=0 (token part1=%d chars)" % len(part1))

    # --- step 4: wait for the server ACK of 447 ---
    got_447_ack = False
    deadline = time.time() + timeout
    resend = time.time() + 0.3
    while time.time() < deadline and not got_447_ack:
        try:
            data, _ = sock.recvfrom(4096)
            dec = decode_packet(data, key, order)
            if dec is None:
                continue
            if dec["Cmd"] == CMD_ACK:
                got_447_ack = True
                print("[4] server ACK for 447 received")
            else:
                print("[4] server reply while waiting 447-ack:")
                _print_reply(dec)
        except socket.timeout:
            if time.time() >= resend:
                handler_c2s(CMD_JOIN_PREPARE, SENDOPTION_RELIABLE, 0, FLAG_ENCRYPTED, body447, key, order, sock, addr)
                resend = time.time() + 0.3
    if not got_447_ack:
        print(">>> no ACK for 447, aborting before 448")
        sock.close()
        return

    # --- step 5: send Cmd 448 (JoinMatchPost) OrderID 1 ---
    body448 = build_join_post_body(account_id, part2, game_mode=game_mode,
                                   match_mode=match_mode, map_id=map_id,
                                   match_id=match_id)
    if delay > 0:
        time.sleep(delay)
    handler_c2s(CMD_JOIN_POST, SENDOPTION_RELIABLE, 1, FLAG_ENCRYPTED, body448, key, order, sock, addr)
    print("[5] sent Cmd 448 OrderID=1 (token part2=%d chars)" % len(part2))

    # --- step 6: follow whoever calls ---
    # Cmd 551 (RELIABLE) says WHO to follow: its SenderID is a packed PlayerID
    # whose low byte is the ShortPlayerID. Cmd 2012 (UNRELIABLE) says WHERE
    # everyone is. We latch the caller from the reliable event and refresh their
    # position from the unreliable stream, then walk there on our own timer.
    # Everything is also logged to udp_capture.txt for later analysis.
    import os
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "udp_capture.txt")
    log = open(log_path, "w", encoding="utf-8")
    log.write("# Free Fire UDP capture\n")
    log.write("# target=%s:%s account=%s secret=%s mask=%s\n"
              % (ip, port, account_id, secret, udp_mask))
    log.write("# seq\tt\tcmd\tname\tso\trel\toid\tlen\tpayload_hex\n")
    log.flush()

    follower = PlayerFollower(step=200)
    # FollowHandler owns the actual chase: it ramps the step up over distance so
    # a far caller is reached instead of crawling and being snapped back, and it
    # leads a moving target rather than trailing their last reported position.
    chase = FollowHandler()
    # The server's own clock. Every movement packet must carry it, so we track
    # it from Cmd 2000 and interpolate between updates.
    clock = ServerClock()
    # The real client sends 10 state updates a second (a 0.100s gap, measured
    # from its own traffic). Matching that rate keeps us indistinguishable from
    # it and avoids flooding the channel.
    move_interval = 0.1

    # Movement runs on its OWN thread. Previously it shared the receive loop,
    # so every burst of incoming packets delayed the next step - with ~19
    # packets a second arriving, the loop spent its time draining the socket
    # and the move timer slipped, which is exactly the stalling seen in
    # captures (fifty ticks in a row with no position change). A dedicated
    # thread keeps the stride perfectly even no matter how busy the socket is.
    stop_moving = threading.Event()
    move_lock = threading.Lock()

    def movement_loop():
        next_tick = time.time()
        while not stop_moving.is_set():
            try:
                now = time.time()
                if now < next_tick:
                    # Sleep exactly to the next tick. A fixed 10ms nap here made
                    # the loop wake early and fire again, pushing the real rate to
                    # 18/s against the client's measured 10/s.
                    time.sleep(min(0.02, next_tick - now))
                    continue
                # Anchor the schedule to the previous tick rather than to `now`, so
                # a slow pass does not permanently shift the cadence.
                next_tick += move_interval
                if next_tick < now:
                    next_tick = now + move_interval
                with move_lock:
                    my_pos = follower.my_pos
                    # dead-reckoned target: keeps the chase alive while the
                    # caller is missing from the broadcast, which is what used
                    # to stop the bot the moment they ran out of range
                    target_pos = follower.predicted_target(now)
                    my_pid = follower.my_player_id
                    t_yrot = follower.target_yrot
                    t_aim_y = follower.target_aim_y
                    t_aim_xz = follower.target_aim_xz
                    t_state = follower.target_state
                    t_pose = follower.target_pose
                if my_pid is None or my_pos is None or target_pos is None:
                    continue
                result = chase.next_position(my_pos, target_pos, now,
                                             dt=move_interval)
                if result is None:
                    continue
                new_pos, dist, yaw = result
                with move_lock:
                    follower.my_pos = new_pos
                # uploads must carry the FULL PlayerID (e.g. 0x02000005),
                # not the short id - the server matches on the full value
                send_position(sock, addr, key, order, my_pid, my_pos, new_pos,
                              clock.now(now), aim_yaw=yaw,
                              target_yrot=t_yrot, target_aim_y=t_aim_y,
                              target_aim_xz=t_aim_xz,
                              copy_state=t_state, copy_pose=t_pose)
            except Exception:
                # The movement thread must never die. A sniff showed it sending
                # 272 identical zero-velocity packets while the caller was
                # 19,000 units away - the tick had thrown once and the whole
                # chase was gone until the next match. Swallowing everything
                # here, with the timing inside the guard too, means a single bad
                # value costs one tick instead of the session.
                try:
                    time.sleep(move_interval)
                except Exception:
                    pass
                continue

    mover = threading.Thread(target=movement_loop, daemon=True)
    mover.start()

    counts = {}
    seq = 0
    t0 = time.time()
    next_ping = time.time()
    next_move = time.time()
    sock.settimeout(move_interval)

    print("following whoever sends a quick chat - logging to %s" % log_path)
    print("press Ctrl+C to stop")
    try:
        while True:
            now = time.time()
            # Keepalive first and guarded: if this ever stops the server marks
            # us offline after DEFAULT_DEACTIVE_TIME (10s). At a 0.2s socket
            # timeout the 4s ping is always sent on schedule, and a failed send
            # must never break the loop.
            if now >= next_ping:
                try:
                    send_ping(sock, addr, key, order)
                except OSError:
                    pass
                next_ping = now + PING_INTERVAL
            # movement now runs on its own thread; this loop only receives
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                continue
            try:
                dec = decode_packet(data, key, order)
            except (ValueError, IndexError, struct.error):
                continue
            if dec is None:
                continue
            # RELIABLE packets must be acked; UNRELIABLE ones never are
            if dec["reliable"]:
                try:
                    req = (dec["OrderID"] + 1) & 0xFFFF
                    ack = encode_packet(CMD_ACK, SENDOPTION_NONE, 0,
                                        FLAG_ENCRYPTED, build_ack_body(req),
                                        key, order)
                    sock.sendto(ack, addr)
                except OSError:
                    pass
            cmd = dec["Cmd"]
            body = dec["body"]
            counts[cmd] = counts.get(cmd, 0) + 1
            seq += 1
            log.write("%04d\t%.3f\t%d\t%s\t%d\t%d\t%d\t%d\t%s\n"
                      % (seq, now - t0, cmd, cmd_name(cmd), dec["SendOption"],
                         1 if dec["reliable"] else 0, dec["OrderID"],
                         len(body) if body is not None else 0,
                         body.hex() if body is not None else "<decrypt-failed>"))
            log.flush()

            # the server's clock. We echo every sync straight back with
            # C2S_UDP_SyncServerTime_Res: the real client answers these, and a
            # client that never does looks out of sync, which is when the
            # server starts discarding its movement.
            if cmd == CMD_SYNC_SERVER_TIME:
                st = decode_server_time(body)
                if st is not None:
                    tick, phase = st
                    clock.sync(tick, phase, now)
                    try:
                        ackpkt = encode_packet(CMD_SYNC_SERVER_TIME,
                                               SENDOPTION_NONE, 0,
                                               FLAG_ENCRYPTED,
                                               build_server_time_ack(tick),
                                               key, order)
                        sock.sendto(ackpkt, addr)
                    except OSError:
                        pass
            # WHO IS WHO: every Cmd 101 adds a player to the roster, so we know
            # which ShortPlayerID (the low byte of the full PlayerID) belongs to
            # which account. The one carrying our own account identifies us.
            elif cmd == CMD_PLAYER_JOIN:
                info = parse_player_join(body)
                if info is not None:
                    uid, full_pid, name = info
                    follower.add_player(full_pid, name)
                    print("PlayerJoin: short=%-3d PlayerID=0x%08X team=%-2d %s"
                          % (full_pid & 0xFF, full_pid, (full_pid >> 24) & 0xFF, name))
                    if uid == int(account_id):
                        follower.set_me(full_pid)
                        print(">>> that is ME: PlayerID=0x%08X short=%d"
                              % (full_pid, full_pid & 0xFF))
            # our position as the server sees it (Cmd 2001 carries only us)
            elif cmd == CMD_PLAYER_STATE_SYNC and body is not None and len(body) > 3:
                try:
                    p = 2                      # skip MatchTime + count
                    _sid = body[p]; p += 1
                    x, p = _rd_varint(body, p)
                    y, p = _rd_varint(body, p)
                    z, p = _rd_varint(body, p)
                    follower.set_my_position((_zag(x), _zag(y), _zag(z)))
                except (IndexError, ValueError):
                    pass
            # WHERE: unreliable stream of everyone's positions
            elif cmd == CMD_PLAYER_STATE_V2:
                follower.on_players(decode_players_v2(body))
            # WHO TO FOLLOW: reliable one-shot telling us who called
            elif cmd == CMD_QUICK_CHAT:
                qc = decode_quick_chat(body)
                if qc is not None:
                    chat_id, short_id, raw, team = qc
                    name = QUICK_CHAT_NAMES.get(chat_id, "chat_%d" % chat_id)
                    who = follower.roster.get(short_id, (0, "?"))[1]
                    print("QUICK CHAT '%s' from 0x%08X -> short=%d (%s)"
                          % (name, raw, short_id, who))
                    if follower.on_quick_chat(chat_id, short_id):
                        chase.reset()   # new caller: forget the old one's motion
                        print(">>> now following player %d (%s)" % (short_id, who))
    except KeyboardInterrupt:
        print("\nstopping...")
    finally:
        stop_moving.set()
        log.write("# --- summary: %d packets ---\n" % seq)
        for c in sorted(counts):
            log.write("# cmd %-5d %-45s x%d\n" % (c, cmd_name(c), counts[c]))
        log.close()
        print("=== %d packets logged to %s ===" % (seq, log_path))
        sock.close()


# ---------------------------------------------------------------------------
# S2C_UDP_PlayerState_Res (Cmd 2001) - high-frequency player movement sync
# ---------------------------------------------------------------------------

CMD_PLAYER_STATE_SYNC = 2001


def _rd_varint(b, p):
    v = i = 0
    while True:
        c = b[p + i]
        v |= (c & 0x7F) << (7 * i)
        i += 1
        if not c & 0x80:
            return v, p + i


def _zag(v):
    return (v >> 1) ^ -(v & 1)


def _read_vec3(b, p):
    x, p = _rd_varint(b, p)
    y, p = _rd_varint(b, p)
    z, p = _rd_varint(b, p)
    return (_zag(x), _zag(y), _zag(z)), p


def _read_vec2(b, p):
    x, p = _rd_varint(b, p)
    y, p = _rd_varint(b, p)
    return (_zag(x), _zag(y)), p


def _decode_player(b, p):
    pid = b[p]; p += 1
    pos, p = _read_vec3(b, p)
    rot, p = _read_vec3(b, p)
    tdir, p = _read_vec2(b, p)
    vel, p = _read_vec3(b, p)
    physx_state = b[p]; p += 1
    physx_pose = b[p]; p += 1
    aim, p = _read_vec3(b, p)
    platform, p = _rd_varint(b, p)
    custom = b[p]; p += 1
    return {
        "pid": pid, "pos": pos, "rot": rot, "tdir": tdir, "vel": vel,
        "physx_state": physx_state, "physx_pose": physx_pose,
        "aim": aim, "platform": platform, "custom": custom,
    }, p


def decode_player_state(body):
    p = 0
    mt, p = _rd_varint(body, p)
    match_time = _zag(mt)
    cnt, p = _rd_varint(body, p)
    count = _zag(cnt)
    players = []
    for _ in range(count):
        pl, p = _decode_player(body, p)
        players.append(pl)
    self_replay = body[p] if p < len(body) else 0
    p += 1
    tick = 0
    if p < len(body):
        tick, p = _rd_varint(body, p)
    return {
        "match_time": match_time, "count": count, "players": players,
        "self_replay": self_replay, "tick": tick,
    }


def print_player_state(body):
    try:
        st = decode_player_state(body)
    except (IndexError, ValueError):
        print("   <player-state decode failed>")
        return
    pids = [pl["pid"] for pl in st["players"]]
    print("PLAYERS: count=%d  ShortPlayerIDs=%s" % (st["count"], pids))
    print("   MatchTime=%d TickCount=%d players=%d SelfForReplay=%d"
          % (st["match_time"], st["tick"], st["count"], st["self_replay"]))
    for pl in st["players"]:
        print("   ShortPlayerID=%-3d pos=%s rot=%s vel=%s aim=%s tdir=%s platform=%d physx=%d/%d custom=%d"
              % (pl["pid"], pl["pos"], pl["rot"], pl["vel"], pl["aim"],
                 pl["tdir"], pl["platform"], pl["physx_state"], pl["physx_pose"], pl["custom"]))


# ---------------------------------------------------------------------------
# C2S_UDP_Ping_Req (Cmd 3) - keepalive so the server does not mark us offline
# ---------------------------------------------------------------------------


def build_ping_body(send_tick, average_ping=0, ping_a500=0, rudp_resend_rate=0):
    o = bytearray()
    _put_zigvarint(o, send_tick & 0xFFFFFFFF)
    _put_zigvarint(o, average_ping)
    _put_zigvarint(o, ping_a500)
    _put_zigvarint(o, rudp_resend_rate)
    return bytes(o)


def send_ping(sock, addr, key, order, average_ping=0):
    tick = int(time.time() * 1000) & 0xFFFFFFFF
    body = build_ping_body(tick, average_ping)
    # Cmd 3, SendOption NONE, Flags 0 (plaintext, matching the captured ping)
    pkt = encode_packet(CMD_PING, SENDOPTION_NONE, 0, 0, body, key, order)
    sock.sendto(pkt, addr)
    return tick


# ---------------------------------------------------------------------------
# S2C_RUDP_PlayerJoin_Res (Cmd 101) - extract my in-match PlayerID
# ---------------------------------------------------------------------------

CMD_PLAYER_JOIN = 101


def extract_my_player_id(body, account_id):
    """The Cmd 101 body opens with PMatchPlayerInfo, whose first three fields
    are UserID (UInt64), SamoUserID (UInt64), PlayerID (UInt32), all varints.
    If UserID matches my account, PlayerID is my in-match id.

    NOTE: the PlayerID returned here is the FULL packed value (e.g. 0x02000005
    = team 2, short id 5). Movement uploads must carry this full value, while
    the player lists in Cmd 2012 are keyed by the low byte only.
    """
    if body is None or len(body) < 3:
        return None
    try:
        p = 0
        user_id, p = _rd_varint(body, p)
        _samo_id, p = _rd_varint(body, p)
        player_id, p = _rd_varint(body, p)
    except (IndexError, ValueError):
        return None
    if user_id == int(account_id):
        return player_id
    return None


def parse_player_join(body):
    """Decode the head of a Cmd 101 (S2C_RUDP_PlayerJoin_Res) into
    (user_id, full_player_id, nickname). Returns None if it cannot be read.

    Every player that joins gets one of these, so collecting them builds the
    roster: which UserID owns which PlayerID, and therefore which ShortPlayerID
    (the low byte) appears in the movement stream.
    """
    if body is None or len(body) < 4:
        return None
    try:
        p = 0
        user_id, p = _rd_varint(body, p)
        _samo_id, p = _rd_varint(body, p)
        player_id, p = _rd_varint(body, p)
        raw_len, p = _rd_varint(body, p)
        n = _zag(raw_len)
        name = body[p:p + n].decode("utf-8", "replace")
    except (IndexError, ValueError):
        return None
    return user_id, player_id, name


# ---------------------------------------------------------------------------
# C2S_UDP_PlayerState_Req (Cmd 2001) - upload our own movement
# ---------------------------------------------------------------------------

CMD_PLAYER_STATE_UPLOAD = 2001


def _put_float_bits(o, f):
    bits = struct.unpack("<I", struct.pack("<f", f))[0]
    _put_varint(o, bits)


def build_player_state_upload(player_id, pos, rot, tdir, vel, aim_float,
                              physx_state=0, physx_pose=0, platform=0,
                              low_grav=0, ping=0, jump=0, slide=0, custom=0):
    o = bytearray()
    _put_varint(o, player_id)
    # Position PVector3IntPos (Int32 zigzag)
    _put_zigvarint(o, pos[0]); _put_zigvarint(o, pos[1]); _put_zigvarint(o, pos[2])
    # Rotation PVector3Int (Int16 zigzag)
    _put_zigvarint(o, rot[0]); _put_zigvarint(o, rot[1]); _put_zigvarint(o, rot[2])
    # TargetDirection PVector2Int (X, Z)
    _put_zigvarint(o, tdir[0]); _put_zigvarint(o, tdir[1])
    # Velocity PVector3Int
    _put_zigvarint(o, vel[0]); _put_zigvarint(o, vel[1]); _put_zigvarint(o, vel[2])
    o.append(physx_state & 0xFF)
    o.append(physx_pose & 0xFF)
    # AimRotation PVector3Float (float32 as varint bits)
    _put_float_bits(o, aim_float[0]); _put_float_bits(o, aim_float[1]); _put_float_bits(o, aim_float[2])
    _put_varint(o, platform)
    o.append(1 if low_grav else 0)
    _put_varint(o, ping)
    o.append(jump & 0xFF)
    _put_varint(o, slide)
    o.append(custom & 0xFF)
    return bytes(o)


def build_c2s_player_state(player_id, pos, rot, tdir, vel, aim_float,
                           server_time, **kw):
    o = bytearray()
    o += build_player_state_upload(player_id, pos, rot, tdir, vel, aim_float, **kw)
    _put_varint(o, server_time & 0xFFFFFFFF)
    return bytes(o)


def send_my_movement(sock, addr, key, order, my_player_id, other_players,
                     server_time, ping=0, offset=(100, 100, 100)):
    """Take any other player's data, shift the position by `offset` on each
    axis, and send it as our own C2S movement stamped with OUR PlayerID. This
    puts the bot next to a real player rather than exactly on top of them, so it
    registers as movement. The offset can be negative and the resulting
    coordinates can be negative too - Position is a signed (zigzag) field.
    Picks the first player that is not us; if none, nothing is sent this tick.
    """
    if not other_players or my_player_id is None:
        return
    ref = None
    for pl in other_players:
        if pl["pid"] != my_player_id:
            ref = pl
            break
    if ref is None:
        return
    new_pos = (
        ref["pos"][0] + offset[0],
        ref["pos"][1] + offset[1],
        ref["pos"][2] + offset[2],
    )
    aim = tuple(float(v) for v in ref["aim"])   # int16 aim -> float for the C2S float field
    body = build_c2s_player_state(
        player_id=my_player_id,              # OUR in-match id
        pos=new_pos,                         # server pos shifted by offset
        rot=ref["rot"],                      # from server
        tdir=ref["tdir"],                    # from server
        vel=ref["vel"],                      # from server
        aim_float=aim,                       # from server (int16 -> float)
        server_time=server_time,
        platform=ref["platform"],            # from server
        physx_state=ref["physx_state"],      # from server
        physx_pose=ref["physx_pose"],        # from server
        custom=ref["custom"],                # from server
        ping=ping,
    )
    pkt = encode_packet(CMD_PLAYER_STATE_UPLOAD, SENDOPTION_NONE, 0,
                        FLAG_ENCRYPTED, body, key, order)
    sock.sendto(pkt, addr)
    print("C2S UPLOAD -> server: Cmd=%d SendOption=%d bytes=%d"
          % (CMD_PLAYER_STATE_UPLOAD, SENDOPTION_NONE, len(pkt)))
    print("   PlayerID=%d pos=%s rot=%s vel=%s aim=%s tdir=%s platform=%d physx=%d/%d custom=%d ServerTime=%d"
          % (my_player_id, new_pos, ref["rot"], ref["vel"], aim,
             ref["tdir"], ref["platform"], ref["physx_state"], ref["physx_pose"],
             ref["custom"], server_time))
    print("   body hex:", body.hex())


# ---------------------------------------------------------------------------
# S2C_RUDP_SafeZone_Changed (Cmd 117) - reliable safe-zone update
# ---------------------------------------------------------------------------

CMD_SAFE_ZONE_CHANGE = 117


def _read_vec2pos(b, p):
    x, p = _rd_varint(b, p)
    z, p = _rd_varint(b, p)
    return (_zag(x), _zag(z)), p


def _read_float(b, p):
    bits, p = _rd_varint(b, p)
    return struct.unpack("<f", struct.pack("<I", bits))[0], p


def decode_safezone(body):
    p = 0
    stage = body[p]; p += 1
    outer_center, p = _read_vec2pos(body, p)
    outer_radius, p = _rd_varint(body, p)
    inner_center, p = _read_vec2pos(body, p)
    inner_radius, p = _rd_varint(body, p)
    time_span_type = body[p]; p += 1
    start_time, p = _rd_varint(body, p)
    end_time, p = _rd_varint(body, p)
    quick_preshrink = body[p]; p += 1
    random_inner = body[p]; p += 1
    minimap_scale, p = _read_float(body, p)
    return {
        "stage": stage,
        "outer_center": outer_center, "outer_radius": outer_radius,
        "inner_center": inner_center, "inner_radius": inner_radius,
        "time_span_type": time_span_type,
        "start_time": start_time, "end_time": end_time,
        "quick_preshrink": quick_preshrink, "random_inner": random_inner,
        "minimap_scale": minimap_scale,
    }


def print_safezone(body):
    try:
        z = decode_safezone(body)
    except (IndexError, ValueError):
        print("   <safezone decode failed>")
        return
    print("SAFE ZONE (Cmd 117):")
    print("   StageID       =", z["stage"])
    print("   OuterCenter   =", z["outer_center"], " OuterRadius =", z["outer_radius"])
    print("   InnerCenter   =", z["inner_center"], " InnerRadius =", z["inner_radius"])
    print("   TimeSpanType  =", z["time_span_type"])
    print("   StartTime     =", z["start_time"], " EndTime =", z["end_time"])
    print("   QuickPreShrink=", z["quick_preshrink"], " RandomInner =", z["random_inner"])
    print("   MiniMapScale  =", z["minimap_scale"])


# ---------------------------------------------------------------------------
# Safe-zone navigation - keep the player alive by walking toward the zone
# ---------------------------------------------------------------------------

import math


class ZoneNavigator:
    """Drives movement purely from zone packets (Cmd 117), NOT from the GRI
    phase. Each zone packet is treated as the start of a new round: it carries
    a new center (InnerCenter) and a StartTime/EndTime window. On every zone
    packet we recompute the per-tick step so we pace to reach the center within
    that round's window - a short window makes us walk faster, a long one
    slower. We keep walking toward the current center every tick until the next
    zone packet updates the target. This repeats every round automatically.

    Heading for the center is always safe regardless of the radius unit/scale,
    since the exact center is inside the circle by definition.
    """

    def __init__(self, ticks_per_sec=20, min_step=50):
        self.ticks_per_sec = ticks_per_sec
        self.min_step = min_step
        self.step = 250
        self.center = None       # current target (InnerCenter)
        self.start_time = None
        self.end_time = None
        self.my_pos = None       # our tracked (x, y, z)
        self.round_num = 0
        self.active = False      # only move after the FIRST zone arrives
        self.last_yaw = 0

    def ensure_start(self, ref_player):
        """Seed our position from a real player's position the first time."""
        if self.my_pos is None and ref_player is not None:
            self.my_pos = ref_player["pos"]

    def on_zone(self, zone):
        """A new zone packet arrived = a new round. Update the target center and
        recompute the step so we arrive within StartTime->EndTime."""
        self.round_num += 1
        self.center = zone["inner_center"]
        self.start_time = zone["start_time"]
        self.end_time = zone["end_time"]
        self.active = True
        if self.my_pos is not None:
            dx = self.center[0] - self.my_pos[0]
            dz = self.center[1] - self.my_pos[2]
            dist = math.sqrt(dx * dx + dz * dz)
            window = max(1, self.end_time - self.start_time)
            total_ticks = window * self.ticks_per_sec
            self.step = max(self.min_step, int(dist / total_ticks) + 1)
        window = self.end_time - self.start_time
        print("ROUND %d: new zone center=%s window=%ds -> step=%d/tick"
              % (self.round_num, self.center, window, self.step))

    def step_toward(self):
        """One step toward the current zone center. Returns
        (old_pos, new_pos, dist, yaw), or None before the first zone / start.
        Keeps moving continuously; at the center it stays put but keeps facing
        the zone so we keep reporting a valid position.
        """
        if not self.active or self.center is None or self.my_pos is None:
            return None
        old_pos = self.my_pos
        cx, cz = self.center
        dx = cx - self.my_pos[0]
        dz = cz - self.my_pos[2]
        dist = math.sqrt(dx * dx + dz * dz)
        if dist >= 1:
            self.last_yaw = int(math.degrees(math.atan2(dx, dz)))
        yaw = self.last_yaw
        if dist <= self.step:
            self.my_pos = (cx, self.my_pos[1], cz)
        else:
            nx = self.my_pos[0] + dx / dist * self.step
            nz = self.my_pos[2] + dz / dist * self.step
            self.my_pos = (int(nx), self.my_pos[1], int(nz))
        return old_pos, self.my_pos, dist, yaw


# ---------------------------------------------------------------------------
# FollowHandler - the whole "stick to the caller" behaviour in one place
# ---------------------------------------------------------------------------


class FollowHandler:
    """Decides where the bot should be next, and how fast to get there.

    Kept deliberately small: it owns no sockets and does no I/O, it just answers
    "what is my next position". Three things it gets right, each one a bug found
    in a real capture:

    1. It never parks itself. An earlier version held station whenever the
       target was within 1500 units, but players stand much closer than that,
       so the bot simply froze and stopped following. Now it always closes to
       `stick_dist` (a couple of body widths) and only eases off inside that.

    2. It ramps speed up over distance and back down on arrival. The server
       snaps a player back when a single move is too large, so a far target is
       reached by gradually raising the step to `max_step`, and the step is
       reset the moment we are near - otherwise we overshoot and oscillate.

    3. It leads a moving target. Positions arrive about five times a second, so
       aiming at the last reported point always trails a running player. The
       target's own speed is measured and projected forward a fraction of a
       second. Prediction is skipped when we are already close, where it would
       only cause jitter.
    """

    def __init__(self, base_step=515, max_step=650, ramp=50,
                 far_dist=8000, stick_dist=150, lead=0.2):
        # Measured from the real client's own packets: it sends 10 updates a
        # second and moves at a median 5147 units/second, so one step is about
        # 515 units. Matching the game's own pace is what keeps the server
        # accepting the movement - earlier values were both too slow to keep up
        # and, when ramped, fast enough to look like a speed hack.
        self.base_step = base_step
        self.max_step = max_step      # 90th percentile of real player speed
        self.ramp = ramp
        self.far_dist = far_dist      # beyond this we speed up slightly
        # How close we get before holding station. This was 600, and a sniff of
        # the bot alongside the real client showed it parking half a pitch away
        # and looking frozen whenever the caller circled on the spot. 150 is
        # close enough to read as standing next to someone.
        self.stick_dist = stick_dist
        self.lead = lead              # seconds of prediction on a moving target
        self.step = base_step
        self._last_target = None
        self._last_time = None
        self._velocity = (0.0, 0.0)

    def reset(self):
        """Forget the previous target's motion - call when the caller changes."""
        self.step = self.base_step
        self._last_target = None
        self._last_time = None
        self._velocity = (0.0, 0.0)

    def track(self, target_pos, now):
        """Measure the target's speed from consecutive position updates."""
        if target_pos is None:
            return
        if self._last_target is not None and self._last_time is not None:
            dt = now - self._last_time
            if dt > 0.01:
                vx = (target_pos[0] - self._last_target[0]) / dt
                vz = (target_pos[2] - self._last_target[2]) / dt
                # a teleport would poison the prediction, so ignore huge jumps
                if abs(vx) < 20000 and abs(vz) < 20000:
                    self._velocity = (vx, vz)
                else:
                    self._velocity = (0.0, 0.0)
        self._last_target = target_pos
        self._last_time = now

    def next_position(self, my_pos, target_pos, now, dt=0.05):
        """Return (new_pos, dist, yaw) for this tick, or None if we cannot move.
        The returned position is always a small step - never a jump - so the
        movement reads as walking rather than teleporting.
        """
        if my_pos is None or target_pos is None:
            return None
        self.track(target_pos, now)

        # raw distance decides both the speed and whether to predict
        rdx = target_pos[0] - my_pos[0]
        rdz = target_pos[2] - my_pos[2]
        raw_dist = math.sqrt(rdx * rdx + rdz * rdz)

        # Follow the caller's height too. Keeping our own Y is what put the bot
        # on top of the player: on a roof or a slope the two sit metres apart
        # vertically even when the ground distance is nil. Easing into it
        # rather than snapping makes a stairway read as climbing.
        ty = target_pos[1] if len(target_pos) > 1 else my_pos[1]
        new_y = int(my_pos[1] + (ty - my_pos[1]) * 0.35)

        # lead a moving target, but only while there is ground to cover;
        # predicting at point-blank range just makes the bot wobble
        if raw_dist > self.far_dist:
            vx, vz = self._velocity
            aim = (target_pos[0] + vx * self.lead, target_pos[2] + vz * self.lead)
        else:
            aim = (target_pos[0], target_pos[2])

        dx = aim[0] - my_pos[0]
        dz = aim[1] - my_pos[2]
        dist = math.sqrt(dx * dx + dz * dz)
        yaw = int(math.degrees(math.atan2(dx, dz))) if dist >= 1 else 0

        # speed: ramp up when far, snap back to base as soon as we are near, so
        # arriving never carries the long-range speed into close quarters
        if raw_dist > self.far_dist:
            self.step = min(self.max_step, self.step + self.ramp * dt)
        else:
            self.step = self.base_step

        # close enough - hold station, but still settle onto their height.
        # The dist<1e-6 guard also stops a divide-by-zero when we are exactly
        # on the target, which crashed the movement thread.
        if dist <= self.stick_dist or dist < 1e-6:
            return (my_pos[0], new_y, my_pos[2]), raw_dist, yaw

        # Step a full stride unless that would overshoot the target itself.
        # Clamping to `dist - stick_dist` instead made the bot inch to the
        # boundary and stall there; overshooting the stick radius slightly is
        # harmless, stopping short of it is not.
        move = self.step if dist > self.step else dist
        nx = my_pos[0] + dx / dist * move
        nz = my_pos[2] + dz / dist * move
        return (int(nx), new_y, int(nz)), raw_dist, yaw


def send_position(sock, addr, key, order, my_player_id, old_pos, new_pos,
                  server_time, aim_yaw=0, speed=500, ping=90,
                  target_yrot=None, target_aim_y=None, target_aim_xz=None,
                  copy_state=None, copy_pose=None):
    """Send our new position as an unreliable C2S player-state (Cmd 2001).

    Every value below was read out of the real client's own packets, captured
    with WinDivert while walking in a match. A representative one:

        pos=(1182057, 5094, -419757)  vel=(-90, 0, -286)
        rot=(-30, 0, -95)             tdir=(-30, -95)
        physx=0/2                     aim=(-0.292, -0.214, -0.932)
        ping=82                       ServerTimeOnClient=36207

    The relationships that matter, none of which we had right before:

      Rotation is the heading as a unit vector scaled by 100 - (-30, 0, -95)
      has length 99.6 - and TargetDirection is the same vector with Y dropped.
      They are not angles.

      AimRotation is the same direction as a true unit vector, including a Y
      component for looking up or down, so rot is essentially aim * 100.

      PhysXPose is DASHING (2) while moving. STANDING is for standing still.

      Velocity length tracks actual speed: 300 while walking, 500 while
      running.

      Ping carries a real round-trip figure, never zero.
    """
    PHYSX_WALKING = 0        # EPHYSXSTATE_WALKING - on the ground
    PHYSX_POSE_DASHING = 2   # EPHYSXPOSE_DASHING - what a moving player sends
    PHYSX_POSE_STANDING = 0
    # Cast to int to avoid float << int errors in varint encoding
    new_pos = (int(new_pos[0]), int(new_pos[1]), int(new_pos[2]))
    old_pos = (int(old_pos[0]), int(old_pos[1]), int(old_pos[2]))
    dx = new_pos[0] - old_pos[0]
    dz = new_pos[2] - old_pos[2]
    dist = math.sqrt(dx * dx + dz * dz)
    if dist >= 1:
        ux, uz = dx / dist, dz / dist        # heading as a unit vector
        velocity = (int(ux * speed), 0, int(uz * speed))
        # rotation is that heading scaled by 100, and tdir is it without Y
        rotation = (int(ux * 100), 0, int(uz * 100))
        tdir = (int(ux * 100), int(uz * 100))
        aim = (ux, 0.0, uz)                  # unit vector, level gaze
        pose = PHYSX_POSE_DASHING
    else:
        # Standing still. The real client still reports a facing when it is not
        # moving - only the velocity drops to zero. Sending zeros for rotation
        # and aim as well produced a 35-byte "blank" packet next to the game's
        # 51-byte one, and a player frozen with no orientation at all. So we
        # keep pointing where the caller is instead.
        velocity = (0, 0, 0)
        if target_aim_xz is not None or target_aim_y is not None:
            fx = float(target_aim_xz or 0)
            fz = float(target_aim_y or 0)
            n = math.sqrt(fx * fx + fz * fz)
            if n > 0:
                fx, fz = fx / n, fz / n
        else:
            fx = fz = 0.0
        if fx == 0.0 and fz == 0.0:
            rad = math.radians(aim_yaw)
            fx, fz = math.sin(rad), math.cos(rad)
        rotation = (int(fx * 100), 0, int(fz * 100))
        tdir = (int(fx * 100), int(fz * 100))
        aim = (fx, 0.0, fz)
        pose = PHYSX_POSE_STANDING
    state = PHYSX_WALKING
    # Mirror the caller's own stance so the bot crouches, crawls, falls and
    # goes prone exactly when they do. The poses seen in real traffic are
    # STANDING, DASHING, CROUCHING, CREEPING, KNOCKDOWN and the two falling
    # ones; copying the pair straight across reproduces all of them. DASHING is
    # left to our own movement logic, since that depends on whether *we* are
    # running, not on what the caller is doing.
    if copy_state is not None:
        state = copy_state
    if copy_pose is not None and copy_pose != PHYSX_POSE_DASHING:
        pose = copy_pose
    body = build_c2s_player_state(
        player_id=my_player_id, pos=new_pos, rot=rotation,
        tdir=tdir, vel=velocity, aim_float=aim,
        server_time=server_time, physx_state=state,
        physx_pose=pose, ping=ping)
    pkt = encode_packet(CMD_PLAYER_STATE_UPLOAD, SENDOPTION_NONE, 0,
                        FLAG_ENCRYPTED, body, key, order)
    sock.sendto(pkt, addr)
    return velocity


# ---------------------------------------------------------------------------
# GRI sync (Cmd 1901) - match phase; Fight opens combat and lets us move
# ---------------------------------------------------------------------------

CMD_GRI_SYNC = 1901
def parse_gri_block(body):
    """Parse a GRI data block: u16 blockLen, then a run of
    u8 fieldId + varint value. Returns {fieldId: value}.

    Confirmed against a full Clash Squad capture. The earlier reading - a type
    byte before each field id, values as fixed-width integers - produced
    nonsense field numbers like 136 and 247; reading id-then-varint decodes
    every packet in the match cleanly.
    """
    if body is None or len(body) < 2:
        return {}
    block_len = struct.unpack_from("<H", body, 0)[0]
    p = 2
    # blockLen counts the field bytes that follow the header. Clamping to the
    # body length as well guards a truncated packet without cutting a valid
    # one short.
    end = min(2 + block_len, len(body))
    fields = {}
    while p < end:
        field_id = body[p]; p += 1
        if p >= end:
            break
        try:
            value, p = _rd_varint(body, p)
        except (IndexError, ValueError):
            break
        fields[field_id] = value
    return fields


# GRI field ids, read off the capture.
GRI_FIELD_ROUND = 2            # 1, 2, 3 ... as the rounds go by
GRI_FIELD_PHASE = 3            # start<<32 | phase<<16 | end

# Phases within a round. The cycle repeats exactly: buy, fight, round over.
PHASE_PREPARE = 1              # buy period, 24 seconds in the capture
PHASE_FIGHT = 3                # combat
PHASE_ROUND_END = 5
PHASE_NAMES = {1: "PREPARE", 2: "phase2", 3: "FIGHT", 4: "phase4",
               5: "ROUND_END"}


def get_match_phase(body):
    """Return (phase, round_no, start, end) from a Cmd 1901 packet.

    Field 3 packs three numbers: the server-time the phase began in the high
    32 bits, the phase itself in the next 16, and its end time in the low 16.
    A capture of four rounds shows the pattern without exception:

        round 1  PREPARE 8->27    FIGHT 63->70
        round 2  PREPARE 74->98   FIGHT 122->129
        round 3  PREPARE 133->157 FIGHT 187->194
        round 4  PREPARE 198->222 FIGHT 240->247

    Not every field 3 is a packed phase though. The first GRI of a match is a
    twelve-field block where field 3 is a plain small number - 11 in a capture
    - and unpacking that yields phase 0, a phase that does not exist. Every
    genuine packed value in two captures exceeds 0x10000, because the phase
    itself sits above that bit, so anything smaller is an ordinary field and
    is reported as no phase at all.

    Returns None when this packet carries no phase - most GRI packets only
    update a counter, and that is normal rather than an error.
    """
    fields = parse_gri_block(body)
    if GRI_FIELD_PHASE not in fields:
        return None
    value = fields[GRI_FIELD_PHASE]
    if value < 0x10000:
        return None
    phase = (value >> 16) & 0xFFFF
    start = (value >> 32) & 0xFFFFFFFF
    end = value & 0xFFFF
    return phase, fields.get(GRI_FIELD_ROUND), start, end


# ---------------------------------------------------------------------------
# Cmd 2012 - UDP_PLAYER_STATE_SYNC_V2: where the OTHER players' movement is
# ---------------------------------------------------------------------------
#
# Confirmed by decoding real captures: after a 2-byte header the body is a run
# of fixed 20-byte records, one per player, then a trailing TickCount varint.
# Each record opens with ShortPlayerID and three zigzag varints for Position;
# the remaining bytes (velocity/rotation/state) are not needed for following.
#
# Record order changes between packets, so always read ShortPlayerID from the
# record rather than trusting position in the list.

CMD_PLAYER_STATE_V2 = 2012
PLAYER_RECORD_SIZE = 20

# UDP_SYNC_SERVER_TIME. MPMatch keeps m_BaseServerTime and m_BaseClientTime and
# derives ServerTimeOnClient from them, so the value we put in every movement
# packet must be the SERVER's clock, not ours. Captures show it starting near
# zero at match start and advancing ~30 ticks per second - sending a unix
# millisecond timestamp instead (billions) makes the server treat our packets
# as stale and silently drop them, which is what left the bot standing still
# for long stretches.
CMD_SYNC_SERVER_TIME = 2000
SERVER_TICKS_PER_SECOND = 30.0


class ServerClock:
    """Keeps the match clock in step with the server, the way MPMatch does.

    S2C_UDP_SyncServerTime_Req (Cmd 2000) carries ServerGameTickCount and a
    Phase byte, and the client stores it as m_LastValidServerGameTickCount.
    Between those updates the tick is interpolated, so every packet we send
    carries a current, plausible game tick rather than a wall-clock value.
    """

    def __init__(self):
        self.base_tick = None      # ServerGameTickCount at the last sync
        self.base_local = None     # local time.time() when it arrived
        self.phase = 0
        self.rate = SERVER_TICKS_PER_SECOND

    def sync(self, tick, phase, now):
        """Apply a Cmd 2000. Also re-estimates the tick rate from consecutive
        updates, so we track the server's real pace instead of assuming one."""
        if self.base_tick is not None and self.base_local is not None:
            dt = now - self.base_local
            dtick = tick - self.base_tick
            if dt > 0.5 and 0 < dtick < 10000:
                measured = dtick / dt
                # smooth it; a single jittery sample should not swing the clock
                self.rate = self.rate * 0.7 + measured * 0.3
        self.base_tick = tick
        self.base_local = now
        self.phase = phase

    def now(self, now):
        """Value for ServerTimeOnClient: match time in MILLISECONDS.

        Confirmed by sniffing the real client. Its packets carry 56303, 56402,
        56501 ... - rising ~1000 per second, i.e. milliseconds since the match
        began, NOT a unix timestamp and not the raw Cmd 2000 tick. The tick
        counter advances 30 per second, so the two relate by 1000/30.

        Sending a unix millisecond timestamp here (billions) is why the server
        discarded our movement: the value sits impossibly far in the future
        compared to its own match clock.
        """
        if self.base_tick is None:
            return 0
        elapsed = now - self.base_local
        ticks = self.base_tick + elapsed * self.rate
        return int(ticks * 1000.0 / self.rate) & 0xFFFFFFFF


def decode_server_time(body):
    """Cmd 2000: UInt32 ServerGameTickCount then Byte Phase.
    Returns (tick, phase)."""
    if body is None or len(body) < 1:
        return None
    try:
        tick, p = _rd_varint(body, 0)
        phase = body[p] if p < len(body) else 0
    except (IndexError, ValueError):
        return None
    return tick, phase


def build_server_time_ack(tick):
    """C2S_UDP_SyncServerTime_Res: echo the tick straight back.

    The client answers every time sync, and the server uses that round trip to
    judge whether a client is keeping up. Never replying is what lets it treat
    us as out of sync and start ignoring our movement.
    """
    o = bytearray()
    _put_varint(o, tick & 0xFFFFFFFF)
    return bytes(o)


def decode_players_v2(body):
    """Return {ShortPlayerID: {...}} for every player in a Cmd 2012 body.

    Records are VARIABLE length, not a fixed stride. A captured 66-byte packet
    holding three players decodes as 22, 21 and 19 bytes - the varint fields
    (position, velocity, platform id) shrink and grow with their values. An
    earlier version walked the body in fixed 20-byte steps, which drifted out
    of alignment after the first record and silently lost every player behind
    it. That is why the follow target kept vanishing from the roster - in one
    capture it was found in only 9 of 51 packets - and the bot stood still.

    Reading the fields in order consumes each record exactly, so the whole
    packet parses and no player is missed.

    Layout per record (POptimizedSyncedPlayerState):
        ShortPlayerID   byte
        Position        3 x zigzag varint
        Velocity        3 x zigzag varint
        PlayerYRotation byte
        AimYRotation    byte
        AimXZRotation   byte
        PhysXState      byte
        PhysXPose       byte
        MovePlatformID  varint
        CustomParam     byte
    """
    players = {}
    if body is None or len(body) < 4:
        return players
    p = 2                                  # skip MatchTime + count header
    while p < len(body) - 1:
        try:
            short_id = body[p]; p += 1
            x, p = _rd_varint(body, p)
            y, p = _rd_varint(body, p)
            z, p = _rd_varint(body, p)
            vx, p = _rd_varint(body, p)
            vy, p = _rd_varint(body, p)
            vz, p = _rd_varint(body, p)
            yrot = body[p]; p += 1
            aim_y = body[p]; p += 1
            aim_xz = body[p]; p += 1
            physx_state = body[p]; p += 1
            physx_pose = body[p]; p += 1
            platform, p = _rd_varint(body, p)
            custom = body[p]; p += 1
        except (IndexError, ValueError):
            break
        pos = (_zag(x), _zag(y), _zag(z))
        # a record decoding to nonsense means alignment was lost; stop rather
        # than poison the roster with bogus ids and positions
        if not (1 <= short_id <= 64) or any(abs(v) > 4000000 for v in pos):
            break
        players[short_id] = {
            "pos": pos,
            "vel": (_zag(vx), _zag(vy), _zag(vz)),
            "yrot": yrot, "aim_y": aim_y, "aim_xz": aim_xz,
            "physx_state": physx_state, "physx_pose": physx_pose,
            "platform": platform, "custom": custom,
        }
    return players


# ---------------------------------------------------------------------------
# Cmd 551 - RUDP_SYNC_QUICK_CHAT: "follow me" / "help me" and who sent it
# ---------------------------------------------------------------------------
#
# S2C_RUDP_Send_Quick_Chat_res opens with QuickChatID, ItemID, SenderID.
# SenderID is a packed PlayerID (struct PlayerID { m_Value, m_ID, m_TeamID,
# m_ShortID, m_IDMask }): the low byte is the ShortPlayerID used everywhere
# else, the high byte is the team. Confirmed on a real capture where
# SenderID 0x02000007 resolved to ShortPlayerID 7, which was present in the
# matching Cmd 2012 player list.

CMD_QUICK_CHAT = 551
QUICK_CHAT_FOLLOW_ME = 1
QUICK_CHAT_HELP_ME = 2
QUICK_CHAT_NAMES = {1: "follow me", 2: "help me"}

# Only these quick chats retarget the bot. A real capture showed plenty of
# other ids flying around (9, 1002, 1003, 1010, 3010, ...) - those are other
# canned lines, pings and stickers. Reacting to every id made the bot chase
# whoever happened to speak last, which is why it followed the wrong player.
QUICK_CHAT_FOLLOW_TRIGGERS = (QUICK_CHAT_FOLLOW_ME, QUICK_CHAT_HELP_ME)


def decode_quick_chat(body):
    """Return (quick_chat_id, sender_short_id, sender_raw, team_id) or None."""
    if body is None or len(body) < 3:
        return None
    try:
        p = 0
        chat_id, p = _rd_varint(body, p)
        _item_id, p = _rd_varint(body, p)
        sender, p = _rd_varint(body, p)
    except (IndexError, ValueError):
        return None
    return chat_id, sender & 0xFF, sender, (sender >> 24) & 0xFF


# ---------------------------------------------------------------------------
# Follow-the-caller: chase whoever sends a quick chat
# ---------------------------------------------------------------------------


class PlayerFollower:
    """Follows the player who last sent a quick chat, and keeps following them
    until somebody else calls.

    The design separates WHO from WHERE, because the two arrive on channels with
    different guarantees:

      Cmd 551 is RELIABLE - a one-shot event that is guaranteed to arrive, but
      only once. It tells us who to follow, so we latch the target and keep it.

      Cmd 2012 is UNRELIABLE - a continuous stream where packets can be dropped
      and the record order changes. It tells us where that player currently is,
      so we refresh the target's position from every packet that contains them.

    Waiting for coordinates at the moment the chat arrives would be wrong: the
    unreliable stream may not carry the target in that exact instant. Latching
    the id and refreshing the position separately makes the follow robust to
    dropped packets - if the target is missing from a packet we simply keep
    walking toward their last known position.
    """

    def __init__(self, step=200, resync_dist=400000):
        # step is per movement tick. We tick every 50ms for smooth motion, so
        # 200 units/tick is 4000 units/second - the median speed of a real
        # running player measured from a capture. Stepping in large jumps once
        # per server broadcast instead made the bot lurch and appear stuck
        # between packets.
        self.step = step
        # Only snap to the server's position when it differs by more than this.
        # It must stay well above the distance we cover between echoes,
        # otherwise every echo drags us backwards - that was the "running
        # backwards" behaviour.
        self.resync_dist = resync_dist
        self.target_short = None   # ShortPlayerID we are following
        self.target_pos = None     # their last known (x, y, z)
        self.my_player_id = None   # our FULL PlayerID, e.g. 0x02000005
        self.my_short = None       # our ShortPlayerID, e.g. 5
        self.my_pos = None         # our last known (x, y, z)
        self.last_yaw = 0
        self.roster = {}           # ShortPlayerID -> (full_player_id, name)
        # the caller's own facing, copied so we look where they look
        self.target_yrot = 0
        self.target_aim_y = 0
        self.target_aim_xz = 0
        # dead-reckoning state: when we last actually saw the target, and how
        # fast they were moving, so we can coast through gaps in the broadcast
        self.target_seen_at = None
        self.target_vel = (0.0, 0.0)
        # the caller's stance, mirrored so the bot copies their movements
        self.target_state = 0
        self.target_pose = 0

    def add_player(self, full_player_id, name):
        """Record a player from Cmd 101. The roster maps the ShortPlayerID that
        appears in the movement stream back to the full PlayerID and name.
        Joins arrive once, in the first seconds of the match."""
        self.roster[full_player_id & 0xFF] = (full_player_id, name)

    def set_me(self, full_player_id):
        """Our own identity, taken from the Cmd 101 that carries our account.
        Uploads must use the FULL PlayerID; lookups use the low byte."""
        self.my_player_id = full_player_id
        self.my_short = full_player_id & 0xFF

    def on_quick_chat(self, chat_id, sender_short_id):
        """A quick chat arrived. Only "follow me" and "help me" retarget us -
        every other canned line is ignored, otherwise the bot chases whoever
        spoke last. Returns True when the target was (re)set.

        The cached position is deliberately NOT cleared here. The movement
        stream only carries a given player in roughly half its packets, so
        wiping the last known position on every request left the bot with
        nothing to walk toward until that player happened to reappear - which
        is exactly the "sometimes it doesn't follow" behaviour. Keeping the
        last position means we start moving immediately and refine the aim as
        soon as a packet carrying them arrives.
        """
        if chat_id not in QUICK_CHAT_FOLLOW_TRIGGERS:
            return False
        if self.my_short is not None and sender_short_id == self.my_short:
            return False           # never follow ourselves
        if sender_short_id != self.target_short:
            # different player: their old position is meaningless, drop it
            self.target_pos = None
        # Any new call clears the stale motion estimate. Without this a repeat
        # call reused a velocity measured minutes earlier, and the bot walked
        # off toward where that old vector pointed instead of toward the caller
        # - which is why calling it over from close by sometimes did nothing.
        self.target_vel = (0.0, 0.0)
        self.target_seen_at = None
        self.target_short = sender_short_id
        return True

    def on_players(self, players):
        """A Cmd 2012 arrived: refresh the target's position, facing and stance.

        Note we do NOT look for ourselves in here. A sniff of the live traffic
        showed the server splits the two streams: Cmd 2001 carries only our own
        player, and Cmd 2012 carries only the others - our own ShortPlayerID
        never appears in it. Searching for it was dead code.

        A target missing from one packet is normal, not a reason to stop: we
        keep the last known values and record when we last saw them, which lets
        the chase dead-reckon through the gaps instead of stalling.
        """
        if self.target_short is None or self.target_short not in players:
            return
        t = players[self.target_short]
        prev_pos = self.target_pos
        prev_seen = self.target_seen_at
        self.target_pos = t["pos"]
        self.target_seen_at = time.time()
        # measure the target's own speed so we can carry on in a straight
        # line while they are missing from the broadcast
        if prev_pos is not None and prev_seen is not None:
            dt = self.target_seen_at - prev_seen
            if 0.01 < dt < 2.0:
                vx = (self.target_pos[0] - prev_pos[0]) / dt
                vz = (self.target_pos[2] - prev_pos[2]) / dt
                if abs(vx) < 30000 and abs(vz) < 30000:
                    self.target_vel = (vx, vz)
        self.target_yrot = t["yrot"]
        self.target_aim_y = t["aim_y"]
        self.target_aim_xz = t["aim_xz"]
        # Their stance, so we crouch, crawl and fall along with them. The
        # server relays a pose change about 190ms after the player makes it, so
        # we adopt it the instant it arrives rather than smoothing it further -
        # any extra delay on our side is delay the viewer can see.
        self.target_state = t.get("physx_state", self.target_state)
        self.target_pose = t.get("physx_pose", self.target_pose)

    def predicted_target(self, now, max_coast=3.0):
        """Where the target is right now, including while they are absent from
        the broadcast.

        This is what stops the bot dying at the last reported point when the
        caller runs off: for up to `max_coast` seconds we keep extending their
        last known velocity, so the chase continues in the direction they were
        heading rather than freezing. Past that the projection would be
        guesswork, so we fall back to the last solid position.
        """
        if self.target_pos is None:
            return None
        if self.target_seen_at is None:
            return self.target_pos
        gap = now - self.target_seen_at
        if gap <= 0.05 or gap > max_coast:
            return self.target_pos
        vx, vz = self.target_vel
        return (int(self.target_pos[0] + vx * gap),
                self.target_pos[1],
                int(self.target_pos[2] + vz * gap))

    def set_my_position(self, pos):
        """Our position as the server sees us.

        We do NOT blindly overwrite our own position on every packet: our
        stepping is what drives the walk, and the server echoes our position
        back many times per second. Overwriting each time would cancel every
        step and leave the bot standing still.

        The threshold has to clear the distance a long chase legitimately
        covers between echoes. At 515 units per tick and 10 ticks a second we
        move 5150 units/second, so a 50000 threshold was crossed after ten
        seconds of running and yanked the bot back to a stale server position
        mid-journey - the stall that happened on the way to a distant caller.
        A far higher bar still catches a genuine teleport or knockback while
        leaving normal travel alone.
        """
        if self.my_pos is None:
            self.my_pos = pos
            return
        dx = pos[0] - self.my_pos[0]
        dz = pos[2] - self.my_pos[2]
        if math.sqrt(dx * dx + dz * dz) > self.resync_dist:
            self.my_pos = pos

    def step_toward_target(self):
        """One step toward the target. Returns (old_pos, new_pos, dist, yaw)
        or None when there is nothing to chase yet."""
        if self.target_pos is None or self.my_pos is None:
            return None
        old_pos = self.my_pos
        dx = self.target_pos[0] - self.my_pos[0]
        dz = self.target_pos[2] - self.my_pos[2]
        dist = math.sqrt(dx * dx + dz * dz)
        if dist >= 1:
            self.last_yaw = int(math.degrees(math.atan2(dx, dz)))
        yaw = self.last_yaw
        if dist <= self.step:
            self.my_pos = (self.target_pos[0], self.my_pos[1], self.target_pos[2])
        else:
            nx = self.my_pos[0] + dx / dist * self.step
            nz = self.my_pos[2] + dz / dist * self.step
            self.my_pos = (int(nx), self.my_pos[1], int(nz))
        return old_pos, self.my_pos, dist, yaw
