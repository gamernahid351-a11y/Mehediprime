# ============================================================
# RASIN                        X                        MEHEDI
# ============================================================
import sys, os, json, time, uuid, random, asyncio, base64, struct, socket
import itertools, traceback, ssl, hmac, hashlib, string, re, subprocess
import httpx
import aiohttp
import aiohttp.web
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception: pass

from google_play_scraper import app as play_scraper
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from protobuf_decoder.protobuf_decoder import Parser
from message_ids import MESSAGE_ID_TO_NAME
import thunderFF_pb2

import config as _cfg
import tools as _tools
import toolsudp as _toolsudp
import ff_udp as _ff_udp
import ff_match as _ff_match

import infoClan_pb2

try:
    import StartMatch_pb2
except Exception:
    StartMatch_pb2 = None

try:
    import reqClan_pb2
    _CLAN_PB_AVAILABLE = True
except Exception:
    _CLAN_PB_AVAILABLE = False

# ==================== CONFIG ====================
WEB_HOST = "0.0.0.0"
WEB_PORT = 1234
TOKEN_CACHE_FILE = "token_cache.json"
DEVICES_FILE = "devices.json"
TOKEN_CACHE_TTL = 1200
INDEX_HTML_PATH = "index.html"

TEAMS_DIR = "ss"
os.makedirs(TEAMS_DIR, exist_ok=True)

START_MATCH_INTERVAL = 5.0
NEW_MATCH_DELAY = 4.0
MAX_MATCH_DURATION = 1500
MATCH_IDLE_TIMEOUT  = 90.0

_accept_friend_request = True
DEBUG_ALL_PACKETS = False

# ── ALWAYS SQUAD. NEVER SOLO. ──
TEAM_SIZE = 4
TEAM_READY_DELAY = 6.0
TEAM_INVITE_WAIT = 2.5
CLAN_ID_DEFAULT = "3105331459"

AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
KEYSTREAM = bytes([0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30])
HEX_KEY = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
API_KEY = HEX_KEY.encode()

REGION_LANG = {"ME":"ar","IND":"hi","ID":"id","VN":"vi","TH":"th","BD":"bn",
               "PK":"ur","TW":"zh","RU":"ru","SAC":"es","BR":"pt","NA":"pt",
               "SG":"pt","US":"pt"}

# ==================== STATE ====================
class BotState:
    def __init__(self):
        self.accounts: Dict[str, dict] = {}
        self.account_credentials: Dict[str, dict] = {}
        self.account_workers: Dict[str, asyncio.Task] = {}
        self.auth_to_game_id: Dict[str, str] = {}
        self.game_to_auth_id: Dict[str, str] = {}
        self.account_token_map: Dict[str, str] = {}
        self.paused: set = set()
        self.writers: Dict[str, list] = {}
        self.logs: List[dict] = []
        self.total_matches = 0
        self.matches_started = 0
        self.total_exp_gained = 0
        self.create_progress: List[str] = []
        self.creating = False
        self.start_time = time.time()
        self._writer_lock = asyncio.Lock()
        self._clan_cache = {}

    def log(self, msg, level="info"):
        try:
            t = datetime.now().strftime("%H:%M:%S")
            self.logs.append({"t": time.time(), "time": t, "message": str(msg), "level": level})
            if len(self.logs) > 500:
                self.logs = self.logs[-500:]
        except Exception:
            pass

    def register_account(self, uid, nickname, region="BD", level=1, exp=0,
                         likes=0, token=None, auth_uid=None):
        uid = str(uid)
        existing = self.accounts.get(uid, {})
        self.accounts[uid] = {
            "uid": uid, "nickname": nickname, "region": region,
            "level": level, "exp": exp, "likes": likes,
            "token": token, "auth_uid": auth_uid,
            "status": "ONLINE",
            "current_exp": exp,
            "initial_exp": existing.get("initial_exp", exp),
            "gained_exp": existing.get("gained_exp", 0),
            "matches": existing.get("matches", 0),
            "active_matches": 0,
            "uptime_seconds": existing.get("uptime_seconds", 0),
            "last_match_time": existing.get("last_match_time", "Running..."),
            "is_paused": False,
        }

    def update_status(self, uid, status, matches=0):
        uid = str(uid)
        if uid in self.accounts:
            self.accounts[uid]["status"] = status
            self.accounts[uid]["active_matches"] = matches
            self.accounts[uid]["is_paused"] = (status == "PAUSED")

    def update_exp(self, uid, exp, level=None):
        uid = str(uid)
        if uid in self.accounts:
            a = self.accounts[uid]
            old = a.get("current_exp", 0)
            if exp > old:
                a["gained_exp"] = a.get("gained_exp", 0) + (exp - old)
                self.total_exp_gained += (exp - old)
            a["current_exp"] = exp
            a["exp"] = exp
            if level: a["level"] = level

    def increment_match(self, uid):
        self.total_matches += 1
        uid = str(uid)
        if uid in self.accounts:
            self.accounts[uid]["matches"] = self.accounts[uid].get("matches", 0) + 1
            self.accounts[uid]["last_match_time"] = datetime.now().strftime("%H:%M:%S")

    def increment_match_started(self):
        self.matches_started += 1

    def register_writer(self, uid, w):
        self.writers.setdefault(str(uid), []).append(w)

    def unregister_writer(self, uid, w):
        try: self.writers.get(str(uid), []).remove(w)
        except Exception: pass

    def close_writers_for_account(self, uid):
        for w in list(self.writers.get(str(uid), [])):
            try: w.close()
            except Exception: pass
        self.writers[str(uid)] = []

    def is_paused(self, uid):
        return str(uid) in self.paused

    def toggle_pause(self, uid, state):
        uid = str(uid)
        if state:
            self.paused.add(uid)
            if uid in self.accounts:
                self.accounts[uid]["is_paused"] = True
                self.accounts[uid]["status"] = "PAUSED"
        else:
            self.paused.discard(uid)
            if uid in self.accounts:
                self.accounts[uid]["is_paused"] = False
                if self.accounts[uid].get("status") == "PAUSED":
                    self.accounts[uid]["status"] = "ONLINE"

bot_state = BotState()

# ==================== FULL SCRIPT RESTART ====================
RESTART_MARKER = "restart.marker"
_group_match_done: Dict[str, int] = {}
_group_restart_lock = asyncio.Lock()
_restart_scheduled: Dict[str, bool] = {}

# ==================== MATCH START WATCHDOG ====================
# If no 0300 (match found) is observed for this many seconds across the group,
# the WHOLE process restarts. Default 20 min — app.py overrides at startup.
MATCH_START_WATCHDOG = 20 * 60  # 1200 seconds
_group_last_match_start: Dict[str, float] = {}
_group_in_match: Dict[str, bool] = {}
_watchdog_tasks: Dict[str, asyncio.Task] = {}

def _full_script_restart(reason: str = ""):
    """Nuclear option: kill and replace the whole Python process."""
    try:
        with open(RESTART_MARKER, "w", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} | {reason}\n")
    except Exception:
        pass
    print_warning("=" * 60)
    print_warning(f"[RESTART] FULL SCRIPT RESTART")
    print_warning(f"[RESTART] reason: {reason}")
    print_warning(f"[RESTART] exec: {sys.executable} {' '.join(sys.argv)}")
    print_warning("=" * 60)
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass
    time.sleep(0.8)
    try:
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as e:
        print_error(f"[RESTART] execv failed: {e}")
        try:
            import subprocess
            subprocess.Popen([sys.executable] + sys.argv)
            time.sleep(1.0)
            os._exit(0)
        except Exception as e2:
            print_error(f"[RESTART] subprocess also failed: {e2}")
            os._exit(1)

async def _on_match_complete(group_id: str, uid: str):
    """One bot finished its match. Increment group counter, schedule restart when all done."""
    gid = str(group_id or "default")
    # WATCHDOG: reset flags — restart is already pending from this call
    _group_in_match[gid] = False
    _group_last_match_start[gid] = time.time()
    async with _group_restart_lock:
        _group_match_done[gid] = _group_match_done.get(gid, 0) + 1
        count = _group_match_done[gid]
        already = _restart_scheduled.get(gid, False)
        if not already:
            _restart_scheduled[gid] = True
    print_warning(f"[RESTART] {uid} → group {gid}: {count}/{TEAM_SIZE} matches done")
    if not already:
        asyncio.create_task(_wait_and_restart_group(gid))

async def _wait_and_restart_group(group_id: str):
    """Wait up to 90s for all TEAM_SIZE bots to finish, then restart the whole script."""
    gid = str(group_id or "default")
    for _ in range(180):
        async with _group_restart_lock:
            count = _group_match_done.get(gid, 0)
        if count >= TEAM_SIZE:
            break
        await asyncio.sleep(0.5)
    async with _group_restart_lock:
        final = _group_match_done.get(gid, 0)
    _full_script_restart(reason=f"group {gid}: {final}/{TEAM_SIZE} matches done")


# ==================== MATCH START WATCHDOG ====================
def _on_match_start(group_id: str, uid: str):
    """Called the instant a 0300 (match found) packet arrives for any bot."""
    gid = str(group_id or "default")
    _group_last_match_start[gid] = time.time()
    _group_in_match[gid] = True
    print_info(f"[WATCHDOG] {uid} → group {gid}: timer reset (match started)")


async def _watchdog_loop(group_id: str):
    """Restart the whole script if no match starts within MATCH_START_WATCHDOG."""
    gid = str(group_id or "default")
    _group_last_match_start.setdefault(gid, time.time())
    try:
        while True:
            await asyncio.sleep(30)
            # Skip while a match is actively running
            if _group_in_match.get(gid, False):
                continue
            last = _group_last_match_start.get(gid, 0.0)
            if last <= 0:
                _group_last_match_start[gid] = time.time()
                continue
            idle = time.time() - last
            if idle >= MATCH_START_WATCHDOG:
                print_warning(
                    f"[WATCHDOG] group {gid}: no match started for {idle:.0f}s "
                    f"(≥ {MATCH_START_WATCHDOG:.0f}s) → FULL SCRIPT RESTART"
                )
                _full_script_restart(
                    reason=f"watchdog: group {gid} no match start for {int(idle)}s"
                )
                return
    except asyncio.CancelledError:
        raise
    except Exception as e:
        print_error(f"[WATCHDOG] loop error: {e}")


def _ensure_watchdog(group_id: str):
    """Start (or confirm running) the watchdog task for this group."""
    gid = str(group_id or "default")
    if gid in _watchdog_tasks and not _watchdog_tasks[gid].done():
        return
    _group_last_match_start.setdefault(gid, time.time())
    _group_in_match.setdefault(gid, False)
    _watchdog_tasks[gid] = asyncio.create_task(_watchdog_loop(gid))
    print_info(f"[WATCHDOG] armed for group {gid} (timeout {MATCH_START_WATCHDOG:.0f}s)")


# ==================== PER-GROUP TEAM STATE ====================
_team_states: Dict[str, dict] = {}
_team_states_lock = asyncio.Lock()


def get_team_state(group_id: str) -> dict:
    gid = str(group_id or "default")
    if gid not in _team_states:
        _team_states[gid] = {
            "peers": {},
            "leader_uid": None,
            "team_code": None,
            "lock": asyncio.Lock(),
        }
    return _team_states[gid]


def drop_team_state(group_id: str):
    gid = str(group_id or "default")
    ts = _team_states.get(gid)
    if ts and not ts["peers"]:
        _team_states.pop(gid, None)

# ==================== PRINT HELPERS ====================
class C:
    GREEN='\033[92m'; FAIL='\033[91m'; WARNING='\033[93m'
    CYAN='\033[96m'; MAGENTA='\033[95m'; WHITE='\033[97m'; ENDC='\033[0m'

def print_success(t): print(f"{C.GREEN}[+] {t}{C.ENDC}"); bot_state.log(t, "success")
def print_error(t):   print(f"{C.FAIL}[-] {t}{C.ENDC}");   bot_state.log(t, "error")
def print_warning(t): print(f"{C.WARNING}[!] {t}{C.ENDC}"); bot_state.log(t, "warning")
def print_info(t):    print(f"{C.CYAN}[i] {t}{C.ENDC}");   bot_state.log(t, "info")

GGRE_RAW = bytes.fromhex(
    "47475245010101006d020000b260ee08e1f86b4c57f9c70f86bba26ed5d1436bcf52e142db3249d905eded757764991ca31a8373cdd26eab91b80f3f1f6f262f4f10b895d7b6937ddba30a27197453890e9da49373f736c679b8254e2f8e1623e91084a5fdd5374fe478ff99e010834553fddeb0bec4018d142e49df9bb236675b67e852f92a43586f7a7d4d0d7a197a1d4da32714dab4d069ad53214e2c33b3877420a12459738c4c619cbd815fa878bbd104776bb3e1ac7818d5397b04a666ac57f682763ff2df31bc2f846ddc7904f3dce1bda0c4b01f9698e9166f98c84f92640abe3f6317834a42e5c12573b46842c1a6ea8fe6ca9c006dca48a2087e1f983dfb5692771e4a0b15b337ad669b1d08b40862b176bace5331b49a767375b1a8469012aa70a67b55fe71b72478201d0b3ac7269c064c960361e92ee7ba8a42cc6b582bf9b965fb388fa9172ad44c4b073ac23c02080a6bcd106b691ffdf4c7cf71e42f2063fcf196e9bddc5e85be1fe5048eb1b31b460efbb46d76195eef9904c4cba326f2e17ff51fec17dd965aa06dadd4ab07d6966e4a7c38e8afd66dfde56c872bb87516a8f7313c797e4d80e5ad4a5f7afad95c1e0449254adae052e71a3fb98399f93ab30848e0d23252dd45e6fd41bc5fa7303dfb846a8fd713a0032a0b0ae96dfba1bbe41d20abd8099e2cb7fccc329d25bd153029139ef05d090a5093ea557693c0a8d491395b8a23ca844b3887dd5dfc29ac06f4b9be87883a793211b973465e2644c4f5de02b8ab01571401203fc2740423826858cc6da0194c195d27aac4ec4b9d23d506c1501d06440aca3fc180926d75d4a004d3dff21eb4ea1e8c86e6c9627248eff953e1d192d5c8efc006a7e512388ef2ebdb72ee3ad42d719f28e8f994e12ebf4c79f2ffe3abd7408ccd2236a7b89b2606247a732c10c4"
)

def _encode_proto_std(fields):
    out = b""
    for f in sorted(fields.keys()):
        v = fields[f]
        if isinstance(v, bool):
            out += encode_varint((f << 3) | 0) + encode_varint(int(v))
        elif isinstance(v, int):
            out += encode_varint((f << 3) | 0) + encode_varint(v)
        elif isinstance(v, (str, bytes)):
            if isinstance(v, str): v = v.encode()
            out += encode_varint((f << 3) | 2) + encode_varint(len(v)) + v
    return out

async def major_register(release_v, access_token, open_id, name, game_version,
                          login_url, lang_code="en"):
    field14 = bytes(ord(c) ^ KEYSTREAM[i % 32] for i, c in enumerate(open_id))
    fields = {
        1: name, 2: access_token, 3: open_id,
        5: 102000007, 6: 4, 7: 1, 13: 1, 14: field14, 15: lang_code,
        16: 2, 20: game_version, 21: 1, 22: GGRE_RAW,
    }
    proto = _encode_proto_std(fields)
    payload = AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(proto, 16))
    url = f"{login_url.rstrip('/')}/MajorRegister"
    hdrs = {
        "Accept": "*/*", "Authorization": "Bearer ",
        "Content-Type": "application/x-www-form-urlencoded",
        "ReleaseVersion": f"{release_v}",
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "X-GA": "v1 1", "X-GA-SV": str(int(time.time())),
        "X-Unity-Version": "2018.4.12f1",
    }
    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False; ssl_ctx.verify_mode = ssl.CERT_NONE
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as s:
            async with s.post(url, headers=hdrs, data=payload, ssl=ssl_ctx) as resp:
                content = await resp.read()
                print_info(f"[MAJOR-REG] status={resp.status} len={len(content)}")
                if resp.status != 200 or not content: return None
                for off in [0, 64, 48, 32, 16]:
                    if off >= len(content): continue
                    try:
                        r = decode_protobuf_2(content[off:])
                        if r and 3 in r:
                            print_success(f"[MAJOR-REG] decoded at offset {off}")
                            return {str(k): {"data": v} for k, v in r.items()}
                    except Exception: pass
                if len(content) % 16 == 0:
                    try:
                        pt = AES.new(AES_KEY, AES.MODE_CBC, AES_IV).decrypt(content)
                        pad_len = pt[-1]
                        if 1 <= pad_len <= 16 and all(b == pad_len for b in pt[-pad_len:]):
                            pt = pt[:-pad_len]
                        r = decode_protobuf_2(pt)
                        if r and 3 in r:
                            print_success(f"[MAJOR-REG] decrypted")
                            return {str(k): {"data": v} for k, v in r.items()}
                    except Exception: pass
                return None
    except Exception as e:
        print_error(f"[MAJOR-REG] {e}"); return None


# ==================== CLAN INFO ====================
def _enc_clan_req(clan_id: int) -> Optional[bytes]:
    try:
        msg = infoClan_pb2.GuildReq()
        msg.guildId = int(clan_id)
        msg.garena = 1
        raw = msg.SerializeToString()
        return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(raw, AES.block_size))
    except Exception as e:
        print_error(f"[CLAN-ENC] {e}")
        return None


def _decode_repeated(data: bytes) -> list:
    results = []
    offset = 0
    data_len = len(data)
    while offset < data_len:
        header, offset = decode_varint(data, offset)
        if header is None: break
        fn = header >> 3; wt = header & 0x7
        if wt == 2:
            length, offset = decode_varint(data, offset)
            if length is None: break
            value = data[offset:offset+length]; offset += length
            if fn == 1:
                nested = decode_protobuf_2(value)
                results.append(nested)
        elif wt == 0:
            _, offset = decode_varint(data, offset)
        elif wt == 1: offset += 8
        elif wt == 5: offset += 4
        else: break
    return results


async def get_clan_info(jwt_token: str, clan_id: str) -> Optional[Dict]:
    if not _CLAN_PB_AVAILABLE:
        return None

    payload = _enc_clan_req(int(clan_id))
    if not payload:
        return None

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    hdrs_main = {
        "User-Agent":      "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept":          "*/*",
        "Accept-Encoding": "deflate, gzip",
        "Authorization":   f"Bearer {jwt_token}",
        "Content-Type":    "application/x-www-form-urlencoded",
        "X-GA":            "v1 1",
        "X-GA-SV":         str(int(time.time())),
        "ReleaseVersion":  "OB55",
        "X-Unity-Version": "2022.3.47f1",
        "Host":            "clientbp.ppmainecoonghj.com",
    }
    hdrs_members = {**hdrs_main,
        "User-Agent":      "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "X-Unity-Version": "2018.4.12f1",
    }

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
            clan_info_result = {}
            async with s.post(
                "https://clientbp.ppmainecoonghj.com/GetClanMainPageInfo",
                headers=hdrs_main, data=payload, ssl=ssl_ctx
            ) as r:
                if r.status == 200:
                    binary = await r.read()
                    if binary and len(binary) >= 10:
                        raw = decode_protobuf_2(binary)
                        guild = raw.get(1, {})
                        if isinstance(guild, dict):
                            clan_info_result = {
                                "clan_id":      int(guild.get(1, int(clan_id)) or int(clan_id)),
                                "clan_name":    str(guild.get(2, "") or ""),
                                "leader_uid":   int(guild.get(4, 0) or 0),
                                "region":       str(guild.get(13, "") or ""),
                                "level":        int(guild.get(5, 0) or 0),
                                "capacity":     int(guild.get(6, 0) or 0),
                                "member_count": int(guild.get(7, 0) or 0),
                                "honor_points": int(guild.get(39, 0) or 0),
                                "weekly_glory": int(guild.get(37, 0) or 0),
                                "total_glory":  int(guild.get(36, 0) or 0),
                            }

            members = []
            async with s.post(
                "https://clientbp.ppmainecoonghj.com/GetClanMembers",
                headers=hdrs_members, data=payload, ssl=ssl_ctx
            ) as r:
                if r.status == 200:
                    binary = await r.read()
                    if binary and len(binary) >= 10:
                        members_list = _decode_repeated(binary)
                        for m in members_list:
                            if not isinstance(m, dict):
                                continue
                            try:
                                basic    = m.get(1, {})
                                if not isinstance(basic, dict): basic = {}
                                uid      = int(basic.get(1, 0) or 0)
                                nickname = str(basic.get(3, "") or "")
                                region   = str(basic.get(5, "") or "")
                                level    = int(basic.get(6, 0) or 0)
                                role_v   = int(m.get(4, 1) or 1)
                                weekly   = int(m.get(11, 0) or 0)
                                total    = int(m.get(10, 0) or 0)
                                role     = {3:"leader", 2:"co-leader", 1:"member"}.get(role_v, "member")
                                if uid:
                                    members.append({
                                        "uid":          uid,
                                        "nickname":     nickname,
                                        "level":        level,
                                        "region":       region,
                                        "weekly_glory": weekly,
                                        "total_glory":  total,
                                        "role":         role,
                                    })
                            except Exception as e:
                                print_warning(f"[CLAN-MEMBER] {e}")
                                continue
                        members.sort(key=lambda x: x["weekly_glory"], reverse=True)

        if not clan_info_result:
            clan_info_result = {
                "clan_id":      int(clan_id),
                "clan_name":    "",
                "leader_uid":   0,
                "region":       "BD",
                "level":        0,
                "capacity":     0,
                "member_count": len(members),
                "honor_points": 0,
                "weekly_glory": 0,
                "total_glory":  0,
                "has_bot":      False,
                "bot_count":    0,
                "bots":         [],
            }

        bot_uids = set()
        try:
            teams = load_all_team_files()
            for t in teams:
                if str(t["clan_id"]) == str(clan_id):
                    for a in t["accounts"]:
                        auth_uid = str(a["uid"])
                        game_uid = bot_state.auth_to_game_id.get(auth_uid, auth_uid)
                        try:
                            bot_uids.add(int(game_uid))
                        except Exception:
                            pass
        except Exception:
            pass

        bots_list = []
        for m in members:
            if m["uid"] in bot_uids:
                m["is_bot"] = True
                bots_list.append({
                    "uid":          m["uid"],
                    "nickname":     m["nickname"],
                    "level":        m["level"],
                    "region":       m["region"],
                    "role":         m["role"],
                    "weekly_glory": m["weekly_glory"],
                    "total_glory":  m["total_glory"],
                })
            else:
                m["is_bot"] = False

        clan_info_result["has_bot"] = len(bots_list) > 0
        clan_info_result["bot_count"] = len(bots_list)
        clan_info_result["bots"] = bots_list
        clan_info_result["member_count"] = len(members) or clan_info_result["member_count"]

        print_success(
            f"[CLAN] {clan_info_result.get('clan_name')} | "
            f"Lvl {clan_info_result.get('level')} | "
            f"{clan_info_result['member_count']}/{clan_info_result.get('capacity')} | "
            f"Bots {len(bots_list)} | "
            f"Total Glory {clan_info_result.get('total_glory',0):,} "
            f"(Week {clan_info_result.get('weekly_glory',0):,})"
        )
        return clan_info_result

    except Exception as e:
        print_error(f"[CLAN-INFO] {e}")
        return None

# ==================== TEAM FILE STORAGE ====================
def _generate_group_id() -> str:
    return f"{random.randint(10000000, 99999999)}"


def _team_file_path(group_id: str) -> str:
    safe_id = re.sub(r'[^0-9A-Za-z_]', '', str(group_id))
    return os.path.join(TEAMS_DIR, f"group_{safe_id}.json")


def save_team_file(clan_id: str, region: str, accounts: List[Dict],
                   group_id: Optional[str] = None) -> Optional[str]:
    try:
        os.makedirs(TEAMS_DIR, exist_ok=True)
        if not group_id:
            for _ in range(10):
                gid = _generate_group_id()
                if not os.path.exists(_team_file_path(gid)):
                    group_id = gid
                    break
            else:
                group_id = _generate_group_id()

        data = {
            "group_id": str(group_id),
            "clan_id": str(clan_id),
            "region": str(region).upper(),
            "created_at": datetime.now().isoformat(),
            "accounts": [
                {
                    "nickname": str(a.get("nickname", "")),
                    "account_id": str(a.get("account_id", "")),
                    "uid": str(a["uid"]),
                    "password": str(a["password"]),
                }
                for a in accounts
            ],
        }
        path = _team_file_path(group_id)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print_success(f"[TEAM-FILE] Saved {path} ({len(accounts)} accounts)")
        return str(group_id)
    except Exception as e:
        print_error(f"[TEAM-FILE] save error: {e}")
        return None


def load_all_team_files() -> List[Dict]:
    teams = []
    if not os.path.isdir(TEAMS_DIR):
        return teams
    for fname in sorted(os.listdir(TEAMS_DIR)):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(TEAMS_DIR, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                continue
            clan_id = str(data.get("clan_id", "")).strip()
            group_id = str(data.get("group_id", "")).strip() or fname.replace("group_", "").replace(".json", "")
            accounts = data.get("accounts", [])
            region = str(data.get("region", "BD")).upper()
            if not clan_id or not isinstance(accounts, list) or not accounts:
                print_warning(f"[TEAM-FILE] Skipping malformed {fname}")
                continue
            clean_accounts = []
            for a in accounts:
                if not isinstance(a, dict):
                    continue
                u = str(a.get("uid", "")).strip()
                p = str(a.get("password", "")).strip()
                if u and p:
                    clean_accounts.append({"uid": u, "password": p})
            if not clean_accounts:
                print_warning(f"[TEAM-FILE] No valid accounts in {fname}")
                continue
            teams.append({
                "clan_id": clan_id,
                "group_id": group_id,
                "region": region,
                "file": fname,
                "accounts": clean_accounts,
            })
            print_info(f"[TEAM-FILE] Loaded {fname} | clan={clan_id} | group={group_id} | {len(clean_accounts)} bots")
        except Exception as e:
            print_error(f"[TEAM-FILE] Failed to read {fname}: {e}")
    return teams


def delete_team_file(group_id: str) -> bool:
    try:
        path = _team_file_path(group_id)
        if os.path.exists(path):
            os.remove(path)
            print_success(f"[TEAM-FILE] Deleted {path}")
            return True
        return False
    except Exception as e:
        print_error(f"[TEAM-FILE] delete error: {e}")
        return False

# ==================== DEVICE ====================
def _generate_new_device() -> dict:
    device_list = [
        ("Samsung","SM-G998B","Adreno (TM) 660","Android OS 12 / API-31"),
        ("Xiaomi","2201122G","Adreno (TM) 730","Android OS 13 / API-33"),
        ("Realme","RMX3700","Mali-G710","Android OS 14 / API-34"),
        ("OnePlus","CPH2451","Adreno (TM) 740","Android OS 13 / API-33"),
        ("OPPO","CPH2611","Adreno (TM) 720","Android OS 14 / API-34"),
    ]
    brand, model, gpu, os_ver = random.choice(device_list)
    return {"unique_device_id":f"Google|{uuid.uuid4()}","brand":brand,"model":model,
            "gpu_renderer":gpu,"system_software":os_ver,
            "screen_width":random.choice([1080,1440,720]),
            "screen_height":random.choice([2400,3200,1600]),
            "screen_dpi":str(random.randint(300,420)),
            "memory":random.randint(2800,6500)}

def get_device_for_account(acc_key: str) -> dict:
    devices = {}
    if os.path.exists(DEVICES_FILE):
        try:
            with open(DEVICES_FILE,"r",encoding="utf-8") as f:
                devices = json.load(f)
                if not isinstance(devices, dict): devices = {}
        except Exception: devices = {}
    if acc_key in devices: return devices[acc_key]
    nd = _generate_new_device()
    devices[acc_key] = nd
    try:
        with open(DEVICES_FILE,"w",encoding="utf-8") as f:
            json.dump(devices, f, indent=2)
    except Exception: pass
    return nd

# ==================== DNS ====================
_DNS_CACHE: Dict[str, Tuple[str,float]] = {}
_DNS_CACHE_TTL = 300.0

async def resolve_host_cloudflare(hostname: str) -> str:
    if not hostname: return hostname
    parts = hostname.split('.')
    if len(parts)==4 and all(p.isdigit() for p in parts): return hostname
    now = time.time()
    if hostname in _DNS_CACHE:
        ip, exp = _DNS_CACHE[hostname]
        if now < exp: return ip
    try:
        loop = asyncio.get_running_loop()
        info = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
        if info:
            ip = info[0][4][0]
            _DNS_CACHE[hostname] = (ip, now + _DNS_CACHE_TTL)
            return ip
    except Exception: pass
    return hostname

def optimize_tcp_socket(sock):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 131072)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 131072)
    except Exception: pass

async def safe_close_writer(writer):
    if not writer: return
    try:
        if not writer.is_closing(): writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=1.5)
    except Exception: pass

def optimize_udp_socket(sock):
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 131072)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 131072)
    except Exception: pass

# ==================== HTTP CLIENT ====================
client = httpx.AsyncClient(verify=False, timeout=15.0,
    limits=httpx.Limits(max_connections=300, max_keepalive_connections=150))
_LOGIN_SEMAPHORE = asyncio.Semaphore(4)

# ==================== CRYPTO / PROTOBUF ====================
CRC7_TABLE = bytes([
    0,9,18,27,36,45,54,63,72,65,90,83,108,101,126,119,
    25,16,11,2,61,52,47,38,81,88,67,74,117,124,103,110,
    50,59,32,41,22,31,4,13,122,115,104,97,94,87,76,69,
    43,34,57,48,15,6,29,20,99,106,113,120,71,78,85,92,
    100,109,118,127,64,73,82,91,44,37,62,55,8,1,26,19,
    125,116,111,102,89,80,75,66,53,60,39,46,17,24,3,10,
    86,95,68,77,114,123,96,105,30,23,12,5,58,51,40,33,
    79,70,93,84,107,98,121,112,7,14,21,28,35,42,49,56,
    65,72,83,90,101,108,119,126,9,0,27,18,45,36,63,54,
    88,81,74,67,124,117,110,103,16,25,2,11,52,61,38,47,
    115,122,97,104,87,94,69,76,59,50,41,32,31,22,13,4,
    106,99,120,113,78,71,92,85,34,43,48,57,6,15,20,29,
    37,44,55,62,1,8,19,26,109,100,127,118,73,64,91,82,
    60,53,46,39,24,17,10,3,116,125,102,111,80,89,66,75,
    23,30,5,12,51,58,33,40,95,86,77,68,123,114,105,96,
    14,7,28,21,42,35,56,49,70,79,84,93,98,107,112,121,
])
_DELTA = 0x9E3779B9
_ROUNDS = 16
_FIELD_SIZES = {0:1,1:2,2:2,3:1,4:2}
_FIELD_NAMES = {0:"sendOption",1:"cmd",2:"orderId",3:"flags",4:"length"}

def crc7_sync(data: bytes) -> int:
    c = 0
    for b in data:
        c = CRC7_TABLE[((2*(c & 0xFF)) ^ (b & 0xFF)) & 0xFF] & 0x7F
    return c & 0x7F

def encode_varint(n: int) -> bytes:
    out = bytearray()
    if n < 0: n &= 0xFFFFFFFFFFFFFFFF
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        out.append(b)
        if not n: break
    return bytes(out)

def _pb_varint(fn, val): return encode_varint((fn<<3)|0) + encode_varint(val)
def _pb_length(fn, val):
    enc = val.encode('utf-8') if isinstance(val,str) else val
    return encode_varint((fn<<3)|2) + encode_varint(len(enc)) + enc

def create_proto(fields) -> bytes:
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(field, str): field = int(field)
        if isinstance(value, dict):
            packet.extend(_pb_length(field, bytes(create_proto(value))))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    packet.extend(_pb_length(field, bytes(create_proto(item))))
                elif isinstance(item, str):
                    packet.extend(_pb_length(field, item))
                elif isinstance(item, (bytes, bytearray)):
                    packet.extend(_pb_length(field, bytes(item)))
                elif isinstance(item, bool):
                    packet.extend(_pb_varint(field, 1 if item else 0))
                elif isinstance(item, int):
                    packet.extend(_pb_varint(field, item))
        elif isinstance(value, bool):
            packet.extend(_pb_varint(field, 1 if value else 0))
        elif isinstance(value, int):
            packet.extend(_pb_varint(field, value))
        elif isinstance(value, str):
            packet.extend(_pb_length(field, value))
        elif isinstance(value, (bytes, bytearray)):
            packet.extend(_pb_length(field, bytes(value)))
    return bytes(packet)

def encrypt_aes(hex_data: str) -> str:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(bytes.fromhex(hex_data), AES.block_size)).hex()

def decode_varint(data, offset):
    result = 0; shift = 0
    while offset < len(data):
        byte = data[offset]
        result |= (byte & 0x7F) << shift
        offset += 1
        if not (byte & 0x80): return result, offset
        shift += 7
    return None, offset

def decode_protobuf_2(data):
    result = {}; offset = 0
    data_len = len(data)
    while offset < data_len:
        header, offset = decode_varint(data, offset)
        if header is None: break
        fn = header >> 3; wt = header & 0x7
        if wt == 0:
            v, offset = decode_varint(data, offset)
            if v is not None: result[fn] = v
        elif wt == 2:
            length, offset = decode_varint(data, offset)
            if length is None: break
            value = data[offset:offset+length]; offset += length
            try:
                s = value.decode('utf-8')
                result[fn] = s if s else value.hex()
            except UnicodeDecodeError:
                nested = decode_protobuf_2(value)
                result[fn] = nested if nested else value.hex()
        elif wt == 1: offset += 8
        elif wt == 3: offset += 4
        else: break
    return result

def extract_raw_fields(data: bytes) -> dict:
    result = {}; offset = 0; data_len = len(data)
    while offset < data_len:
        header, offset = decode_varint(data, offset)
        if header is None: break
        fn = header >> 3; wt = header & 0x7
        if wt == 0:
            v, offset = decode_varint(data, offset)
            if v is not None: result[fn] = v
        elif wt == 2:
            length, offset = decode_varint(data, offset)
            if length is None: break
            if offset + length > data_len: break
            result[fn] = bytes(data[offset:offset+length]); offset += length
        elif wt == 1: offset += 8
        elif wt == 3: offset += 4
        else: break
    return result

def _parse_results_sync(results):
    out = {}
    for r in results:
        fd = {"wire_type": r.wire_type}
        if r.wire_type == "varint": fd["data"] = r.data
        elif r.wire_type in ("string","bytes"): fd["data"] = r.data
        elif r.wire_type == "length_delimited":
            if hasattr(r.data, "results"): fd["data"] = _parse_results_sync(r.data.results)
            elif isinstance(r.data, list): fd["data"] = _parse_results_sync(r.data)
            else: fd["data"] = str(r.data)
        out[str(r.field)] = fd
    return out

def decode_protobuf_dict(data: bytes) -> dict:
    try:
        parsed = Parser().parse(data)
        return _parse_results_sync(parsed)
    except Exception:
        return {}

async def decode_protobuf_async(data):
    try:
        parsed = Parser().parse(data)
        return json.dumps(_parse_results_sync(parsed))
    except Exception:
        return "{}"

# ==================== ZIGZAG / ULEB ====================
def zigzag_encode(n: int) -> bytes:
    z = (n << 1) if n >= 0 else ((-n) << 1) - 1
    return encode_varint(z)

def uleb_encode(n: int) -> bytes:
    return encode_varint(n)

def create_packet(Pk, N, K, V):
    if isinstance(K, str): K = bytes.fromhex(K) if len(K)==32 else K.encode()
    if isinstance(V, str): V = bytes.fromhex(V) if len(V)==32 else V.encode()
    PkEnc = AES.new(K, AES.MODE_CBC, V).encrypt(pad(bytes.fromhex(Pk),16)).hex()
    L = len(PkEnc)//2
    hexlen = hex(L)[2:]
    if len(hexlen)%2 != 0: hexlen = '0'+hexlen
    total_pad = 12 - len(N) - len(hexlen)
    if total_pad < 0: total_pad = 0
    return bytes.fromhex(N + ('0'*total_pad) + hexlen + PkEnc)

# ==================== TEAM PACKETS ====================
def create_team(key, iv, game_version="1.132.9"):
    fields = {
        1: 1, 2: {2: bytes.fromhex("01"), 3:1, 4:3, 5:"en",
            8: {1:"IDC3",2:123,3:"BD"}, 9:1,
            10: bytes.fromhex("01090a0b1219202729"), 11:2, 13:1,
            14: {1:"08FBA33B4BABE2790205390333330000009700050092005F72697EB2134DCBB2467625142201040e38e848dc0e748c3f6aa04d81000000ff1113090dcacfa16d",
                 2:478, 3:"7e585d55", 4:"y[Z]", 6:12, 7:"15686677735a7506101c",
                 8:str(game_version), 9:3, 10:1, 11:"03626253513637754174"},
            19: 329, 21: bytes.fromhex("374f521955"), 24:{1:21},
            27:"a_6534489873065906362"}}
    return create_packet(create_proto(fields).hex(), "0514", key, iv)

def team_fresh(account_id, key, iv):
    return create_packet(create_proto({1:72, 2:{1:int(account_id)}}).hex(), "0514", key, iv)

def invite_player_in_team(target_uid, key, iv):
    return create_packet(create_proto({1:2, 2:{1:int(target_uid),2:"BD",4:1}}).hex(), "0514", key, iv)

def accept_team_invite(target_uid, group_id, key, iv):
    fields = {1:4, 2:{1:int(target_uid), 3:int(target_uid),
        4: bytes.fromhex("0107090a0b120f19202729"), 8:1,
        9: {1:"08FBA33B0522052002041B0222220007000C00010004000547E265AE1080779546762514110104076fa2e8770e748c3f6a68ed75000000ff08080500cacfa16d",
            2:235, 3:{14:80,11:86}, 4:"{Y\\R", 6:13, 7:{2:4},
            8:"1.132.9", 9:2, 10:1, 11:"0362625351"},
        10: str(group_id),
        11: {"1":"IDC3","2":107,"3":"BD"}, 13:"en", 16:"374f5219",
        20:{1:21}, 23:"a_6534489873065906362",
        24:"https://dl-sg-production.freefiremobile.com/",
        27:{1:2, 2:4}}}
    return create_packet(create_proto(fields).hex(), "0514", key, iv)

def start_match_team(account_id, key, iv, region="BD"):
    fields = {1:9, 2:{1:int(account_id), 7:{1:"IDC3", 2:410, 3:region}}}
    return create_packet(create_proto(fields).hex(), "0514", key, iv)

def ready_for_game(uid, key, iv):
    fields = {1: 15, 2: {1: uid, 2: 1}}
    return create_packet(create_proto(fields).hex(), "0514", key, iv)

# ==================== KEY EXTRACT ====================
def _extract_key_iv(res_json):
    if "__RAW_HEX__" in res_json and "__OFFSET__" in res_json:
        try:
            raw = bytes.fromhex(res_json["__RAW_HEX__"])
            off = int(res_json["__OFFSET__"])
            rf = extract_raw_fields(raw[off:])
            for kf, vf in [(22,23),(24,25),(6,7)]:
                k = rf.get(kf); v = rf.get(vf)
                if isinstance(k,(bytes,bytearray)) and len(k)==16 and \
                   isinstance(v,(bytes,bytearray)) and len(v)==16:
                    return bytes(k), bytes(v)
        except Exception: pass
    found = {}
    for k, v in res_json.items():
        if str(k).startswith("__"): continue
        if not isinstance(v, dict): continue
        data = v.get("data")
        if data is None: continue
        raw = None
        if isinstance(data, (bytes,bytearray)) and len(data)==16: raw = bytes(data)
        elif isinstance(data, str) and len(data)==32:
            try:
                c = bytes.fromhex(data)
                if len(c)==16: raw = c
            except Exception: pass
        if raw and len(raw)==16:
            try: found[int(k)] = raw
            except Exception: pass
    if len(found) < 2: return None, None
    for kf, vf in [(22,23),(24,25),(6,7)]:
        if kf in found and vf in found: return found[kf], found[vf]
    sk = sorted(found.keys())
    return found[sk[0]], found[sk[1]]

async def aes_encrypt(payload, key, iv):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(payload, AES.block_size))

# ==================== VERSION / LOGIN ====================
def get_app_version():
    try: return play_scraper('com.dts.freefireth').get('version')
    except Exception: return "1.132.9"

async def version_config(region="BD"):
    app_version = get_app_version()
    lang = REGION_LANG.get(region.upper(), "en")
    url = (f"https://version.ggwhitehawk.com/live/ver.php?version={app_version}"
           f"&lang={lang}&device=android&channel=android&appstore=googleplay"
           f"&region={region.upper()}&whitelist_version=1.3.0&whitelist_sp_version=1.0.0")
    try:
        r = await client.get(url)
        j = r.json()
        server_url = j.get("server_url")
        remote_version = j.get("remote_version")
        latest_release_version = j.get("latest_release_version")
        gops = [u.strip() for u in j.get("gop_url","").split(";") if u.strip()]
        gop_1 = gops[0] if gops else "https://ffmconnect.ppmainecoonghj.com"
        if not server_url: return None
        return latest_release_version, remote_version, server_url, gop_1, app_version
    except Exception as e:
        print_error(f"[VERCONFIG] {e}"); return None

async def get_access_token(uid, password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    hdrs = {"Host":"100067.connect.garena.com",
        "User-Agent":"Dalvik/2.1.0 (Linux; U; Android 12; SM-G998B)",
        "Content-Type":"application/x-www-form-urlencoded",
        "Accept-Encoding":"gzip, deflate, br","Connection":"close"}
    data = {"uid":str(uid),"password":password,"response_type":"token","client_type":"2",
        "client_secret":HEX_KEY,"client_id":"100067"}
    for _ in range(4):
        try:
            r = await client.post(url, headers=hdrs, data=data)
            if r.status_code == 200:
                j = r.json()
                oid = j.get("open_id"); at = j.get("access_token"); pf = j.get("platform",4)
                if oid and at: return oid, at, pf
        except Exception: pass
        await asyncio.sleep(0.7)
    return None

def generate_signature(payload_str):
    return hmac.new(API_KEY, payload_str.encode(), hashlib.sha256).hexdigest()

async def register_account(password, gop_url, app_version):
    connector = aiohttp.TCPConnector(resolver=aiohttp.ThreadedResolver())
    rp = {"app_id":100067,"client_type":2,"password":password,"source":2}
    payload = json.dumps(rp, separators=(',',':'))
    sig = generate_signature(payload)
    headers = {
        "User-Agent": f"GarenaMSDK/4.0.44(SM-E135F ;Android 14;en;GB;app {app_version} 2019118525;)",
        "Authorization": f"Signature {sig}",
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8"}
    try:
        async with aiohttp.ClientSession(connector=connector) as s:
            async with s.post(f"{gop_url}/api/v2/oauth/guest:register",
                              headers=headers, data=payload,
                              timeout=aiohttp.ClientTimeout(total=15)) as resp:
                data = json.loads(await resp.text())
                if data.get("code") == 0: return data["data"]["uid"]
    except Exception as e:
        print_error(f"[REGISTER] {e}")
    return None

async def grant_token(uid, password, gop_url, app_version):
    connector = aiohttp.TCPConnector(resolver=aiohttp.ThreadedResolver())
    gp = {"client_id":100067,"client_secret":HEX_KEY,"client_type":2,
          "device_id":f"02-{uuid.uuid4()}","password":password,
          "response_type":"token","uid":int(uid)}
    payload = json.dumps(gp, separators=(',',':'))
    sig = generate_signature(payload)
    headers = {
        "User-Agent": f"GarenaMSDK/4.0.44(SM-E135F ;Android 14;en;GB;app {app_version} 2019118525;)",
        "Authorization": f"Signature {sig}",
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8"}
    try:
        async with aiohttp.ClientSession(connector=connector) as s:
            async with s.post(f"{gop_url}/api/v2/oauth/guest/token:grant",
                              headers=headers, data=payload,
                              timeout=aiohttp.ClientTimeout(total=15)) as resp:
                data = json.loads(await resp.text())
                if data.get("code") == 0: return data["data"]
    except Exception as e:
        print_error(f"[GRANT] {e}")
    return None

# ==================== PAYLOAD ====================
async def get_payload(access_token, open_id, platform, version, lang_code="en"):
    device_id = f"Google|{uuid.uuid4()}"
    major_login = {
        "3": str(datetime.now())[:-7], "4": "free fire", "5": 1,
        "7": f"{version}",
        "8": "Android OS 14 / API-34 (UP1A.231005.007/E135FXXSEEZE2)",
        "9": "Handheld", "11": "CarrierDataNetwork",
        "12": 1672, "13": 750, "14": "338",
        "15": "ARMv7 VFPv3 NEON | 2002 | 8",
        "16": 3702, "17": "Mali-G52",
        "18": "OpenGL ES 3.2 v1.r38p1-01bet0-mbs2v41_0.6d20ec041e51b2f2d25dfc265586ebe8",
        "19": device_id, "20": "104.28.197.151", "21": lang_code,
        "22": f"{open_id}", "23": f"{platform}", "24": "Handheld",
        "25": "samsung SM-E135F", "26": "BD",
        "29": f"{access_token}", "30": 1, "42": "Cellular",
        "57": "7428b253defc164018c604a1ebbfebdf",
        "60": 52037, "61": 5355, "62": 3723, "63": 3,
        "64": 5483, "65": 52037, "66": 5483, "67": 52037,
        "73": 2,
        "74": "/data/app/~~yACsV8QOk9OexgajWQP30A==/com.dts.freefireth-Bi_wPVrrhYM2nYncc29q7Q==/lib/arm",
        "76": 1,
        "77": "b8e0cd5e295eee42f5860d3c86e483dd|/data/app/~~yACsV8QOk9OexgajWQP30A==/com.dts.freefireth-Bi_wPVrrhYM2nYncc29q7Q==/base.apk",
        "78": 3, "79": 1, "81": "32", "83": "2019121229",
        "86": "OpenGLES2", "87": 8191, "88": int(platform),
        "92": 16091, "93": "android",
        "94": "KqsHT3Yeqo3RLRl8efNiL3aL/1SHwlSrtK0DwNAqdkNBQz70TeVy+icaIwuR3UK4b65Uf3IG5xBFEv0uu+jQZI+rOYCmNCsXjJT4QcZaYgoaaUGG",
        "95": 111107,
        "96": "{\"cur_rate\":null,\"support_etc2\":false}",
        "97": 1, "98": 1,
        "99": f"{platform}", "100": f"{platform}",
        "102": "4503454457550c0766",
        "104": 53792, "105": 1,
        "106": "https://dl-bs.ggpolarbear.com/live/ABHotUpdates/|https://core-bs.ggpolarbear.com/live/ABHotUpdates/|6b2078db9d22dd98f8e9386a39af8462",
        "107": "c8e41b7a93f02d56e1a94c7b8203f5d1",
    }
    get_login_data = dict(major_login)
    get_login_data["90"] = "Khulna"
    get_login_data["91"] = "D"
    get_login_data["99"] = "0"
    get_login_data["103"] = 1
    proto1 = create_proto(major_login).hex()
    proto2 = create_proto(get_login_data).hex()
    return bytes.fromhex(encrypt_aes(proto1)), bytes.fromhex(encrypt_aes(proto2))

async def major_login(payload, login_url, release_version):
    url = f"{login_url.rstrip('/')}/MajorLogin"
    req_headers = {
        "Accept": "*/*", "Authorization": "Bearer ",
        "Content-Type": "application/x-www-form-urlencoded",
        "ReleaseVersion": f"{release_version}",
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "X-GA": "v1 1", "X-GA-SV": str(int(time.time())),
        "X-Unity-Version": "2018.4.12f1",
    }
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
            async with session.post(url, headers=req_headers, data=payload, ssl=ssl_context) as response:
                response_content = await response.read()
                print_info(f"[MAJOR-LOGIN] status={response.status} len={len(response_content)}")
                if response.status != 200:
                    print_warning(f"[MAJOR-LOGIN] HTTP {response.status}: {response_content[:120]!r}")
                    return None
                if len(response_content) < 200:
                    print_warning(f"[MAJOR-LOGIN] Short: {response_content.hex()}")
                    return None

                best = None; best_score = -1; best_off = 0
                offsets_to_try = [64, 0, 48, 32, 80, 16, 128, 8, 96, 60, 56, 40, 24, 20, 12, 4]
                for offset in offsets_to_try:
                    if offset >= len(response_content): continue
                    cb = response_content[offset:]
                    cand = None
                    try: cand = decode_protobuf_dict(cb)
                    except Exception: cand = None
                    if not cand:
                        try:
                            c2 = decode_protobuf_2(cb)
                            if c2: cand = {str(k): {"data": v} for k, v in c2.items()}
                        except Exception: cand = None
                    if not cand: continue
                    keys = set(cand.keys())
                    has_jwt = ("8" in keys) or (8 in keys)
                    has_url = ("10" in keys) or (10 in keys)
                    score = len(cand) + (100 if has_jwt else 0) + (50 if has_url else 0)
                    if score > best_score:
                        best = cand; best_score = score; best_off = offset
                    if has_jwt and has_url: break
                if not best:
                    print_warning(f"[MAJOR-LOGIN] Could not decode response")
                    return None
                keys_found = sorted(best.keys(), key=lambda x: int(x) if str(x).isdigit() else 0)
                print_info(f"[MAJOR-LOGIN] decoded at offset {best_off} | fields={keys_found}")
                if ("8" not in best) and (8 not in best):
                    print_warning(f"[MAJOR-LOGIN] No JWT (field 8)")
                    return None
                best["__RAW_HEX__"] = response_content.hex()
                best["__OFFSET__"] = best_off
                return best
    except asyncio.TimeoutError:
        print_error("[MAJOR-LOGIN] TIMEOUT"); return None
    except Exception as e:
        print_error(f"[MAJOR-LOGIN] {e}"); traceback.print_exc(); return None

async def get_login_data(payload, jwt_token, server_url, release_version):
    url = f"{server_url.rstrip('/')}/GetLoginData"
    hdrs = {"Accept":"*/*","Authorization":f"Bearer {jwt_token}",
        "Content-Type":"application/x-www-form-urlencoded",
        "ReleaseVersion":f"{release_version}",
        "User-Agent":"UnityPlayer/2018.4.12f1","X-GA":"v1 1",
        "X-GA-SV":str(int(time.time())),"X-Unity-Version":"2018.4.12f1"}
    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False; ssl_ctx.verify_mode = ssl.CERT_NONE
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
            async with s.post(url, headers=hdrs, data=payload, ssl=ssl_ctx) as r:
                if r.status != 200: return None
                content = await r.read()
                for off in [0,64,48,32,80,16,128,8,96]:
                    if off >= len(content): continue
                    try:
                        c = decode_protobuf_dict(content[off:])
                        if c and len(c) >= 3: return c
                    except Exception: pass
                for off in [0,64,48,32,80]:
                    if off >= len(content): continue
                    c = decode_protobuf_2(content[off:])
                    if c and len(c) >= 3:
                        return {str(k):{"data":v} for k,v in c.items()}
        return None
    except Exception: return None

async def get_player_personal_show(target_uid, jwt_token, server_url, release_version):
    url = f"{server_url}/GetPlayerPersonalShow"
    payload = bytes.fromhex(encrypt_aes(create_proto({"1":int(target_uid)}).hex()))
    hdrs = {"authorization":f"Bearer {jwt_token}",
        "host":server_url.replace("https://","").split("/")[0],
        "x-ga":"v1 1","content-type":"application/x-www-form-urlencoded",
        "releaseversion":f"{release_version}",
        "user-agent":"UnityPlayer/2022.3.47f1","accept":"*/*",
        "x-unity-version":"2022.3.47f1"}
    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False; ssl_ctx.verify_mode = ssl.CERT_NONE
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as s:
            async with s.post(url, headers=hdrs, data=payload, ssl=ssl_ctx) as r:
                if r.status != 200: return None
                return decode_protobuf_2(await r.read())
    except Exception: return None

# ==================== CLAN ====================
def _get_region_from_jwt(jwt_token):
    try:
        p = jwt_token.split('.')[1]
        p += '=' * (-len(p) % 4)
        d = json.loads(base64.urlsafe_b64decode(p))
        return (d.get('lock_region') or d.get('noti_region') or 'BD').upper()
    except Exception: return "BD"

def _get_region_url(region):
    region = region.upper()
    if region == "IND": return "https://client.ind.freefiremobile.com"
    if region in ["BR","US","NA"]: return "https://client.us.freefiremobile.com"
    return "https://clientbp.ggpolarbear.com"

def _create_clan_payload(clan_id):
    if not _CLAN_PB_AVAILABLE: return None
    try:
        msg = reqClan_pb2.MyMessage()
        msg.field_1 = int(clan_id)
        raw = msg.SerializeToString()
        return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(raw, AES.block_size))
    except Exception as e:
        print_error(f"[CLAN] payload: {e}"); return None

async def join_clan(jwt_token, clan_id):
    if not _CLAN_PB_AVAILABLE:
        print_warning("[CLAN] reqClan_pb2 not available"); return False
    try:
        region = _get_region_from_jwt(jwt_token)
        base_url = _get_region_url(region)
        url = base_url.rstrip("/") + "/RequestJoinClan"
        host = base_url.replace("https://","")
        payload = _create_clan_payload(clan_id)
        if not payload: return False
        hdrs = {"Authorization":f"Bearer {jwt_token}",
            "X-Unity-Version":"2018.4.11f1","X-GA":"v1 1","ReleaseVersion":"OB55",
            "Content-Type":"application/octet-stream","Host":host,
            "Connection":"Keep-Alive","Accept-Encoding":"gzip"}
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False; ssl_ctx.verify_mode = ssl.CERT_NONE
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as s:
            async with s.post(url, headers=hdrs, data=payload, ssl=ssl_ctx) as r:
                if r.status == 200:
                    print_success(f"[CLAN] ✅ Join sent for {clan_id}"); return True
                print_warning(f"[CLAN] Join status {r.status}"); return False
    except Exception as e:
        print_error(f"[CLAN] {e}"); return False

# ==================== TCP ====================
async def build_tcp_startup_packet(account_id, token, server_time, key, iv, region="BD", typ='OnLine'):
    uid_hex = f"{int(account_id):016x}"
    ts_hex = f"{int(server_time):08x}"
    enc = (await aes_encrypt(token.encode(), key, iv)).hex()
    enc_len = f"{len(enc)//2:08x}"
    reg = str(region).upper() if region else "BD"
    if typ == 'OnLine':
        pfx = '7219' if reg == 'BD' else ('7214' if reg == 'IND' else '7215')
        return f"{pfx}{uid_hex}{ts_hex}00000000{enc_len}{enc}"
    pfx = '8119' if reg == 'BD' else ('8114' if reg == 'IND' else '8115')
    return f"{pfx}{uid_hex}{ts_hex}{enc_len}{enc}"

async def send_keep_alive(region="BD"):
    reg = str(region).upper() if region else "BD"
    return bytes.fromhex("0219" if reg == "BD" else ("0214" if reg == "IND" else "0215"))

# ==================== MATCH COUNTERS ====================
_match_counters: Dict[str, int] = {}
_match_counter_lock = asyncio.Lock()

async def _inc_match(uid):
    async with _match_counter_lock:
        _match_counters[uid] = _match_counters.get(uid, 0) + 1
        return _match_counters[uid]

async def _dec_match(uid):
    async with _match_counter_lock:
        if uid in _match_counters and _match_counters[uid] > 0:
            _match_counters[uid] -= 1
        return _match_counters.get(uid, 0)

# ==================== TOKEN CACHE ====================
_token_cache_memo: Dict[str, Any] = {}
_token_cache_memo_time: float = 0.0
_TOKEN_CACHE_MEMO_TTL = 5.0

def _json_serializer(obj):
    if isinstance(obj, (bytes, bytearray)):
        return {"__bytes_hex__": bytes(obj).hex()}
    raise TypeError(f"Type {type(obj)} not serializable")

def _json_deserializer(obj):
    if isinstance(obj, dict):
        if "__bytes_hex__" in obj and len(obj) == 1:
            try: return bytes.fromhex(obj["__bytes_hex__"])
            except Exception: return b""
        return {k: _json_deserializer(v) for k, v in obj.items()}
    if isinstance(obj, list): return [_json_deserializer(x) for x in obj]
    return obj

def _load_token_cache() -> Dict[str, Any]:
    global _token_cache_memo, _token_cache_memo_time
    now = time.time()
    if _token_cache_memo and (now - _token_cache_memo_time) < _TOKEN_CACHE_MEMO_TTL:
        return _token_cache_memo
    if not os.path.exists(TOKEN_CACHE_FILE):
        return {}
    try:
        with open(TOKEN_CACHE_FILE,"r",encoding="utf-8") as f:
            content = f.read().strip()
        if not content: return {}
        data = json.loads(content)
        parsed = _json_deserializer(data)
        _token_cache_memo = parsed
        _token_cache_memo_time = now
        return parsed
    except Exception as e:
        print_error(f"Token cache corrupt → deleting: {e}")
        try: os.remove(TOKEN_CACHE_FILE)
        except Exception: pass
        return {}

def _save_token_cache(cache: Dict[str, Any]):
    global _token_cache_memo, _token_cache_memo_time
    try:
        tmp_file = TOKEN_CACHE_FILE + ".tmp"
        with open(tmp_file,"w",encoding="utf-8") as f:
            json.dump(cache, f, indent=2, default=_json_serializer)
        os.replace(tmp_file, TOKEN_CACHE_FILE)
        _token_cache_memo = cache
        _token_cache_memo_time = time.time()
    except Exception as e:
        print_error(f"Token cache save error: {e}")

def cache_get(uid: str) -> Optional[Dict]:
    cache = _load_token_cache()
    entry = cache.get(str(uid))
    if not entry: return None
    if time.time() - entry.get("cached_at",0) > TOKEN_CACHE_TTL:
        print_info(f"[CACHE] UID {uid} expired. Re-login needed.")
        cache_invalidate(uid); return None
    if str(entry.get("account_id","")).isdigit():
        entry["account_id"] = int(entry["account_id"])
    if not isinstance(entry.get("login_payload_data"), (bytes, bytearray)):
        print_warning(f"[CACHE] UID {uid} missing payload → invalidating")
        cache_invalidate(uid); return None
    return entry

def cache_set(uid: str, data: Dict):
    try:
        cache = _load_token_cache()
        entry = dict(data)
        entry["cached_at"] = time.time()
        cache[str(uid)] = entry
        _save_token_cache(cache)
        print_success(f"[CACHE] Saved credentials for UID {uid}")
    except Exception as e:
        print_error(f"cache_set error: {type(e).__name__}: {e}")

def cache_invalidate(uid: str):
    cache = _load_token_cache()
    if str(uid) in cache:
        del cache[str(uid)]
        _save_token_cache(cache)
        print_warning(f"[CACHE] Invalidated: {uid}")

# ==================== PLAY GAME ====================
async def play_game(server_ip_port, udp_jwt, udp_key, match_code,
                    account_id, player_region, client_version,
                    tcp_key, tcp_iv, match_index,
                    game_mode=1, map_id=1, match_mode=1, sleep_ms=0,
                    match_id=0, verbose=True):
    uid_str = str(account_id)
    completed_cleanly = False
    try:
        if ":" not in server_ip_port:
            print_error(f"[MATCH #{match_index}] bad server {server_ip_port!r}")
            return
        ip, port_s = server_ip_port.split(":", 1)
        port = int(port_s)

        print_success(f"[MATCH #{match_index}] → toolsudp.run_match {ip}:{port}")
        print_info(f"    udp_jwt_len={len(udp_jwt) if udp_jwt else 0} "
                   f"udp_key={udp_key[:8] if udp_key else 'None'}... "
                   f"mask={match_code} mode={game_mode} map={map_id}")

        try:
            _toolsudp.set_base_url("https://clientbp.ppmainecoonghj.com")
        except Exception:
            pass

        loop = asyncio.get_running_loop()

        def _run():
            return _toolsudp.run_match(
                ip, port,
                int(account_id),
                udp_key,
                udp_jwt,
                match_code,
                "0",
                int(game_mode),
                int(map_id),
                int(match_mode),
                int(sleep_ms),
                3.0,
                None,
                int(match_id),
                bool(verbose),
            )

        try:
            await loop.run_in_executor(None, _run)
        except Exception as exc:
            print_error(f"[MATCH #{match_index}] run_match: {exc}")
            traceback.print_exc()
        else:
            completed_cleanly = True
            print_success(f"[★] Match #{match_index} Finished")
    except Exception as e:
        print_error(f"[MATCH #{match_index}] {e}")
    finally:
        if completed_cleanly:
            try:
                bot_state.increment_match(uid_str)
                print_success(f"[★] Match #{match_index} Complete | UID: {uid_str}")
                async def _post_exp(uid):
                    try:
                        for wait in (5.0, 8.0, 12.0):
                            await asyncio.sleep(wait)
                            await refresh_account_profile(uid)
                    except Exception: pass
                asyncio.create_task(_post_exp(uid_str))
            except Exception: pass
        remaining = await _dec_match(uid_str)
        try:
            bot_state.update_status(uid_str, "ONLINE" if remaining == 0 else "IN_MATCH", remaining)
        except Exception: pass

# ==================== FUNCTIONAL LONE WOLF ====================
async def functional_lone_wolf(addrs, starter_packet, account_region, client_version,
                                key, iv, account_id="", account_data=None, max_reconnects=10,
                                group_id: str = "default"):
    reconnects = 0
    ip, port = addrs.split(":")
    play_matches: List[asyncio.Task] = []
    no_response_count = 0
    search_attempts = 0
    uid_str = str(account_id)

    current_token = starter_packet
    current_key = key
    current_iv = iv
    current_account_data = account_data
    _writer_ref = {"w": None}
    _team_active = {"flag": True}
    _match_played = {"flag": False}

    _team_state = get_team_state(group_id)

    # Arm the watchdog — no match start within MATCH_START_WATCHDOG → full restart
    try:
        _ensure_watchdog(group_id)
    except Exception as _wd_err:
        print_warning(f"[WATCHDOG] ensure failed: {_wd_err}")

    async def _process_social_packet(raw_bytes, tag="MAIN"):
        try:
            hex_data = raw_bytes.hex()
            print_info(f"[SOCIAL-{tag}] len={len(raw_bytes)} hex={hex_data[:60]}")
            candidates = []
            if len(raw_bytes) >= 6:
                plen = raw_bytes[4]
                if 0 < plen <= (len(raw_bytes) - 5):
                    try:
                        inner = bytes(raw_bytes[5:5 + plen])
                        d0 = decode_protobuf_dict(inner)
                        if not d0:
                            a0 = decode_protobuf_2(inner)
                            if a0:
                                d0 = {str(k): {"data": v} for k, v in a0.items()}
                        if d0:
                            candidates.append((5, d0))
                    except Exception:
                        pass
            for off in [5, 6, 10, 8, 12, 14, 4, 16, 0]:
                if off >= len(hex_data): continue
                try:
                    inner_bytes = bytes.fromhex(hex_data[off:])
                except Exception: continue
                decoded = None
                try:
                    d1 = decode_protobuf_dict(inner_bytes)
                    if d1: decoded = d1
                except Exception: pass
                if not decoded:
                    try:
                        d2 = decode_protobuf_2(inner_bytes)
                        if d2: decoded = {str(k): {"data": v} for k, v in d2.items()}
                    except Exception: pass
                if decoded:
                    candidates.append((off, decoded))
            if not candidates:
                print_warning(f"[SOCIAL-{tag}] no decodable protobuf found"); return
            def _score(item):
                _off, d = item
                s = len(d)
                if "0" in d or 0 in d: s -= 100
                if "5" in d: s += 6
                if "1" in d: s += 4
                if "2" in d: s += 2
                return s
            candidates.sort(key=_score, reverse=True)
            best_off, decoded = candidates[0]
            print_info(f"[SOCIAL-{tag}] decoded@{best_off} fields={list(decoded.keys())[:15]}")

            def _val(container, k):
                if not isinstance(container, dict): return None
                v = container.get(k) if k in container else container.get(str(k))
                if isinstance(v, dict) and "data" in v: return v["data"]
                return v

            f5wrap = decoded.get("5") or decoded.get(5)
            f5 = None
            if isinstance(f5wrap, dict) and "data" in f5wrap: f5 = f5wrap["data"]
            elif isinstance(f5wrap, dict): f5 = f5wrap

            target_uid = None
            if isinstance(f5, dict):
                for fk in [1, 2, 3, 4, 6]:
                    cand = _val(f5, fk)
                    if cand and str(cand).isdigit() and 6 <= len(str(cand)) <= 15:
                        target_uid = str(cand); break
            if not target_uid:
                for fk in [1, 2, 3]:
                    cand = _val(decoded, fk)
                    if cand and str(cand).isdigit() and 6 <= len(str(cand)) <= 15:
                        target_uid = str(cand); break
            if not target_uid:
                print_warning(f"[SOCIAL-{tag}] could not find target UID"); return

            own_acc = None
            if current_account_data:
                own_acc = str(current_account_data.get('account_id', ''))
            if own_acc and target_uid == own_acc:
                print_info(f"[SOCIAL-{tag}] skip (self)"); return
            if not _accept_friend_request or not current_account_data: return

            jwt_l = current_account_data.get('token')
            srv_l = current_account_data.get('server_url')
            rel_l = current_account_data.get('release_version')
            own_id = current_account_data.get('account_id')
            if not (jwt_l and srv_l and rel_l and own_id): return

            print_info(f"[FRIEND-{tag}] ConfirmFriendRequest: target={target_uid} own={own_id}")
            url = f"{srv_l.rstrip('/')}/ConfirmFriendRequest"
            fields = {"1": int(target_uid), "2": int(own_id)}
            try:
                payload = bytes.fromhex(encrypt_aes(create_proto(fields).hex()))
                hdrs = {
                    "authorization": f"Bearer {jwt_l}",
                    "host": srv_l.replace("https://", "").replace("http://", "").split("/")[0],
                    "x-ga": "v1 1",
                    "content-type": "application/x-www-form-urlencoded",
                    "accept-encoding": "deflate, gzip",
                    "releaseversion": f"{rel_l}",
                    "user-agent": "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
                    "accept": "*/*", "x-unity-version": "2022.3.47f1",
                }
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False; ssl_ctx.verify_mode = ssl.CERT_NONE
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as s:
                    async with s.post(url, headers=hdrs, data=payload, ssl=ssl_ctx) as r:
                        body = await r.read()
                        if r.status == 200 and len(body) > 0:
                            print_success(f"[FRIEND-{tag}] ✅ Accepted {target_uid}")
                        else:
                            print_warning(f"[FRIEND-{tag}] HTTP {r.status} len={len(body)}")
            except Exception as e:
                print_warning(f"[FRIEND-{tag}] {type(e).__name__}: {e}")
        except Exception as e:
            print_warning(f"[SOCIAL-{tag}] exception: {type(e).__name__}: {e}")

    async def _team_coordinator():
        try:
            while True:
                async with _team_state["lock"]:
                    n = len(_team_state["peers"])
                if n >= TEAM_SIZE: break
                if bot_state.is_paused(uid_str): return
                if _match_played["flag"]: return
                await asyncio.sleep(0.5)

            await asyncio.sleep(TEAM_READY_DELAY)

            async with _team_state["lock"]:
                is_leader = (_team_state["leader_uid"] == uid_str)
                peers_snapshot = dict(_team_state["peers"])
            if not is_leader:
                print_info(f"[TEAM] {uid_str} waiting as member..."); return

            live_peers = {
                p: v for p, v in peers_snapshot.items()
                if v.get("writer") and not v["writer"].is_closing()
            }
            if len(live_peers) < TEAM_SIZE:
                print_warning(f"[TEAM] only {len(live_peers)}/{TEAM_SIZE} live peers after delay, aborting")
                return

            print_success(f"[TEAM] 👑 {uid_str} — creating team ({len(live_peers)} live peers)")

            async with _team_state["lock"]:
                _team_state["team_code"] = None

            own_id_num = None
            if current_account_data: own_id_num = current_account_data.get('account_id')
            if not own_id_num:
                try: own_id_num = int(uid_str)
                except Exception: own_id_num = 0

            try:
                pkt = create_team(current_key, current_iv, client_version)
                if _writer_ref["w"] and not _writer_ref["w"].is_closing():
                    _writer_ref["w"].write(pkt); await _writer_ref["w"].drain()
            except Exception as e:
                print_error(f"[TEAM] create_team err: {e}")
            await asyncio.sleep(1.5)

            try:
                pkt = team_fresh(int(own_id_num), current_key, current_iv)
                if _writer_ref["w"] and not _writer_ref["w"].is_closing():
                    _writer_ref["w"].write(pkt); await _writer_ref["w"].drain()
            except Exception as e:
                print_warning(f"[TEAM] team_fresh err: {e}")
            await asyncio.sleep(1.0)

            async def _invite_uid(target_uid, label=""):
                for attempt in range(2):
                    try:
                        inv = invite_player_in_team(int(target_uid), current_key, current_iv)
                        if _writer_ref["w"] and not _writer_ref["w"].is_closing():
                            _writer_ref["w"].write(inv); await _writer_ref["w"].drain()
                    except Exception as e:
                        print_warning(f"[TEAM] invite err: {e}")
                    await asyncio.sleep(0.6)

            invited_uids = set()
            invite_count = 0
            for peer_uid, peer_info in live_peers.items():
                if peer_uid == uid_str: continue
                peer_acc_id = None
                try: peer_acc_id = peer_info["data"].get("account_id")
                except Exception: pass
                if not peer_acc_id: peer_acc_id = peer_uid
                print_success(f"[TEAM] 📨 Inviting bot{invite_count+2} {peer_acc_id}...")
                await _invite_uid(int(peer_acc_id), f" bot{invite_count+2}")
                invited_uids.add(peer_uid)
                invite_count += 1
            await asyncio.sleep(TEAM_INVITE_WAIT + 3.0)

            try:
                pkt = team_fresh(int(own_id_num), current_key, current_iv)
                if _writer_ref["w"] and not _writer_ref["w"].is_closing():
                    _writer_ref["w"].write(pkt); await _writer_ref["w"].drain()
            except Exception as e:
                print_warning(f"[TEAM] team_fresh #2 err: {e}")
            await asyncio.sleep(1.0)

            print_success(f"[TEAM] 🚀 {uid_str} loop: ready → 1s → start (every 5s, full squad only)")

            while _team_active["flag"] and not _match_played["flag"]:
                try:
                    if bot_state.is_paused(uid_str): break

                    async with _team_state["lock"]:
                        if _team_state["leader_uid"] != uid_str: break
                        current_peers = dict(_team_state["peers"])

                    live_current = {
                        p: v for p, v in current_peers.items()
                        if v.get("writer") and not v["writer"].is_closing()
                    }

                    new_peers = set(live_current.keys()) - invited_uids - {uid_str}
                    for peer_uid in new_peers:
                        peer_info = live_current[peer_uid]
                        peer_acc_id = None
                        try: peer_acc_id = peer_info["data"].get("account_id")
                        except Exception: pass
                        if not peer_acc_id: peer_acc_id = peer_uid
                        print_success(f"[TEAM] 📨 Re-inviting late peer {peer_acc_id}")
                        await _invite_uid(int(peer_acc_id))
                        invited_uids.add(peer_uid)

                    if len(live_current) < TEAM_SIZE:
                        print_info(f"[TEAM] team {len(live_current)}/{TEAM_SIZE} live — waiting")
                        await asyncio.sleep(2.0)
                        continue

                    own_id = current_account_data.get('account_id', own_id_num) if current_account_data else own_id_num
                    try:
                        rdy = ready_for_game(int(own_id), current_key, current_iv)
                        if _writer_ref["w"] and not _writer_ref["w"].is_closing():
                            _writer_ref["w"].write(rdy); await _writer_ref["w"].drain()
                    except Exception as e:
                        print_warning(f"[TEAM] ready_for_game err: {e}")
                    await asyncio.sleep(1.0)
                    sm = start_match_team(int(own_id), current_key, current_iv, region=account_region)
                    if _writer_ref["w"] and not _writer_ref["w"].is_closing():
                        _writer_ref["w"].write(sm); await _writer_ref["w"].drain()
                except Exception as e:
                    print_warning(f"[TEAM] start_match err: {e}")
                try: await asyncio.wait_for(asyncio.sleep(5.0), timeout=5.5)
                except asyncio.TimeoutError: pass
        except asyncio.CancelledError: raise
        except Exception as e:
            print_error(f"[TEAM] coordinator error: {e}")

    async def _member_match_trigger():
        try:
            while True:
                async with _team_state["lock"]:
                    if _team_state["leader_uid"] == uid_str: return
                    team_size = len(_team_state["peers"])
                if team_size >= TEAM_SIZE: break
                if bot_state.is_paused(uid_str): return
                if _match_played["flag"]: return
                await asyncio.sleep(1.0)

            await asyncio.sleep(TEAM_READY_DELAY + 8.0)

            print_success(f"[TEAM] 🚀 Member {uid_str} loop (full squad)")
            my_id = current_account_data.get('account_id', uid_str) if current_account_data else uid_str
            while _team_active["flag"] and not _match_played["flag"]:
                try:
                    if bot_state.is_paused(uid_str): break
                    async with _team_state["lock"]:
                        if _team_state["leader_uid"] == uid_str: break
                        current_peers = dict(_team_state["peers"])
                    live_current = {
                        p: v for p, v in current_peers.items()
                        if v.get("writer") and not v["writer"].is_closing()
                    }
                    if len(live_current) < TEAM_SIZE:
                        await asyncio.sleep(2.0)
                        continue
                    if _writer_ref["w"] and not _writer_ref["w"].is_closing():
                        try:
                            rdy = ready_for_game(int(my_id), current_key, current_iv)
                            _writer_ref["w"].write(rdy); await _writer_ref["w"].drain()
                        except Exception as e:
                            print_warning(f"[TEAM] member ready err: {e}")
                        await asyncio.sleep(1.0)
                        sm = start_match_team(int(my_id), current_key, current_iv, region=account_region)
                        _writer_ref["w"].write(sm); await _writer_ref["w"].drain()
                except Exception as e:
                    print_warning(f"[TEAM] member trigger: {e}")
                try: await asyncio.wait_for(asyncio.sleep(5.0), timeout=5.5)
                except asyncio.TimeoutError: pass
        except asyncio.CancelledError: raise
        except Exception as e:
            print_warning(f"[TEAM] member trigger outer: {e}")

    try:
        while True:
            while bot_state.is_paused(uid_str):
                try: bot_state.update_status(uid_str, "PAUSED", 0)
                except Exception: pass
                await asyncio.sleep(1.0)

            writer = None
            gateway_ping_task = None
            team_coord_task = None
            member_trigger_task = None
            try:
                if current_account_data:
                    fresh = None
                    if current_account_data.get('auth_type') == 'guest' and current_account_data.get('auth_uid'):
                        fresh = cache_get(str(current_account_data['auth_uid']))
                    elif current_account_data.get('auth_type') == 'token' and current_account_data.get('auth_token'):
                        fresh = cache_get(f"tok_{current_account_data['auth_token'][:20]}")
                    if fresh:
                        current_account_data = fresh
                        current_key = fresh['aes_ak']; current_iv = fresh['iv_i']
                        current_token = await build_tcp_startup_packet(
                            fresh['account_id'], fresh['token'], fresh['server_time'],
                            current_key, current_iv,
                            region=fresh.get('region', account_region), typ='OnLine')
                    else:
                        raise ConnectionError("Cache expired")

                resolved_ip = await resolve_host_cloudflare(ip)
                reader, writer = await asyncio.open_connection(resolved_ip, int(port))
                bot_state.register_writer(uid_str, writer)
                _writer_ref["w"] = writer
                raw_sock = writer.get_extra_info('socket')
                if raw_sock: optimize_tcp_socket(raw_sock)
                writer.write(bytes.fromhex(current_token)); await writer.drain()
                try:
                    init_ka = await send_keep_alive(account_region)
                    if init_ka and not writer.is_closing():
                        writer.write(init_ka)
                        await asyncio.wait_for(writer.drain(), timeout=3)
                except Exception: pass

                async def func_gateway_keepalive():
                    ka_bytes = await send_keep_alive(account_region)
                    while True:
                        await asyncio.sleep(5)
                        try:
                            if writer and not writer.is_closing():
                                writer.write(ka_bytes); await writer.drain()
                        except Exception: break

                gateway_ping_task = asyncio.create_task(func_gateway_keepalive())
                print_success(f"[✓] TCP Gateway Connected | UID: {uid_str}")
                reconnects = 0
                no_response_count = 0

                async with _team_state["lock"]:
                    _team_state["peers"][uid_str] = {
                        "writer": writer, "data": current_account_data,
                        "key": current_key, "iv": current_iv}
                    if _team_state["leader_uid"] is None:
                        _team_state["leader_uid"] = uid_str
                        print_success(f"[TEAM] 👑 {uid_str} is first peer (leader)")

                if not _match_played["flag"]:
                    team_coord_task = asyncio.create_task(_team_coordinator())
                    member_trigger_task = asyncio.create_task(_member_match_trigger())
                else:
                    print_info(f"[IDLE] {uid_str} resuming in idle mode")

                # ============ MAIN READ LOOP ============
                while True:
                    play_matches[:] = [m for m in play_matches if not m.done()]
                    if bot_state.is_paused(uid_str): break

                    if _match_played["flag"]:
                        print_success(f"[RESTART] {uid_str} → match done, closing gateway → full script restart pending")
                        break

                    try:
                        data = await asyncio.wait_for(reader.read(8192), timeout=0.5)
                    except asyncio.TimeoutError:
                        no_response_count += 1; continue
                    if not data:
                        raise ConnectionError("Connection closed")
                    hex_data = data.hex()
                    packet_length = len(data)
                    no_response_count = 0

                    if DEBUG_ALL_PACKETS:
                        print_info(f"[RAW-PKT] len={packet_length} prefix={hex_data[:20]}")

                    if hex_data.startswith("0600") and packet_length > 20:
                        await _process_social_packet(data, tag="MAIN"); continue

                    if hex_data.startswith("0500") and packet_length > 10:
                        try:
                            inner = bytes.fromhex(hex_data[10:])
                            dec = decode_protobuf_dict(inner)
                            if not dec:
                                alt = decode_protobuf_2(inner)
                                if alt: dec = {str(k): {"data": v} for k, v in alt.items()}
                            f5w = dec.get("5") or dec.get(5)
                            f5 = f5w.get("data") if isinstance(f5w, dict) and "data" in f5w else f5w
                            if not isinstance(f5, dict): f5 = dec
                            def _f5g(key):
                                if not isinstance(f5, dict): return None
                                v = f5.get(key) if key in f5 else f5.get(str(key))
                                if isinstance(v, dict) and "data" in v: return v["data"]
                                return v
                            tc = None
                            for fk in [11, 5, 1, 3]:
                                cand = _f5g(fk)
                                if cand and str(cand).isdigit() and len(str(cand)) == 7:
                                    tc = str(cand); break
                            if tc:
                                async with _team_state["lock"]:
                                    _team_state["team_code"] = tc
                                print_success(f"[TEAM] 📢 Team Code captured: {tc}")
                            group_id_pkt = _f5g(8)
                            if group_id_pkt and isinstance(group_id_pkt, str) and 20 <= len(group_id_pkt) <= 40:
                                pass
                            else: group_id_pkt = None
                            own_acc = None
                            if current_account_data: own_acc = str(current_account_data.get('account_id'))
                            inviter = None
                            for fk in [1, 2, 3, 4, 6, 7, 13, 15, 20]:
                                cand = _f5g(fk)
                                if cand and str(cand).isdigit() and 6 <= len(str(cand)) <= 15:
                                    if str(cand) != uid_str and str(cand) != own_acc:
                                        inviter = cand; break
                            if inviter and group_id_pkt and _team_state["leader_uid"] != uid_str:
                                print_success(f"[TEAM] 📨 Invite from {inviter} → accepting...")
                                for _ in range(2):
                                    try:
                                        acc = accept_team_invite(int(inviter), group_id_pkt, current_key, current_iv)
                                        if writer and not writer.is_closing():
                                            writer.write(acc); await writer.drain()
                                            print_success(f"[TEAM] ✅ accept sent ({len(acc)}B)")
                                    except Exception as e:
                                        print_warning(f"[TEAM] accept err: {e}")
                                    await asyncio.sleep(0.4)
                        except Exception as e:
                            print_warning(f"[TEAM] 0500 parse: {e}")
                        continue

                    if hex_data.startswith("0300") and 10 < packet_length < 30:
                        continue

                    if hex_data.startswith("0300") and packet_length >= 300:
                        print_success(f"[⚔] Match Found | UID: {uid_str}")
                        # WATCHDOG: timer reset — squad is no longer stuck
                        try:
                            _on_match_start(group_id, uid_str)
                        except Exception as _wd_err:
                            print_warning(f"[WATCHDOG] on_start failed: {_wd_err}")
                        for tk in (team_coord_task, member_trigger_task):
                            if tk and not tk.done():
                                tk.cancel()
                        team_coord_task = None
                        member_trigger_task = None
                        _team_active["flag"] = False

                        async with _team_state["lock"]:
                            _team_state["peers"].pop(uid_str, None)
                            if _team_state["leader_uid"] == uid_str:
                                _team_state["leader_uid"] = None
                                _team_state["team_code"] = None
                        print_info(f"[MATCH-START] {uid_str} left peer registry (in match)")

                        try:
                            res = json.loads(await decode_protobuf_async(hex_data[10:]))
                            token = udp_key = match_code = server_ip_port = None
                            match_account_id = block_val = None
                            match_game_mode = 1
                            match_map_id = 1
                            match_match_mode = 1
                            match_sleep_ms = 0
                            match_id = 0

                            if '42' in res and 'data' in res['42']:
                                match_code = res['42']['data']
                            if '5' in res and 'data' in res['5']:
                                rf5 = res['5']['data']
                                server_ip_port = rf5.get('2', {}).get('data')
                                udp_key = rf5.get('3', {}).get('data')
                                token = rf5.get('4', {}).get('data')
                                if '42' in rf5:
                                    match_code = rf5['42']['data']
                                try: match_id = int(rf5.get('1', {}).get('data') or 0)
                                except Exception: match_id = 0
                                try: match_map_id = int(rf5.get('6', {}).get('data') or 1)
                                except Exception: match_map_id = 1
                                try: match_game_mode = int(rf5.get('7', {}).get('data') or 1)
                                except Exception: match_game_mode = 1
                                try: match_match_mode = int(rf5.get('8', {}).get('data') or 1)
                                except Exception: match_match_mode = 1
                                try: match_sleep_ms = int(rf5.get('5', {}).get('data') or 0)
                                except Exception: match_sleep_ms = 0
                            if '1' in res and 'data' in res['1']:
                                match_account_id = res['1']['data']
                            if '5' in res and 'data' in res['5']:
                                block_val = res['5']['data'].get('1', {}).get('data')

                            effective_acc_id = match_account_id or account_id or "BD_BOT"

                            if token and udp_key and match_code and server_ip_port:
                                match_index = await _inc_match(uid_str)
                                print_info(f"[⚔] Match #{match_index} → {server_ip_port} "
                                           f"(mode={match_game_mode} map={match_map_id})")
                                try:
                                    bot_state.increment_match_started()
                                    bot_state.update_status(uid_str, "IN_MATCH", 1)
                                except Exception: pass

                                new_match = asyncio.create_task(play_game(
                                    server_ip_port,
                                    token,
                                    udp_key,
                                    match_code,
                                    effective_acc_id,
                                    account_region,
                                    client_version,
                                    current_key,
                                    current_iv,
                                    match_index,
                                    game_mode=match_game_mode,
                                    map_id=match_map_id,
                                    match_mode=match_match_mode,
                                    sleep_ms=match_sleep_ms,
                                    match_id=match_id,
                                    verbose=True,
                                ))
                                play_matches.append(new_match)

                                async def drain_gw():
                                    while not new_match.done():
                                        try:
                                            dg = await asyncio.wait_for(reader.read(4096), timeout=1.0)
                                            if not dg: break
                                            gh = dg.hex()
                                            if gh.startswith("0600") and len(dg) > 20:
                                                await _process_social_packet(dg, tag="DRAIN")
                                        except asyncio.TimeoutError: continue
                                        except Exception: break
                                drain_task = asyncio.create_task(drain_gw())
                                try:
                                    await asyncio.wait_for(new_match, timeout=MAX_MATCH_DURATION)
                                except asyncio.TimeoutError:
                                    print_warning(f"[MATCH #{match_index}] exceeded {MAX_MATCH_DURATION}s → cancelling")
                                    new_match.cancel()
                                except Exception as e:
                                    print_error(f"[MATCH #{match_index}] {e}")
                                finally:
                                    drain_task.cancel()
                                    try: await drain_task
                                    except asyncio.CancelledError: pass
                                play_matches[:] = [m for m in play_matches if not m.done()]

                                _match_played["flag"] = True
                                print_success(f"[RESTART] {uid_str} → match #{match_index} done → scheduling full script restart")
                                asyncio.create_task(_on_match_complete(group_id, uid_str))
                                break
                        except Exception as e:
                            print_warning(f"[MATCH] {e}"); continue

                    if 30 <= packet_length <= 40:
                        continue

            except asyncio.CancelledError: raise
            except Exception as e:
                if "Cache expired" in str(e):
                    print_warning(f"[!] Token expired {uid_str}"); break
                reconnects += 1
                if reconnects > max_reconnects:
                    if current_account_data:
                        try:
                            if current_account_data.get('auth_uid'):
                                cache_invalidate(str(current_account_data['auth_uid']))
                            if current_account_data.get('auth_token'):
                                cache_invalidate(f"tok_{current_account_data['auth_token'][:20]}")
                        except Exception: pass
                    reconnects = 0; break
                print_warning(f"[{uid_str}] Reconnect #{reconnects}: {e}")
                await asyncio.sleep(min(reconnects * 0.5, 2.0))
            finally:
                _team_active["flag"] = False
                async with _team_state["lock"]:
                    _team_state["peers"].pop(uid_str, None)
                    if _team_state["leader_uid"] == uid_str:
                        _team_state["leader_uid"] = None
                        _team_state["team_code"] = None
                for tk in (team_coord_task, member_trigger_task):
                    if tk and not tk.done():
                        tk.cancel()
                        try: await tk
                        except asyncio.CancelledError: pass
                if gateway_ping_task:
                    gateway_ping_task.cancel()
                    try: await gateway_ping_task
                    except asyncio.CancelledError: pass
                if writer:
                    bot_state.unregister_writer(uid_str, writer)
                    await safe_close_writer(writer)

                if _match_played["flag"]:
                    print_warning(f"[RESTART] {uid_str} → group {group_id} waiting for full script restart")
                    async with _group_restart_lock:
                        is_restarting = _restart_scheduled.get(group_id, False)
                    if is_restarting:
                        try:
                            while True:
                                await asyncio.sleep(3600)
                        except asyncio.CancelledError:
                            raise
                    return

                _match_played["flag"] = False
                _team_active["flag"] = True
    except asyncio.CancelledError:
        print_info(f"[FUNCTIONAL] Task cancelled for {uid_str}")
        raise
    finally:
        for m in play_matches:
            if not m.done(): m.cancel()

# ==================== INFORMATIONAL ====================
async def informational(addrs, starter_packet, key, iv, region="BD",
                        account_id="", max_reconnects=3, account_data=None):
    uid_str = str(account_id); reconnects = 0
    ip, port = addrs.split(":")
    while True:
        while uid_str and bot_state.is_paused(uid_str):
            await asyncio.sleep(1.0)
        writer = None; ping_task = None
        try:
            resolved_ip = await resolve_host_cloudflare(ip)
            reader, writer = await asyncio.open_connection(resolved_ip, int(port))
            if uid_str: bot_state.register_writer(uid_str, writer)
            raw_sock = writer.get_extra_info('socket')
            if raw_sock: optimize_tcp_socket(raw_sock)
            writer.write(bytes.fromhex(starter_packet)); await writer.drain()
            reconnects = 0
            try:
                init_ka = await send_keep_alive(region)
                if init_ka and not writer.is_closing():
                    writer.write(init_ka)
                    await asyncio.wait_for(writer.drain(), timeout=3)
            except Exception: pass
            async def info_ka():
                ka = await send_keep_alive(region)
                while True:
                    await asyncio.sleep(5)
                    try:
                        if writer and not writer.is_closing():
                            writer.write(ka); await writer.drain()
                    except Exception: break
            ping_task = asyncio.create_task(info_ka())
            print_success(f"[INFO] Connected | UID: {uid_str}")
            while True:
                if uid_str and bot_state.is_paused(uid_str):
                    if ping_task: ping_task.cancel()
                    if uid_str: bot_state.unregister_writer(uid_str, writer)
                    await safe_close_writer(writer); writer = None
                    while bot_state.is_paused(uid_str): await asyncio.sleep(1.0)
                    break
                try: data = await asyncio.wait_for(reader.read(8192), timeout=1.0)
                except asyncio.TimeoutError: continue
                if not data: raise ConnectionError("closed")
        except asyncio.CancelledError:
            if ping_task: ping_task.cancel()
            if uid_str: bot_state.unregister_writer(uid_str, writer)
            await safe_close_writer(writer); raise
        except Exception:
            if ping_task: ping_task.cancel()
            if uid_str: bot_state.unregister_writer(uid_str, writer)
            await safe_close_writer(writer)
            reconnects += 1
            if reconnects > max_reconnects:
                await asyncio.sleep(3); reconnects = 0
            else: await asyncio.sleep(1)

# ==================== ACCOUNT HELPERS ====================
def _register_credentials(ad):
    try:
        bot_state.account_credentials[str(ad['account_id'])] = ad
        if ad.get('auth_uid'): bot_state.account_credentials[str(ad['auth_uid'])] = ad
    except Exception: pass

async def refresh_account_profile(ad_or_uid):
    try:
        if isinstance(ad_or_uid, str):
            uid = str(ad_or_uid); ad = bot_state.account_credentials.get(uid)
        else:
            ad = ad_or_uid; uid = str(ad.get('account_id'))
        if not ad: return
        token = ad.get('token'); acc_id = ad.get('account_id')
        srv = ad.get('server_url'); rel = ad.get('release_version')
        if not (token and acc_id and srv and rel): return
        data = await get_player_personal_show(int(acc_id), token, srv, rel)
        if not data: return
        pd = data.get(1, {}) if isinstance(data.get(1), dict) else {}
        nickname = pd.get(3); lvl = pd.get(6); exp = pd.get(7)
        if exp is None: return
        try:
            exp = int(exp); lvl = int(lvl) if lvl else 1
        except Exception: return
        aid = str(acc_id)
        if aid not in bot_state.accounts:
            bot_state.register_account(aid, nickname or f"Player_{aid}",
                region=ad.get('region','BD'), level=lvl, exp=exp,
                auth_uid=ad.get('auth_uid'))
            return
        old = bot_state.accounts[aid].get("current_exp", 0)
        bot_state.update_exp(aid, exp, lvl)
        if nickname: bot_state.accounts[aid]["nickname"] = nickname
        if exp > old: print_success(f"[★] +{exp-old:,} EXP | {aid}")
    except Exception: pass

async def process_account_uid_pass(uid, password, region_override=None):
    cached = cache_get(uid)
    if cached:
        aid = str(cached['account_id'])
        nick = cached.get('nickname', f"Player_{aid}")
        lvl = cached.get('level', 1); expv = cached.get('exp', 0)
        print_success(f"[✓] Online (cache): {aid} | {nick}")
        bot_state.register_account(aid, nick, cached.get('region','BD'),
            lvl, expv, cached.get('likes',0), auth_uid=str(uid))
        _register_credentials(cached); return cached
    print_info(f"[LOGIN] UID: {uid}")
    try:
        async with _LOGIN_SEMAPHORE:
            vc = await version_config(region_override or "BD")
            if not vc: return None
            release_version, client_version, server_url, gop_1, app_version = vc
            tg = await get_access_token(uid, password)
            if not tg: return None
            open_id, access_token, platform = tg
            major_payload, login_payload = await get_payload(
                access_token, open_id, platform, client_version)
            res_json = await major_login(major_payload, server_url, release_version)
            if not res_json: return None

            def _gd(k):
                v = res_json.get(str(k))
                if isinstance(v, dict) and "data" in v: return v["data"]
                if k in res_json and not isinstance(res_json[k], dict): return res_json[k]
                if isinstance(v, dict): return v.get("data")
                return None

            acc_id_raw = _gd(1); region_raw = _gd(2) or "BD"
            jwt_token = _gd(8); server_url_raw = _gd(10); server_time = _gd(21)
            aes_ak, iv_i = _extract_key_iv(res_json)
            if not jwt_token or not server_url_raw or not aes_ak: return None
            getlogin_json = await get_login_data(
                login_payload, jwt_token, server_url_raw, release_version)
            if not getlogin_json: return None

        def _gf(f, d=None):
            v = getlogin_json.get(str(f), {}).get("data")
            return v if v is not None else d

        level = int(_gf(6,1) or 1); exp = int(_gf(7,0) or 0)
        likes = int(_gf(8,0) or 0)
        nickname = _gf(4, f"Player_{acc_id_raw}") or f"Player_{acc_id_raw}"
        region = region_raw or _gf(3,"BD") or "BD"
        acc_id = str(acc_id_raw)

        bot_state.register_account(acc_id, nickname, region, level, exp, likes, auth_uid=str(uid))
        print_success(f"[✓] Login: {acc_id} | {nickname} | Lvl {level}")

        ad = {'account_id':acc_id_raw,'nickname':nickname,'region':region,
            'level':level,'exp':exp,'likes':likes,'open_id':open_id,
            'access_token':access_token,'platform':str(platform),
            'token':jwt_token,'server_time':server_time,
            'aes_ak':aes_ak,'iv_i':iv_i,
            'functional_addrs':_gf(14),'informational_addrs':_gf(32),
            'release_version':release_version,'client_version':client_version,
            'server_url':server_url_raw,'login_payload_data':login_payload,
            'auth_type':'guest','auth_uid':uid,'auth_password':password}
        _register_credentials(ad); cache_set(uid, ad); return ad
    except Exception as e:
        print_error(f"login err: {e}"); return None

async def run_account_worker(ad, label, region_override=None, clan_override=None,
                             group_id: str = "default"):
    acc_id = str(ad['account_id'])
    info_task = None; exp_task = None; clan_task = None
    try:
        reg = region_override or ad.get('region','BD')
        tcp_online = await build_tcp_startup_packet(
            ad['account_id'], ad['token'], ad['server_time'],
            ad['aes_ak'], ad['iv_i'], region=reg, typ='OnLine')
        tcp_chat = await build_tcp_startup_packet(
            ad['account_id'], ad['token'], ad['server_time'],
            ad['aes_ak'], ad['iv_i'], region=reg, typ='ChaT')

        if clan_override:
            try:
                await asyncio.sleep(1.0)
                await join_clan(ad['token'], clan_override)
            except Exception as e:
                print_warning(f"[CLAN] {e}")

            async def clan_info_refresher():
                while True:
                    try:
                        fresh_ad = bot_state.account_credentials.get(acc_id) or ad
                        fresh_token = fresh_ad.get('token') or ad['token']
                        info = await get_clan_info(fresh_token, clan_override)
                        if info:
                            bot_state.clan_info = info
                    except Exception as e:
                        print_warning(f"[CLAN-INFO] {e}")
                    await asyncio.sleep(30)

            clan_task = asyncio.create_task(clan_info_refresher())

        info_task = asyncio.create_task(informational(
            ad['informational_addrs'], tcp_chat, ad['aes_ak'], ad['iv_i'],
            region=reg, account_id=acc_id, account_data=ad))

        async def exp_refresher():
            while True:
                await asyncio.sleep(90 + random.uniform(-10,10))
                fresh = bot_state.account_credentials.get(acc_id)
                if fresh: await refresh_account_profile(fresh)
        exp_task = asyncio.create_task(exp_refresher())

        await functional_lone_wolf(
            ad['functional_addrs'], tcp_online, reg, ad['client_version'],
            ad['aes_ak'], ad['iv_i'], account_id=acc_id, account_data=ad,
            group_id=group_id)

    except asyncio.CancelledError: raise
    except Exception as e:
        print_error(f"worker err {label}: {e}")
    finally:
        for t in (info_task, exp_task, clan_task):
            if t and not t.done(): t.cancel()
        for t in (info_task, exp_task, clan_task):
            if t:
                try: await t
                except Exception: pass

        try:
            if ad.get('auth_uid'):
                cache_invalidate(str(ad['auth_uid']))
                print_info(f"[RESTART] Cache cleared for {ad['auth_uid']} (group {group_id})")
        except Exception: pass

async def account_loop_guest(uid, password, region_override=None, clan_override=None,
                              group_id: str = "default"):
    uid_str = str(uid)
    bot_state.account_workers[uid_str] = asyncio.current_task()
    acc_id = None
    while True:
        try:
            cache_invalidate(uid_str)

            bot_state.update_status(uid_str, "CONNECTING")
            ad = await process_account_uid_pass(uid_str, password, region_override)
            if not ad:
                print_error(f"Login failed {uid_str}. Retry 15s"); await asyncio.sleep(15); continue
            acc_id = str(ad['account_id'])
            bot_state.account_workers[acc_id] = asyncio.current_task()
            bot_state.auth_to_game_id[uid_str] = acc_id
            bot_state.game_to_auth_id[acc_id] = uid_str

            print_success(f"[LOGIN ✓] {uid_str} → acc_id {acc_id} | group {group_id}")

            await run_account_worker(ad, uid_str, region_override, clan_override,
                                     group_id=group_id)

            async with _group_restart_lock:
                is_restarting = _restart_scheduled.get(group_id, False)
            if is_restarting:
                print_info(f"[RESTART] {uid_str} — waiting for full script restart (group {group_id})")
                try:
                    while True:
                        await asyncio.sleep(3600)
                except asyncio.CancelledError:
                    raise

            jitter = random.uniform(0, 4.0)
            print_warning(f"[RESTART] {uid_str} → re-login in {3+jitter:.1f}s (group {group_id})")
            await asyncio.sleep(3 + jitter)

        except asyncio.CancelledError:
            try:
                bot_state.update_status(uid_str, "OFFLINE")
                if acc_id: bot_state.update_status(acc_id, "OFFLINE")
            except Exception: pass
            break
        except Exception as e:
            print_error(f"err {uid_str}: {e}"); await asyncio.sleep(10)

# ==================== CREATE ACCOUNTS ====================
def _gf_field(ld, key, default=None):
    if not ld: return default
    v = ld.get(str(key), {})
    if isinstance(v, dict): return v.get("data", default)
    return v if v is not None else default


def generate_password() -> str:
    return hashlib.sha256(
        (str(uuid.uuid4()) + str(time.time())).encode()
    ).hexdigest().upper()


async def choose_region(region, jwt_token, login_url, release_version):
    region_code = region.upper()
    url = f"{login_url.rstrip('/')}/ChooseRegion"
    proto = create_proto({1: region_code})
    payload = bytes.fromhex(encrypt_aes(proto.hex()))
    hdrs = {
        "Accept-Encoding": "gzip",
        "Authorization": f"Bearer {jwt_token}",
        "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "ReleaseVersion": f"{release_version}",
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "X-GA": "v1 1", "X-GA-SV": str(int(time.time())),
        "X-Unity-Version": "2018.4.12f1",
    }
    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False; ssl_ctx.verify_mode = ssl.CERT_NONE
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as s:
            async with s.post(url, data=payload, headers=hdrs, ssl=ssl_ctx) as r:
                body = await r.read()
                print_info(f"[CHOOSE-REGION] {region} → HTTP {r.status}")
                return r.status
    except Exception as e:
        print_error(f"[CHOOSE-REGION] {e}"); return None

async def create_four_accounts(region: str, clan_id: str, count: int = 4):
    bot_state.creating = True
    bot_state.create_progress = []

    def _prog(s):
        try:
            print(f"[CREATE] {s}")
            bot_state.log(s, "info")
        except Exception: pass
        bot_state.create_progress.append(s)

    try:
        _prog(f"⌛ Fetching version config for {region}...")
        vc = await version_config(region)
        if not vc:
            _prog("❌ version config failed"); return []
        release_v, remote_v, login_url, gop_1, app_version = vc
        if not login_url.endswith("/"): login_url += "/"
        lang = REGION_LANG.get(region.upper(), "en")
        game_version = remote_v or app_version
        _prog(f"✅ Version OK | release={release_v} | game={game_version}")

        created = []
        for i in range(count):
            _prog(f"⌛ Creating bot {i+1}/{count}...")

            password = generate_password()
            _prog(f"   → Password: {password[:16]}...{password[-8:]}")

            try:
                uid = await register_account(password, gop_1, app_version)
                if not uid:
                    _prog(f"❌ bot {i+1}: register failed"); continue
                _prog(f"   → registered UID {uid}")

                tok = await grant_token(uid, password, gop_1, app_version)
                if not tok:
                    _prog(f"❌ bot {i+1}: grant failed"); continue
                open_id = tok["open_id"]; access_token = tok["access_token"]
                platform = tok.get("platform", 4)

                major_payload, login_payload = await get_payload(
                    access_token, open_id, platform, game_version, lang)
                if not major_payload or not login_payload:
                    _prog(f"❌ bot {i+1}: payload build failed"); continue

                nickname_final = f"MEHEDI_{''.join(random.choices(string.ascii_letters + string.digits, k=5))}"
                mr = await major_register(release_v, access_token, open_id,
                                          nickname_final, game_version, login_url, lang)
                if not mr:
                    _prog(f"❌ bot {i+1}: MajorRegister failed"); continue

                def _mrg(k, d=None):
                    v = mr.get(str(k))
                    if isinstance(v, dict) and "data" in v: return v["data"]
                    return v if v is not None else d

                mr_acc_id = _mrg(3)
                _prog(f"   → MajorRegister OK | acc_id={mr_acc_id}")
                _prog(f"   → waiting 3s for provisioning...")
                await asyncio.sleep(3.0)

                res_json = None
                for attempt in range(3):
                    mp, lp = await get_payload(access_token, open_id, platform, game_version, lang)
                    _prog(f"   → MajorLogin #1 attempt {attempt+1}/3...")
                    res_json = await major_login(mp, login_url, release_v)
                    if res_json and (("8" in res_json) or (8 in res_json)):
                        major_payload = mp; login_payload = lp; break
                    res_json = None
                    await asyncio.sleep(2.0)

                if not res_json:
                    _prog(f"❌ bot {i+1}: MajorLogin #1 failed"); continue

                def _gd(k):
                    v = res_json.get(str(k))
                    if isinstance(v, dict) and "data" in v: return v["data"]
                    if k in res_json and not isinstance(res_json[k], dict): return res_json[k]
                    if isinstance(v, dict): return v.get("data")
                    return None

                jwt_token = _gd(8); server_url_raw = _gd(10)
                server_time = _gd(21); acc_id_raw = _gd(1)

                if not jwt_token:
                    _prog(f"❌ bot {i+1}: no JWT"); continue

                if not server_url_raw:
                    _prog(f"   → server_url missing — ChooseRegion({region})...")
                    try:
                        cr_status = await choose_region(region, jwt_token, login_url, release_v)
                    except Exception as e:
                        cr_status = None; _prog(f"   ❌ ChooseRegion error: {e}")
                    if cr_status != 200:
                        _prog(f"❌ bot {i+1}: ChooseRegion failed ({cr_status})"); continue
                    _prog(f"   ✅ ChooseRegion OK — re-running MajorLogin...")
                    await asyncio.sleep(2.0)
                    res_json2 = None
                    for attempt in range(3):
                        mp2, lp2 = await get_payload(access_token, open_id, platform, game_version, lang)
                        res_json2 = await major_login(mp2, login_url, release_v)
                        if res_json2 and (("10" in res_json2) or (10 in res_json2)):
                            res_json = res_json2; login_payload = lp2; break
                        res_json2 = None
                        await asyncio.sleep(2.0)
                    if not res_json2:
                        _prog(f"❌ bot {i+1}: MajorLogin #2 no server_url"); continue
                    res_json = res_json2

                    def _gd2(k):
                        v = res_json.get(str(k))
                        if isinstance(v, dict) and "data" in v: return v["data"]
                        if k in res_json and not isinstance(res_json[k], dict): return res_json[k]
                        if isinstance(v, dict): return v.get("data")
                        return None
                    jwt_token = _gd2(8); server_url_raw = _gd2(10)
                    server_time = _gd2(21); acc_id_raw = _gd2(1)
                    if not server_url_raw:
                        _prog(f"❌ bot {i+1}: no server_url"); continue

                _prog(f"   ✅ server_url = {server_url_raw}")

                aes_ak, iv_i = _extract_key_iv(res_json)
                if not aes_ak or not iv_i:
                    _prog(f"❌ bot {i+1}: AES key/IV fail"); continue

                ld = await get_login_data(login_payload, jwt_token, server_url_raw, release_v)
                level = 1; exp = 0; likes = 0
                if ld:
                    def _gf(f, d=None):
                        v = ld.get(str(f), {}).get("data")
                        return v if v is not None else d
                    level = int(_gf(6, 1) or 1); exp = int(_gf(7, 0) or 0)
                    likes = int(_gf(8, 0) or 0)
                    nickname_final = _gf(4, nickname_final) or nickname_final

                ad = {
                    'account_id': acc_id_raw, 'nickname': nickname_final,
                    'region': region, 'level': level, 'exp': exp, 'likes': likes,
                    'open_id': open_id, 'access_token': access_token,
                    'platform': str(platform), 'token': jwt_token,
                    'server_time': server_time, 'aes_ak': aes_ak, 'iv_i': iv_i,
                    'functional_addrs': _gf_field(ld, 14),
                    'informational_addrs': _gf_field(ld, 32),
                    'release_version': release_v, 'client_version': game_version,
                    'server_url': server_url_raw, 'login_payload_data': login_payload,
                    'auth_type': 'guest', 'auth_uid': uid, 'auth_password': password,
                }
                _register_credentials(ad); cache_set(uid, ad); created.append(ad)
                _prog(f"✅ bot {i+1}: {nickname_final} | UID {acc_id_raw} | Lvl {level}")
                await asyncio.sleep(0.6)
            except Exception as e:
                _prog(f"❌ bot {i+1}: {e}")
                traceback.print_exc()

        if not created:
            _prog("❌ No accounts created."); return []

        group_id = None
        try:
            team_accounts = [
                {
                    "uid": str(a['auth_uid']),
                    "password": str(a['auth_password']),
                    "account_id": str(a.get('account_id', '')),
                    "nickname": str(a.get('nickname', '')),
                }
                for a in created
            ]
            group_id = save_team_file(clan_id, region, team_accounts)
            if group_id:
                _prog(f"📦 Group saved → {TEAMS_DIR}/group_{group_id}.json ({len(created)} bots)")
            else:
                _prog(f"⚠️ Group file save failed")
        except Exception as e:
            _prog(f"⚠️ save group file failed: {e}")

        _prog(f"🚀 Starting {len(created)} bot workers...")
        for i, a in enumerate(created):
            try:
                task = asyncio.create_task(account_loop_guest(
                    str(a['auth_uid']), a['auth_password'],
                    region_override=region, clan_override=clan_id,
                    group_id=group_id))
                bot_state.account_workers[str(a['auth_uid'])] = task
                _prog(f"   → worker started ({i+1}/{len(created)})")
                await asyncio.sleep(0.35)
            except Exception as e:
                _prog(f"   ❌ worker {i+1} failed: {e}")

        _prog(f"✅ All {len(created)} bots launched.")
        return created
    except Exception as e:
        _prog(f"❌ create_four_accounts error: {e}")
        traceback.print_exc(); return []
    finally:
        bot_state.creating = False

# ==================== AUTO-LOAD ON STARTUP ====================
async def _autoload_teams():
    try:
        teams = load_all_team_files()
        if not teams:
            print_info(f"[BOOT] no teams in {TEAMS_DIR}/ — waiting for API calls")
            return
        total_accounts = sum(len(t["accounts"]) for t in teams)
        print_info(f"[BOOT] {len(teams)} team(s) found in {TEAMS_DIR}/ | {total_accounts} total bots")

        for team in teams:
            clan_id = team["clan_id"]
            region = team["region"]
            group_id = team.get("group_id", "default")
            print_success(f"[BOOT] Team clan={clan_id} group={group_id} region={region} — launching {len(team['accounts'])} bots")

            for acc in team["accounts"]:
                uid = acc["uid"]
                password = acc["password"]

                if uid in bot_state.account_workers and not bot_state.account_workers[uid].done():
                    print_info(f"[BOOT] UID {uid} already running — skipped")
                    continue

                task = asyncio.create_task(account_loop_guest(
                    uid, password,
                    region_override=region,
                    clan_override=clan_id,
                    group_id=group_id,
                ))
                bot_state.account_workers[uid] = task
                print_success(f"[BOOT] worker started → UID {uid} | clan={clan_id} | group={group_id}")
                await asyncio.sleep(0.4)
    except Exception as e:
        print_error(f"[BOOT] team load failed: {e}")

# ==================== HTTP SERVER ====================
@aiohttp.web.middleware
async def _req_logger(request, handler):
    print(f"\033[90m[REQ] {request.method} {request.path}\033[0m")
    try:
        resp = await handler(request)
        print(f"\033[90m[RES] {request.method} {request.path} → {resp.status}\033[0m")
        return resp
    except aiohttp.web.HTTPException as e:
        print(f"\033[91m[ERR] {request.method} {request.path} → HTTP {e.status}\033[0m")
        if request.path.startswith("/api/"):
            return aiohttp.web.json_response(
                {"ok": False, "status": "error", "error": e.reason or str(e)},
                status=e.status)
        raise
    except Exception as e:
        print(f"\033[91m[ERR] {request.method} {request.path} → {e}\033[0m")
        traceback.print_exc()
        if request.path.startswith("/api/"):
            return aiohttp.web.json_response(
                {"ok": False, "status": "error", "error": str(e)}, status=500)
        raise

async def serve_index(request):
    for path in (INDEX_HTML_PATH, "index.html"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return aiohttp.web.Response(text=f.read(), content_type="text/html")
        except Exception:
            continue
    return aiohttp.web.Response(
        text="<h1>RAW MARUF</h1><p>index.html not found</p>",
        content_type="text/html")

async def api_ping(request):
    return aiohttp.web.json_response({"pong": True, "app": "RAW MARUF", "version": "2.0"})

async def api_stats(request):
    try:
        accs = list(bot_state.accounts.values())
        online = sum(1 for a in accs if a.get("status") in ("ONLINE","IN_MATCH","SEARCHING"))
        active_matches = sum(a.get("active_matches", 0) for a in accs)
        uptime = max(1, int(time.time() - bot_state.start_time))
        uptime_h = max(0.016, uptime / 3600.0)
        exp_rate = int(bot_state.total_exp_gained / uptime_h) if uptime_h > 0 else 0
        matches_rate = int(bot_state.matches_started / uptime_h) if uptime_h > 0 else 0
        logs_out = []
        for l in bot_state.logs[-200:]:
            try:
                logs_out.append({"time": str(l.get("time","")),
                                 "message": str(l.get("message","")),
                                 "level": str(l.get("level","info"))})
            except Exception: continue
        data = {
            "accounts": accs, "logs": logs_out,
            "total_accounts": len(accs), "total_online": online,
            "total_matches": bot_state.total_matches,
            "total_matches_started": bot_state.matches_started,
            "total_active_matches": active_matches,
            "total_gained_exp": bot_state.total_exp_gained,
            "uptime": uptime, "exp_per_hour": exp_rate,
            "matches_per_hour": matches_rate,
            "creating": bool(bot_state.creating),
            "create_progress": [str(x) for x in bot_state.create_progress[-40:]],
            "team_code": {gid: ts.get("team_code") for gid, ts in _team_states.items()},
            "leader_uid": {gid: ts.get("leader_uid") for gid, ts in _team_states.items()},
            "team_size": sum(len(ts["peers"]) for ts in _team_states.values()),
            "restart_finished": 0,
            "restart_target": 0,
            "restarting": False,
        }
        return aiohttp.web.Response(text=json.dumps(data, default=str, ensure_ascii=False),
                                    content_type="application/json", charset="utf-8")
    except Exception as e:
        traceback.print_exc()
        return aiohttp.web.Response(text=json.dumps({
            "error": str(e), "accounts": [], "logs": [], "create_progress": [],
            "creating": False, "total_accounts": 0, "total_matches_started": 0,
            "total_matches": 0, "total_active_matches": 0, "total_gained_exp": 0,
            "uptime": 1, "exp_per_hour": 0,
        }), content_type="application/json", charset="utf-8")

async def api_state(request):
    try:
        return aiohttp.web.Response(text=json.dumps({
            "creating": bool(bot_state.creating),
            "create_progress": [str(x) for x in bot_state.create_progress[-40:]],
            "accounts": list(bot_state.accounts.values()),
            "team_size": sum(len(ts["peers"]) for ts in _team_states.values()),
            "team_groups": list(_team_states.keys()),
        }, default=str, ensure_ascii=False), content_type="application/json", charset="utf-8")
    except Exception as e:
        return aiohttp.web.Response(text=json.dumps({"error": str(e), "creating": False,
                                    "create_progress": []}),
                                    content_type="application/json", charset="utf-8")

async def api_progress(request):
    try:
        lines = []
        for x in bot_state.create_progress[-60:]:
            try: lines.append(str(x).encode("ascii","backslashreplace").decode("ascii"))
            except Exception: continue
        text = '{"creating":' + ("true" if bot_state.creating else "false") + \
               ',"create_progress":' + json.dumps(lines) + '}'
        return aiohttp.web.Response(text=text, content_type="application/json")
    except Exception:
        return aiohttp.web.Response(text='{"creating":false,"create_progress":[]}',
                                    content_type="application/json")

async def api_create_team(request):
    try:
        body = await request.json()
        region = str(body.get("region", "BD")).upper()
        clan_id = str(body.get("clan_id", "")).strip()
        count = int(body.get("count", 4))
        if not clan_id:
            return aiohttp.web.json_response({"ok": False, "error": "clan_id required"})
        if bot_state.creating:
            return aiohttp.web.json_response({"ok": False, "error": "already creating"})
        count = max(1, min(4, count))
        asyncio.create_task(create_four_accounts(region, clan_id, count))
        return aiohttp.web.json_response({"ok": True, "msg": f"creating {count} bots for {region}"})
    except Exception as e:
        traceback.print_exc()
        return aiohttp.web.json_response({"ok": False, "error": str(e)})

async def api_account_add(request):
    try:
        body = await request.json()
        if body.get("token"):
            token = str(body["token"]).strip()
            if not token:
                return aiohttp.web.json_response({"status": "error", "error": "empty token"})
            asyncio.create_task(account_loop_token(token))
            return aiohttp.web.json_response({"status": "ok"})
        uid = str(body.get("uid", "")).strip()
        password = str(body.get("password", "")).strip()
        if not uid or not password:
            return aiohttp.web.json_response({"status": "error", "error": "uid and password required"})
        asyncio.create_task(account_loop_guest(uid, password))
        return aiohttp.web.json_response({"status": "ok"})
    except Exception as e:
        return aiohttp.web.json_response({"status": "error", "error": str(e)})

async def api_account_delete(request):
    try:
        body = await request.json()
        uid = str(body.get("uid", "")).strip()
        auth_uid = str(body.get("auth_uid", "")).strip()
        targets = {uid, auth_uid} - {""}
        for u in list(targets):
            if u in bot_state.account_workers:
                try: bot_state.account_workers[u].cancel()
                except Exception: pass
                bot_state.account_workers.pop(u, None)
            if u in bot_state.accounts:
                del bot_state.accounts[u]
            cache_invalidate(u)
            bot_state.toggle_pause(u, False)
        return aiohttp.web.json_response({"status": "ok"})
    except Exception as e:
        return aiohttp.web.json_response({"status": "error", "error": str(e)})

async def api_account_refresh(request):
    try:
        body = await request.json()
        uid = str(body.get("uid", "")).strip()
        asyncio.create_task(refresh_account_profile(uid))
        return aiohttp.web.json_response({"status": "ok"})
    except Exception as e:
        return aiohttp.web.json_response({"status": "error", "error": str(e)})

async def api_account_restart(request):
    try:
        body = await request.json()
        uid = str(body.get("uid", "")).strip()
        resolved = {uid}
        if uid in bot_state.game_to_auth_id: resolved.add(str(bot_state.game_to_auth_id[uid]))
        if uid in bot_state.auth_to_game_id: resolved.add(str(bot_state.auth_to_game_id[uid]))
        for u in resolved:
            if u in bot_state.account_workers:
                try: bot_state.account_workers[u].cancel()
                except Exception: pass
                bot_state.account_workers.pop(u, None)

        try:
            teams = load_all_team_files()
            for team in teams:
                for a in team["accounts"]:
                    if str(a["uid"]) in resolved and a.get("password"):
                        t = asyncio.create_task(account_loop_guest(
                            str(a["uid"]), a["password"],
                            region_override=team["region"],
                            clan_override=team["clan_id"],
                            group_id=team.get("group_id", "default"),
                        ))
                        bot_state.account_workers[str(a["uid"])] = t
                        break
        except Exception:
            pass
        return aiohttp.web.json_response({"status": "ok"})
    except Exception as e:
        return aiohttp.web.json_response({"status": "error", "error": str(e)})

async def api_account_pause(request):
    try:
        body = await request.json()
        uid = str(body.get("uid", "")).strip()
        new_state = not bot_state.is_paused(uid)
        bot_state.toggle_pause(uid, new_state)
        if new_state: bot_state.close_writers_for_account(uid)
        return aiohttp.web.json_response({"status": "ok", "is_paused": new_state})
    except Exception as e:
        return aiohttp.web.json_response({"status": "error", "error": str(e)})

async def api_account_pause_all(request):
    try:
        accs = list(bot_state.accounts.keys())
        if not accs:
            return aiohttp.web.json_response({"status": "ok", "all_paused": False})
        all_paused = all(bot_state.is_paused(u) for u in accs)
        new_state = not all_paused
        for u in accs:
            bot_state.toggle_pause(u, new_state)
            if new_state: bot_state.close_writers_for_account(u)
        return aiohttp.web.json_response({"status": "ok", "all_paused": new_state})
    except Exception as e:
        return aiohttp.web.json_response({"status": "error", "error": str(e)})

async def api_logs_clear(request):
    bot_state.logs = []
    return aiohttp.web.json_response({"status": "ok"})

async def account_loop_token(token):
    print_info(f"[TOKEN] Login with token {token[:20]}...")
    try:
        vc = await version_config("BD")
        if not vc: return
        release_version, client_version, server_url, gop_1, app_version = vc
        url = f"https://100067.connect.garena.com/oauth/token/inspect?token={token}"
        hdrs = {"User-Agent":"GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)"}
        r = await client.get(url, headers=hdrs)
        if r.status_code != 200: return
        data = r.json()
        if 'error' in data: return
        open_id = data.get('open_id')
        platform = data.get('platform', 4)
        if not open_id: return

        major_payload, login_payload = await get_payload(
            token, open_id, platform, client_version)
        res_json = await major_login(major_payload, server_url, release_version)
        if not res_json: return

        def _gd(k):
            v = res_json.get(str(k))
            if isinstance(v, dict) and "data" in v: return v["data"]
            return v

        acc_id_raw = _gd(1); jwt_token = _gd(8)
        server_url_raw = _gd(10); server_time = _gd(21)
        region_raw = _gd(2) or "BD"
        aes_ak, iv_i = _extract_key_iv(res_json)
        if not (jwt_token and server_url_raw and aes_ak): return

        ld = await get_login_data(login_payload, jwt_token, server_url_raw, release_version)

        def _gf(f, d=None):
            v = (ld or {}).get(str(f), {}).get("data")
            return v if v is not None else d

        level = int(_gf(6,1) or 1); exp = int(_gf(7,0) or 0)
        nickname = _gf(4, f"Player_{acc_id_raw}") or f"Player_{acc_id_raw}"

        ad = {'account_id':acc_id_raw,'nickname':nickname,'region':region_raw,
            'level':level,'exp':exp,'likes':int(_gf(8,0) or 0),
            'open_id':open_id,'access_token':token,'platform':str(platform),
            'token':jwt_token,'server_time':server_time,
            'aes_ak':aes_ak,'iv_i':iv_i,
            'functional_addrs':_gf_field(ld, 14),
            'informational_addrs':_gf_field(ld, 32),
            'release_version':release_version,'client_version':client_version,
            'server_url':server_url_raw,'login_payload_data':login_payload,
            'auth_type':'token','auth_token':token}
        _register_credentials(ad)
        cache_set(f"tok_{token[:20]}", ad)
        await run_account_worker(ad, str(acc_id_raw))
    except Exception as e:
        print_error(f"[TOKEN] {e}")

async def api_teams(request):
    try:
        teams = load_all_team_files()
        return aiohttp.web.json_response({
            "ok": True,
            "teams": [
                {
                    "group_id": t.get("group_id", ""),
                    "clan_id": t["clan_id"],
                    "region": t["region"],
                    "file": t["file"],
                    "count": len(t["accounts"]),
                    "uids": [a["uid"] for a in t["accounts"]],
                }
                for t in teams
            ],
        })
    except Exception as e:
        return aiohttp.web.json_response({"ok": False, "error": str(e)})

async def api_team_delete(request):
    try:
        body = await request.json()
        group_id = str(body.get("group_id", "")).strip()
        if not group_id:
            return aiohttp.web.json_response({"ok": False, "error": "group_id required"})

        teams = load_all_team_files()
        for t in teams:
            if str(t.get("group_id", "")) != group_id:
                continue
            for a in t["accounts"]:
                u = a["uid"]
                if u in bot_state.account_workers:
                    try: bot_state.account_workers[u].cancel()
                    except Exception: pass
                    bot_state.account_workers.pop(u, None)
                if u in bot_state.accounts:
                    del bot_state.accounts[u]
                cache_invalidate(u)
            break

        delete_team_file(group_id)
        return aiohttp.web.json_response({"ok": True})
    except Exception as e:
        return aiohttp.web.json_response({"ok": False, "error": str(e)})

async def api_clan_info(request):
    try:
        force = request.rel_url.query.get("force", "0") == "1"
        req_clan_id = request.rel_url.query.get("clan_id", "").strip()

        if not hasattr(bot_state, '_clan_cache'):
            bot_state._clan_cache = {}

        teams = load_all_team_files()

        async def _fetch_clan(team):
            clan_id = team["clan_id"]
            cached_key = f"clan_{clan_id}"

            if not force and cached_key in bot_state._clan_cache:
                return bot_state._clan_cache[cached_key]

            token = None
            for acc in team["accounts"]:
                auth_uid = str(acc["uid"])
                game_uid = bot_state.auth_to_game_id.get(auth_uid, auth_uid)
                creds = (bot_state.account_credentials.get(game_uid) or
                         bot_state.account_credentials.get(auth_uid))
                if creds and creds.get('token'):
                    token = creds['token']
                    break

            if not token:
                print_warning(f"[CLAN-API] No token for clan {clan_id}")
                return None

            print_info(f"[CLAN-API] Fetching clan {clan_id}")
            info = await get_clan_info(token, clan_id)
            if info:
                bot_state._clan_cache[cached_key] = info
            return info

        if req_clan_id:
            target_team = next((t for t in teams if t["clan_id"] == req_clan_id), None)
            if not target_team:
                return aiohttp.web.json_response({"ok": False, "error": f"No team file for clan {req_clan_id}"})
            info = await _fetch_clan(target_team)
            if not info:
                return aiohttp.web.json_response({"ok": False, "error": "fetch failed"})
            return aiohttp.web.json_response({"ok": True, **info})

        results = []
        for team in teams:
            info = await _fetch_clan(team)
            if info:
                results.append(info)

        return aiohttp.web.json_response({"ok": True, "clans": results})

    except Exception as e:
        traceback.print_exc()
        return aiohttp.web.json_response({"ok": False, "error": str(e)})

async def start_web_server():
    app = aiohttp.web.Application(middlewares=[_req_logger])
    app.router.add_get("/", serve_index)
    app.router.add_get("/index.html", serve_index)
    app.router.add_get("/api/ping", api_ping)
    app.router.add_get("/api/stats", api_stats)
    app.router.add_get("/api/state", api_state)
    app.router.add_post("/api/create_team", api_create_team)
    app.router.add_post("/api/account/add", api_account_add)
    app.router.add_post("/api/account/delete", api_account_delete)
    app.router.add_post("/api/account/refresh", api_account_refresh)
    app.router.add_post("/api/account/restart", api_account_restart)
    app.router.add_post("/api/account/pause", api_account_pause)
    app.router.add_post("/api/account/pause_all", api_account_pause_all)
    app.router.add_post("/api/logs/clear", api_logs_clear)
    app.router.add_get("/api/progress", api_progress)
    app.router.add_get("/api/teams", api_teams)
    app.router.add_get("/api/clan/info", api_clan_info)
    app.router.add_post("/api/team/delete", api_team_delete)
    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, WEB_HOST, WEB_PORT)
    await site.start()
    print_success(f"[WEB] RAW MARUF Dashboard → http://localhost:{WEB_PORT}")
    for r in app.router.routes():
        method = ",".join(r.method)
        print(f"      {method:5} {r.resource}")
    return runner

# ==================== MAIN ====================
async def main():
    if os.path.exists(RESTART_MARKER):
        try:
            with open(RESTART_MARKER, "r", encoding="utf-8") as f:
                content = f.read().strip()
            print_info(f"[BOOT] ⚡ Previous restart: {content}")
            os.remove(RESTART_MARKER)
        except Exception:
            pass

    try:
        await start_web_server()
    except Exception as e:
        print_error(f"[WEB] {e}")
        return

    try:
        await _autoload_teams()
    except Exception as e:
        print_error(f"[BOT] autoload failed: {e}")

    try:
        while True:
            await asyncio.sleep(1)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print_warning("Shutting down...")
        for t in list(bot_state.account_workers.values()):
            t.cancel()
        await asyncio.gather(*bot_state.account_workers.values(), return_exceptions=True)
        try: await client.aclose()
        except Exception: pass

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print_warning("stopped")