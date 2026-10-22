# ============================================================
# RASIN                        X                        MEHEDI
# ============================================================
import sys, os, json, time, uuid, random, asyncio, base64, struct, socket
import itertools, traceback, ssl, hmac, hashlib, string, re, subprocess
import concurrent.futures as _cf
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
WEB_PORT = 20331
TOKEN_CACHE_FILE = "token_cache.json"
DEVICES_FILE = "devices.json"
VERSION_CACHE_FILE = "version.json"
AUTO_CACHE_FILE = "auto.json"
TOKEN_CACHE_TTL = 1200
VERSION_CACHE_TTL  = 3600
INDEX_HTML_PATH = "templates/index.html"

TEAMS_DIR = "teams"
os.makedirs(TEAMS_DIR, exist_ok=True)

START_MATCH_INTERVAL = 5.0
NEW_MATCH_DELAY = 4.0
MAX_MATCH_DURATION = 1500
MATCH_IDLE_TIMEOUT  = 90.0

_accept_friend_request = True
DEBUG_ALL_PACKETS = False

TEAM_MODE = True
TEAM_SIZE = 4
TEAM_READY_DELAY = 6.0
TEAM_INVITE_WAIT = 2.5
CLAN_ID_DEFAULT = "3105331459"

# ── MATCH-IN-MATCH FLOW ──
MATCH_IN_MATCH_3S = 3.0        # wait before TCP off, and before team restart
MAX_CONCURRENT_MATCHES = 999999
REFIRE_CACHED_ON_MATCH_END = True
REFIRE_DELAY = 3.0
MIN_REFIRE_INTERVAL = 2.0

# ── INSTANCE LIMITS ──
MAX_INSTANCES = 5
INSTANCE_TIMEOUT = 8 * 3600

_instance_start_times: Dict[str, float] = {}
_instance_timeout_tasks: Dict[str, asyncio.Task] = {}


AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
KEYSTREAM = bytes([0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30])
HEX_KEY = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
API_KEY = HEX_KEY.encode()

REGION_LANG = {"ME":"ar","IND":"hi","ID":"id","VN":"vi","TH":"th","BD":"en",
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
        self._clan_cache: Dict[str, dict] = {}

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

# ==================== INSTANCE HELPERS ====================
def _active_instance_count() -> int:
    try:
        teams = load_all_team_files()
    except Exception:
        return 0
    count = 0
    for team in teams:
        for acc in team.get("accounts", []):
            uid = acc.get("uid")
            if not uid: continue
            task = bot_state.account_workers.get(str(uid))
            if task and not task.done():
                count += 1
                break
    return count


async def _instance_timeout_watch(group_id: str):
    try:
        await asyncio.sleep(INSTANCE_TIMEOUT)
    except asyncio.CancelledError:
        return

    print_warning(f"[INSTANCE] {group_id} expired after {INSTANCE_TIMEOUT/3600:.1f}h — DELETING")

    target = None
    try:
        teams = load_all_team_files()
        for t in teams:
            if str(t.get("group_id", "")) == str(group_id):
                target = t
                break
    except Exception:
        pass

    if target:
        for acc in target["accounts"]:
            uid = str(acc["uid"])
            task = bot_state.account_workers.get(uid)
            if task and not task.done():
                try: task.cancel()
                except Exception: pass
            bot_state.account_workers.pop(uid, None)
            cache_invalidate(uid)
            aid = bot_state.auth_to_game_id.get(uid)
            if aid and aid in bot_state.accounts:
                del bot_state.accounts[aid]
            if uid in bot_state.accounts:
                del bot_state.accounts[uid]

    try:
        path = _team_file_path(group_id)
        if os.path.exists(path):
            os.remove(path)
            print_success(f"[INSTANCE] {group_id} file deleted")
    except Exception as e:
        print_error(f"[INSTANCE] delete failed: {e}")

    _team_states.pop(str(group_id), None)
    _instance_start_times.pop(group_id, None)
    _instance_timeout_tasks.pop(group_id, None)

    if target:
        try:
            bot_state._clan_cache.pop(f"clan_{target['clan_id']}", None)
        except Exception:
            pass

    print_success(f"[INSTANCE] {group_id} removed — slot ({_active_instance_count()}/{MAX_INSTANCES})")


def _ensure_instance_timer(group_id: str):
    gid = str(group_id or "default")
    if gid in _instance_timeout_tasks and not _instance_timeout_tasks[gid].done():
        return
    _instance_start_times[gid] = time.time()
    _instance_timeout_tasks[gid] = asyncio.create_task(_instance_timeout_watch(gid))


# ==================== MATCH EXECUTOR ====================
_MATCH_EXECUTOR = None

def _get_match_executor():
    global _MATCH_EXECUTOR
    if _MATCH_EXECUTOR is None:
        _MATCH_EXECUTOR = _cf.ThreadPoolExecutor(max_workers=256, thread_name_prefix="match")
    return _MATCH_EXECUTOR

# ==================== MATCH SLOTS ====================
_active_match_count = 0
_active_match_lock  = asyncio.Lock()
_cached_0300_matches: Dict[str, dict] = {}
_last_refire_time:    Dict[str, float] = {}


async def _acquire_match_slot(uid):
    global _active_match_count
    async with _active_match_lock:
        _active_match_count += 1
        return _active_match_count


async def _release_match_slot(uid):
    global _active_match_count
    async with _active_match_lock:
        if _active_match_count > 0:
            _active_match_count -= 1
        return _active_match_count


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
            "match_finished_uids": set(),
            "match_total_uids": set(),
        }
    return _team_states[gid]

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
                if resp.status != 200: return None
                if not content: return None
                for off in [0, 64, 48, 32, 16]:
                    if off >= len(content): continue
                    try:
                        r = decode_protobuf_2(content[off:])
                        if r and 3 in r:
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
        print_error(f"[CLAN-ENC] {e}"); return None


async def get_clan_info(jwt_token: str, clan_id: str) -> Optional[Dict]:
    if not _CLAN_PB_AVAILABLE: return None
    payload = _enc_clan_req(int(clan_id))
    if not payload: return None
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False; ssl_ctx.verify_mode = ssl.CERT_NONE
    hdrs_main = {
        "User-Agent": "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*", "Accept-Encoding": "deflate, gzip",
        "Authorization": f"Bearer {jwt_token}",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-GA": "v1 1", "X-GA-SV": str(int(time.time())),
        "ReleaseVersion": "OB55", "X-Unity-Version": "2022.3.47f1",
        "Host": "clientbp.ppmainecoonghj.com",
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
                                "clan_id": int(guild.get(1, int(clan_id)) or int(clan_id)),
                                "clan_name": str(guild.get(2, "") or ""),
                                "leader_uid": int(guild.get(4, 0) or 0),
                                "region": str(guild.get(13, "") or ""),
                                "level": int(guild.get(5, 0) or 0),
                                "capacity": int(guild.get(6, 0) or 0),
                                "member_count": int(guild.get(7, 0) or 0),
                                "honor_points": int(guild.get(39, 0) or 0),
                                "weekly_glory": int(guild.get(37, 0) or 0),
                                "total_glory": int(guild.get(36, 0) or 0),
                            }
            if not clan_info_result:
                clan_info_result = {
                    "clan_id": int(clan_id), "clan_name": "", "leader_uid": 0,
                    "region": "BD", "level": 0, "capacity": 0,
                    "member_count": 0, "honor_points": 0,
                    "weekly_glory": 0, "total_glory": 0,
                }
        return clan_info_result
    except Exception as e:
        print_error(f"[CLAN-INFO] {e}"); return None


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
                {"nickname": str(a.get("nickname", "")),
                 "account_id": str(a.get("account_id", "")),
                 "uid": str(a["uid"]), "password": str(a["password"])}
                for a in accounts
            ],
        }
        path = _team_file_path(group_id)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print_success(f"[TEAM-FILE] Saved {path} ({len(accounts)} accounts)")
        return str(group_id)
    except Exception as e:
        print_error(f"[TEAM-FILE] save error: {e}"); return None

def load_all_team_files() -> List[Dict]:
    teams = []
    if not os.path.isdir(TEAMS_DIR): return teams
    for fname in sorted(os.listdir(TEAMS_DIR)):
        if not fname.endswith(".json"): continue
        path = os.path.join(TEAMS_DIR, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict): continue
            clan_id = str(data.get("clan_id", "")).strip()
            group_id = str(data.get("group_id", "")).strip() or fname.replace("group_", "").replace(".json", "")
            accounts = data.get("accounts", [])
            region = str(data.get("region", "BD")).upper()
            if not clan_id or not isinstance(accounts, list) or not accounts:
                continue
            clean_accounts = []
            for a in accounts:
                if not isinstance(a, dict): continue
                u = str(a.get("uid", "")).strip()
                p = str(a.get("password", "")).strip()
                if u and p: clean_accounts.append({"uid": u, "password": p})
            if not clean_accounts: continue
            teams.append({
                "clan_id": clan_id, "group_id": group_id,
                "region": region, "file": fname,
                "accounts": clean_accounts,
            })
        except Exception as e:
            print_error(f"[TEAM-FILE] Failed to read {fname}: {e}")
    return teams


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

client = httpx.AsyncClient(verify=False, timeout=15.0,
    limits=httpx.Limits(max_connections=300, max_keepalive_connections=150))
_LOGIN_SEMAPHORE = asyncio.Semaphore(4)

# ==================== CRYPTO / PROTOBUF ====================
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
    except Exception: return {}

async def decode_protobuf_async(data):
    try:
        parsed = Parser().parse(data)
        return json.dumps(_parse_results_sync(parsed))
    except Exception: return "{}"

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

# ==================== TEAM PACKETS (BD) ====================
def create_team(key, iv, game_version="1.132.9", mode=15):
    fields = {
        1: 1, 2: {2: bytes.fromhex("01"), 3: mode, 4:3, 5:"en",
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

def start_match_team(account_id, key, iv, region="BD", mode=15):
    fields = {1: 9, 2: {1: int(account_id), 3: mode, 7: {1: "IDC3", 2: 410, 3: region}}}
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

# ==================== VERSION CACHE (auto.json) ====================
def _atomic_json_write(path: str, data):
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp, path)
    except Exception as e:
        print_warning(f"[CACHE] write {path} failed: {e}")

def _load_auto_cache() -> Optional[Dict]:
    if not os.path.exists(AUTO_CACHE_FILE): return None
    try:
        with open(AUTO_CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception: return None

def _save_auto_cache(data: Dict):
    try:
        tmp = AUTO_CACHE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp, AUTO_CACHE_FILE)
    except Exception as e:
        print_warning(f"[AUTO] save failed: {e}")

def get_app_version(force: bool = False) -> str:
    if not force:
        cache = _load_auto_cache()
        if cache and cache.get("app_version"):
            print_info(f"[AUTO] using cached app_version = {cache['app_version']}")
            return str(cache["app_version"])
    try:
        fresh = play_scraper('com.dts.freefireth').get('version')
        if fresh:
            cache = _load_auto_cache() or {}
            cache["app_version"] = str(fresh)
            cache["app_version_ts"] = time.time()
            _save_auto_cache(cache)
            print_success(f"[AUTO] saved app_version = {fresh} → {AUTO_CACHE_FILE}")
            return str(fresh)
    except Exception as e:
        print_warning(f"[AUTO] play_scraper failed: {e}")
    cache = _load_auto_cache()
    if cache and cache.get("app_version"):
        print_warning(f"[AUTO] using stale app_version = {cache['app_version']}")
        return str(cache["app_version"])
    return "1.132.9"

async def version_config(region="BD", force: bool = False):
    region_uc = (region or "BD").upper()
    if not force:
        cache = _load_auto_cache()
        if cache:
            entry = cache.get(f"region_{region_uc}")
            if entry and entry.get("server_url"):
                print_info(f"[AUTO] using cached version for {region_uc}")
                return (
                    entry.get("release_version"),
                    entry.get("remote_version"),
                    entry.get("server_url"),
                    entry.get("gop_url") or "https://ffmconnect.ppmainecoonghj.com",
                    entry.get("app_version") or get_app_version(),
                )
    app_version = get_app_version(force=force)
    lang = REGION_LANG.get(region_uc, "en")
    url = (
        f"https://version.ggwhitehawk.com/live/ver.php?version={app_version}"
        f"&lang={lang}&device=android&channel=android&appstore=googleplay"
        f"&region={region_uc}&whitelist_version=1.3.0&whitelist_sp_version=1.0.0"
    )
    try:
        r = await client.get(url)
        if r.status_code == 200:
            j = r.json()
            server_url = j.get("server_url")
            remote_version = j.get("remote_version")
            latest_release_version = j.get("latest_release_version")
            gops = [u.strip() for u in (j.get("gop_url") or "").split(";") if u.strip()]
            gop_1 = gops[0] if gops else "https://ffmconnect.ppmainecoonghj.com"
            if server_url:
                cache = _load_auto_cache() or {}
                cache[f"region_{region_uc}"] = {
                    "release_version": latest_release_version,
                    "remote_version": remote_version,
                    "server_url": server_url, "gop_url": gop_1,
                    "app_version": app_version, "fetched_at": time.time(),
                }
                cache["app_version"] = app_version
                cache["app_version_ts"] = time.time()
                _save_auto_cache(cache)
                print_success(f"[AUTO] fresh fetch OK → saved")
                return latest_release_version, remote_version, server_url, gop_1, app_version
    except Exception as e:
        print_warning(f"[AUTO] version fetch failed: {e}")
    cache = _load_auto_cache()
    if cache:
        entry = cache.get(f"region_{region_uc}")
        if entry and entry.get("server_url"):
            print_warning(f"[AUTO] using stale auto.json for {region_uc}")
            return (
                entry.get("release_version"), entry.get("remote_version"),
                entry.get("server_url"),
                entry.get("gop_url") or "https://ffmconnect.ppmainecoonghj.com",
                entry.get("app_version") or app_version,
            )
    return None


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
    for attempt in range(4):
        try:
            async with aiohttp.ClientSession(connector=connector) as s:
                async with s.post(f"{gop_url}/api/v2/oauth/guest:register",
                                  headers=headers, data=payload,
                                  timeout=aiohttp.ClientTimeout(total=20)) as resp:
                    text = await resp.text()
                    try: data = json.loads(text)
                    except Exception:
                        await asyncio.sleep(3.0 + attempt * 2.0); continue
                    if data.get("code") == 0: return data["data"]["uid"]
        except Exception as e:
            print_error(f"[REGISTER] attempt {attempt+1}: {e}")
        await asyncio.sleep(3.0 + attempt * 2.0)
    return None

async def grant_token(uid, password, gop_url, app_version):
    result = await get_access_token(uid, password)
    if not result: return None
    oid, at, pf = result
    return {"open_id": oid, "access_token": at, "platform": pf}

# ==================== DEVICE ====================
def _generate_new_device():
    dl = [("Samsung","SM-G998B","Adreno (TM) 660","Android OS 12 / API-31"),
        ("Xiaomi","2201122G","Adreno (TM) 730","Android OS 13 / API-33"),
        ("Realme","RMX3700","Mali-G710","Android OS 14 / API-34"),
        ("OnePlus","CPH2451","Adreno (TM) 740","Android OS 13 / API-33"),
        ("OPPO","CPH2611","Adreno (TM) 720","Android OS 14 / API-34")]
    brand, model, gpu, os_ver = random.choice(dl)
    return {"unique_device_id":f"Google|{uuid.uuid4()}","brand":brand,"model":model,
            "gpu_renderer":gpu,"system_software":os_ver,
            "screen_width":random.choice([1080,1440,720]),
            "screen_height":random.choice([2400,3200,1600]),
            "screen_dpi":str(random.randint(300,420)),"memory":random.randint(2800,6500)}

def get_device_for_account(acc_key):
    devices = {}
    if os.path.exists(DEVICES_FILE):
        try:
            with open(DEVICES_FILE,"r",encoding="utf-8") as f:
                devices = json.load(f)
                if not isinstance(devices, dict): devices = {}
        except Exception: devices = {}
    key = str(acc_key)
    if key in devices: return devices[key]
    nd = _generate_new_device()
    devices[key] = nd
    try:
        with open(DEVICES_FILE,"w",encoding="utf-8") as f:
            json.dump(devices, f, indent=2)
    except Exception: pass
    return nd

# ==================== PAYLOAD ====================
async def get_payload(access_token, open_id, platform, version, lang_code="en", acc_key=None):
    if acc_key:
        device = get_device_for_account(str(acc_key))
        device_id = device["unique_device_id"]
    else:
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
    get_login_data["90"] = "Khulna"; get_login_data["91"] = "D"
    get_login_data["99"] = "0"; get_login_data["103"] = 1
    proto1 = create_proto(major_login).hex()
    proto2 = create_proto(get_login_data).hex()
    return bytes.fromhex(encrypt_aes(proto1)), bytes.fromhex(encrypt_aes(proto2))


# ==================== MAJOR LOGIN (robust) ====================
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
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as session:
            async with session.post(url, headers=req_headers, data=payload, ssl=ssl_context) as response:
                content = await response.read()
                print_info(f"[MAJOR-LOGIN] status={response.status} len={len(content)}")
                if response.status != 200 or len(content) < 100: return None
                best = None; best_score = -1; best_off = 0
                for offset in range(0, min(500, len(content)), 2):
                    cb = content[offset:]
                    rf = extract_raw_fields(cb)
                    jwt_raw = rf.get(8); url_raw = rf.get(10); id_raw = rf.get(1)
                    jwt_str = None; url_str = None
                    if isinstance(jwt_raw, (bytes, bytearray)) and len(jwt_raw) > 20:
                        try:
                            if bytes(jwt_raw[:3]) == b"eyJ":
                                jwt_str = bytes(jwt_raw).decode('utf-8', 'ignore')
                        except Exception: pass
                    if isinstance(url_raw, (bytes, bytearray)) and len(url_raw) > 5:
                        try:
                            s = bytes(url_raw).decode('utf-8', 'ignore')
                            if "://" in s or "." in s: url_str = s
                        except Exception: pass
                    cand = None
                    try: cand = decode_protobuf_dict(cb)
                    except Exception: cand = None
                    if not cand:
                        try:
                            c2 = decode_protobuf_2(cb)
                            if c2: cand = {str(k): {"data": v} for k, v in c2.items()}
                        except Exception: cand = None
                    score = (len(cand) if cand else 0)
                    score += (300 if jwt_str else 0)
                    score += (150 if url_str else 0)
                    score += (50 if id_raw else 0)
                    if score > best_score:
                        best = cand or {}; best_score = score; best_off = offset
                    if jwt_str and url_str and id_raw: break
                final_jwt = None; final_url = None; final_accid = None; final_time = None
                if best_off > 0 or (best is not None):
                    try:
                        rf_final = extract_raw_fields(content[best_off:])
                        jr = rf_final.get(8)
                        if isinstance(jr, (bytes, bytearray)) and bytes(jr[:3]) == b"eyJ":
                            final_jwt = bytes(jr).decode('utf-8', 'ignore')
                        ur = rf_final.get(10)
                        if isinstance(ur, (bytes, bytearray)):
                            s = bytes(ur).decode('utf-8', 'ignore')
                            if "://" in s or "." in s: final_url = s
                        final_accid = rf_final.get(1); final_time = rf_final.get(21)
                    except Exception: pass
                if not final_jwt:
                    jwt_idx = content.find(b"eyJ")
                    if jwt_idx > 0:
                        for back in range(0, 30, 2):
                            try_off = jwt_idx - back
                            if try_off < 0: continue
                            if content[try_off] == 0x42:
                                try:
                                    rf_j = extract_raw_fields(content[try_off:])
                                    jr = rf_j.get(8)
                                    if isinstance(jr, (bytes, bytearray)) and bytes(jr[:3]) == b"eyJ":
                                        final_jwt = bytes(jr).decode('utf-8', 'ignore')
                                        best_off = try_off
                                        if not final_url:
                                            ur = rf_j.get(10)
                                            if isinstance(ur, (bytes, bytearray)):
                                                s = bytes(ur).decode('utf-8', 'ignore')
                                                if "://" in s or "." in s: final_url = s
                                        if not final_accid: final_accid = rf_j.get(1)
                                        if not final_time: final_time = rf_j.get(21)
                                        break
                                except Exception: pass
                if not final_url:
                    for pattern in [b"loginbp", b"clientbp", b".ggpolarbear", b".ppmainecoonghj", b"https://"]:
                        pidx = content.find(pattern)
                        if pidx > 20:
                            for back in range(2, 40, 2):
                                try_off = pidx - back
                                if try_off < 0: continue
                                if content[try_off] == 0x52:
                                    try:
                                        rf_u = extract_raw_fields(content[try_off:])
                                        ur = rf_u.get(10)
                                        if isinstance(ur, (bytes, bytearray)):
                                            s = bytes(ur).decode('utf-8', 'ignore')
                                            if "://" in s or "." in s:
                                                final_url = s; break
                                    except Exception: pass
                            if final_url: break
                if not final_jwt:
                    return None
                if not final_url:
                    final_url = "https://loginbp.ggpolarbear.com"
                if best is None: best = {}
                best["__JWT__"] = final_jwt
                best["__URL__"] = final_url
                best["__ACCID__"] = final_accid
                best["__TIME__"] = final_time
                best["__RAW_HEX__"] = content.hex()
                best["__OFFSET__"] = best_off
                print_success(f"[MAJOR-LOGIN] OK off={best_off} jwt={len(final_jwt)}")
                return best
    except Exception as e:
        print_error(f"[MAJOR-LOGIN] {e}"); return None


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
        p = jwt_token.split('.')[1]; p += '=' * (-len(p) % 4)
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
    except Exception: return None

async def join_clan(jwt_token, clan_id):
    if not _CLAN_PB_AVAILABLE: return False
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
                return r.status == 200
    except Exception: return False

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
    if not os.path.exists(TOKEN_CACHE_FILE): return {}
    try:
        with open(TOKEN_CACHE_FILE,"r",encoding="utf-8") as f:
            content = f.read().strip()
        if not content: return {}
        data = json.loads(content)
        parsed = _json_deserializer(data)
        _token_cache_memo = parsed
        _token_cache_memo_time = now
        return parsed
    except Exception:
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
    except Exception: pass

def cache_get(uid: str) -> Optional[Dict]:
    cache = _load_token_cache()
    entry = cache.get(str(uid))
    if not entry: return None
    if time.time() - entry.get("cached_at",0) > TOKEN_CACHE_TTL:
        cache_invalidate(uid); return None
    if str(entry.get("account_id","")).isdigit():
        entry["account_id"] = int(entry["account_id"])
    if not isinstance(entry.get("login_payload_data"), (bytes, bytearray)):
        cache_invalidate(uid); return None
    return entry

def cache_set(uid: str, data: Dict):
    try:
        cache = _load_token_cache()
        entry = dict(data)
        entry["cached_at"] = time.time()
        cache[str(uid)] = entry
        _save_token_cache(cache)
    except Exception: pass

def cache_invalidate(uid: str):
    cache = _load_token_cache()
    if str(uid) in cache:
        del cache[str(uid)]
        _save_token_cache(cache)

# ==================== PLAY GAME ====================
async def play_game(server_ip_port, udp_jwt, udp_key, match_code,
                    account_id, player_region, client_version,
                    tcp_key, tcp_iv, match_index,
                    game_mode=1, map_id=1, match_mode=1, sleep_ms=0,
                    match_id=0, verbose=True):
    uid_str = str(account_id)
    completed_cleanly = False
    try:
        if ":" not in server_ip_port: return
        ip, port_s = server_ip_port.split(":", 1)
        port = int(port_s)
        try: _toolsudp.set_base_url("https://clientbp.ppmainecoonghj.com")
        except Exception: pass
        loop = asyncio.get_running_loop()
        def _run():
            return _toolsudp.run_match(
                ip, port, int(account_id), udp_key, udp_jwt, match_code,
                "0", int(game_mode), int(map_id), int(match_mode),
                int(sleep_ms), 3.0, None, int(match_id), bool(verbose),
            )
        try:
            await loop.run_in_executor(_get_match_executor(), _run)
        except Exception as exc:
            print_error(f"[MATCH #{match_index}] run_match: {exc}")
        else:
            completed_cleanly = True
    except Exception as e:
        print_error(f"[MATCH #{match_index}] {e}")
    finally:
        if completed_cleanly:
            try:
                bot_state.increment_match(uid_str)
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

# ==================== FUNCTIONAL LONE WOLF — MATCH-IN-MATCH ====================
async def functional_lone_wolf(addrs, starter_packet, account_region, client_version,
                                key, iv, account_id="", account_data=None, max_reconnects=10,
                                group_id: str = "default"):
    reconnects = 0
    ip, port = addrs.split(":")
    play_matches: List[asyncio.Task] = []
    no_response_count = 0
    uid_str = str(account_id)

    current_token = starter_packet
    current_key = key
    current_iv = iv
    current_account_data = account_data
    _writer_ref = {"w": None}
    _team_active = {"flag": True}

    _team_state = get_team_state(group_id)

    async def _team_coordinator():
        try:
            while True:
                async with _team_state["lock"]:
                    n = len(_team_state["peers"])
                if n >= TEAM_SIZE: break
                if bot_state.is_paused(uid_str): return
                await asyncio.sleep(0.5)
            await asyncio.sleep(TEAM_READY_DELAY)
            async with _team_state["lock"]:
                is_leader = (_team_state["leader_uid"] == uid_str)
                peers_snapshot = dict(_team_state["peers"])
            if not is_leader: return
            async with _team_state["lock"]: _team_state["team_code"] = None
            own_id_num = None
            if current_account_data: own_id_num = current_account_data.get('account_id')
            if not own_id_num:
                try: own_id_num = int(uid_str)
                except Exception: own_id_num = 0
            try:
                pkt = create_team(current_key, current_iv, client_version, mode=15)
                if _writer_ref["w"] and not _writer_ref["w"].is_closing():
                    _writer_ref["w"].write(pkt); await _writer_ref["w"].drain()
            except Exception: pass
            await asyncio.sleep(1.5)
            try:
                pkt = team_fresh(int(own_id_num), current_key, current_iv)
                if _writer_ref["w"] and not _writer_ref["w"].is_closing():
                    _writer_ref["w"].write(pkt); await _writer_ref["w"].drain()
            except Exception: pass
            await asyncio.sleep(1.0)
            async def _invite_uid(target_uid):
                for _ in range(2):
                    try:
                        inv = invite_player_in_team(int(target_uid), current_key, current_iv)
                        if _writer_ref["w"] and not _writer_ref["w"].is_closing():
                            _writer_ref["w"].write(inv); await _writer_ref["w"].drain()
                    except Exception: pass
                    await asyncio.sleep(0.6)
            for peer_uid, peer_info in peers_snapshot.items():
                if peer_uid == uid_str: continue
                peer_acc_id = None
                try: peer_acc_id = peer_info["data"].get("account_id")
                except Exception: pass
                if not peer_acc_id: peer_acc_id = peer_uid
                await _invite_uid(int(peer_acc_id))
            await asyncio.sleep(TEAM_INVITE_WAIT + 3.0)
            try:
                pkt = team_fresh(int(own_id_num), current_key, current_iv)
                if _writer_ref["w"] and not _writer_ref["w"].is_closing():
                    _writer_ref["w"].write(pkt); await _writer_ref["w"].drain()
            except Exception: pass
            await asyncio.sleep(1.0)
            while _team_active["flag"]:
                try:
                    if bot_state.is_paused(uid_str): break
                    async with _team_state["lock"]:
                        if _team_state["leader_uid"] != uid_str: break
                    own_id = current_account_data.get('account_id', own_id_num) if current_account_data else own_id_num
                    try:
                        rdy = ready_for_game(int(own_id), current_key, current_iv)
                        if _writer_ref["w"] and not _writer_ref["w"].is_closing():
                            _writer_ref["w"].write(rdy); await _writer_ref["w"].drain()
                    except Exception: pass
                    await asyncio.sleep(1.0)
                    sm = start_match_team(int(own_id), current_key, current_iv, region=account_region, mode=15)
                    if _writer_ref["w"] and not _writer_ref["w"].is_closing():
                        _writer_ref["w"].write(sm); await _writer_ref["w"].drain()
                except Exception: pass
                try: await asyncio.wait_for(asyncio.sleep(5.0), timeout=5.5)
                except asyncio.TimeoutError: pass
        except asyncio.CancelledError: raise
        except Exception as e:
            print_error(f"[TEAM] coordinator error: {e}")

    async def _member_match_trigger():
        try:
            await asyncio.sleep(TEAM_READY_DELAY + 18.0)
            async with _team_state["lock"]:
                if _team_state["leader_uid"] == uid_str: return
            my_id = current_account_data.get('account_id', uid_str) if current_account_data else uid_str
            while _team_active["flag"]:
                try:
                    if bot_state.is_paused(uid_str): break
                    if _writer_ref["w"] and not _writer_ref["w"].is_closing():
                        try:
                            rdy = ready_for_game(int(my_id), current_key, current_iv)
                            _writer_ref["w"].write(rdy); await _writer_ref["w"].drain()
                        except Exception: pass
                        await asyncio.sleep(1.0)
                        sm = start_match_team(int(my_id), current_key, current_iv, region=account_region, mode=15)
                        _writer_ref["w"].write(sm); await _writer_ref["w"].drain()
                except Exception: pass
                try: await asyncio.wait_for(asyncio.sleep(5.0), timeout=5.5)
                except asyncio.TimeoutError: pass
        except asyncio.CancelledError: raise
        except Exception: pass

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
                reconnects = 0
                no_response_count = 0

                async with _team_state["lock"]:
                    _team_state["peers"][uid_str] = {
                        "writer": writer, "data": current_account_data,
                        "key": current_key, "iv": current_iv}
                    _team_state["match_total_uids"].add(uid_str)
                    if _team_state["leader_uid"] is None:
                        _team_state["leader_uid"] = uid_str

                team_coord_task = asyncio.create_task(_team_coordinator())
                member_trigger_task = asyncio.create_task(_member_match_trigger())

                # ═══════════════════════════════════════════════════════
                # MAIN READ LOOP
                # ═══════════════════════════════════════════════════════
                while True:
                    play_matches[:] = [m for m in play_matches if not m.done()]
                    if bot_state.is_paused(uid_str): break

                    try:
                        data = await asyncio.wait_for(reader.read(8192), timeout=0.5)
                    except asyncio.TimeoutError:
                        no_response_count += 1; continue
                    if not data:
                        raise ConnectionError("Connection closed")
                    hex_data = data.hex()
                    packet_length = len(data)
                    no_response_count = 0

                    # ── Team invite (0500) handler ──
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
                            group_id_pkt = _f5g(8)
                            if group_id_pkt and isinstance(group_id_pkt, str) and 20 <= len(group_id_pkt) <= 40: pass
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
                                for _ in range(2):
                                    try:
                                        acc = accept_team_invite(int(inviter), group_id_pkt, current_key, current_iv)
                                        if writer and not writer.is_closing():
                                            writer.write(acc); await writer.drain()
                                    except Exception: pass
                                    await asyncio.sleep(0.4)
                        except Exception: pass
                        continue

                    if hex_data.startswith("0300") and 10 < packet_length < 30: continue

                    # ═══════════════════════════════════════════════════════
                    # ═══ MATCH FOUND — MATCH-IN-MATCH FLOW ═══
                    # ═══════════════════════════════════════════════════════
                    if hex_data.startswith("0300") and packet_length >= 300:
                        print_success(f"[⚔] Match Found | {uid_str}")
                        await _acquire_match_slot(uid_str)
                        slot_held = True

                        try:
                            # Stop current team search
                            for tk in (team_coord_task, member_trigger_task):
                                if tk and not tk.done(): tk.cancel()
                            team_coord_task = None
                            member_trigger_task = None
                            _team_active["flag"] = False

                            # Parse 0300 → cache UDP credentials
                            res = json.loads(await decode_protobuf_async(hex_data[10:]))
                            token = udp_key = match_code = server_ip_port = None
                            match_account_id = None
                            match_game_mode = 1; match_map_id = 1; match_match_mode = 1
                            match_sleep_ms = 0; match_id = 0

                            if '42' in res and 'data' in res['42']:
                                match_code = res['42']['data']
                            if '5' in res and 'data' in res['5']:
                                rf5 = res['5']['data']
                                server_ip_port = rf5.get('2', {}).get('data')
                                udp_key = rf5.get('3', {}).get('data')
                                token = rf5.get('4', {}).get('data')
                                if '42' in rf5: match_code = rf5['42']['data']
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

                            effective_acc_id = match_account_id or account_id or "BD_BOT"

                            if token and udp_key and match_code and server_ip_port:
                                # ══ CACHE 0300 for refire ══
                                _cached_0300_matches[uid_str] = {
                                    "server_ip_port": server_ip_port, "token": token,
                                    "udp_key": udp_key, "match_code": match_code,
                                    "effective_acc_id": effective_acc_id,
                                    "client_version": client_version,
                                    "game_mode": match_game_mode, "map_id": match_map_id,
                                    "match_mode": match_match_mode,
                                    "sleep_ms": match_sleep_ms, "match_id": match_id,
                                    "cached_at": time.time(),
                                }

                                match_index = await _inc_match(uid_str)
                                print_success(f"[MATCH #{match_index}] → {server_ip_port}")
                                try:
                                    bot_state.increment_match_started()
                                    bot_state.update_status(uid_str, "IN_MATCH", 1)
                                except Exception: pass

                                # ═══════════════════════════════════════
                                # STEP 1: FIRE UDP MATCH (background)
                                # ═══════════════════════════════════════
                                new_match = asyncio.create_task(play_game(
                                    server_ip_port, token, udp_key, match_code,
                                    effective_acc_id, "BD", client_version,
                                    current_key, current_iv, match_index,
                                    game_mode=match_game_mode, map_id=match_map_id,
                                    match_mode=match_match_mode, sleep_ms=match_sleep_ms,
                                    match_id=match_id, verbose=True,
                                ))
                                play_matches.append(new_match)
                                slot_held = False

                                async def _watch(m_task, uid_r):
                                    try: await m_task
                                    except Exception: pass
                                    finally: await _release_match_slot(uid_r)
                                asyncio.create_task(_watch(new_match, uid_str))

                                print_success(f"[MATCH #{match_index}] UDP running in background")

                                # ═══════════════════════════════════════
                                # STEP 2: 3s WAIT (TCP still on, UDP running)
                                # ═══════════════════════════════════════
                                print_info(f"[MATCH #{match_index}] waiting {MATCH_IN_MATCH_3S}s")
                                await asyncio.sleep(MATCH_IN_MATCH_3S)

                                # ═══════════════════════════════════════
                                # STEP 3: TCP GATEWAY OFF (UDP STILL RUNNING)
                                # ═══════════════════════════════════════
                                print_warning(f"[MATCH #{match_index}] TCP OFF (UDP still running)")
                                async with _team_state["lock"]:
                                    _team_state["peers"].pop(uid_str, None)
                                    if _team_state["leader_uid"] == uid_str:
                                        _team_state["leader_uid"] = None
                                        _team_state["team_code"] = None
                                if gateway_ping_task and not gateway_ping_task.done():
                                    gateway_ping_task.cancel()
                                    try: await gateway_ping_task
                                    except asyncio.CancelledError: pass
                                gateway_ping_task = None
                                try: bot_state.unregister_writer(uid_str, writer)
                                except Exception: pass
                                await safe_close_writer(writer)
                                writer = None
                                _writer_ref["w"] = None

                                # ═══════════════════════════════════════
                                # STEP 4: TCP GATEWAY ON (reconnect)
                                # ═══════════════════════════════════════
                                print_info(f"[MATCH #{match_index}] TCP ON (reconnect)")
                                try:
                                    resolved_ip2 = await resolve_host_cloudflare(ip)
                                    reader, writer = await asyncio.open_connection(resolved_ip2, int(port))
                                    bot_state.register_writer(uid_str, writer)
                                    _writer_ref["w"] = writer
                                    raw_sock2 = writer.get_extra_info('socket')
                                    if raw_sock2: optimize_tcp_socket(raw_sock2)
                                    writer.write(bytes.fromhex(current_token))
                                    await writer.drain()
                                    try:
                                        init_ka2 = await send_keep_alive(account_region)
                                        if init_ka2 and not writer.is_closing():
                                            writer.write(init_ka2)
                                            await asyncio.wait_for(writer.drain(), timeout=3)
                                    except Exception: pass
                                    async def _new_ka():
                                        ka_bytes = await send_keep_alive(account_region)
                                        while True:
                                            await asyncio.sleep(5)
                                            try:
                                                if writer and not writer.is_closing():
                                                    writer.write(ka_bytes); await writer.drain()
                                            except Exception: break
                                    gateway_ping_task = asyncio.create_task(_new_ka())

                                    async with _team_state["lock"]:
                                        _team_state["peers"][uid_str] = {
                                            "writer": writer, "data": current_account_data,
                                            "key": current_key, "iv": current_iv}
                                        _team_state["match_total_uids"].add(uid_str)
                                        if _team_state["leader_uid"] is None:
                                            _team_state["leader_uid"] = uid_str
                                    print_success(f"[MATCH #{match_index}] TCP reconnected")
                                except Exception as e:
                                    print_error(f"[MATCH #{match_index}] reconnect failed: {e}")
                                    raise ConnectionError(f"Reconnect failed: {e}")

                                # ═══════════════════════════════════════
                                # STEP 5: 3s WAIT (team formation)
                                # ═══════════════════════════════════════
                                print_info(f"[MATCH #{match_index}] team formation {MATCH_IN_MATCH_3S}s")
                                await asyncio.sleep(MATCH_IN_MATCH_3S)

                                # ═══════════════════════════════════════
                                # STEP 6: RESTART TEAM SEARCH (parallel)
                                # ═══════════════════════════════════════
                                _team_active["flag"] = True
                                team_coord_task = asyncio.create_task(_team_coordinator())
                                member_trigger_task = asyncio.create_task(_member_match_trigger())
                                print_success(f"[MATCH #{match_index}] search restarted — UDP in background")
                                continue
                        except Exception as e:
                            print_warning(f"[MATCH] {e}")
                            continue
                        finally:
                            if slot_held:
                                await _release_match_slot(uid_str)

                    if 30 <= packet_length <= 40: continue

            except asyncio.CancelledError: raise
            except Exception as e:
                if "Cache expired" in str(e): break
                reconnects += 1
                if reconnects > max_reconnects:
                    if current_account_data:
                        try:
                            if current_account_data.get('auth_uid'):
                                cache_invalidate(str(current_account_data['auth_uid']))
                        except Exception: pass
                    reconnects = 0; break
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
    except asyncio.CancelledError: raise
    finally:
        for m in play_matches:
            if not m.done(): m.cancel()


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
        bot_state.update_exp(aid, exp, lvl)
        if nickname: bot_state.accounts[aid]["nickname"] = nickname
    except Exception: pass

async def process_account_uid_pass(uid, password, region_override=None):
    cached = cache_get(uid)
    if cached:
        aid = str(cached['account_id'])
        nick = cached.get('nickname', f"Player_{aid}")
        lvl = cached.get('level', 1); expv = cached.get('exp', 0)
        bot_state.register_account(aid, nick, cached.get('region','BD'),
            lvl, expv, cached.get('likes',0), auth_uid=str(uid))
        _register_credentials(cached); return cached
    try:
        async with _LOGIN_SEMAPHORE:
            vc = await version_config(region_override or "BD")
            if not vc: return None
            release_version, client_version, server_url, gop_1, app_version = vc
            tg = await get_access_token(uid, password)
            if not tg: return None
            open_id, access_token, platform = tg
            major_payload, login_payload = await get_payload(
                access_token, open_id, platform, client_version, acc_key=str(uid))
            res_json = await major_login(major_payload, server_url, release_version)
            if not res_json: return None
            jwt_token = res_json.get("__JWT__")
            server_url_raw = res_json.get("__URL__") or server_url
            server_time = res_json.get("__TIME__")
            acc_id_raw = res_json.get("__ACCID__")
            region_raw = "BD"
            if not jwt_token: return None
            aes_ak, iv_i = _extract_key_iv(res_json)
            if not aes_ak: return None
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
    try:
        reg = region_override or ad.get('region','BD')
        tcp_online = await build_tcp_startup_packet(
            ad['account_id'], ad['token'], ad['server_time'],
            ad['aes_ak'], ad['iv_i'], region=reg, typ='OnLine')
        if clan_override:
            try:
                await asyncio.sleep(1.0)
                await join_clan(ad['token'], clan_override)
            except Exception: pass
        await functional_lone_wolf(
            ad['functional_addrs'], tcp_online, reg, ad['client_version'],
            ad['aes_ak'], ad['iv_i'], account_id=acc_id, account_data=ad,
            group_id=group_id)
    except asyncio.CancelledError: raise
    except Exception as e:
        print_error(f"worker err {label}: {e}")

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
                await asyncio.sleep(15); continue
            acc_id = str(ad['account_id'])
            bot_state.account_workers[acc_id] = asyncio.current_task()
            bot_state.auth_to_game_id[uid_str] = acc_id
            bot_state.game_to_auth_id[acc_id] = uid_str
            await run_account_worker(ad, uid_str, region_override, clan_override,
                                     group_id=group_id)
            jitter = random.uniform(0, 4.0)
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
    return hashlib.sha256((str(uuid.uuid4()) + str(time.time())).encode()).hexdigest().upper()

async def get_newbie_roles(jwt_token, server_url, release_version):
    try:
        url = f"{server_url}/GiveAccountNewbieRoles"
        payload = bytes.fromhex(encrypt_aes(create_proto({"1": 1}).hex()))
        headers = {
            "authorization": f"Bearer {jwt_token}",
            "host": server_url.replace("https://", "").replace("http://", "").split("/")[0],
            "x-ga": "v1 1", "content-type": "application/x-www-form-urlencoded",
            "accept-encoding": "deflate, gzip",
            "releaseversion": f"{release_version}",
            "user-agent": "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
            "accept": "*/*", "x-unity-version": "2022.3.47f1",
        }
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            async with session.post(url, headers=headers, data=payload) as response:
                return response.status == 200
    except Exception: return None

async def set_newbie_roles(jwt_token, server_url, release_version):
    try:
        url = f"{server_url}/SelectPresetLoadout"
        fields = {
            "1": {"1": 102000037},
            "2": {"1": 102000037, "2": 50462976, "3": 414929892933512066, "4": 0},
            "6": {"1": {"1": 1, "2": 102000037, "3": {"1": 3, "2": 706}, "6": "PRESET 1", "7": 1}},
            "11": 1,
        }
        payload = bytes.fromhex(encrypt_aes(create_proto(fields).hex()))
        headers = {
            "authorization": f"Bearer {jwt_token}",
            "host": server_url.replace("https://", "").replace("http://", "").split("/")[0],
            "x-ga": "v1 1", "content-type": "application/x-www-form-urlencoded",
            "accept-encoding": "deflate, gzip",
            "releaseversion": f"{release_version}",
            "user-agent": "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
            "accept": "*/*", "x-unity-version": "2022.3.47f1",
        }
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            async with session.post(url, headers=headers, data=payload) as response:
                return response.status == 200
    except Exception: return None


async def create_four_accounts(region: str, clan_id: str, count: int = 4):
    running = _active_instance_count()
    if running >= MAX_INSTANCES:
        print_error(f"[INSTANCE] Max {MAX_INSTANCES} instances running.")
        return []

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
            bot_ok = False
            for bot_attempt in range(3):
                if bot_attempt > 0:
                    _prog(f"   ↻ bot {i+1} attempt {bot_attempt+1}/3")
                    await asyncio.sleep(5.0)
                try:
                    uid = await register_account(password, gop_1, app_version)
                    if not uid:
                        _prog(f"   ❌ bot {i+1}: register failed"); continue
                    _prog(f"   → registered UID {uid}")
                    await asyncio.sleep(3.0)
                    tok = await grant_token(uid, password, gop_1, app_version)
                    if not tok:
                        _prog(f"   ❌ bot {i+1}: grant failed"); continue
                    open_id = tok["open_id"]; access_token = tok["access_token"]
                    platform = tok.get("platform", 4)
                    await asyncio.sleep(1.0)
                    major_payload, login_payload = await get_payload(
                        access_token, open_id, platform, game_version, lang, acc_key=str(uid))
                    nickname_final = f"MEHEDI_{''.join(random.choices(string.ascii_letters + string.digits, k=5))}"
                    mr = await major_register(release_v, access_token, open_id,
                                              nickname_final, game_version, login_url, lang)
                    if not mr:
                        _prog(f"   ❌ bot {i+1}: MajorRegister failed"); continue
                    _prog(f"   → MajorRegister OK")
                    await asyncio.sleep(10.0)
                    res_json = None
                    for attempt in range(5):
                        mp, lp = await get_payload(
                            access_token, open_id, platform, game_version, lang, acc_key=str(uid))
                        res_json = await major_login(mp, login_url, release_v)
                        if res_json and res_json.get("__JWT__"):
                            login_payload = lp; break
                        res_json = None
                        await asyncio.sleep(3.0 + attempt * 2.0)
                    if not res_json or not res_json.get("__JWT__"):
                        _prog(f"   ❌ bot {i+1}: MajorLogin failed"); continue
                    jwt_token = res_json.get("__JWT__")
                    server_url_raw = res_json.get("__URL__") or "https://loginbp.ggpolarbear.com"
                    server_time = res_json.get("__TIME__")
                    acc_id_raw = res_json.get("__ACCID__")
                    if not jwt_token:
                        _prog(f"   ❌ bot {i+1}: JWT empty"); continue
                    if not server_url_raw:
                        server_url_raw = "https://loginbp.ggpolarbear.com"
                    aes_ak, iv_i = _extract_key_iv(res_json)
                    if not aes_ak or not iv_i:
                        _prog(f"   ❌ bot {i+1}: AES key/IV missing"); continue
                    ld = await get_login_data(login_payload, jwt_token, server_url_raw, release_v)
                    level = 1; exp = 0; likes = 0
                    if ld:
                        def _gf(f, d=None):
                            v = ld.get(str(f), {}).get("data")
                            return v if v is not None else d
                        level = int(_gf(6, 1) or 1); exp = int(_gf(7, 0) or 0)
                        likes = int(_gf(8, 0) or 0)
                        nickname_final = _gf(4, nickname_final) or nickname_final
                    await get_newbie_roles(jwt_token, server_url_raw, release_v)
                    await asyncio.sleep(0.5)
                    await set_newbie_roles(jwt_token, server_url_raw, release_v)
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
                    _prog(f"✅ bot {i+1}: {nickname_final} | UID {acc_id_raw}")
                    bot_ok = True; break
                except Exception as e:
                    _prog(f"   ❌ bot {i+1} attempt {bot_attempt+1}: {e}")
            if not bot_ok:
                _prog(f"❌ bot {i+1}: all attempts failed")
            await asyncio.sleep(7.0)

        if not created:
            _prog("❌ No accounts created."); return []
        group_id = None
        try:
            team_accounts = [
                {"uid": str(a['auth_uid']), "password": str(a['auth_password']),
                 "account_id": str(a.get('account_id', '')),
                 "nickname": str(a.get('nickname', ''))}
                for a in created
            ]
            group_id = save_team_file(clan_id, region, team_accounts)
        except Exception: pass

        _prog(f"🚀 Starting {len(created)} bot workers...")
        for i, a in enumerate(created):
            try:
                task = asyncio.create_task(account_loop_guest(
                    str(a['auth_uid']), a['auth_password'],
                    region_override=region, clan_override=clan_id,
                    group_id=group_id))
                bot_state.account_workers[str(a['auth_uid'])] = task
                await asyncio.sleep(0.35)
            except Exception: pass
        if group_id:
            _ensure_instance_timer(group_id)
            _prog(f"⏱ Instance timer armed (8h)")
        _prog(f"✅ All {len(created)} bots launched.")
        return created
    except Exception as e:
        _prog(f"❌ create error: {e}"); return []
    finally:
        bot_state.creating = False

# ==================== AUTO-LOAD ====================
async def _autoload_teams():
    try:
        teams = load_all_team_files()
        if not teams: return
        for team in teams:
            clan_id = team["clan_id"]
            region = team["region"]
            group_id = team.get("group_id", "default")
            for acc in team["accounts"]:
                uid = acc["uid"]; password = acc["password"]
                if uid in bot_state.account_workers and not bot_state.account_workers[uid].done():
                    continue
                task = asyncio.create_task(account_loop_guest(
                    uid, password, region_override=region,
                    clan_override=clan_id, group_id=group_id))
                bot_state.account_workers[uid] = task
                await asyncio.sleep(0.4)
            _ensure_instance_timer(group_id)
            print_success(f"[BOOT] Team {group_id} loaded — 8h timer armed")
    except Exception as e:
        print_error(f"[BOOT] team load failed: {e}")

# ==================== HTTP SERVER ====================
@aiohttp.web.middleware
async def _req_logger(request, handler):
    try: return await handler(request)
    except aiohttp.web.HTTPException as e:
        if request.path.startswith("/api/"):
            return aiohttp.web.json_response(
                {"ok": False, "status": "error", "error": e.reason or str(e)}, status=e.status)
        raise
    except Exception as e:
        if request.path.startswith("/api/"):
            return aiohttp.web.json_response(
                {"ok": False, "status": "error", "error": str(e)}, status=500)
        raise

async def serve_index(request):
    for path in (INDEX_HTML_PATH, "index.html"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return aiohttp.web.Response(text=f.read(), content_type="text/html")
        except Exception: continue
    return aiohttp.web.Response(text="<h1>index.html not found</h1>", content_type="text/html")

async def api_ping(request):
    return aiohttp.web.json_response({"pong": True})

async def api_stats(request):
    try:
        accs = list(bot_state.accounts.values())
        online = sum(1 for a in accs if a.get("status") in ("ONLINE","IN_MATCH","SEARCHING"))
        active_matches = sum(a.get("active_matches", 0) for a in accs)
        uptime = max(1, int(time.time() - bot_state.start_time))
        uptime_h = max(0.016, uptime / 3600.0)
        exp_rate = int(bot_state.total_exp_gained / uptime_h) if uptime_h > 0 else 0
        matches_rate = int(bot_state.matches_started / uptime_h) if uptime_h > 0 else 0
        running_instances = _active_instance_count()
        instance_ages = {}
        now = time.time()
        for gid, start_ts in _instance_start_times.items():
            instance_ages[gid] = int(now - start_ts)
        data = {
            "accounts": accs, "logs": bot_state.logs[-200:],
            "total_accounts": len(accs), "total_online": online,
            "total_matches": bot_state.total_matches,
            "total_matches_started": bot_state.matches_started,
            "total_active_matches": active_matches,
            "total_gained_exp": bot_state.total_exp_gained,
            "uptime": uptime, "exp_per_hour": exp_rate,
            "matches_per_hour": matches_rate,
            "creating": bool(bot_state.creating),
            "create_progress": [str(x) for x in bot_state.create_progress[-40:]],
            "team_size": sum(len(ts["peers"]) for ts in _team_states.values()),
            "active_match_count": _active_match_count,
            "running_instances": running_instances,
            "max_instances": MAX_INSTANCES,
            "instance_timeout": INSTANCE_TIMEOUT,
            "instance_ages": instance_ages,
        }
        return aiohttp.web.Response(text=json.dumps(data, default=str),
                                    content_type="application/json")
    except Exception as e:
        return aiohttp.web.Response(
            text=json.dumps({"error": str(e), "accounts": [], "logs": []}),
            content_type="application/json")

async def api_teams(request):
    try:
        teams = load_all_team_files()
        return aiohttp.web.json_response({
            "ok": True,
            "teams": [{"group_id": t.get("group_id", ""), "clan_id": t["clan_id"],
                       "region": t["region"], "file": t.get("file", ""),
                       "count": len(t["accounts"]),
                       "uids": [str(a["uid"]) for a in t["accounts"]]}
                      for t in teams],
        })
    except Exception as e:
        return aiohttp.web.json_response({"ok": False, "error": str(e)})

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
        running = _active_instance_count()
        if running >= MAX_INSTANCES:
            return aiohttp.web.json_response({
                "ok": False,
                "error": f"Max {MAX_INSTANCES} instances running. Wait for expiry."
            })
        count = max(1, min(4, count))
        asyncio.create_task(create_four_accounts(region, clan_id, count))
        return aiohttp.web.json_response({"ok": True, "msg": f"Creating {count} bots..."})
    except Exception as e:
        return aiohttp.web.json_response({"ok": False, "error": str(e)})

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

async def api_clan_info(request):
    try:
        force = request.rel_url.query.get("force", "0") == "1"
        req_clan_id = request.rel_url.query.get("clan_id", "").strip()
        teams = load_all_team_files()
        async def _fetch_clan(team):
            clan_id = team["clan_id"]
            cached_key = f"clan_{clan_id}"
            if not force and cached_key in bot_state._clan_cache:
                cached = bot_state._clan_cache[cached_key]
                age = time.time() - cached.get("_cached_at", 0)
                if age < 60: return cached
            token = None
            for acc in team["accounts"]:
                auth_uid = str(acc["uid"])
                game_uid = bot_state.auth_to_game_id.get(auth_uid, auth_uid)
                creds = (bot_state.account_credentials.get(game_uid) or
                         bot_state.account_credentials.get(auth_uid))
                if creds and creds.get('token'):
                    token = creds['token']; break
            if not token:
                if cached_key in bot_state._clan_cache:
                    return bot_state._clan_cache[cached_key]
                return None
            info = await get_clan_info(token, clan_id)
            if info:
                info["_cached_at"] = time.time()
                bot_state._clan_cache[cached_key] = info
            elif cached_key in bot_state._clan_cache:
                return bot_state._clan_cache[cached_key]
            return info
        if req_clan_id:
            target_team = next((t for t in teams if t["clan_id"] == req_clan_id), None)
            if not target_team:
                return aiohttp.web.json_response({"ok": False, "error": f"No team for {req_clan_id}"})
            info = await _fetch_clan(target_team)
            if not info:
                return aiohttp.web.json_response({"ok": False, "error": "fetch failed"})
            info.pop("_cached_at", None)
            return aiohttp.web.json_response({"ok": True, **info})
        results = []
        for team in teams:
            info = await _fetch_clan(team)
            if info:
                info.pop("_cached_at", None); results.append(info)
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
    app.router.add_get("/api/teams", api_teams)
    app.router.add_get("/api/clan/info", api_clan_info)
    app.router.add_post("/api/create_team", api_create_team)
    app.router.add_post("/api/account/pause", api_account_pause)
    app.router.add_post("/api/account/pause_all", api_account_pause_all)
    app.router.add_post("/api/logs/clear", api_logs_clear)
    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, WEB_HOST, WEB_PORT)
    await site.start()
    print_success(f"[WEB] → http://localhost:{WEB_PORT}")
    return runner

# ==================== MAIN ====================
async def main():
    try:
        await start_web_server()
    except Exception as e:
        print_error(f"[WEB] {e}"); return
    try:
        await _autoload_teams()
    except Exception as e:
        print_error(f"[BOT] autoload failed: {e}")
    try:
        while True:
            await asyncio.sleep(1)
    except (KeyboardInterrupt, asyncio.CancelledError):
        for t in list(bot_state.account_workers.values()):
            t.cancel()
        for t in list(_instance_timeout_tasks.values()):
            t.cancel()
        await asyncio.gather(*bot_state.account_workers.values(), return_exceptions=True)
        try: await client.aclose()
        except Exception: pass

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print_warning("stopped")