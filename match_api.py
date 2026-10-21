"""
End-of-match lobby calls.

Watching a real client finish a match shows it hitting a run of HTTP endpoints
on the live client host the moment the result screen appears:

    /GetMatchMakingBlackList
    /GetPlayerHippoRakingainfo
    /GetModeStatsConfig
    /GetBrRakingInfo
    /initPlayerCsRakingInfo
    /GetPlayerRakingInfo

They are POSTs with an empty body, encrypted the same way every other API call
in this project is. The bot never made them: it played the match over UDP and
then simply went quiet, which is not what a client that finished a game looks
like from the server's side.

This module makes the same calls with the same headers. It is deliberately
forgiving - a failure here is logged and skipped, never raised, because the
match is already over and nothing downstream depends on the reply.
"""

import threading

import requests
import urllib3

import config
from tools import encrypt_api

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://clientbp.ppmainecoonghj.com"


def set_base_url(url):
    """Point these calls at the host MajorLogin handed back.

    The login response carries the client server in field 10, and it is not
    always the one hardcoded here - a session pointed at a different host
    would have every one of these calls land on the wrong server.
    """
    global BASE_URL
    if not url:
        return
    cleaned = url.rstrip("/")
    if not cleaned.startswith("http"):
        cleaned = "https://" + cleaned
    BASE_URL = cleaned

# The endpoints the client hits when the result screen opens, with the exact
# spelling it uses. Every one of these was captured from the game itself, and
# the casing matters: the earlier guesses differed by a letter or two -
# "Raking" for "Ranking", "BlackList" for "Blacklist" - and every one of them
# came back 404.
ENDPOINTS = (
    "GetMatchmakingBlacklist",
    "GetPlayerHippoRankingInfo",
    "GetModeStatsConfig",
    "GetBRRankingInfo",
    "InitPlayerCSRankingInfo",
    "GetPlayerRankingInfo",
    "GetBM26SysRedDotInfo",
    "GetOccupationInfo",
)

# Paths that answer 404 are not retried: hammering a missing endpoint every
# match achieves nothing and clutters the log.
_dead = set()


def _live_release_version():
    try:
        import autoupdate
        return autoupdate.release_version()
    except Exception:
        try:
            return config.LIVE.release_version
        except Exception:
            return "OB55"


def _headers(jwt_token):
    """Exactly the headers the game sends, captured from a real session.

    The User-Agent and X-Unity-Version identify the engine build and are
    checked, so they have to be the client's own values rather than something
    plausible - live OB55 login used Unity 2018.4.12f1. Host follows
    BASE_URL so a live client host from MajorLogin is not overwritten
    by a stale literal.
    """
    host = BASE_URL.split("//", 1)[-1].split("/", 1)[0]
    return {
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "Authorization": "Bearer %s" % jwt_token,
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": host,
        "ReleaseVersion": _live_release_version(),
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "X-GA": "v1 1",
        "X-Unity-Version": "2018.4.12f1",
    }


def _payload():
    """The 16-byte body every one of these calls carries.

    Captured from the game as 1a725b2c56ec52ba7d09623454c0a003, which is
    exactly what encrypt_api("") produces: an empty plaintext padded to one
    AES block. So "no parameters" is not an empty body at all - it is a full
    encrypted block, and sending nothing gets rejected.
    """
    try:
        return bytes.fromhex(encrypt_api(""))
    except Exception:
        return bytes.fromhex("1a725b2c56ec52ba7d09623454c0a003")


def call_endpoint(name, jwt_token, timeout=10, verbose=True):
    """POST one endpoint. Returns True on a 2xx."""
    if name in _dead:
        return False
    url = "%s/%s" % (BASE_URL, name)
    try:
        response = requests.post(url, headers=_headers(jwt_token),
                                 data=_payload(), verify=False,
                                 timeout=timeout)
    except Exception as exc:
        if verbose:
            print("[api] %-28s failed: %r" % (name, exc))
        return False
    if 200 <= response.status_code < 300:
        if verbose:
            print("[api] %-28s %s (%d bytes)"
                  % (name, response.status_code, len(response.content)))
        return True
    if response.status_code == 404:
        _dead.add(name)
    if verbose:
        print("[api] %-28s %s" % (name, response.status_code))
    return False


def claim_match_rewards(jwt_token, verbose=True):
    """Run the whole end-of-match sequence. Returns how many calls succeeded.

    Called after the UDP side has asked for the result screen, so the lobby
    sees the same pattern a finishing client produces.
    """
    if not jwt_token:
        if verbose:
            print("[api] no token - skipping end-of-match calls")
        return 0
    if verbose:
        print("[api] claiming match rewards (%d endpoints)" % len(ENDPOINTS))
    done = 0
    for name in ENDPOINTS:
        if call_endpoint(name, jwt_token, verbose=verbose):
            done += 1
    if verbose:
        print("[api] %d/%d succeeded" % (done, len(ENDPOINTS)))
    return done


def claim_in_background(jwt_token, verbose=True):
    """Fire the sequence off a thread so the caller is not blocked by six
    round trips it does not need to wait for."""
    th = threading.Thread(target=claim_match_rewards,
                          args=(jwt_token,), kwargs={"verbose": verbose},
                          daemon=True)
    th.start()
    return th
