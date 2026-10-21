import re
import threading
import time
from typing import Any, Dict, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def version_endpoint() -> str:
    return "https://version.ggwhitehawk.com/live/ver.php"


def play_details_url() -> str:
    return "https://play.google.com/store/apps/details"


def game_package() -> str:
    return "com.dts.freefireth"


def probe_params(region: str, version: str) -> Dict[str, str]:
    return {
        "version": version,
        "lang": "en",
        "device": "android",
        "region": region,
    }


def probe_headers() -> Dict[str, str]:
    return {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)",
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive",
    }


def browser_headers() -> Dict[str, str]:
    return {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/126.0.0.0 Safari/537.36"),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }


def fallback_server_url() -> str:
    return "https://loginbp.ppmainecoonghj.com"


def fallback_release_version() -> str:
    return "OB55"


def fallback_remote_version() -> str:
    # What MajorLogin actually accepted in the live JWT (client_version).
    return "1.132.3"


def refresh_seconds() -> float:
    return 1800.0


def request_timeout() -> float:
    return 15.0


def normalise_url(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    return url.rstrip("/")


def looks_like_version(text: Optional[str]) -> bool:
    if not text:
        return False
    return bool(re.fullmatch(r'[0-9]{1,4}(\.[0-9]{1,4}){1,3}', text))


def script_blobs(html: str) -> list:
    return re.findall(r"AF_initDataCallback\((\{.*?\})\);", html, re.S)


def scan_version_blobs(html: str) -> Optional[str]:
    candidates = []
    for blob in script_blobs(html):
        for found in re.findall(r'"([0-9]{1,4}(?:\.[0-9]{1,4}){1,3})"', blob):
            candidates.append(found)
    if not candidates:
        return None
    return sorted(candidates, key=lambda v: (-len(v.split(".")), -len(v)))[0]


def extract_play_version(html: str) -> Optional[str]:
    for pattern in (r'\[\[\["([0-9]{1,4}(?:\.[0-9]{1,4}){1,3})"\]\]',
                    r'"([0-9]{1,4}(?:\.[0-9]{1,4}){2,3})"\s*\]\s*\]\s*,\s*(?:null|\d)',
                    r'Current Version.{0,200}?>\s*([0-9]{1,4}(?:\.[0-9]{1,4}){1,3})\s*<',
                    r'"softwareVersion"\s*:\s*"([^"]+)"'):
        found = re.search(pattern, html, re.S)
        if found and looks_like_version(found.group(1).strip()):
            return found.group(1).strip()
    return scan_version_blobs(html)


def fetch_play_version(package: str) -> Optional[str]:
    try:
        response = requests.get(play_details_url(),
                                params={"id": package, "hl": "en", "gl": "US"},
                                headers=browser_headers(),
                                timeout=request_timeout(), verify=False)
    except Exception:
        return None
    if response.status_code != 200:
        return None
    return extract_play_version(response.text)


def fetch_live(region: str, version: str) -> Optional[Dict[str, str]]:
    try:
        response = requests.get(version_endpoint(),
                                params=probe_params(region, version),
                                headers=probe_headers(),
                                timeout=request_timeout(), verify=False)
    except Exception:
        return None
    if response.status_code != 200:
        return None
    try:
        data = response.json()
    except Exception:
        return None
    server_url = normalise_url(data.get("server_url"))
    release = data.get("latest_release_version")
    remote = data.get("remote_version")
    if not (server_url and release and remote):
        return None
    return {
        "server_url": server_url,
        "release_version": release,
        "remote_version": remote,
        "raw": data,
    }


def defaults() -> Dict[str, Any]:
    return {
        "server_url": fallback_server_url(),
        "release_version": fallback_release_version(),
        "remote_version": fallback_remote_version(),
        "play_version": None,
        "raw": {},
    }


class AutoUpdate:
    def __init__(self, region: str = "ME", verbose: bool = True,
                 use_play: bool = True):
        self._region = region
        self._verbose = verbose
        self._use_play = use_play
        self._lock = threading.Lock()
        self._values = defaults()
        self._checked_at = 0.0
        self._live = False

    def _say(self, message: str) -> None:
        if self._verbose:
            print("[update] %s" % message)

    def _merge(self, fetched: Optional[Dict[str, str]],
               play: Optional[str]) -> Dict[str, Any]:
        merged = dict(self._values)
        if fetched:
            merged.update(fetched)
        merged["play_version"] = play
        if play and looks_like_version(play):
            current = merged.get("remote_version")
            # Only take Play Store when it is newer than the endpoint value.
            # Overwriting unconditionally made an older Play listing win
            # (1.132.1 over 1.132.6) and the login packet then sent a version
            # the server had already moved past.
            if not looks_like_version(current) or play > current:
                if play != current:
                    self._say("play store newer: %s (had %s)"
                              % (play, current))
                merged["remote_version"] = play
        return merged

    def _apply(self, merged: Dict[str, Any]) -> None:
        with self._lock:
            changed = {
                key: (self._values.get(key), merged.get(key))
                for key in ("server_url", "release_version", "remote_version")
                if self._values.get(key) != merged.get(key)
            }
            self._values = merged
            self._checked_at = time.time()
        for key, (was, now) in changed.items():
            self._say("%s: %s -> %s" % (key, was, now))

    def check(self, force: bool = False) -> bool:
        with self._lock:
            fresh = (time.time() - self._checked_at) < refresh_seconds()
        if fresh and not force:
            return self._live

        play = fetch_play_version(game_package()) if self._use_play else None
        with self._lock:
            known = self._values["remote_version"]
        fetched = fetch_live(self._region, play or known)

        if fetched is None and play is None:
            with self._lock:
                self._checked_at = time.time()
            self._say("check failed, keeping %s / %s"
                      % (self._values["release_version"],
                         self._values["remote_version"]))
            return self._live

        self._apply(self._merge(fetched, play))
        with self._lock:
            self._live = True
        return True

    def _get(self, key: str) -> Any:
        self.check()
        with self._lock:
            return self._values.get(key)

    def server_url(self) -> str:
        return self._get("server_url")

    def release_version(self) -> str:
        return self._get("release_version")

    def remote_version(self) -> str:
        return self._get("remote_version")

    def play_version(self) -> Optional[str]:
        return self._get("play_version")

    def is_live(self) -> bool:
        self.check()
        return self._live

    def snapshot(self) -> Dict[str, Any]:
        self.check()
        with self._lock:
            return dict(self._values)

    def start(self, interval: Optional[float] = None) -> threading.Thread:
        every = interval if interval is not None else refresh_seconds()

        def loop() -> None:
            while True:
                time.sleep(every)
                try:
                    self.check(force=True)
                except Exception:
                    pass

        thread = threading.Thread(target=loop, daemon=True)
        thread.start()
        return thread


def shared() -> AutoUpdate:
    global _SHARED
    try:
        return _SHARED
    except NameError:
        _SHARED = AutoUpdate(verbose=False)
        return _SHARED


def server_url() -> str:
    return shared().server_url()


def release_version() -> str:
    return shared().release_version()


def remote_version() -> str:
    return shared().remote_version()


def play_version() -> Optional[str]:
    return shared().play_version()


def main() -> None:
    updater = AutoUpdate()
    values = updater.snapshot()
    print("Server URL      : %s" % values["server_url"])
    print("Release Version : %s" % values["release_version"])
    print("Remote Version  : %s" % values["remote_version"])
    print("Play Version    : %s" % (values.get("play_version") or "-"))
    print("Live            : %s" % updater.is_live())
    extra = {k: v for k, v in values.get("raw", {}).items()
             if k not in ("server_url", "latest_release_version",
                          "remote_version")}
    if extra:
        print("Other fields    :")
        for key in sorted(extra):
            print("    %-28s %s" % (key, extra[key]))


if __name__ == "__main__":
    main()
