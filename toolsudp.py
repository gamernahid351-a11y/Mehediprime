import os
import sys
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import config
import tools

import ff_udp
import ff_match
import match_api
from ff_match import MatchSession, PHASE_FIGHT, PHASE_PREPARE

CMD_PICKUP = 111
CMD_CHANGE_INVENTORY = 108
CMD_START_FIRE = 104
CMD_STOP_FIRE = 105
CMD_PURCHASE = 413
CMD_USE_SKILL = 248
CMD_SKILL_STATE = 250

WEAPON_ITEM_MAX = 200
CLIP_SIZE = 30


def set_base_url(url):
    match_api.set_base_url(url)


class ActiveSession(MatchSession):
    def __init__(self, *args, **kwargs):
        MatchSession.__init__(self, *args, **kwargs)
        self.claimed = threading.Event()
        self.inventory = {}
        self.weapon = None
        self.ammo = CLIP_SIZE
        self.bought = False
        self._acted = 0.0
        self.skill_id = config.LIVE.get_skill_id()
        self._skill_ready = 0.0
        self.router.handlers[CMD_PICKUP] = self.on_pickup
        self.router.handlers[CMD_SKILL_STATE] = self.on_skill_state

    def _claim_result(self):
        """Run the parent claim, then say it is done.

        The claim is fired from a timer that nobody waits on, so the session
        used to return while the eight end-of-match calls were still pending -
        and safe mode would start the next match before the XP for this one had
        been asked for. The event lets the caller wait for the real end.
        """
        try:
            MatchSession._claim_result(self)
        finally:
            self.claimed.set()

    def wait_claimed(self, timeout):
        return self.claimed.wait(timeout)

    def on_skill_state(self, body, now):
        if not body:
            return
        try:
            player_id, skill_id, state, ready = tools.parse_skill_state(body)
        except Exception:
            return
        snap = self.state.snapshot()
        if snap.my_id is not None and player_id != snap.my_id:
            return
        if skill_id:
            self.skill_id = skill_id
            config.LIVE.set_skill(skill_id=skill_id)
        if ready > 0.0:
            self._skill_ready = ready
            used = self.planner.server_time(snap, now) / 1000.0
            if ready > used:
                config.LIVE.set_skill(cooldown=ready - used)

    def use_skill(self, snap, now):
        if snap.my_id is None or not self.skill_id:
            return False
        elapsed = self.planner.server_time(snap, now) / 1000.0
        if elapsed < self._skill_ready:
            return False
        try:
            self.send(CMD_USE_SKILL,
                      tools.build_use_skill(snap.my_id, self.skill_id,
                                            self.planner.server_time(snap, now)),
                      send_option=ff_udp.SENDOPTION_RELIABLE)
        except Exception:
            return False
        self._skill_ready = elapsed + config.LIVE.get_skill_cooldown()
        return True

    def on_pickup(self, body, now):
        if not body:
            return
        try:
            player_id, unique_id, item_id = tools.parse_pickup(body)
        except Exception:
            return
        snap = self.state.snapshot()
        if snap.my_id is not None and player_id != snap.my_id:
            return
        self.inventory[unique_id] = item_id
        if item_id <= WEAPON_ITEM_MAX and self.weapon is None:
            self.weapon = unique_id

    def best_weapon(self):
        if self.weapon is not None:
            return self.weapon
        for unique_id, item_id in self.inventory.items():
            if item_id <= WEAPON_ITEM_MAX:
                self.weapon = unique_id
                return unique_id
        return None

    def buy_round(self):
        for item_id, quantity in config.Buy_Items:
            try:
                self.send(CMD_PURCHASE, tools.build_purchase(item_id, quantity),
                          send_option=ff_udp.SENDOPTION_RELIABLE)
            except Exception:
                return False
        return True

    def switch_weapon(self, snap):
        unique_id = self.best_weapon()
        if unique_id is None or snap.my_id is None:
            return False
        try:
            self.send(CMD_CHANGE_INVENTORY,
                      tools.build_switch_weapon(snap.my_id, unique_id),
                      send_option=ff_udp.SENDOPTION_RELIABLE)
            return True
        except Exception:
            return False

    def fire_burst(self, snap, now):
        unique_id = self.best_weapon()
        if unique_id is None or snap.my_id is None:
            return False
        tick = self.planner.server_time(snap, now)
        try:
            self.send(CMD_START_FIRE,
                      tools.build_start_fire(snap.my_id, unique_id, tick),
                      send_option=ff_udp.SENDOPTION_RELIABLE)
        except Exception:
            return False
        self.ammo = max(0, self.ammo - 1)
        if self.ammo == 0:
            self.ammo = CLIP_SIZE
        try:
            self.send(CMD_STOP_FIRE,
                      tools.build_stop_fire(snap.my_id, unique_id, self.ammo,
                                            tick + config.Fire_Burst_Ticks),
                      send_option=ff_udp.SENDOPTION_RELIABLE)
            return True
        except Exception:
            return False

    def act(self, snap, now):
        if not config.AntiAFK:
            return
        if now - self._acted < config.Action_Interval:
            return
        if snap.my_id is None or not snap.alive:
            return
        self._acted = now
        if snap.phase == PHASE_PREPARE:
            if config.Buy_In_Prepare and not self.bought:
                self.bought = self.buy_round()
            if config.Switch_Weapon:
                self.switch_weapon(snap)
            return
        if snap.phase == PHASE_FIGHT:
            self.bought = False
            if getattr(config, "Use_Skill", True):
                self.use_skill(snap, now)
            if config.Fire_In_Fight:
                self.fire_burst(snap, now)

    def _tend_downed(self, snap, now):
        MatchSession._tend_downed(self, snap, now)
        self.act(snap, now)


def claim_wait_seconds():
    return float(getattr(config, "Claim_Wait", 45.0) or 45.0)


def run_match(ip, port, account_id, secret, udp_jwt, udp_mask, suffix="0",
              game_mode=15, map_id=1, match_mode=1, sleep_ms=0, timeout=3.0,
              api_token=None, match_id=0, verbose=False):
    session = ActiveSession(ip, port, account_id, secret, udp_jwt, udp_mask,
                            suffix=suffix, api_token=api_token,
                            match_id=match_id, verbose=verbose)
    joined = session.run(game_mode=game_mode, map_id=map_id,
                         match_mode=match_mode, sleep_ms=sleep_ms,
                         timeout=timeout)
    if joined and getattr(config, "Safe_Mode", False):
        session.wait_claimed(claim_wait_seconds())
    return joined
