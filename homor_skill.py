# homor_skill.py — cmd 248 (USE_ACTIVE_SKILL) for skill 5506 (homor).
# Fires ONCE per round, on ENTRY into FIGHT phase (code 3).
#
# FIXES APPLIED:
#   BUG1: PHASE_FIRE_ON was (PHASE_COMBAT,) = (2,) — phase 2 never arrives
#         in Clash Squad. Changed to (PHASE_FIGHT,) = (3,).
#   BUG2: build_skill_body had wrong field order: skill_id first, then target_uid.
#         Server expects player_id first. Signature updated to match tools.py wire
#         format: player_id | skill_id | tick | 6x00.

SKILL_ID        = 5506
COOLDOWN_SEC    = 30.0     # real in-game homor cooldown (matches Fallback_Skill_Cooldown)
FIRST_DELAY_SEC = 5.0

CMD_USE_ACTIVE_SKILL = 248

PHASE_PREPARE   = 1
PHASE_COMBAT    = 2   # not sent in Clash Squad — kept for reference only
PHASE_FIGHT     = 3
PHASE_ROUND_END = 5

# BUG1 FIX: was (PHASE_COMBAT,) = (2,) — never fires in Clash Squad
PHASE_FIRE_ON = (PHASE_FIGHT,)


def _uleb(n: int) -> bytes:
    if n < 0:
        n &= 0xFFFFFFFFFFFFFFFF
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


# BUG2 FIX: was build_skill_body(skill_id, target_uid, tick, x, y, z)
# with body = skill_id | target_uid | tick_zz | x_zz | y_zz | z_zz
# Server expects player_id first, matching tools.build_use_skill wire format.
def build_skill_body(player_id: int, skill_id: int, tick: int,
                     x: int = 0, y: int = 0, z: int = 0) -> bytes:
    """Encode a USE_ACTIVE_SKILL body.

    Wire format (confirmed from working tools.py path):
        player_id (uleb128) | skill_id (uleb128) | tick (uleb128) | 6 zero bytes

    x, y, z accepted but unused — kept so old call sites that pass position
    still compile without changes.
    """
    return (_uleb(int(player_id)) + _uleb(int(skill_id)) +
            _uleb(int(tick)) + bytes(6))


class HomorSkill:
    def __init__(self, skill_id: int = SKILL_ID,
                 cooldown: float = COOLDOWN_SEC,
                 target_uid: int = 0,
                 first_delay: float = FIRST_DELAY_SEC):
        self.skill_id    = int(skill_id)
        self.cooldown    = float(cooldown)
        self.target_uid  = int(target_uid)
        self.first_delay = float(first_delay)
        self._last_cast  = 0.0
        self._last_phase = None

    def should_cast_round(self, now: float, joined_at, round_no, phase) -> bool:
        phase_changed = (self._last_phase != phase)
        self._last_phase = phase

        if joined_at is None:
            return False
        if (now - joined_at) < self.first_delay:
            return False
        if phase not in PHASE_FIRE_ON:
            return False
        if not phase_changed:
            return False
        if (now - self._last_cast) < self.cooldown:
            return False
        return True

    def mark_fired_round(self, round_no=None) -> None:
        """Compatibility shim — ff_match.py still calls this."""
        pass

    def mark_cast(self, now: float) -> None:
        self._last_cast = now

    def reset(self) -> None:
        self._last_cast = 0.0
        self._last_phase = None
