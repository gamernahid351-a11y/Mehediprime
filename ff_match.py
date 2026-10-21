"""
Match session: a layered rewrite of the follow bot.
"""

import math
import socket
import threading
import time

import ff_udp

try:
    import match_api
except ImportError:
    match_api = None

try:
    import config
except ImportError:
    class config(object):
        Chat_CommandUdp = True
        AutoSafeZone = True
        AutoXp = True
        Use_Plane_Phase = True
        WAIT_LOBBY_TIME = 30.0
        PLANE_DURATION = 30.0
        PLANE_START_HEIGHT = 36000.0
        PLANE_JUMP_HEIGHT = 28000.0
        LAND_HEIGHT = 500.0
        PARACHUTE_DESCENT = 2000.0
        PARACHUTE_STEER = 3000.0
        PLANE_SPEED = 8000.0
        LANDING_TARGET = (0.0, 0.0)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEND_HZ = 10.0
MOVE_INTERVAL = 1.0 / SEND_HZ
WALK_SPEED = 5150.0
STEP_PER_TICK = WALK_SPEED / SEND_HZ
SERVER_TICK_HZ = 30.0

CMD_PLAYER_JOIN = 101
CMD_MATCH_END = 103
CMD_DEAD = 107
CMD_SAFE_ZONE = 117
CMD_KNOCK_DOWN = 139
CMD_KNOCK_REVIVE = 140
CMD_START_RESCUE = 142
CMD_STOP_RESCUE = 143
CMD_PENDING_REVIVE = 256
CMD_REVIVE = 393
CMD_SHOW_MATCH_RESULT = 407
CMD_QUICK_CHAT = 551
CMD_GRI_SYNC = 1901
CMD_SERVER_TIME = 2000
CMD_MY_STATE = 2001
CMD_OTHER_STATES = 2012

POSE_KNOCKDOWN = 8

REVIVE_RANGE = 3000.0
REVIVE_TIMEOUT = 12.0
REVIVE_RETRY = 1.5

PHASE_PREPARE = 1
PHASE_FIGHT = 3
PHASE_ROUND_END = 5
PHASE_NAMES = {1: "PREPARE", 2: "phase2", 3: "FIGHT", 4: "phase4",
               5: "ROUND_END"}

MATCH_RESULT_DELAY = 6.45
POST_RESULT_LINGER = 6.7
JOIN_TIMEOUT = 8.0

FOLLOW_TRIGGERS = (1, 2)
CHAT_NAMES = {1: "follow me", 2: "help me"}

POSE_STANDING = 0
POSE_DASHING = 2

ZONE_RADIUS_SCALE = 1000.0
ZONE_DANGER_FRACTION = 0.75

RESYNC_DIST = 120000.0

BLOCK_DIST = 1500.0
BLOCK_TICKS = 5
SLIDE_ANGLE = 65.0
SLIDE_HOLD = 1.5

# ═══════════════════════════════════════════════════════════════════════
# PLANE PHASE CONSTANTS
# ═══════════════════════════════════════════════════════════════════════

PLANE_PHASE_NONE = "none"
PLANE_PHASE_WAITING = "waiting"
PLANE_PHASE_PLANE = "plane"
PLANE_PHASE_JUMP = "jump"
PLANE_PHASE_PARACHUTE = "parachute"
PLANE_PHASE_LANDED = "landed"


class Snapshot(object):
    __slots__ = ("my_id", "my_short", "my_pos", "target_short", "target_pos",
                 "target_vel", "target_seen_at", "target_yrot", "target_aim_y",
                 "target_aim_xz", "target_state", "target_pose", "server_tick",
                 "tick_local", "tick_rate", "zone_center", "zone_radius",
                 "server_pos", "blocked_ticks", "phase", "round_no", "alive",
                 "downed", "rescuing", "rescue_started", "joined_at",
                 "plane_phase", "plane_pos", "plane_started", "jumped_at")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))


class MatchState(object):
    def __init__(self):
        self._lock = threading.Lock()
        self.my_id = None
        self.my_short = None
        self.my_pos = None
        self.roster = {}
        self.target_short = None
        self.target_pos = None
        self.target_vel = (0.0, 0.0)
        self.target_seen_at = None
        self.target_yrot = 0
        self.target_aim_y = 0
        self.target_aim_xz = 0
        self.target_state = 0
        self.target_pose = 0
        self.server_tick = None
        self.tick_local = None
        self.tick_rate = SERVER_TICK_HZ
        self.zone_center = None
        self.zone_radius = 0.0
        self.server_pos = None
        self.blocked_ticks = 0
        self.phase = None
        self.round_no = None
        self.alive = True
        self.downed = {}
        self.rescuing = None
        self.rescue_started = 0.0
        self.joined_at = None
        self.plane_phase = PLANE_PHASE_NONE
        self.plane_pos = None
        self.plane_started = None
        self.jumped_at = None

    def teammates(self):
        with self._lock:
            if self.my_id is None:
                return set()
            my_team = (self.my_id >> 24) & 0xFF
            return {short for short, (full, _) in self.roster.items()
                    if (full >> 24) & 0xFF == my_team and short != self.my_short}

    def full_id_of(self, short_id):
        with self._lock:
            entry = self.roster.get(short_id)
            return entry[0] if entry else None

    def set_downed(self, downed):
        with self._lock:
            self.downed = downed

    def mark_down(self, short_id, pos=None):
        with self._lock:
            if pos is not None or short_id not in self.downed:
                self.downed[short_id] = pos

    def clear_down(self, short_id):
        with self._lock:
            self.downed.pop(short_id, None)

    def begin_rescue(self, full_id, now):
        with self._lock:
            if self.rescuing is not None:
                return False
            self.rescuing = full_id
            self.rescue_started = now
            return True

    def end_rescue(self, full_id=None):
        with self._lock:
            if full_id is not None and self.rescuing != full_id:
                return None
            done = self.rescuing
            self.rescuing = None
            self.rescue_started = 0.0
            return done

    def snapshot(self):
        with self._lock:
            return Snapshot(
                my_id=self.my_id, my_short=self.my_short, my_pos=self.my_pos,
                target_short=self.target_short, target_pos=self.target_pos,
                target_vel=self.target_vel, target_seen_at=self.target_seen_at,
                target_yrot=self.target_yrot, target_aim_y=self.target_aim_y,
                target_aim_xz=self.target_aim_xz,
                target_state=self.target_state, target_pose=self.target_pose,
                server_tick=self.server_tick, tick_local=self.tick_local,
                tick_rate=self.tick_rate, zone_center=self.zone_center,
                zone_radius=self.zone_radius, server_pos=self.server_pos,
                blocked_ticks=self.blocked_ticks, phase=self.phase,
                round_no=self.round_no, alive=self.alive,
                downed=dict(self.downed), rescuing=self.rescuing,
                rescue_started=self.rescue_started,
                joined_at=self.joined_at,
                plane_phase=self.plane_phase, plane_pos=self.plane_pos,
                plane_started=self.plane_started, jumped_at=self.jumped_at)

    def set_alive(self, alive):
        with self._lock:
            changed = alive != self.alive
            self.alive = alive
            return changed

    def set_phase(self, phase, round_no):
        with self._lock:
            changed = phase != self.phase
            self.phase = phase
            if round_no is not None:
                self.round_no = round_no
            return changed, self.round_no

    def set_zone(self, center, radius):
        with self._lock:
            self.zone_center = center
            self.zone_radius = radius

    def set_identity(self, full_id):
        with self._lock:
            self.my_id = full_id
            self.my_short = full_id & 0xFF
            if self.joined_at is None:
                self.joined_at = time.time()

    def add_player(self, full_id, name):
        with self._lock:
            self.roster[full_id & 0xFF] = (full_id, name)

    def name_of(self, short_id):
        with self._lock:
            return self.roster.get(short_id, (0, "?"))[1]

    def set_my_pos(self, pos):
        with self._lock:
            self.my_pos = (int(pos[0]), int(pos[1]), int(pos[2]))

    def seed_my_pos(self, pos):
        with self._lock:
            pos = (int(pos[0]), int(pos[1]), int(pos[2]))
            self.server_pos = pos
            if self.my_pos is None:
                self.my_pos = pos
                self.blocked_ticks = 0
                return
            dx = pos[0] - self.my_pos[0]
            dz = pos[2] - self.my_pos[2]
            gap = math.sqrt(dx * dx + dz * dz)
            if gap > RESYNC_DIST:
                self.my_pos = pos
                self.blocked_ticks = 0
            elif gap > BLOCK_DIST:
                self.blocked_ticks += 1
                if self.blocked_ticks >= BLOCK_TICKS:
                    self.my_pos = pos
            else:
                self.blocked_ticks = 0

    def set_target(self, short_id):
        with self._lock:
            if self.my_short is not None and short_id == self.my_short:
                return False
            if short_id != self.target_short:
                self.target_pos = None
            self.target_vel = (0.0, 0.0)
            self.target_seen_at = None
            self.target_short = short_id
            return True

    def update_target(self, info, now):
        with self._lock:
            prev_pos, prev_seen = self.target_pos, self.target_seen_at
            self.target_pos = info["pos"]
            self.target_seen_at = now
            if prev_pos is not None and prev_seen is not None:
                dt = now - prev_seen
                if 0.01 < dt < 2.0:
                    vx = (info["pos"][0] - prev_pos[0]) / dt
                    vz = (info["pos"][2] - prev_pos[2]) / dt
                    if abs(vx) < 30000 and abs(vz) < 30000:
                        self.target_vel = (vx, vz)
            self.target_yrot = info.get("yrot", self.target_yrot)
            self.target_aim_y = info.get("aim_y", self.target_aim_y)
            self.target_aim_xz = info.get("aim_xz", self.target_aim_xz)
            self.target_state = info.get("physx_state", self.target_state)
            self.target_pose = info.get("physx_pose", self.target_pose)

    def sync_clock(self, tick, now):
        with self._lock:
            if self.server_tick is not None and self.tick_local is not None:
                dt = now - self.tick_local
                dtick = tick - self.server_tick
                if dt > 0.5 and 0 < dtick < 10000:
                    self.tick_rate = self.tick_rate * 0.7 + (dtick / dt) * 0.3
            self.server_tick = tick
            self.tick_local = now

    def set_plane_phase(self, phase, now=None):
        with self._lock:
            old = self.plane_phase
            self.plane_phase = phase
            if phase == PLANE_PHASE_WAITING and self.plane_started is None:
                self.plane_started = now or time.time()
            elif phase == PLANE_PHASE_PLANE and old != PLANE_PHASE_PLANE:
                self.plane_started = now or time.time()
            elif phase == PLANE_PHASE_JUMP:
                self.jumped_at = now or time.time()
            return old != phase

    def set_plane_pos(self, pos):
        with self._lock:
            pos = (int(pos[0]), int(pos[1]), int(pos[2]))
            self.plane_pos = pos
            self.my_pos = pos

    def is_on_ground(self):
        with self._lock:
            if self.my_pos is None:
                return False
            return self.my_pos[1] <= getattr(config, "LAND_HEIGHT", 500.0)

    def is_plane_phase_done(self):
        with self._lock:
            return self.plane_phase == PLANE_PHASE_LANDED


class MovementPlanner(object):
    def __init__(self, step=STEP_PER_TICK, max_step=STEP_PER_TICK * 1.25,
                 stick_dist=150.0, far_dist=8000.0, lead=0.2,
                 climb_rate=0.35, coast_limit=3.0, auto_zone=True,
                 fixed_step=None, turn_degrees=0.0, move_in_prepare=True,
                 orbit_fraction=0.55, orbit_speed=6.0, dodge=500.0):
        self.step = float(step)
        self.max_step = float(max_step)
        self.stick_dist = float(stick_dist)
        self.far_dist = float(far_dist)
        self.lead = float(lead)
        self.climb_rate = float(climb_rate)
        self.coast_limit = float(coast_limit)
        self.auto_zone = bool(auto_zone)
        self.fixed_step = fixed_step
        self.turn_degrees = float(turn_degrees)
        self.move_in_prepare = bool(move_in_prepare)
        self.orbit_fraction = float(orbit_fraction)
        self.orbit_speed = float(orbit_speed)
        self._orbit_angle = 0.0
        self._yaw = 0.0
        self._slide_sign = 1.0
        self._slide_until = 0.0
        self.dodge = float(dodge)
        self._dodge_tries = 1

    def next_yaw(self):
        if self.turn_degrees:
            self._yaw = (self._yaw + self.turn_degrees) % 360.0
        return self._yaw

    def orbit_point(self, snap, now):
        if snap.zone_center is None or snap.zone_radius <= 0:
            return None
        cx, cz = snap.zone_center[0], snap.zone_center[-1]
        r = snap.zone_radius * self.orbit_fraction
        if r <= 1:
            return None
        stride = float(self.fixed_step) if self.fixed_step else self.step
        max_deg = math.degrees(stride / r) * 0.85
        self._orbit_angle = (self._orbit_angle
                             + min(self.orbit_speed, max_deg)) % 360.0
        rad = math.radians(self._orbit_angle)
        y = snap.my_pos[1] if snap.my_pos else 0
        return (cx + r * math.cos(rad), y, cz + r * math.sin(rad))

    def aim_point(self, snap, now):
        target = None
        if snap.target_pos is not None:
            if snap.target_seen_at is None:
                target = snap.target_pos
            else:
                gap = now - snap.target_seen_at
                if gap <= 0.05 or gap > self.coast_limit:
                    target = snap.target_pos
                else:
                    vx, vz = snap.target_vel
                    target = (snap.target_pos[0] + vx * gap,
                              snap.target_pos[1],
                              snap.target_pos[2] + vz * gap)
        rescue = self.rescue_point(snap)
        if rescue is not None:
            return rescue
        zone = self.zone_point(snap)
        if target is None:
            return zone
        if zone is not None and self.outside_zone(snap, target):
            return zone
        return target

    def rescue_point(self, snap):
        if snap.rescuing is not None:
            return snap.my_pos
        if not snap.downed or snap.my_pos is None:
            return None
        best = None
        best_dist = None
        for pos in snap.downed.values():
            if pos is None:
                continue
            dx = pos[0] - snap.my_pos[0]
            dz = pos[2] - snap.my_pos[2]
            dist = math.sqrt(dx * dx + dz * dz)
            if best_dist is None or dist < best_dist:
                best = pos
                best_dist = dist
        return best

    def zone_point(self, snap):
        if not self.auto_zone or snap.zone_center is None or snap.zone_radius <= 0:
            return None
        cx, cz = snap.zone_center[0], snap.zone_center[-1]
        y = snap.my_pos[1] if snap.my_pos else 0
        ring = snap.zone_radius * self.orbit_fraction
        if snap.my_pos is not None:
            dx = snap.my_pos[0] - cx
            dz = snap.my_pos[2] - cz
            here = math.sqrt(dx * dx + dz * dz)
            if here <= ring * 1.15:
                if here > 1:
                    self._orbit_angle = math.degrees(math.atan2(dz, dx))
                orbit = self.orbit_point(snap, 0)
                if orbit is not None:
                    return orbit
        return (cx, y, cz)

    def outside_zone(self, snap, point):
        if snap.zone_center is None or snap.zone_radius <= 0:
            return False
        cx, cz = snap.zone_center[0], snap.zone_center[-1]
        dx = point[0] - cx
        dz = point[2] - cz
        return math.sqrt(dx * dx + dz * dz) > snap.zone_radius * ZONE_DANGER_FRACTION

    def plan(self, snap, now):
        if snap.my_pos is None or snap.my_id is None:
            return None
        my = snap.my_pos
        if snap.phase is None:
            return my, 0.0, False
        moving_phases = (PHASE_FIGHT,)
        if self.move_in_prepare:
            moving_phases = (PHASE_FIGHT, PHASE_PREPARE, 2, 9)
        if snap.phase not in moving_phases:
            return my, 0.0, False

        aim = self.aim_point(snap, now)
        if aim is None:
            return my, 0.0, False

        dx = aim[0] - my[0]
        dz = aim[2] - my[2]
        dist = math.sqrt(dx * dx + dz * dz)

        ty = aim[1] if len(aim) > 2 else my[1]
        new_y = int(my[1] + (ty - my[1]) * self.climb_rate)

        if dist > self.far_dist:
            vx, vz = snap.target_vel
            dx += vx * self.lead
            dz += vz * self.lead
            dist = math.sqrt(dx * dx + dz * dz)

        if dist <= self.stick_dist or dist < 1e-6:
            return (my[0], new_y, my[2]), dist, False

        if snap.blocked_ticks >= BLOCK_TICKS:
            if now > self._slide_until:
                self._slide_sign = -self._slide_sign
                self._slide_until = now + SLIDE_HOLD
                self._dodge_tries = min(self._dodge_tries + 1, 6)
            reach = self.dodge * self._dodge_tries
            ux, uz = dx / dist, dz / dist
            px, pz = -uz * self._slide_sign, ux * self._slide_sign
            side = (my[0] + px * reach, new_y, my[2] + pz * reach)
            if snap.zone_center is not None and self.outside_zone(snap, side):
                px, pz = -px, -pz
                self._slide_sign = -self._slide_sign
                side = (my[0] + px * reach, new_y, my[2] + pz * reach)
            return (int(side[0]), new_y, int(side[2])), dist, True
        self._dodge_tries = 1

        step = float(self.fixed_step) if self.fixed_step else (
            self.max_step if dist > self.far_dist else self.step)
        move = step if dist > step else dist
        nx = my[0] + dx / dist * move
        nz = my[2] + dz / dist * move
        return (int(nx), new_y, int(nz)), dist, True

    def server_time(self, snap, now):
        if snap.server_tick is None:
            if snap.joined_at is None:
                return 0
            return int((now - snap.joined_at) * 1000.0) & 0xFFFFFFFF
        elapsed = now - snap.tick_local
        ticks = snap.server_tick + elapsed * snap.tick_rate
        return int(ticks * 1000.0 / snap.tick_rate) & 0xFFFFFFFF


class PacketRouter(object):
    def __init__(self, session):
        self.session = session
        self.handlers = {
            CMD_PLAYER_JOIN: session.on_player_join,
            CMD_MATCH_END: session.on_match_end,
            CMD_DEAD: session.on_down,
            CMD_KNOCK_DOWN: session.on_down,
            CMD_KNOCK_REVIVE: session.on_revive_done,
            CMD_START_RESCUE: session.on_rescue_started,
            CMD_STOP_RESCUE: session.on_rescue_stopped,
            CMD_PENDING_REVIVE: session.on_down,
            CMD_REVIVE: session.on_revive,
            CMD_GRI_SYNC: session.on_gri,
            CMD_SERVER_TIME: session.on_server_time,
            CMD_MY_STATE: session.on_my_state,
            CMD_OTHER_STATES: session.on_other_states,
            CMD_QUICK_CHAT: session.on_quick_chat,
            CMD_SAFE_ZONE: session.on_safe_zone,
        }

    def dispatch(self, cmd, body, now):
        handler = self.handlers.get(cmd)
        if handler is None:
            if self.session.state.snapshot().my_id is None:
                self.session.say("    <- %s (%d) %s"
                                 % (ff_udp.cmd_name(cmd) or "unknown", cmd,
                                    body.hex()[:80] if body else "<empty>"))
            return
        if body is None:
            return
        try:
            handler(body, now)
        except Exception as exc:
            self.session.log_error("handler for cmd %d: %r" % (cmd, exc))


class MatchSession(object):
    def __init__(self, ip, port, account_id, secret, udp_jwt, udp_mask,
                 suffix="0", verbose=True, api_token=None, match_id=0):
        self.addr = (ip, int(port))
        self.account_id = int(account_id)
        self.secret = secret
        self.key = bytes.fromhex(secret)
        self.order = ff_udp.parse_udp_mask(udp_mask)
        self.jwt = udp_jwt
        self.match_id = int(match_id or 0)
        self.api_token = api_token
        self.suffix = suffix
        self.verbose = verbose

        self.state = MatchState()
        self.planner = MovementPlanner(
            auto_zone=config.AutoSafeZone,
            fixed_step=getattr(config, "Boot_movement_amount", None),
            turn_degrees=getattr(config, "Boot_turn_degrees", 0.0),
            move_in_prepare=getattr(config, "Boot_move_in_prepare", True),
            orbit_fraction=getattr(config, "Boot_orbit_fraction", 0.55),
            orbit_speed=getattr(config, "Boot_orbit_speed", 6.0),
            dodge=getattr(config, "Boot_dodge_amount", 500.0))
        self.router = PacketRouter(self)
        self.sock = None
        self._stop = threading.Event()
        self._threads = []
        self.errors = 0
        self.match_over = False
        self._stopped = False
        self.packets_in = 0
        self.decoded_in = 0
        self._last_rescue_send = 0.0

    def say(self, msg):
        if self.verbose:
            print(msg)

    def log_error(self, msg):
        self.errors += 1
        if self.verbose and self.errors <= 20:
            print("[warn] %s" % msg)

    # ═══════════════════════════════════════════════════════════════════
    # PLANE PHASE HANDLER
    # ═══════════════════════════════════════════════════════════════════
    def _plane_phase_handler(self, snap, now):
        """Handle plane phase. Returns True if movement should be BLOCKED."""
        if not getattr(config, "Use_Plane_Phase", True):
            return False

        phase = snap.plane_phase

        if phase == PLANE_PHASE_NONE:
            self.state.set_plane_phase(PLANE_PHASE_WAITING, now)
            self.say("plane: waiting lobby started (%.0fs)"
                     % getattr(config, "WAIT_LOBBY_TIME", 30.0))
            return True

        if phase == PLANE_PHASE_WAITING:
            elapsed = now - (snap.plane_started or now)
            wait_time = getattr(config, "WAIT_LOBBY_TIME", 30.0)
            if elapsed < wait_time:
                return True
            self.state.set_plane_phase(PLANE_PHASE_PLANE, now)
            self.say("plane: plane phase started (%.0fs)"
                     % getattr(config, "PLANE_DURATION", 30.0))
            return True

        if phase == PLANE_PHASE_PLANE:
            elapsed = now - (snap.plane_started or now)
            plane_duration = getattr(config, "PLANE_DURATION", 30.0)
            start_height = getattr(config, "PLANE_START_HEIGHT", 36000.0)
            jump_height = getattr(config, "PLANE_JUMP_HEIGHT", 28000.0)
            plane_speed = getattr(config, "PLANE_SPEED", 8000.0)
            target_x, target_z = getattr(config, "LANDING_TARGET", (0.0, 0.0))

            if snap.zone_center:
                target_x, target_z = snap.zone_center[0], snap.zone_center[-1]

            plane_x = target_x - plane_speed * (plane_duration - elapsed)
            plane_z = target_z

            progress = min(elapsed / plane_duration, 1.0)
            plane_y = start_height - (start_height - jump_height) * progress

            self.state.set_plane_pos((int(plane_x), int(plane_y), int(plane_z)))

            if plane_y <= jump_height:
                self.state.set_plane_phase(PLANE_PHASE_JUMP, now)
                self.say("plane: JUMP at height %.0f" % plane_y)

            return True

        if phase == PLANE_PHASE_JUMP:
            elapsed = now - (snap.jumped_at or now)
            if elapsed > 1.5:
                self.state.set_plane_phase(PLANE_PHASE_PARACHUTE, now)
                self.say("plane: parachute opening")
            return True

        if phase == PLANE_PHASE_PARACHUTE:
            plane_x, plane_y, plane_z = snap.plane_pos or (0, 0, 0)
            target_x, target_z = getattr(config, "LANDING_TARGET", (0.0, 0.0))
            if snap.zone_center:
                target_x, target_z = snap.zone_center[0], snap.zone_center[-1]
            descent = getattr(config, "PARACHUTE_DESCENT", 2000.0)
            steer = getattr(config, "PARACHUTE_STEER", 3000.0)
            land_height = getattr(config, "LAND_HEIGHT", 500.0)

            dx = target_x - plane_x
            dz = target_z - plane_z
            dist = math.sqrt(dx * dx + dz * dz)

            if dist > 100:
                steer_amount = min(steer * 0.1, dist)
                new_x = plane_x + dx / dist * steer_amount
                new_z = plane_z + dz / dist * steer_amount
            else:
                new_x, new_z = target_x, target_z

            new_y = plane_y - descent * 0.1

            self.state.set_plane_pos((int(new_x), int(new_y), int(new_z)))

            if new_y <= land_height:
                self.state.set_plane_pos((int(new_x), int(land_height), int(new_z)))
                self.state.set_plane_phase(PLANE_PHASE_LANDED, now)
                self.say("plane: *** LANDED *** at (%d, %d)"
                         % (int(new_x), int(new_z)))
                return False

            return True

        if phase == PLANE_PHASE_LANDED:
            return False

        return False

    # -- packet handlers -------------------------------------------------

    def on_player_join(self, body, now):
        info = ff_udp.parse_player_join(body)
        if info is None:
            return
        uid, full_id, name = info
        self.state.add_player(full_id, name)
        self.say("join: short=%-3d id=0x%08X %s" % (full_id & 0xFF, full_id, name))
        if uid == self.account_id:
            self.state.set_identity(full_id)
            self.say(">>> that is us: 0x%08X (short %d)" % (full_id, full_id & 0xFF))

    def on_match_end(self, body, now):
        if self.match_over:
            return
        self.match_over = True
        rank = body[1] if len(body) > 1 else 0
        if not config.AutoXp:
            self.say("match end (rank ~%d) - AutoXp off, not claiming" % rank)
            return
        self.say("match end (rank ~%d) - claiming result in %.1fs"
                 % (rank, MATCH_RESULT_DELAY))
        threading.Timer(MATCH_RESULT_DELAY, self._claim_result).start()

    def _claim_result(self):
        try:
            self.say("requesting match result")
            self.send(CMD_SHOW_MATCH_RESULT, b"",
                      send_option=ff_udp.SENDOPTION_RELIABLE)
        except Exception as exc:
            self.log_error("claim result: %r" % exc)
        if match_api is not None and self.api_token:
            try:
                match_api.claim_match_rewards(self.api_token,
                                              verbose=self.verbose)
            except Exception as exc:
                self.log_error("lobby calls: %r" % exc)

        def finish():
            self.say("match complete - leaving")
            self._stop.set()
        threading.Timer(POST_RESULT_LINGER, finish).start()

    def on_down(self, body, now):
        if not body:
            return
        pid, _ = ff_udp._rd_varint(body, 0)
        snap = self.state.snapshot()
        if snap.my_id is not None and pid == snap.my_id:
            if self.state.set_alive(False):
                self.say("we are down - holding position updates")
            return
        short = pid & 0xFF
        if short in self.state.teammates():
            self.state.mark_down(short)
            self.say("teammate 0x%08X is down" % pid)

    def on_revive(self, body, now):
        if not body:
            return
        pid, _ = ff_udp._rd_varint(body, 0)
        snap = self.state.snapshot()
        if snap.my_id is None or pid != snap.my_id:
            return
        if self.state.set_alive(True):
            self.say("revived - resuming")

    def on_rescue_started(self, body, now):
        if not body:
            return
        success = body[0] != 0
        try:
            player_id, pos = ff_udp._rd_varint(body, 1)
            target_id, pos = ff_udp._rd_varint(body, pos)
            start_time, pos = ff_udp._rd_varint(body, pos)
            stop_time, pos = ff_udp._rd_varint(body, pos)
        except Exception:
            return
        if success:
            self.say("reviving 0x%08X - server holds it for %d ticks"
                     % (target_id, stop_time - start_time))
            return
        reason = body[pos] if pos < len(body) else 0
        if self.state.end_rescue(target_id) is not None:
            self.say("revive of 0x%08X refused (reason %d)"
                     % (target_id, reason))

    def on_rescue_stopped(self, body, now):
        if not body:
            return
        try:
            player_id, pos = ff_udp._rd_varint(body, 0)
            target_id, pos = ff_udp._rd_varint(body, pos)
        except Exception:
            return
        self.state.end_rescue(target_id)

    def on_revive_done(self, body, now):
        if not body:
            return
        try:
            target_id, pos = ff_udp._rd_varint(body, 0)
        except Exception:
            return
        if self.state.end_rescue(target_id) is not None:
            self.say("revived 0x%08X" % target_id)

    def on_gri(self, body, now):
        parsed = ff_udp.get_match_phase(body)
        if parsed is None:
            return
        phase, round_no, start, end = parsed
        changed, current_round = self.state.set_phase(phase, round_no)
        if changed:
            self.say("round %s: %s (%d -> %d)"
                     % (current_round if current_round is not None else 1,
                        PHASE_NAMES.get(phase, "phase%d" % phase), start, end))

    def on_server_time(self, body, now):
        parsed = ff_udp.decode_server_time(body)
        if parsed is None:
            return
        tick = parsed[0] if isinstance(parsed, tuple) else parsed
        self.state.sync_clock(tick, now)
        self.send(CMD_SERVER_TIME, ff_udp.build_server_time_ack(tick))

    def on_my_state(self, body, now):
        if len(body) < 4:
            return
        _mt, p = ff_udp._rd_varint(body, 0)
        _count, p = ff_udp._rd_varint(body, p)
        p += 1
        x, p = ff_udp._rd_varint(body, p)
        y, p = ff_udp._rd_varint(body, p)
        z, p = ff_udp._rd_varint(body, p)
        snap = self.state.snapshot()
        if snap.plane_phase in (PLANE_PHASE_NONE, PLANE_PHASE_LANDED):
            self.state.seed_my_pos((ff_udp._zag(x), ff_udp._zag(y), ff_udp._zag(z)))

    def on_other_states(self, body, now):
        players = ff_udp.decode_players_v2(body)
        snap = self.state.snapshot()
        mates = self.state.teammates()
        for short, info in players.items():
            if short not in mates:
                continue
            if info.get("physx_pose") == POSE_KNOCKDOWN:
                self.state.mark_down(short, info["pos"])
            elif short in snap.downed:
                self.state.clear_down(short)
        if snap.target_short is None:
            return
        info = players.get(snap.target_short)
        if info is not None:
            self.state.update_target(info, now)

    def on_quick_chat(self, body, now):
        if not config.Chat_CommandUdp:
            return
        parsed = ff_udp.decode_quick_chat(body)
        if parsed is None:
            return
        chat_id, short_id, raw, team = parsed
        if chat_id not in FOLLOW_TRIGGERS:
            return
        if self.state.set_target(short_id):
            self.say("'%s' from 0x%08X -> following %d (%s)"
                     % (CHAT_NAMES.get(chat_id, chat_id), raw, short_id,
                        self.state.name_of(short_id)))

    def on_safe_zone(self, body, now):
        zone = ff_udp.decode_safezone(body)
        if zone is None:
            return
        center = zone.get("inner_center") or zone.get("outer_center")
        radius = zone.get("inner_radius") or zone.get("outer_radius") or 0
        if not center or radius <= 0:
            return
        self.state.set_zone(center, radius * ZONE_RADIUS_SCALE)
        snap = self.state.snapshot()
        if snap.my_pos is not None:
            dx = snap.my_pos[0] - center[0]
            dz = snap.my_pos[2] - center[-1]
            dist = math.sqrt(dx * dx + dz * dz)
            self.say("zone: centre=%s radius=%d (we are %.0f away, %s)"
                     % (center, radius, dist,
                        "inside" if dist <= radius * ZONE_RADIUS_SCALE else "OUTSIDE"))
        else:
            self.say("zone: centre=%s radius=%d" % (center, radius))

    # -- socket ----------------------------------------------------------

    def send(self, cmd, body, send_option=None, flags=None):
        if self.sock is None:
            return False
        if send_option is None:
            send_option = ff_udp.SENDOPTION_NONE
        if flags is None:
            flags = ff_udp.FLAG_ENCRYPTED
        try:
            pkt = ff_udp.encode_packet(cmd, send_option, 0, flags,
                                       body, self.key, self.order)
            self.sock.sendto(pkt, self.addr)
            return True
        except Exception as exc:
            self.log_error("send cmd %d: %r" % (cmd, exc))
            return False

    # -- threads ---------------------------------------------------------

    def _receiver(self):
        while not self._stop.is_set():
            try:
                try:
                    data, _ = self.sock.recvfrom(4096)
                except socket.timeout:
                    continue
                now = time.time()
                self.packets_in += 1
                dec = ff_udp.decode_packet(data, self.key, self.order)
                if dec is None:
                    continue
                self.decoded_in += 1
                if dec["reliable"]:
                    req = (dec["OrderID"] + 1) & 0xFFFF
                    self.send(ff_udp.CMD_ACK, ff_udp.build_ack_body(req))
                self.router.dispatch(dec["Cmd"], dec["body"], now)
            except Exception as exc:
                self.log_error("receiver: %r" % exc)
                time.sleep(0.01)

    def _sender(self):
        next_tick = time.time()
        next_ping = time.time()
        while not self._stop.is_set():
            try:
                now = time.time()
                if now >= next_ping:
                    ff_udp.send_ping(self.sock, self.addr, self.key, self.order)
                    next_ping = now + ff_udp.PING_INTERVAL
                if now < next_tick:
                    time.sleep(min(0.02, next_tick - now))
                    continue
                next_tick += MOVE_INTERVAL
                if next_tick < now:
                    next_tick = now + MOVE_INTERVAL

                snap = self.state.snapshot()
                if not snap.alive:
                    continue

                # ═══════════════════════════════════════════════════════
                # PLANE PHASE — position sync only
                # ═══════════════════════════════════════════════════════
                if self._plane_phase_handler(snap, now):
                    if snap.my_pos and snap.my_id:
                        pos = (int(snap.my_pos[0]),
                               int(snap.my_pos[1]),
                               int(snap.my_pos[2]))
                        tick = self.planner.server_time(snap, now)

                        # JUMP + PARACHUTE → airborne state (4,0).
                        # Matches C2S_MOVE_JUMP_START / C2S_MOVE_PARACHUTE_OPEN:
                        #   body: ... 04 00 ... (state=4, pose=0)
                        # WAITING / PLANE → walk state (0,0), no airborne marker.
                        if snap.plane_phase in (PLANE_PHASE_JUMP,
                                                PLANE_PHASE_PARACHUTE):
                            vx, vz = 0.0, 0.0
                            yaw_now = self.planner.next_yaw()
                            if snap.plane_phase == PLANE_PHASE_PARACHUTE:
                                rad = math.radians(yaw_now)
                                vx = math.sin(rad) * 3000.0
                                vz = math.cos(rad) * 3000.0
                            ff_udp.send_airborne_position(
                                self.sock, self.addr, self.key, self.order,
                                snap.my_id, pos, tick,
                                horizontal_vel=(vx, vz),
                                yaw=yaw_now)
                        else:
                            ff_udp.send_position(
                                self.sock, self.addr, self.key, self.order,
                                snap.my_id, pos, pos,
                                tick, aim_yaw=0)
                    continue

                # ═══════════════════════════════════════════════════════
                # NORMAL MOVEMENT (on ground + fight phase)
                # ═══════════════════════════════════════════════════════
                self._tend_downed(snap, now)
                planned = self.planner.plan(snap, now)
                if planned is None:
                    continue
                new_pos, dist, moving = planned
                old_pos = snap.my_pos
                self.state.set_my_pos(new_pos)
                yaw = self.planner.next_yaw()
                ff_udp.send_position(
                    self.sock, self.addr, self.key, self.order,
                    snap.my_id, old_pos, new_pos,
                    self.planner.server_time(snap, now),
                    aim_yaw=yaw,
                    target_yrot=snap.target_yrot,
                    target_aim_y=snap.target_aim_y,
                    target_aim_xz=snap.target_aim_xz,
                    copy_state=snap.target_state,
                    copy_pose=snap.target_pose)
            except Exception as exc:
                self.log_error("sender: %r" % exc)
                time.sleep(MOVE_INTERVAL)

    def jump_on_ground(self):
        """Send a single airborne tick while on the ground — a visible jump.

        From C2S_MOVE_JUMP_START captures: state=4, pose=0, jump byte 0.
        Server interprets state=4 as the player leaving the ground for that
        tick. Call this from a firing loop or planner when we want the bot
        to actually hop instead of walk.
        """
        snap = self.state.snapshot()
        if snap.my_id is None or snap.my_pos is None or not snap.alive:
            return False
        pos = (int(snap.my_pos[0]), int(snap.my_pos[1]), int(snap.my_pos[2]))
        try:
            ff_udp.send_airborne_position(
                self.sock, self.addr, self.key, self.order,
                snap.my_id, pos,
                self.planner.server_time(snap, time.time()),
                horizontal_vel=(0.0, 0.0), yaw=0)
            return True
        except Exception as exc:
            self.log_error("jump_on_ground: %r" % (exc,))
            return False

    # -- lifecycle -------------------------------------------------------

    def _tend_downed(self, snap, now):
        if snap.rescuing is not None:
            if now - snap.rescue_started > REVIVE_TIMEOUT:
                abandoned = self.state.end_rescue()
                if abandoned is not None:
                    self.say("revive of 0x%08X timed out" % abandoned)
            elif now - self._last_rescue_send >= REVIVE_RETRY:
                self._last_rescue_send = now
                self.send(CMD_START_RESCUE,
                          ff_udp.build_start_rescue_body(
                              snap.rescuing,
                              self.planner.server_time(snap, now)),
                          send_option=ff_udp.SENDOPTION_RELIABLE)
            return
        if not snap.downed or snap.my_pos is None:
            return
        short = self._nearest_downed(snap)
        if short is None:
            return
        full_id = self.state.full_id_of(short)
        if full_id is None or full_id == snap.my_id:
            return
        if not self.state.begin_rescue(full_id, now):
            return
        self._last_rescue_send = now
        self.send(CMD_START_RESCUE,
                  ff_udp.build_start_rescue_body(
                      full_id, self.planner.server_time(snap, now)),
                  send_option=ff_udp.SENDOPTION_RELIABLE)
        self.say("reviving 0x%08X (short %d)" % (full_id, short))

    def _nearest_downed(self, snap):
        best = None
        best_dist = REVIVE_RANGE
        for short, pos in snap.downed.items():
            if pos is None:
                if best is None:
                    best = short
                continue
            dx = pos[0] - snap.my_pos[0]
            dz = pos[2] - snap.my_pos[2]
            dist = math.sqrt(dx * dx + dz * dz)
            if dist <= best_dist:
                best = short
                best_dist = dist
        return best

    def run(self, game_mode=15, map_id=1, match_mode=1, sleep_ms=0,
            timeout=3.0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(0.2)
        self.say("=== match session -> %s:%d ===" % self.addr)

        auth_token = self.api_token or self.jwt
        if getattr(config, "Use_Auth_Packet", False) and auth_token:
            pkt = ff_udp.send_auth_packet(
                self.sock, self.addr, auth_token, self.account_id)
            if pkt is not None:
                self.say("auth: sent raw AES datagram (%d bytes) cmd=0x%02x "
                         "region=0x%02x account=%d"
                         % (len(pkt),
                            getattr(config, "Auth_Cmd", 0x65),
                            getattr(config, "Auth_Region", 0x15),
                            self.account_id))
            else:
                self.say("auth: packet not sent (missing token or send failed)")

        if not self._handshake(timeout):
            self.say("handshake failed")
            return False

        for fn in (self._receiver, self._sender):
            th = threading.Thread(target=fn, daemon=True)
            th.start()
            self._threads.append(th)

        self._join(game_mode, map_id, match_mode, sleep_ms)
        self.say("running - press Ctrl+C to stop")
        threading.Timer(JOIN_TIMEOUT, self._check_joined).start()
        try:
            while not self._stop.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.say("stopping")
        finally:
            self.stop()
        return True

    def _check_joined(self):
        if self._stop.is_set():
            return
        snap = self.state.snapshot()
        if snap.my_id is not None:
            return
        self.say("no join after %.0fs - the match server did not accept us"
                 % JOIN_TIMEOUT)
        self.say("    packets in: %d, decoded: %d"
                 % (self.packets_in, self.decoded_in))
        if self.packets_in == 0:
            self.say("    nothing arrived at all - wrong address, or the "
                     "match was already gone")
        elif self.decoded_in == 0:
            self.say("    packets arrived but none decrypted - wrong secret "
                     "or mask")
        else:
            self.say("    traffic decodes but no Cmd 101 - the join token was "
                     "refused (expired, or the slot is taken)")
        self._stop.set()

    def _handshake(self, timeout):
        hello = ff_udp.build_hello_body(self.account_id, self.suffix)
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.send(ff_udp.CMD_HELLO, hello,
                      send_option=ff_udp.SENDOPTION_HELLO)
            try:
                data, _ = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            dec = ff_udp.decode_packet(data, self.key, self.order)
            if dec is not None and dec["Cmd"] == ff_udp.CMD_HELLO:
                req = (dec["OrderID"] + 1) & 0xFFFF
                self.send(ff_udp.CMD_ACK, ff_udp.build_ack_body(req))
                return True
        return False

    def _join(self, game_mode, map_id, match_mode, sleep_ms):
        part1, part2 = ff_udp.split_token(self.jwt)
        time.sleep(sleep_ms / 1000.0)
        pkt = ff_udp.encode_packet(447, ff_udp.SENDOPTION_RELIABLE, 0,
                                   ff_udp.FLAG_ENCRYPTED,
                                   ff_udp.build_join_prepare_body(part1),
                                   self.key, self.order)
        try:
            self.sock.sendto(pkt, self.addr)
        except Exception as exc:
            self.log_error("send 447: %r" % exc)
        time.sleep(sleep_ms / 1000.0)
        body = ff_udp.build_join_post_body(self.account_id, part2,
                                           game_mode=game_mode, map_id=map_id,
                                           match_mode=match_mode,
                                           match_id=self.match_id)
        pkt = ff_udp.encode_packet(448, ff_udp.SENDOPTION_RELIABLE, 1,
                                   ff_udp.FLAG_ENCRYPTED, body,
                                   self.key, self.order)
        try:
            self.sock.sendto(pkt, self.addr)
            self.say("    -> 448 join: match_id=%d mode=%d map=%d (%d bytes)"
                     % (self.match_id, game_mode, map_id, len(body)))
        except Exception as exc:
            self.log_error("send 448: %r" % exc)

    def stop(self):
        if self._stopped:
            return
        self._stopped = True
        self._stop.set()
        for th in self._threads:
            if th is not threading.current_thread():
                th.join(timeout=1.0)
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception:
                pass
        self.say("stopped (%d warnings)" % self.errors)


def run_match(ip, port, account_id, secret, udp_jwt, udp_mask, suffix="0",
              game_mode=15, map_id=1, match_mode=1, sleep_ms=0, timeout=3.0,
              api_token=None, match_id=0, verbose=True):
    session = MatchSession(ip, port, account_id, secret, udp_jwt, udp_mask,
                           suffix=suffix, api_token=api_token,
                           match_id=match_id, verbose=verbose)
    return session.run(game_mode=game_mode, map_id=map_id,
                       match_mode=match_mode, sleep_ms=sleep_ms,
                       timeout=timeout)