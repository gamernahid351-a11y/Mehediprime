import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import config
import toolsudp


def main() -> None:
    if len(sys.argv) < 13:
        return
    host = sys.argv[1]
    port = sys.argv[2]
    account_id = int(sys.argv[3])
    secret = sys.argv[4]
    udp_jwt = sys.argv[5]
    udp_mask = sys.argv[6]
    game_mode = int(sys.argv[7])
    map_id = int(sys.argv[8])
    match_mode = int(sys.argv[9])
    sleep_ms = int(sys.argv[10])
    match_id = int(sys.argv[11])
    api_token = sys.argv[12]
    verbose = len(sys.argv) > 13 and sys.argv[13] == "1"
    try:
        toolsudp.run_match(host, port, account_id, secret, udp_jwt, udp_mask,
                           suffix="0", game_mode=game_mode, map_id=map_id,
                           match_mode=match_mode, sleep_ms=sleep_ms,
                           api_token=api_token, match_id=match_id,
                           verbose=verbose)
    except Exception as exc:
        # Go blocks on this process, so a failure here is a match that never
        # happened. Swallowing it silently was how three earlier faults stayed
        # hidden; the caller decides whether anyone is listening.
        if getattr(config, "Show_Login", False) or verbose:
            sys.stderr.write("run_match failed: %r\n" % (exc,))
            sys.stderr.flush()


if __name__ == "__main__":
    main()
