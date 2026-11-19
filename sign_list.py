"""RS-AC-keys: sign keys.txt into list.txt (run by the GitHub Action on every push and once a day).
Needs the secret LIST_KEY (hex seed of the LIST key - it can only sign lists, never make keys) and cert.txt
(wsad's master signature over the list key, written by keygen.py init). Python 3 stdlib + keylib.py next to it.
"""
import datetime
import os
import re
import sys

import keylib as K

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    seed_hex = os.environ.get("LIST_KEY", "").strip()
    if len(seed_hex) != 64:
        sys.exit("LIST_KEY secret missing or wrong (64 hex chars) - GitHub > Settings > Secrets > Actions")
    seed = bytes.fromhex(seed_hex)
    cert_txt = open(os.path.join(HERE, "cert.txt"), encoding="utf-8").read()
    lk = re.search(r"^listkey=([0-9a-f]{64})", cert_txt, re.M).group(1)
    cert = bytes.fromhex(re.search(r"^cert=([0-9a-f]{128})", cert_txt, re.M).group(1))
    if K.public_key(seed).hex() != lk:
        sys.exit("LIST_KEY does not match cert.txt - paste the LIST_KEY keygen.py printed with this cert.txt")
    data = K.parse_keys_txt(open(os.path.join(HERE, "keys.txt"), encoding="utf-8").read())
    old = ""
    if os.path.exists(os.path.join(HERE, "list.txt")):
        old = open(os.path.join(HERE, "list.txt"), encoding="utf-8").read()
    m = re.search(r"^num=(\d+)", old, re.M)
    num = (int(m.group(1)) if m else 0) + 1
    date = os.environ.get("RSAC_TODAY") or datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    text = K.build_list(seed, cert, num, date, data)
    with open(os.path.join(HERE, "list.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(f"list #{num} signed {date}: {len(data['keys'])} key entries")


if __name__ == "__main__":
    main()
