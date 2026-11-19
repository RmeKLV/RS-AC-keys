"""RS-AC part 6: shared key / list code for keygen.py and the RS-AC-keys GitHub Action (sign_list.py).
Python 3 stdlib only. Ed25519 = RFC 8032 section 6 reference maths. The C side (src/license.inc.c) reads what this
writes; tests/license/ checks both against each other.
"""
import datetime
import hashlib

# ---------------- Ed25519 (RFC 8032) ----------------
_p = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_d = -121665 * pow(121666, _p - 2, _p) % _p
_I = pow(2, (_p - 1) // 4, _p)


def _inv(x):
    return pow(x, _p - 2, _p)


def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C = 2 * P[3] * Q[3] * _d % _p
    D = 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _recover_x(y, sign):
    x2 = (y * y - 1) * _inv(_d * y * y + 1) % _p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p:
        x = x * _I % _p
    if (x * x - x2) % _p:
        return None
    if (x & 1) != sign:
        x = _p - x
    return x


_gy = 4 * _inv(5) % _p
_gx = _recover_x(_gy, 0)
_G = (_gx, _gy, 1, _gx * _gy % _p)


def _enc(P):
    zi = _inv(P[2])
    x, y = P[0] * zi % _p, P[1] * zi % _p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _dec(b):
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _p:
        return None
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _p)


def _h(*parts):
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")


def _expand(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed):
    a, _ = _expand(seed)
    return _enc(_mul(a, _G))


def sign(seed, msg):
    a, prefix = _expand(seed)
    A = _enc(_mul(a, _G))
    r = _h(prefix, msg) % _L
    R = _enc(_mul(r, _G))
    k = _h(R, A, msg) % _L
    return R + int.to_bytes((r + k * a) % _L, 32, "little")


def verify(pk, msg, sig):
    if len(sig) != 64 or len(pk) != 32:
        return False
    A, R = _dec(pk), _dec(sig[:32])
    s = int.from_bytes(sig[32:], "little")
    if A is None or R is None or s >= _L:
        return False
    k = _h(sig[:32], pk, msg) % _L
    return _enc(_mul(s, _G)) == _enc(_add(R, _mul(k, A)))


# ---------------- base32 with check characters ----------------
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_FIX = {"0": "O", "1": "I", "8": "B"}       # look-alikes a person may type


def _b32(data, nchars):
    v = int.from_bytes(data, "big") << (nchars * 5 - len(data) * 8)
    return "".join(B32[(v >> (5 * (nchars - 1 - i))) & 31] for i in range(nchars))


def _unb32(text, nbytes):
    v = 0
    for c in text:
        v = (v << 5) | B32.index(c)
    v >>= len(text) * 5 - nbytes * 8
    return int.to_bytes(v, nbytes, "big")


def check_char(group):
    """weighted sum (catches a wrong character and two swapped neighbours)"""
    return B32[sum((i + 1) * B32.index(c) for i, c in enumerate(group)) % 32]


def normalize(text):
    t = "".join(ch for ch in text.strip().upper() if not ch.isspace())
    return "".join(_FIX.get(ch, ch) for ch in t)


def _grouped(chars, size):
    groups = [chars[i:i + size] for i in range(0, len(chars), size)]
    return "-".join(g + check_char(g) for g in groups)


def _ungrouped(text, size, count):
    """-> (chars, None) or (None, 'typo in group N') / (None, 'wrong length')"""
    groups = text.split("-")
    if len(groups) != count:
        return None, "wrong length"
    out = ""
    for n, g in enumerate(groups, 1):
        want = size if n < count else len(g)
        if len(g) != want or len(g) < 2 or any(c not in B32 for c in g):
            return None, f"typo in group {n}"
        if check_char(g[:-1]) != g[-1]:
            return None, f"typo in group {n}"
        out += g[:-1]
    return out, None


# ---------------- server code: public IPv4 + port ----------------
def server_code(ip, port):
    """'85.12.3.4', 28960 -> 'XXXX-XXXX-XXXX' (10 data chars, check char per group of 4 incl.)"""
    raw = bytes(int(x) for x in ip.split(".")) + int(port).to_bytes(2, "big")
    chars = _b32(raw, 10)
    return _grouped(chars[:3], 3) + "-" + _grouped(chars[3:6], 3) + "-" + _grouped(chars[6:10], 4)


def parse_server_code(text):
    """-> ((ip, port), None) or (None, reason)"""
    t = normalize(text)
    groups = t.split("-")
    if len(groups) != 3 or [len(g) for g in groups] != [4, 4, 5]:
        return None, "wrong length"
    chars = ""
    for n, g in enumerate(groups, 1):
        if any(c not in B32 for c in g) or check_char(g[:-1]) != g[-1]:
            return None, f"typo in group {n}"
        chars += g[:-1]
    raw = _unb32(chars, 6)
    return (".".join(str(b) for b in raw[:4]), int.from_bytes(raw[4:], "big")), None


def server_raw(code):
    sc, why = parse_server_code(code)
    if why:
        raise ValueError(why)
    ip, port = sc
    return bytes(int(x) for x in ip.split(".")) + port.to_bytes(2, "big")


# ---------------- keys ----------------
TYPE_PERM, TYPE_MONTHLY = 1, 2
KEY_DOMAIN = b"RSAC-KEY1"
KEY_GROUPS = 16                      # 80 bytes -> 128 chars -> 16 groups of 8 (+1 check char each)


def day_number(d):
    """date or 'YYYY-MM-DD' -> days since 1970-01-01"""
    if isinstance(d, str):
        d = datetime.date.fromisoformat(d)
    return (d - datetime.date(1970, 1, 1)).days


def day_text(n):
    return (datetime.date(1970, 1, 1) + datetime.timedelta(days=n)).isoformat()


def key_payload(key_id, ktype, made_day, srv_raw):
    return bytes([1, ktype]) + int(key_id).to_bytes(4, "big") + int(made_day).to_bytes(4, "big") + srv_raw


def make_key(master_seed, key_id, ktype, made_day, code):
    payload = key_payload(key_id, ktype, made_day, server_raw(code))
    sig = sign(master_seed, KEY_DOMAIN + payload)
    return "RSAC1-" + _grouped(_b32(payload + sig, 128), 8)


def parse_key(text, master_pk):
    """-> (dict, None) or (None, reason) - same reasons as the plugin"""
    t = "".join(ch for ch in text.strip().upper() if not ch.isspace())
    if not t:
        return None, "no key"
    if t[:6] not in ("RSAC1-", "RSACI-"):
        return None, "typo in key (it must start with RSAC1-)"
    chars, why = _ungrouped(normalize(t[6:]), 9, KEY_GROUPS)
    if why:
        return None, "typo in key (" + why.replace("typo in ", "") + ")"
    raw = _unb32(chars, 80)
    payload, sig = raw[:16], raw[16:]
    if payload[0] != 1 or payload[1] not in (TYPE_PERM, TYPE_MONTHLY):
        return None, "bad key"
    if not verify(master_pk, KEY_DOMAIN + payload, sig):
        return None, "bad signature (not a key made by wsad)"
    srv = payload[10:16]
    return {"type": payload[1], "id": int.from_bytes(payload[2:6], "big"),
            "made": int.from_bytes(payload[6:10], "big"),
            "ip": ".".join(str(b) for b in srv[:4]), "port": int.from_bytes(srv[4:], "big"),
            "code": server_code(".".join(str(b) for b in srv[:4]), int.from_bytes(srv[4:], "big"))}, None


# ---------------- paper backup code for the master seed ----------------
def paper_code(seed):
    """32 bytes -> 52 chars + check per group of 4 -> 13 groups 'ABCDE-...'"""
    return _grouped(_b32(seed, 52), 4)


def parse_paper_code(text):
    chars, why = _ungrouped(normalize(text), 5, 13)
    if why:
        raise ValueError(why)
    return _unb32(chars, 32)


# ---------------- key list ----------------
LISTKEY_DOMAIN = b"RSAC-LISTKEY1"


def cert_listkey(master_seed, list_pk):
    return sign(master_seed, LISTKEY_DOMAIN + list_pk)


def parse_keys_txt(text):
    """keys.txt (what keygen.py edits): ver=, mirror=, key=<id> <states...>; '#' comments"""
    data = {"ver": "", "mirrors": [], "keys": {}}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k == "ver":
            data["ver"] = v.strip()
        elif k == "mirror":
            data["mirrors"].append(v.strip())
        elif k == "key":
            parts = v.split()
            if parts and parts[0].isdigit():
                data["keys"][int(parts[0])] = parts[1:]
    return data


def format_keys_txt(data):
    out = ["# RS-AC key list source - edited by keygen.py, signed every day by the Action into list.txt",
           f"ver={data['ver']}"]
    out += [f"mirror={m}" for m in data["mirrors"]]
    for kid in sorted(data["keys"]):
        if data["keys"][kid]:
            out.append(f"key={kid:04d} " + " ".join(data["keys"][kid]))
    return "\n".join(out) + "\n"


def build_list(list_seed, cert, num, date_text, data):
    """signed list.txt text"""
    lines = ["RSAC-LIST 1", f"num={num}", f"date={date_text}", f"ver={data['ver']}",
             f"listkey={public_key(list_seed).hex()}", f"cert={cert.hex()}"]
    lines += [f"mirror={m}" for m in data["mirrors"]]
    for kid in sorted(data["keys"]):
        if data["keys"][kid]:
            lines.append(f"key={kid} " + " ".join(data["keys"][kid]))
    body = "\n".join(lines) + "\n"
    return body + "sig=" + sign(list_seed, body.encode()).hex() + "\n"


def parse_list(text, master_pk):
    """-> (dict, None) or (None, reason)"""
    if len(text) > 65536:
        return None, "list too big"
    if not text.startswith("RSAC-LIST 1\n"):
        return None, "not a key list"
    i = text.rfind("sig=")
    if i <= 0 or text[i - 1] != "\n":
        return None, "list has no signature"
    body, sig_hex = text[:i], text[i + 4:].strip()
    out = {"num": 0, "date": "", "ver": "", "mirrors": [], "keys": {}}
    lk = cert = None
    for line in body.splitlines()[1:]:
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k == "num":
            out["num"] = int(v)
        elif k == "date":
            out["date"] = v
        elif k == "ver":
            out["ver"] = v
        elif k == "listkey":
            lk = bytes.fromhex(v)
        elif k == "cert":
            cert = bytes.fromhex(v)
        elif k == "mirror":
            out["mirrors"].append(v)
        elif k == "key":
            parts = v.split()
            out["keys"][int(parts[0])] = parts[1:]
    if not lk or not cert or not verify(master_pk, LISTKEY_DOMAIN + lk, cert):
        return None, "list key not certified by wsad"
    try:
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        return None, "bad list signature"
    if not verify(lk, body.encode(), sig):
        return None, "bad list signature"
    return out, None


# ---------------- the check code on an `rsac key` line ----------------
CHECK_SALT = b"rsac-line-v1:7Q2w9Kd3"    # also in src/license.inc.c (lic_check_code)


def line_check_code(line_without_code):
    return _b32(hashlib.sha256(CHECK_SALT + line_without_code.encode()).digest()[:5], 8)[:4]
