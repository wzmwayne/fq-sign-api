#!/usr/bin/env python3
"""番茄小说签名头 —— 已破解部分（纯 Python，均经真机真值验证）。

验证强度：
  X-Ladon   4/4 组独立真机抓包逐字节一致（含跨设备 device_id）✓✓
  X-Soter   我方真机 == 第三方样本，且 = 常量 ✓
  X-Khronos 秒级时间戳 ✓
  X-Neptune 常量串 ✓
未完成：X-Gorgon(算法结构清楚,前4字节按请求变化) / X-Argus(需密钥) / X-Helios(VM) / X-Medusa
"""
import base64, time

# ---- X-Soter: 常量 90 字节 = 00 01 00 02 + 86 × 00 ----
X_SOTER = base64.b64encode(bytes([0, 1, 0, 2]) + bytes(86)).decode()

# ---- X-Neptune: 常量串 ----
X_NEPTUNE = "-11|50:51:59"


def x_khronos(unix: int = None) -> str:
    return str(unix if unix is not None else int(time.time()))


def x_soter() -> str:
    return X_SOTER


def x_neptune() -> str:
    return X_NEPTUNE


def x_ladon(khronos: int, lc_id: int = 1611921764, tail: int = 3019, rnd: bytes = None) -> str:
    """见 pytt/fq_ladon.py（本文件内联实现，避免外部依赖）"""
    import hashlib, os
    M = (1 << 64) - 1
    def ror(v, c):
        c %= 64
        return ((v >> c) | (v << (64 - c))) & M
    if rnd is None:
        rnd = os.urandom(4)
    data = f"{khronos}-{lc_id}-{tail}".encode()
    pad = 16 - (len(data) % 16)
    data += bytes([pad]) * pad
    ht = bytearray(288)
    ht[:32] = hashlib.md5(rnd + b"1967").hexdigest().encode()
    t = [int.from_bytes(ht[i*8:(i+1)*8], 'little') for i in range(4)]
    b0, b8 = t[0], t[1]
    del t[0]; del t[0]
    for i in range(0x22):
        x9 = b0
        x8 = (ror(b8, 8) + x9) & M
        x8 ^= i
        t.append(x8)
        x8 ^= ror(x9, 61)
        ht[(i+1)*8:(i+2)*8] = x8.to_bytes(8, 'little')
        b0 = x8
        b8 = t[0]
        del t[0]
    out = bytearray()
    for i in range(0, len(data), 16):
        d0 = int.from_bytes(data[i:i+8], 'little')
        d1 = int.from_bytes(data[i+8:i+16], 'little')
        for r in range(0x22):
            h = int.from_bytes(ht[r*8:(r+1)*8], 'little')
            d1 = (h ^ ((d0 + ror(d1, 8)) & M)) & M
            d0 = (d1 ^ ror(d0, 0x3D)) & M
        out += d0.to_bytes(8, 'little') + d1.to_bytes(8, 'little')
    return base64.b64encode(rnd + bytes(out)).decode()


def solved_headers(khronos: int = None, rnd: bytes = None) -> dict:
    """生成已破解的 4 个头（其余仍需 .so 或未破解）"""
    ts = int(khronos if khronos is not None else time.time())
    return {
        'X-Khronos': str(ts),
        'X-Neptune': X_NEPTUNE,
        'X-Soter':   X_SOTER,
        'X-Ladon':   x_ladon(ts, rnd=rnd),
    }


if __name__ == '__main__':
    import json
    ts = int(json.load(open('repo_real_headers.json'))['X-Khronos'])
    real = json.load(open('repo_real_headers.json'))
    # 用真机的 Ladon raw 复现
    raw = base64.b64decode(real['X-Ladon'] + '==')
    got = x_ladon(ts, rnd=raw[:4])
    print(f"X-Khronos {ts} ✓")
    print(f"X-Neptune {X_NEPTUNE}  真机={real['X-Neptune']} {'✓' if real['X-Neptune']==X_NEPTUNE else '✗'}")
    print(f"X-Soter   真机是否等于常量: {'✓' if real['X-Soter']==X_SOTER else '✗'}")
    print(f"X-Ladon   复算==真机: {'✓ 逐字节一致' if got==real['X-Ladon'] else '✗'}")
