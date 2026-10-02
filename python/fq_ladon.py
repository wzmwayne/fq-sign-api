#!/usr/bin/env python3
"""X-Ladon 纯 Python 实现 —— 已与真机 .so 输出【逐字节验证一致】。

算法（逆向自 libmetasec_ml.so，参考 linzj/fanqie-dl 并经真值校正）：
    rnd = 4 随机字节
    keygen = rnd + b"1967"                       # 注意: 密钥表用 aid=1967
    table[0:32] = md5(keygen) 的 ASCII(32B)
    34 轮 Speck 式扩展填充 table
    明文 = f"{khronos}-{lc_id}-3019"             # lc_id=1611921764, 末字段=3019
    PKCS7 填充 → 每 16B 块做 0x22 轮:
        d1 = table[i] ^ (d0 + ror(d1,8))
        d0 = d1 ^ ror(d0,0x3D)
    输出 = base64(rnd + 密文)
"""
import hashlib, base64, os, time

M = (1 << 64) - 1
AID_KEY = 1967           # 密钥表用的 aid
LC_ID   = 1611921764     # license id
TAIL    = 3019           # 明文末字段


def _ror(v, c):
    c %= 64
    return ((v >> c) | (v << (64 - c))) & M


def _build_table(rnd: bytes, aid: int = AID_KEY) -> bytearray:
    md5hex = hashlib.md5(rnd + str(aid).encode()).hexdigest().encode()
    ht = bytearray(272 + 16)
    ht[:32] = md5hex
    t = [int.from_bytes(ht[i*8:(i+1)*8], 'little') for i in range(4)]
    b0, b8 = t[0], t[1]
    del t[0]; del t[0]
    for i in range(0x22):
        x9 = b0
        x8 = (_ror(b8, 8) + x9) & M
        x8 ^= i
        t.append(x8)
        x8 ^= _ror(x9, 61)
        ht[(i+1)*8:(i+2)*8] = x8.to_bytes(8, 'little')
        b0 = x8
        b8 = t[0]
        del t[0]
    return ht


def x_ladon(khronos: int, lc_id: int = LC_ID, tail: int = TAIL, rnd: bytes = None) -> str:
    """生成 X-Ladon 头值（与 .so 输出逐字节一致，rnd 可指定以便复现）"""
    if rnd is None:
        rnd = os.urandom(4)
    data = f"{khronos}-{lc_id}-{tail}".encode()
    pad = 16 - (len(data) % 16)
    data += bytes([pad]) * pad
    ht = _build_table(rnd)
    out = bytearray()
    for i in range(0, len(data), 16):
        d0 = int.from_bytes(data[i:i+8], 'little')
        d1 = int.from_bytes(data[i+8:i+16], 'little')
        for r in range(0x22):
            h = int.from_bytes(ht[r*8:(r+1)*8], 'little')
            d1 = (h ^ ((d0 + _ror(d1, 8)) & M)) & M
            d0 = (d1 ^ _ror(d0, 0x3D)) & M
        out += d0.to_bytes(8, 'little') + d1.to_bytes(8, 'little')
    return base64.b64encode(rnd + bytes(out)).decode()


if __name__ == '__main__':
    import json, sys
    if len(sys.argv) > 1 and sys.argv[1] == 'verify':
        # 用真机抓到的值反解并正向复算
        hdrs = json.load(open('repo_real_headers.json'))
        real = hdrs['X-Ladon']
        kh = int(hdrs['X-Khronos'])
        raw = base64.b64decode(real + '==')
        rnd, ct = raw[:4], raw[4:]
        got = x_ladon(kh, rnd=rnd)
        print(f"真机 : {real}")
        print(f"复算 : {got}")
        print("★ 逐字节一致 ✓✓" if got == real else "✗ 不一致")
    else:
        print(x_ladon(int(time.time())))
