#!/usr/bin/env python3
"""仓库版 libmetasec_ml.so(3.6.0) 中的 AES 变体 —— 纯 Python 实现。

反汇编依据（全部来自本会话实测）：
  * 密钥编排 0x1dc740 : 标准 AES（标准 S 盒 @0x2e859c = 63 7c 77 7b f2 6b 6f c5 …
                       标准 Rcon @0x2e959c = 01,02,04,08,10,20,40,80,1b,36）
                       支持 128/192/256 位（cmp w2,#0x10/#0x18/#0x20），rev=大端装载
  * 轮函数   0x1dca20 : 对每个 32 位状态字做 4 次查表异或（字内独立，无 ShiftRows）
        T(w) = A[(w>>16)&0xff] ^ B[(w>>24)&0xff] ^ C[(w>>8)&0xff] ^ D[w&0xff]
        A=0x2e99c4  B=0x2e95c4  C=0x2e9dc4  D=0x2ea1c4      (均为 256×u32)
  * 4 张表对索引【完全线性】(实测 0/256 不符) ⇒ T 是 GF(2) 线性映射 ⇒ 可精确求逆
"""
import struct

SO = 'repo_so/libmetasec_ml.so'
TAB_ADDR = {'A': 0x2e99c4, 'B': 0x2e95c4, 'C': 0x2e9dc4, 'D': 0x2ea1c4}
SBOX_STD_ADDR = 0x2e859c      # 标准 AES S 盒，按 S[i]<<24 存放
RCON_ADDR = 0x2e959c

def _load():
    raw = open(SO, 'rb').read()
    T = {k: list(struct.unpack('<256I', raw[a:a+1024])) for k, a in TAB_ADDR.items()}
    # 表在 0x2e859c 以【小端 u32】存放 (字节序列 00 00 00 63 表示 S[0]=0x63)
    sbox = [struct.unpack_from('<I', raw, SBOX_STD_ADDR + 4*i)[0] >> 24 for i in range(256)]
    rcon = list(struct.unpack('<16I', raw[RCON_ADDR:RCON_ADDR + 64]))
    return T, sbox, rcon

T, SBOX, RCON = _load()

def T_round(w):
    """轮函数（字内 4 次查表异或）"""
    return (T['A'][(w >> 16) & 0xff] ^ T['B'][(w >> 24) & 0xff]
            ^ T['C'][(w >> 8) & 0xff] ^ T['D'][w & 0xff]) & 0xffffffff

# ---- 标准 AES 密钥编排 ----
def _sub_word(x):
    """标准 AES SubWord（逐字节查标准 S 盒，位置不变）"""
    return ((SBOX[(x >> 24) & 0xff] << 24) | (SBOX[(x >> 16) & 0xff] << 16)
            | (SBOX[(x >> 8) & 0xff] << 8) | SBOX[x & 0xff]) & 0xffffffff

def _rot_word(x):
    return ((x << 8) | (x >> 24)) & 0xffffffff

def expand_key(key: bytes, nk=4):
    """标准 AES 密钥编排；返回轮密钥字列表 (4*(nr+1) 个)"""
    nr = nk + 6
    w = list(struct.unpack('>%dI' % nk, key[:4*nk]))
    rcon_i = 0
    for i in range(nk, 4 * (nr + 1)):
        t = w[i - 1]
        if i % nk == 0:
            t = _sub_word(_rot_word(t)) ^ (RCON[rcon_i] & 0xff000000)
            rcon_i += 1
        elif nk > 6 and i % nk == 4:
            t = _sub_word(t)
        w.append(w[i - nk] ^ t)
    return w, nr

# ---- 线性求逆（GF(2) 上 32×32 矩阵） ----
def _mat_of_T():
    """T 在 GF(2) 上的 32x32 矩阵：列为 T(1<<k)"""
    return [T_round(1 << k) for k in range(32)]

def _mat_inv(cols):
    """对列向量形式的线性映射求逆：返回新的列向量表"""
    # 构造行形式矩阵 row[j] = {k : cols[k] 的第 j 位}
    rows = []
    for j in range(32):
        r = 0
        for k in range(32):
            if (cols[k] >> j) & 1: r |= (1 << k)
        rows.append(r)
    # 高斯消元求逆（对 32x32 位矩阵）
    aug = [(rows[j] | (1 << (32 + j))) for j in range(32)]
    for c in range(32):
        piv = next((r for r in range(c, 32) if (aug[r] >> c) & 1), None)
        if piv is None: raise ValueError('矩阵奇异')
        aug[c], aug[piv] = aug[piv], aug[c]
        for r in range(32):
            if r != c and ((aug[r] >> c) & 1):
                aug[r] ^= aug[c]
    inv_rows = [aug[j] >> 32 for j in range(32)]
    # 转回列形式
    out = []
    for k in range(32):
        v = 0
        for j in range(32):
            if (inv_rows[j] >> k) & 1: v |= (1 << j)
        out.append(v)
    return out

_T_COLS = _mat_of_T()
_TINV_COLS = _mat_inv(_T_COLS)

def T_inv(w):
    r = 0
    for k in range(32):
        if (w >> k) & 1: r ^= _TINV_COLS[k]
    return r & 0xffffffff

def encrypt_block(block16: bytes, key: bytes):
    w, nr = expand_key(key)
    s = list(struct.unpack('>4I', block16))
    rk = [w[4*r:4*r+4] for r in range(nr+1)]
    for i in range(4): s[i] ^= rk[0][i]
    for r in range(1, nr+1):
        s = [T_round(x) for x in s]
        for i in range(4): s[i] ^= rk[r][i]
    return struct.pack('>4I', *s)

def decrypt_block(block16: bytes, key: bytes):
    w, nr = expand_key(key)
    s = list(struct.unpack('>4I', block16))
    rk = [w[4*r:4*r+4] for r in range(nr+1)]
    for r in range(nr, 0, -1):
        for i in range(4): s[i] ^= rk[r][i]
        s = [T_inv(x) for x in s]
    for i in range(4): s[i] ^= rk[0][i]
    return struct.pack('>4I', *s)
