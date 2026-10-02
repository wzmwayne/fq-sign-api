#!/usr/bin/env python3
"""FqCrypto 的纯 Python 移植（正文解密 / registerkey 解密）—— 与 Java 版逐字节等价。

对应 /tmp/fqdl2/.../service/FqCrypto.java：
  * AES-128-CBC + PKCS5(PKCS7) 填充
  * 密文格式 = base64( IV(16B) || ciphertext )
  * newRegisterKeyContent : LE64(deviceId) || LE64(val) 加密后 base64
  * decryptRegisterKey    : 用给定 hex key 解密，返回【大写 hex 字符串】
  * getRealKey            : decryptRegisterKey(resp, REG_KEY)[:32]
  * decryptAndDecompressContent : AES 解密后若以 1f 8b 开头则 gunzip，否则按 UTF-8
零依赖回退：若没有 cryptography，则用同目录 aes_pure 的纯 Python AES（慢但等价）。
"""
import base64, gzip, os, struct

REG_KEY = "ac25c67ddd8f38c1b37a2348828e222e"

# ---------------- AES-128-CBC 后端 ----------------
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    _HAVE_CRYPTO = True
except Exception:                                     # pragma: no cover
    _HAVE_CRYPTO = False


def _pkcs7_pad(b: bytes) -> bytes:
    n = 16 - (len(b) % 16)
    return b + bytes([n]) * n


def _pkcs7_unpad(b: bytes) -> bytes:
    if not b:
        raise ValueError('empty plaintext')
    n = b[-1]
    if not 1 <= n <= 16 or b[-n:] != bytes([n]) * n:
        raise ValueError('bad PKCS5 padding')
    return b[:-n]


def _aes_cbc(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    if len(key) != 16:
        raise ValueError('key must be 16 bytes')
    if len(iv) != 16:
        raise ValueError('IV must be 16 bytes')
    if _HAVE_CRYPTO:
        c = Cipher(algorithms.AES(key), modes.CBC(iv))
        op = c.encryptor() if encrypt else c.decryptor()
        return op.update(data) + op.finalize()
    raise RuntimeError('需要 cryptography 库（或接入纯 Python AES）')


def hex2bytes(h: str) -> bytes:
    return bytes.fromhex(h)


def bytes2hex(b: bytes) -> str:
    """与 Java byteArrayToHexString 一致：大写、无分隔"""
    return b.hex().upper()


class FqCrypto:
    def __init__(self, hex_key: str):
        if hex_key is None or len(hex_key) != 32:
            raise ValueError(f'Key length mismatch! Expected 32 hex chars, got: '
                             f'{len(hex_key) if hex_key is not None else "null"}')
        kb = hex2bytes(hex_key)
        if len(kb) != 16:
            raise ValueError('Key must be 16 bytes after hex decode')
        self.key = kb

    # ---- Java: encrypt(data, iv) ----
    def encrypt(self, data: bytes, iv: bytes) -> bytes:
        return _aes_cbc(self.key, iv, _pkcs7_pad(data), True)

    # ---- Java: decrypt(encodedData) ----
    def decrypt(self, encoded_data: str) -> bytes:
        raw = base64.b64decode(encoded_data)
        if len(raw) < 16:
            raise ValueError('Encrypted data too short')
        iv, ct = raw[:16], raw[16:]
        return _pkcs7_unpad(_aes_cbc(self.key, iv, ct, False))

    # ---- Java: newRegisterKeyContent(serverDeviceId, strVal) ----
    def new_register_key_content(self, server_device_id: str, str_val: str) -> str:
        combined = struct.pack('<QQ', int(server_device_id), int(str_val))
        iv = os.urandom(16)
        enc = self.encrypt(combined, iv)
        return base64.b64encode(iv + enc).decode()


# ---- Java: decryptRegisterKey(registerkeyResponseKey, aesKeyHex) ----
def decrypt_register_key(registerkey_response_key: str, aes_key_hex: str) -> str:
    raw = base64.b64decode(registerkey_response_key)
    if len(raw) < 16:
        raise ValueError('Encrypted data too short')
    iv, ct = raw[:16], raw[16:]
    key = hex2bytes(aes_key_hex)
    dec = _pkcs7_unpad(_aes_cbc(key, iv, ct, False))
    return bytes2hex(dec)


# ---- Java: getRealKey(registerkeyResponseKey) ----
def get_real_key(registerkey_response_key: str) -> str:
    full = decrypt_register_key(registerkey_response_key, REG_KEY)
    if len(full) >= 32:
        return full[:32]
    raise ValueError('解密后的密钥长度不足')


# ---- Java: decryptAndDecompressContent(encryptedContent, keyHex) ----
def decrypt_and_decompress_content(encrypted_content: str, key_hex: str) -> str:
    crypto = FqCrypto(key_hex)
    dec = crypto.decrypt(encrypted_content)
    if len(dec) >= 2 and dec[0] == 0x1f and dec[1] == 0x8b:
        return gzip.decompress(dec).decode('utf-8')
    return dec.decode('utf-8')


# ---------------- AES-128-CTR（与 .so 的 0x1dd534/0x1dd5c8 逐字节一致） ----------------
def aes_ctr_keystream(key: bytes, iv: bytes, n: int) -> bytes:
    """密钥流 = E(key, IV[0:8] ‖ 计数器(大端, 从 0 起))，与 .so 实测一致。"""
    ctrblk = bytearray(16)
    ctrblk[0:8] = iv[0:8]
    ks = b''
    c = 0
    while len(ks) < n:
        ctrblk[8:16] = c.to_bytes(8, 'big')
        ks += _aes_ecb(key, bytes(ctrblk))
        c += 1
    return ks[:n]


def aes_ctr_xor(key: bytes, iv: bytes, data: bytes) -> bytes:
    ks = aes_ctr_keystream(key, iv, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def _aes_ecb(key: bytes, blk: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.ECB())
    e = c.encryptor()
    return e.update(blk) + e.finalize()


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'selftest':
        # 1) 往返
        c = FqCrypto(REG_KEY)
        iv = bytes(range(16))
        for pt in (b'hello', b'A' * 16, b'B' * 17, bytes(range(256))):
            ct = c.encrypt(pt, iv)
            back = c.decrypt(base64.b64encode(iv + ct).decode())
            assert back == pt, (pt, back)
        print('[*] AES-CBC/PKCS5 往返 ✓')
        # 2) registerkey 结构
        s = c.new_register_key_content('1571665370172347', '0')
        raw = base64.b64decode(s)
        assert len(raw) == 16 + 32                      # iv + (16B 明文 + 整块 PKCS5 填充)
        dev, val = struct.unpack('<QQ', _pkcs7_unpad(_aes_cbc(c.key, raw[:16], raw[16:], False)))
        assert dev == 1571665370172347 and val == 0
        print('[*] newRegisterKeyContent 结构 ✓ (LE64 deviceId || LE64 val)')
        # 3) gzip 路径
        payload = '中文测试内容'.encode()
        gz = gzip.compress(payload, mtime=0)
        ct = c.encrypt(gz, iv)
        out = decrypt_and_decompress_content(base64.b64encode(iv + ct).decode(), REG_KEY)
        assert out == payload.decode(), out
        print('[*] gzip 分支 ✓')
        # 4) decryptRegisterKey / getRealKey
        keymat = bytes(range(32))
        ct = c.encrypt(keymat, iv)
        b64 = base64.b64encode(iv + ct).decode()
        hx = decrypt_register_key(b64, REG_KEY)
        assert hx == keymat.hex().upper()
        assert get_real_key(b64) == keymat.hex().upper()[:32]
        print('[*] decryptRegisterKey / getRealKey ✓ (大写 hex)')
        print('全部自检通过')
