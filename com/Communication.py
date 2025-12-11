import os
import secrets
import hashlib
from typing import Optional, Tuple

from crypto.RSA import RSA3P
from crypto.LfsrBlock import LfsrBlock
from crypto.Hybrid_3RLC import Hybrid_3RLC


def split_24bit(seed_24: int):
    """24비트 정수 → 8비트 3개로 쪼개기."""
    seed_24 &= (1 << 24) - 1
    s1 = (seed_24 >> 16) & 0xFF
    s2 = (seed_24 >> 8) & 0xFF
    s3 = seed_24 & 0xFF
    return [s1, s2, s3]


def build_cipher(seed_even: int, seed_odd: int) -> Hybrid_3RLC:
    """짝수/홀수용 seed 2개로 Hybrid_3RLC 생성."""
    even_seeds = split_24bit(seed_even)
    odd_seeds = split_24bit(seed_odd)

    lfsr_even = LfsrBlock(even_seeds)
    lfsr_odd = LfsrBlock(odd_seeds)

    return Hybrid_3RLC(lfsr_even, lfsr_odd)


def short_int(n: int, front: int = 10, back: int = 6) -> str:
    """
    아주 큰 정수를 보기 좋게 잘라서 표시.
    예) 12345678901234567890 → 1234567890...567890
    """
    s = str(n)
    if len(s) <= front + back:
        return s
    return s[:front] + "..." + s[-back:]


def short_hex(data: bytes, front: int = 8, back: int = 6) -> str:
    """
    바이트열을 16진수 문자열로 바꾸되,
    앞/뒤 일부만 남기고 중간은 ... 로 생략해 표시.
    """
    if not data:
        return ""
    s = data.hex()
    if len(s) <= front + back:
        return s
    return s[:front] + "..." + s[-back:]


# ====== 공개키(N, e)로만 RSA 암호화 (메시지용, 짝/홀 각각 다른 키) ======


def rsa_nlen(N: int) -> int:
    """모듈러스 N의 바이트 길이."""
    return (N.bit_length() + 7) // 8


def rsa_pad_pkcs1_v15(M: bytes, N: int) -> bytes:
    """
    PKCS#1 v1.5 패딩 (encrypt 용)
    구조: 0x00 | 0x02 | PS(0x00 금지 랜덤, 길이 >= 8) | 0x00 | M
    """
    n = rsa_nlen(N)
    if len(M) > n - 11:
        raise ValueError(f"msg too long: max {n - 11}B")

    ps_len = n - len(M) - 3
    ps = bytearray()
    while len(ps) < ps_len:
        b = os.urandom(1)
        if b != b"\x00":
            ps += b

    return b"\x00\x02" + bytes(ps) + b"\x00" + M


def rsa_encrypt_bytes_public(M: bytes, N: int, e: int) -> bytes:
    """
    개인키 없이 (N, e)로만 RSA 바이트 암호화.
    - 블록 단위로 PKCS#1 v1.5 패딩 적용
    - 수신측에서는 RSA3P.decrypt_bytes()로 복호 가능
    """
    n = rsa_nlen(N)
    max_pt = n - 11  # 패딩 때문에 평문 블록 최대 길이

    res = bytearray()
    for i in range(0, len(M), max_pt):
        m_block = M[i:i + max_pt]
        pm = rsa_pad_pkcs1_v15(m_block, N)
        c_int = pow(int.from_bytes(pm, "big"), e, N)
        res += c_int.to_bytes(n, "big")

    return bytes(res)


# --- 교차 인덱스 기반 결합 ---


def interleave(bytes_even: bytes, bytes_odd: bytes) -> bytes:
    """[A0, B0, A1, B1, A2, B2...] 형태로 결합"""
    res = bytearray()
    for a, b in zip(bytes_even, bytes_odd):
        res.append(a)
        res.append(b)
    return bytes(res)


def deinterleave(mixed: bytes) -> Tuple[bytes, bytes]:
    """[A0, B0, A1, B1, A2, B2...] 형태로 분리"""
    bytes_even = mixed[0::2]  # 인덱스 0, 2, 4...
    bytes_odd = mixed[1::2]   # 인덱스 1, 3, 5...
    return bytes_even, bytes_odd


# --- 사용자 키 문자열 → LFSR seed 2개 생성 ---


def derive_seeds_from_key(key: str):
    """
    사용자 키 문자열 → SHA-256 → 앞 6바이트(48비트)를
    짝수/홀수용 24비트 시드 두 개로 나눈다.
    """
    h = hashlib.sha256(key.encode("utf-8")).digest()  # 32 bytes
    seed_even = int.from_bytes(h[0:3], "big")  # 24bit
    seed_odd = int.from_bytes(h[3:6], "big")  # 24bit
    return seed_even, seed_odd


class Receiver:
    """
    수신자:
    - 짝/홀 메시지용 RSA3P 키를 각각 1개씩 자동 생성 (총 2개)
    - enc_seed 는 짝수용 키(rsa_even)로 복호화
    - 이후 메시지:
        - 짝수 스트림: rsa_even.decrypt_bytes()
        - 홀수 스트림: rsa_odd.decrypt_bytes()
        - Hybrid_3RLC.decrypt_merge()로 평문 복원
    """

    def __init__(self, bits: int = 2048) -> None:
        # 항상 자동 생성 (p,q,r,e 모두 내부에서 랜덤)
        self.rsa_even = RSA3P(bits)
        self.rsa_odd = RSA3P(bits)

        self.seed_even: Optional[int] = None
        self.seed_odd: Optional[int] = None
        self.cipher: Optional[Hybrid_3RLC] = None

        print("[Receiver] RSA (짝수/홀수) 키 준비 완료")
        print(f"[Receiver] 짝수 키: N={short_int(self.rsa_even.N)}, e={self.rsa_even.e}")
        print(f"[Receiver] 홀수 키: N={short_int(self.rsa_odd.N)},  e={self.rsa_odd.e}")

    @property
    def public_keys(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        return (self.rsa_even.N, self.rsa_even.e), (self.rsa_odd.N, self.rsa_odd.e)

    def seed_init(self, enc_seed: int) -> None:
        # enc_seed = (seed_even << 24) | seed_odd 를 짝수용 RSA로 복호
        M = self.rsa_even.decryption(enc_seed)

        self.seed_even = (M >> 24) & ((1 << 24) - 1)
        self.seed_odd = M & ((1 << 24) - 1)

        print(f"[Receiver] seed_even={self.seed_even}, seed_odd={self.seed_odd}")

        self.cipher = build_cipher(self.seed_even, self.seed_odd)
        print("[Receiver] 하이브리드 암호 초기화 완료.")

    def decrypt(self, cipher: bytes) -> bytes:
        """
        통신으로 받은 암호문(cipher)을 복호화:
        1) 짝/홀 암호문 분리
        2) RSA3P로 각각 복호 → 짝/홀 스트림
        3) Hybrid_3RLC.decrypt_merge()로 평문 복원
        """
        if self.cipher is None:
            raise RuntimeError("Receiver: seed_init이 아직 호출되지 않았습니다.")

        enc_even, enc_odd = deinterleave(cipher)

        print(f"[Receiver] [5] 짝수 암호문 ({len(enc_even)}B): {short_hex(enc_even)}")
        print(f"[Receiver] [5] 홀수 암호문 ({len(enc_odd)}B): {short_hex(enc_odd)}")

        # 1) 짝/홀 RSA 복호
        even_stream = self.rsa_even.decrypt_bytes(enc_even)
        odd_stream = self.rsa_odd.decrypt_bytes(enc_odd)

        print(f"[Receiver] [6] RSA 복호 짝수: {short_hex(even_stream)}")
        print(f"[Receiver] [6] RSA 복호 홀수: {short_hex(odd_stream)}")

        # 2) LFSR 기반 하이브리드 복호
        plain = self.cipher.decrypt_merge(even_stream, odd_stream)
        print(f"[Receiver] [7] 평문: {plain}")

        return plain


class Sender:
    """
    송신자:
    - 수신자 공개키 2개((N_even, e_even), (N_odd, e_odd))를 전달받음
    - 짝수용 공개키로 enc_seed 암호화해서 seed 전송
    - 같은 seed로 Hybrid_3RLC 초기화
    - 각 메시지:
        1) Hybrid_3RLC.encrypt_split() → 짝/홀 스트림
        2) 각 스트림을 대응하는 공개키로 RSA 암호화
        3) 짝/홀 암호문을 인덱스 기반으로 교차결합(interleave)하여 패킷 생성
    """

    def __init__(
        self,
        public_keys: Tuple[Tuple[int, int], Tuple[int, int]],
        key: Optional[str] = None,
    ) -> None:
        (N_even, e_even), (N_odd, e_odd) = public_keys

        self.N_even, self.e_even = N_even, e_even
        self.N_odd, self.e_odd = N_odd, e_odd

        print(f"[Sender]  짝수 키: N={short_int(self.N_even)}, e={self.e_even}")
        print(f"[Sender]  홀수 키: N={short_int(self.N_odd)},  e={self.e_odd}")

        # 🔑 LFSR 시드 자동/수동 선택
        if key is None:
            # 랜덤 24비트 2개
            self.seed_even = secrets.randbits(24)
            self.seed_odd = secrets.randbits(24)
        else:
            # 사용자 키 문자열 기반
            self.seed_even, self.seed_odd = derive_seeds_from_key(key)

        # 48비트 하나로 묶기
        M = (self.seed_even << 24) | self.seed_odd

        # enc_seed는 짝수용 공개키로만 암호화해서 보냄
        self.enc_seed = pow(M, self.e_even, self.N_even)

        print(f"[Sender] seed_even={self.seed_even}, seed_odd={self.seed_odd}")

        # 동일한 seed 기반으로 하이브리드 스트림 암호 초기화
        self.cipher = build_cipher(self.seed_even, self.seed_odd)
        print("[Sender] 하이브리드 암호 초기화 완료.")

    def encrypt(self, msg: bytes) -> bytes:
        """
        평문 msg를 암호화:
        1) Hybrid_3RLC.encrypt_split() → 짝/홀 스트림
        2) 각 스트림을 대응하는 공개키로 RSA 암호화
        3) 짝/홀 암호문을 인덱스 기반으로 교차결합(interleave)하여 패킷 생성
        """
        print(f"[Sender] [1] 평문 ({len(msg)}B): {msg}")

        # 1) LFSR 기반 짝/홀 스트림 생성
        even_stream, odd_stream = self.cipher.encrypt_split(msg)
        print(f"[Sender] [2] LFSR XOR 짝수: {short_hex(even_stream)}")
        print(f"[Sender] [2] LFSR XOR 홀수: {short_hex(odd_stream)}")

        # 2) 짝/홀 스트림 각각 RSA 암호화 (서로 다른 공개키 사용)
        enc_even = rsa_encrypt_bytes_public(even_stream, self.N_even, self.e_even)
        enc_odd = rsa_encrypt_bytes_public(odd_stream, self.N_odd, self.e_odd)
        print(f"[Sender] [3] RSA 암호화 짝수: {short_hex(enc_even)}")
        print(f"[Sender] [3] RSA 암호화 홀수: {short_hex(enc_odd)}")

        # 3) 인덱스 기반 교차결합
        packet = interleave(enc_even, enc_odd)
        print(f"[Sender] [4] 패킷: {short_hex(packet)}")

        return packet
