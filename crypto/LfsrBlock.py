from typing import Sequence, List
from sympy.ntheory.modular import crt


class LfsrBlock:
    def __init__(
        self,
        seeds: Sequence[int],          # [seed1, seed2, seed3]
        width: int = 8                 # 기본 9비트
    ):
        if len(seeds) != 3:
            raise ValueError("seeds는 [lfsr1, lfsr2, lfsr3] 3개가 필요합니다.")

        self.width = width
        self.mask = (1 << width) - 1

        self.lfsr1 = seeds[0] & self.mask
        self.lfsr2 = seeds[1] & self.mask
        self.lfsr3 = seeds[2] & self.mask

        # LFSR Zero-state 회피
        if self.lfsr1 == 0:
            self.lfsr1 = 1
        if self.lfsr2 == 0:
            self.lfsr2 = 1
        if self.lfsr3 == 0:
            self.lfsr3 = 1

    def shift(self, lfsr: int) -> (int, int):
        # 왼쪽 시프트: 최상위 비트를 출력으로 사용
        out_bit = (lfsr >> (self.width - 1)) & 1

        fb = 0
        for pos in [7, 5, 4, 3]:
            fb ^= (lfsr >> pos) & 1

        lfsr = ((lfsr << 1) & self.mask) | fb

        return lfsr, out_bit

    def generate_key(self) -> int:

        out1 = 0
        out2 = 0
        out3 = 0

        # 초기 8비트 출력값 제외
        for _ in range(7):
            self.lfsr1, _ = self.shift(self.lfsr1)
            self.lfsr2, _ = self.shift(self.lfsr2)
            self.lfsr3, _ = self.shift(self.lfsr3)

        # 8비트 뽑기
        for _ in range(8):
            self.lfsr1, r1 = self.shift(self.lfsr1)
            self.lfsr2, r2 = self.shift(self.lfsr2)
            self.lfsr3, r3 = self.shift(self.lfsr3)

            out1 = ((out1 << 1) | r1) & self.mask
            out2 = ((out2 << 1) | r2) & self.mask
            out3 = ((out3 << 1) | r3) & self.mask

        # 마지막 r1에 따라 다음 문자용 상태를 비선형 업데이트하며
        # 추가로 나온 비트까지 포함한 값으로 CRT 결합을 진행한다.
        if (out1 & 1) == 1:
            # r1 == 1 → LFSR2: 2bit, LFSR3: 1bit 시프트
            self.lfsr2, r2a = self.shift(self.lfsr2)
            self.lfsr2, r2b = self.shift(self.lfsr2)
            out2 = ((out2 << 1) | r2a) & self.mask
            out2 = ((out2 << 1) | r2b) & self.mask

            self.lfsr3, r3a = self.shift(self.lfsr3)
            out3 = ((out3 << 1) | r3a) & self.mask
        else:
            # r1 == 0 → LFSR3: 2bit, LFSR2: 1bit 시프트
            self.lfsr3, r3a = self.shift(self.lfsr3)
            self.lfsr3, r3b = self.shift(self.lfsr3)
            out3 = ((out3 << 1) | r3a) & self.mask
            out3 = ((out3 << 1) | r3b) & self.mask

            self.lfsr2, r2a = self.shift(self.lfsr2)
            out2 = ((out2 << 1) | r2a) & self.mask

        # CRT 결합 → 키 1바이트
        moduli = [101, 103, 107]

        outs = [out1, out2, out3]
        result, _ = crt(moduli, outs)
        key = int(result % 256)

        return key

    def encrypt_byte(self, m: int) -> int:
        k = self.generate_key()
        return k^m

    def decrypt_byte(self, c: int) -> int:
        k = self.generate_key()
        return k ^ c
