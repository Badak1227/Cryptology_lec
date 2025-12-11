import socket
import sys

from com.Communication import Receiver as CryptoReceiver, short_int

HOST = "127.0.0.1"


def recv_exact(conn: socket.socket, n: int) -> bytes:
    """n바이트 딱 맞게 읽기 (길이 프레임용)."""
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            # 연결 끊김
            return b""
        data += chunk
    return data


def main() -> None:
    # 포트는 인자로 받기 (없으면 기본 9000)
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000

    # 🔑 RSA 키는 항상 자동 생성 (p,q,r,e 모두 내부에서 랜덤)
    rcv = CryptoReceiver(2048)
    print("[Receiver] 자동 생성 RSA (짝수/홀수) 키 초기화 완료.")

    # 2) 서버 소켓 열기
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, port))
    server.listen(1)
    print(f"[Receiver] {HOST}:{port}에서 대기 중...")

    conn, addr = server.accept()
    print(f"[Receiver] {addr}에서 연결됨")

    # 3) 송신자에게 공개키 2개 전송
    (N_even, e_even), (N_odd, e_odd) = rcv.public_keys
    pk_str = f"{N_even},{e_even};{N_odd},{e_odd}"
    conn.sendall(pk_str.encode("utf-8"))
    print(f"[Receiver] 짝수: N={short_int(N_even)}, e={e_even}")
    print(f"[Receiver] 홀수: N={short_int(N_odd)},  e={e_odd}")
    print("[Receiver] 공개키 전송 완료.")

    # 4) 송신자로부터 enc_seed(정수) 수신
    enc_seed_data = conn.recv(4096).decode("utf-8").strip()
    if not enc_seed_data:
        print("[Receiver] 오류: 암호화된 시드가 비어있습니다. 송신자 측 오류.")
        conn.close()
        server.close()
        return

    enc_seed = int(enc_seed_data)
    print("[Receiver] 암호화된 시드 수신 완료.")

    # 5) 하이브리드 암호 초기화 (LFSR seed 복원)
    rcv.seed_init(enc_seed)

    print("[Receiver] 메시지 수신 준비 완료.")
    print("[Receiver] (송신자가 종료 패킷을 보내면 자동 종료됩니다.)")

    # 6) 여러 메시지 반복 수신
    while True:
        # 먼저 길이 4바이트 받기
        header = recv_exact(conn, 4)
        if not header:
            print("[Receiver] 송신자에 의해 연결이 종료되었습니다.")
            break

        msg_len = int.from_bytes(header, "big")
        if msg_len == 0:
            print("[Receiver] 종료 신호 수신.")
            break

        cipher = recv_exact(conn, msg_len)
        if not cipher:
            print("[Receiver] 암호문 수신 실패. 종료합니다.")
            break

        plain = rcv.decrypt(cipher)
        try:
            text = plain.decode("utf-8")
        except UnicodeDecodeError:
            text = plain.decode("utf-8", errors="replace")

        print(f"[Receiver] 메시지: {text}")

    conn.close()
    server.close()
    print("[Receiver] 프로그램 종료.")


if __name__ == "__main__":
    main()
