# com/Sender.py
import socket
import sys

from com.Communication import Sender as CryptoSender, short_int

HOST = "127.0.0.1"


def send_with_len(sock: socket.socket, data: bytes) -> None:
    """앞에 길이(4바이트)를 붙여서 전송."""
    length = len(data)
    header = length.to_bytes(4, "big")
    sock.sendall(header + data)


def main() -> None:
    print("[Sender] 프로그램 시작")  # 디버깅용

    # 포트는 인자로 받기 (없으면 기본 9000)
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
    print(f"[Sender] 사용 포트: {port}")

    # 1) 수신자에 TCP 연결 시도
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[Sender] {HOST}:{port} 에 연결 시도 중...")
        client.connect((HOST, port))
        print(f"[Sender] 수신자 {HOST}:{port}에 연결됨")
    except Exception as e:
        print("[Sender] 수신자 연결 실패:", repr(e))
        return

    # 2) 수신자로부터 공개키 2개 수신
    # 형식: "N_even,e_even;N_odd,e_odd"
    try:
        pk_data = client.recv(4096).decode("utf-8").strip()
        pk_even_str, pk_odd_str = pk_data.split(";")
        N_even, e_even = map(int, pk_even_str.split(","))
        N_odd, e_odd = map(int, pk_odd_str.split(","))

    except Exception as e:
        print("[Sender] 공개키 파싱 오류:", repr(e))
        client.close()
        return

    print(f"[Sender]  짝수: N={short_int(N_even)}, e={e_even}")
    print(f"[Sender]  홀수: N={short_int(N_odd)},  e={e_odd}")

    # 3) LFSR 키(시드)를 자동 생성할지, 문자열로 만들지 선택
    try:
        use_key = input("LFSR 키를 직접 입력하시겠습니까? (y/n): ").strip().lower()
    except EOFError:
        print("[Sender] 입력 스트림이 닫혀 있습니다(EOF). 터미널에서 직접 실행해 주세요.")
        client.close()
        return

    key = None
    if use_key == "y":
        try:
            key = input("키 문자열을 입력하세요: ").strip()
        except EOFError:
            print("[Sender] 키 입력 중 EOF. 자동 키 생성 모드로 전환합니다.")
            key = None

    # 4) CryptoSender 생성 및 enc_seed 전송
    try:
        sender = CryptoSender(((N_even, e_even), (N_odd, e_odd)), key=key)
    except Exception as e:
        print("[Sender] CryptoSender 생성 중 오류:", repr(e))
        client.close()
        return

    enc_seed = sender.enc_seed
    client.sendall(str(enc_seed).encode("utf-8"))
    print("[Sender] 암호화된 시드 전송 완료.")

    print("[Sender] 메시지 전송 준비 완료. ('/quit' 입력 시 종료)")

    # 5) 여러 메시지 전송 루프
    while True:
        try:
            msg_text = input("You: ")
        except (EOFError, KeyboardInterrupt):
            msg_text = "/quit"

        if msg_text.strip().lower() in ("/quit", "quit", "exit"):
            # 길이 0 패킷을 종료 신호로 사용
            client.sendall((0).to_bytes(4, "big"))
            print("[Sender] 종료 신호 전송.")
            break

        msg_bytes = msg_text.encode("utf-8")

        try:
            cipher = sender.encrypt(msg_bytes)
        except Exception as e:
            print("[Sender] 암호화 중 오류:", repr(e))
            break

        try:
            send_with_len(client, cipher)
        except Exception as e:
            print("[Sender] 전송 중 오류:", repr(e))
            break

        print("[Sender] 암호문 전송 완료.")

    client.close()
    print("[Sender] 프로그램 종료.")


if __name__ == "__main__":
    main()
