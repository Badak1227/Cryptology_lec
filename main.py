# launcher.py
import subprocess
import time
import os
import sys


def main():
    # 포트는 인자로 받거나, 없으면 기본 9000
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000

    base_path = os.path.dirname(os.path.abspath(__file__))
    receiver_path = os.path.join(base_path, "com", "Receiver.py")
    sender_path = os.path.join(base_path, "com", "Sender.py")

    # Receiver 실행 ( /c : 프로그램 끝나면 창도 같이 닫힘 )
    subprocess.Popen(
        f'start cmd /c python -u "{receiver_path}" {port}',
        shell=True
    )
    print(f"[Launcher] Receiver window opened on port {port}.")

    # 서버 준비시간
    time.sleep(5)

    # Sender 실행
    subprocess.Popen(
        f'start cmd python -u "{sender_path}" {port}',
        shell=True
    )
    print("[Launcher] Sender window opened.")


if __name__ == "__main__":
    main()
