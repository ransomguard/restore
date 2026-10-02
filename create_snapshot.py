import sys
import ctypes
import subprocess


def check_admin() -> None:
    """
    관리자 권한으로 실행 중인지 확인합니다.
    관리자 권한이 아닌 경우 경고 메시지를 출력하고 종료합니다.
    """
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[!] 경고: 본 프로그램은 VSS 스냅샷 생성을 위해 관리자 권한이 필요합니다.")
        print("[!] 관리자 권한으로 실행 후 다시 시도해주세요.")
        sys.exit(1)


def create_vss_snapshot(drive_letter: str = "C:") -> bool:
    """
    wmic shadowcopy call create Volume="C:\" 명령을 subprocess로 실행해 VSS 스냅샷을 생성합니다.
    출력 결과에 "ReturnValue = 0;"이 포함되어 있으면 성공으로 판별합니다.
    """
    drive = drive_letter if drive_letter.endswith("\\") else f"{drive_letter}\\"
    cmd = f'wmic shadowcopy call create Volume="{drive}"'
    print(f"[*] VSS 스냅샷 생성 명령 실행: {cmd}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="cp949",
        errors="ignore",
        shell=True
    )

    output = result.stdout or ""
    if "ReturnValue = 0;" in output:
        print("[+] VSS 스냅샷이 성공적으로 생성되었습니다. (ReturnValue = 0;)")
        return True
    else:
        print("[-] VSS 스냅샷 생성 실패 (ReturnValue = 0; 미발견)")
        if output.strip():
            print(f"[-] 명령 출력:\n{output.strip()}")
        if result.stderr and result.stderr.strip():
            print(f"[-] 오류 출력:\n{result.stderr.strip()}")
        return False


if __name__ == "__main__":
    # 1. 관리자 권한 검사
    check_admin()

    # 2. VSS 스냅샷 생성 실행
    create_vss_snapshot(drive_letter="C:")
