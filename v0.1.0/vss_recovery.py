import os
import sys
import ctypes
import subprocess
import re
import shutil
import threading
import logging
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Callable, Optional

# 스레드 안전(Thread-safe)한 로깅 시스템 설정
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s"
)
logger = logging.getLogger("VssRecoveryEngine")


def check_admin() -> None:
    """
    관리자 권한으로 실행 중인지 확인합니다.
    관리자 권한이 아닌 경우 경고 메시지를 출력하고 종료합니다.
    """
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[!] 경고: 본 프로그램은 Windows VSS 명령 실행 및 심볼릭 링크 생성을 위해 관리자 권한이 필요합니다.")
        print("[!] 관리자 권한으로 실행 후 다시 시도해주세요.")
        sys.exit(1)


class VssRecoveryEngine:
    """
    Windows VSS (Volume Shadow Copy Service) 기반 데이터 복구 엔진 클래스.
    동기(Synchronous) 및 비동기(Asynchronous) 백그라운드 복구를 모두 지원합니다.
    """

    def __init__(self, drive_letter: str = "C:"):
        self.drive_letter = drive_letter
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="VssRecoveryWorker")

    def create_snapshot(self) -> str:
        """
        wmic shadowcopy call create Volume="C:\" 명령을 subprocess로 실행해 VSS 스냅샷을 생성합니다.
        출력 결과에 "ReturnValue = 0;"이 포함되어 있으면 성공으로 판단합니다.
        """
        drive = self.drive_letter if self.drive_letter.endswith("\\") else f"{self.drive_letter}\\"
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
            print("[+] VSS 스냅샷이 성공적으로 생성되었습니다 (ReturnValue = 0;).")
        else:
            print("[-] VSS 스냅샷 생성 실패 (ReturnValue = 0; 미발견)")
            if output.strip():
                print(f"[-] 명령 출력:\n{output.strip()}")
            if result.stderr and result.stderr.strip():
                print(f"[-] 오류 출력:\n{result.stderr.strip()}")

        return output

    def get_latest_shadow_volume(self) -> str:
        """
        vssadmin list shadows 명령 출력을 정규식으로 파싱하여 가장 최신 섀도 볼륨 경로를 추출합니다.
        """
        cmd = "vssadmin list shadows"
        print(f"[*] 섀도 볼륨 목록 조회 실행: {cmd}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="cp949",
            errors="ignore",
            shell=True
        )

        # \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy\d+ 정규식 파싱
        pattern = r"\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+"
        matches = re.findall(pattern, result.stdout, re.IGNORECASE)

        if not matches:
            raise RuntimeError("[-] 시스템에서 섀도 볼륨(VSS Snapshot) 경로를 찾을 수 없습니다.")

        latest_shadow = matches[-1]
        print(f"[+] 최신 섀도 볼륨 경로 추출 성공: {latest_shadow}")
        return latest_shadow

    def recover(
        self,
        target_relative_path: str = "vss_test",
        mount_point: str = r"C:\vss_mount",
        destination_dir: str = r"C:\vss_test"
    ) -> None:
        """
        최신 VSS 스냅샷 경로에 심볼릭 링크를 마운트하고 지정 타깃 데이터를 복원합니다.
        작업 완료 후 또는 예외 발생 시 finally 블록에서 os.rmdir로 마운트 해제합니다.
        (동기적 블로킹 함수 - 핵심 복구 로직)
        """
        latest_shadow = self.get_latest_shadow_volume()

        # 최신 스냅샷 경로 끝에 반드시 백슬래시(\)를 붙임
        if not latest_shadow.endswith("\\"):
            latest_shadow += "\\"

        # 마운트 포인트 잔여물이 있을 경우 미리 제거 시도
        if os.path.lexists(mount_point):
            try:
                os.rmdir(mount_point)
            except Exception:
                pass

        print(f"[*] 심볼릭 링크 마운트 생성: {mount_point} -> {latest_shadow}")
        mount_cmd = f'cmd /c mklink /D "{mount_point}" "{latest_shadow}"'

        try:
            mount_result = subprocess.run(
                mount_cmd,
                capture_output=True,
                text=True,
                encoding="cp949",
                errors="ignore",
                shell=True
            )

            if mount_result.returncode != 0 and not os.path.lexists(mount_point):
                raise RuntimeError(f"[-] 심볼릭 링크 마운트 생성 실패: {mount_result.stderr or mount_result.stdout}")

            print(f"[+] 심볼릭 링크 마운트 성공.")

            # 마운트 폴더 내 타깃 데이터 경로 설정
            src_path = os.path.join(mount_point, target_relative_path)

            if not os.path.exists(src_path):
                raise FileNotFoundError(f"[-] 마운트 경로 내 복원 대상 폴더가 존재하지 않습니다: {src_path}")

            print(f"[*] 데이터 복원 중: {src_path} -> {destination_dir}")
            shutil.copytree(src_path, destination_dir, dirs_exist_ok=True)
            print(f"[+] 데이터 복원 성공: {destination_dir}")

        finally:
            print(f"[*] 마운트 해제 작업 수행 중: {mount_point}")
            if os.path.lexists(mount_point):
                try:
                    os.rmdir(mount_point)
                    print(f"[+] 1차 os.rmdir 마운트 해제 성공: {mount_point}")
                except Exception as e:
                    print(f"[-] 1차 os.rmdir 마운트 해제 실패: {e}")
                    print(f"[*] 2차 강제 마운트 해제 시도 (cmd /c rmdir): {mount_point}")
                    try:
                        subprocess.run(
                            f'cmd /c rmdir "{mount_point}"',
                            capture_output=True,
                            text=True,
                            encoding="cp949",
                            errors="ignore",
                            shell=True
                        )
                        if not os.path.lexists(mount_point):
                            print(f"[+] 2차 cmd rmdir 마운트 해제 성공: {mount_point}")
                        else:
                            print(f"[-] 2차 cmd rmdir 마운트 해제 실패")
                    except Exception as cmd_err:
                        print(f"[-] 2차 강제 마운트 해제 시도 중 오류 발생: {cmd_err}")

    def recover_async(
        self,
        target_relative_path: str = "vss_test",
        mount_point: str = r"C:\vss_mount",
        destination_dir: str = r"C:\vss_test",
        callback: Optional[Callable[[bool, Optional[Exception]], None]] = None
    ) -> threading.Thread:
        """
        recover 복구 작업을 백그라운드 데몬 스레드에서 비동기적으로 실행합니다. (Non-blocking)
        
        :param target_relative_path: 마운트 경로 내 복원 대상 상대 경로
        :param mount_point: 심볼릭 링크 마운트 경로
        :param destination_dir: 복원 대상 원본/목적지 디렉터리
        :param callback: 작업 완료 시 호출되는 콜백 함수 callback(success: bool, error: Optional[Exception])
        :return: 생성 및 시작된 백그라운드 데몬 Thread 객체 (daemon=True)
        """
        def _worker():
            success = False
            error = None
            try:
                logger.info(f"[비동기 복구 시작] 대상 상대 경로: {target_relative_path}")
                self.recover(
                    target_relative_path=target_relative_path,
                    mount_point=mount_point,
                    destination_dir=destination_dir
                )
                success = True
                logger.info(f"[비동기 복구 완료] 성공적으로 복원되었습니다: {destination_dir}")
            except Exception as e:
                error = e
                logger.error(f"[비동기 복구 오류 발생] 복구 실패: {e}")
            finally:
                if callback:
                    try:
                        callback(success, error)
                    except Exception as cb_err:
                        logger.error(f"[콜백 호출 오류] 콜백 함수 처리 중 예외 발생: {cb_err}")

        worker_thread = threading.Thread(
            target=_worker,
            daemon=True,
            name="VssRecoveryDaemonWorker"
        )
        worker_thread.start()
        return worker_thread

    def recover_executor(
        self,
        target_relative_path: str = "vss_test",
        mount_point: str = r"C:\vss_mount",
        destination_dir: str = r"C:\vss_test",
        callback: Optional[Callable[[bool, Optional[Exception]], None]] = None
    ) -> Future:
        """
        ThreadPoolExecutor를 사용하여 recover 작업을 비동기적으로 실행합니다. (Non-blocking)
        
        :param target_relative_path: 마운트 경로 내 복원 대상 상대 경로
        :param mount_point: 심볼릭 링크 마운트 경로
        :param destination_dir: 복원 대상 원본/목적지 디렉터리
        :param callback: 작업 완료 시 호출되는 콜백 함수 callback(success: bool, error: Optional[Exception])
        :return: concurrent.futures.Future 객체
        """
        def _task():
            success = False
            error = None
            try:
                logger.info(f"[Executor 복구 시작] 대상 상대 경로: {target_relative_path}")
                self.recover(
                    target_relative_path=target_relative_path,
                    mount_point=mount_point,
                    destination_dir=destination_dir
                )
                success = True
                logger.info(f"[Executor 복구 완료] 성공적으로 복원되었습니다: {destination_dir}")
                return True
            except Exception as e:
                error = e
                logger.error(f"[Executor 복구 오류 발생]: {e}")
                raise
            finally:
                if callback:
                    try:
                        callback(success, error)
                    except Exception as cb_err:
                        logger.error(f"[콜백 호출 오류] 콜백 함수 처리 중 예외 발생: {cb_err}")

        return self._executor.submit(_task)


if __name__ == "__main__":
    import time

    # 1. 관리자 권한 검사
    check_admin()

    # 2. VssRecoveryEngine 객체 생성
    engine = VssRecoveryEngine(drive_letter="C:")

    # 3. 비동기 결과를 처리할 메인 엔진 콜백 함수 정의
    def edr_recovery_callback(success: bool, error: Optional[Exception]) -> None:
        if success:
            print("\n==========================================")
            print("[EDR 메인 엔진 알림] 백그라운드 VSS 복구 작업 완료!")
            print("==========================================\n")
        else:
            print("\n==========================================")
            print(f"[EDR 메인 엔진 알림] 백그라운드 VSS 복구 작업 실패: {error}")
            print("==========================================\n")

    print("[EDR 메인 탐지 엔진] 랜섬웨어 악성 프로세스 차단 완료.")
    print("[EDR 메인 탐지 엔진] recover_async() 호출하여 비동기 복구 작업 시작 (Non-blocking)...")

    # 4. non-blocking 비동기 복구 호출
    recovery_thread = engine.recover_async(
        target_relative_path="vss_test",
        mount_point=r"C:\vss_mount",
        destination_dir=r"C:\vss_test",
        callback=edr_recovery_callback
    )

    # 5. 메인 탐지 루프가 블로킹 없이 즉시 계속 실행됨을 검증
    print("[EDR 메인 탐지 엔진] 탐지 메인 루프가 멈추지 않고 지속 실행 중입니다.")
    for i in range(1, 6):
        print(f"[EDR 메인 탐지 엔진] 실시간 프로세스 및 파일 감시 중... ({i}초)")
        time.sleep(1)

    # 데몬 스레드가 종료되기 전에 작업 완료를 기다려 줌 (테스트 메인 함수용)
    if recovery_thread.is_alive():
        print("[EDR 메인 탐지 엔진] 백그라운드 복구 데몬 스레드 마무리를 대기합니다...")
        recovery_thread.join()

    print("[EDR 메인 탐지 엔진] 테스트 완료 및 EDR 메인 루프 종료.")



