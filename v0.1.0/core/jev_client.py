import os
import json
from pathlib import Path
from dotenv import load_dotenv
from typesafe_sdk import TypeSafeClient, Noul


def run_jev_test():
    """
    ARW_FILE_EVENT 기반 더미 데이터를 사용하여 JEV API와의 통신 및 랜섬웨어 판별을 테스트하는 함수
    """
    # 1. 환경 설정 및 인증 (.env 파일 로드)
    env_path = Path(__file__).resolve().parent.parent / ".env"
    load_dotenv(dotenv_path=env_path)
    
    api_key = os.getenv("TYPESAFE_API_KEY")
    if not api_key:
        print(f"[!] 경고: {env_path} 경로에서 TYPESAFE_API_KEY를 찾을 수 없습니다.")

    # 2. 커널 이벤트 더미 데이터 정의 (ARW_FILE_EVENT 기반)
    dummy_kernel_event = {
        "pid": 8080,
        "action": "RENAME",
        "target_path": r"C:\doc\test.crypt",
        "extension": ".crypt"
    }

    print("[*] ARW_FILE_EVENT 더미 데이터 준비 완료:")
    print(f"    - PID: {dummy_kernel_event['pid']}")
    print(f"    - Action: {dummy_kernel_event['action']}")
    print(f"    - Target Path: {dummy_kernel_event['target_path']}")
    print(f"    - Extension: {dummy_kernel_event['extension']}")
    print("\n[*] JEV API 연결 및 질의 요청 중...")

    # 3. JEV API 연결 및 질의
    try:
        with TypeSafeClient() as client:
            state_json = json.dumps(dummy_kernel_event, ensure_ascii=False)
            
            response = client.system_one(
                state=state_json,
                questions={
                    "is_ransomware": Noul(instructions="단기간 파일 확장자 변조 및 쓰기 행위 패턴을 분석하여 랜섬웨어인지 판별하시오")
                }
            )
    except Exception as e:
        print(f"[!] JEV API 호출 중 오류 발생: {e}")
        return

    # 4. 결과 파싱 (PID 및 랜섬웨어 확률값 noul 추출)
    pid = dummy_kernel_event.get("pid")
    noul_val = parse_noul_value(response)

    # 5. 최종 결과 출력
    print("\n" + "=" * 50)
    print(" [JEV API 통신 테스트 결과]")
    print(f"  - PID : {pid}")
    print(f"  - 랜섬웨어 확률값 (noul) : {noul_val}")
    print("=" * 50 + "\n")


def parse_noul_value(response):
    """
    JEV API 응답 객체에서 noul (확률값)을 안전하게 추출하는 헬퍼 함수
    """
    try:
        # 우리가 질문할 때 "is_ransomware"라는 키를 썼으므로, 답변도 똑같은 키로 꺼냅니다.
        ans = response.answers["is_ransomware"]
        return getattr(ans, "noul", ans)
    except (KeyError, AttributeError, TypeError):
        # 혹시 모를 다른 응답 구조에 대비한 백업
        if hasattr(response, "noul"):
            return response.noul
        return response


if __name__ == "__main__":
    run_jev_test()
