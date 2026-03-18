import requests
import time
import logging
import argparse

logo = r"""
  ____  __    __  __ __   _____
 /    ||  |__|  ||  |  | / ___/
|  o  ||  |  |  ||  |  |(   \_ 
|     ||  |  |  ||  |  | \__  |
|  _  ||  `  '  ||  :  | /  \ |
|C |C | \ L  O /  \ V /  \  E | v1.0 - 2025-03-19
|__|__|  \_/\_/    \_/    \___| 若似月轮终皎洁，不辞冰雪为君热
------------------------------------------------------------
Author: 小猫之神在哭泣 (https://github.com/DuringApple)

一款基于AWVS API的自动化扫描任务调度工具，支持定时检测扫描状态并自动补充扫描任务，适用于大规模资产管理和持续安全监测。
仅用于合法授权的环境，使用前请确保已获得相关权限。作者不对任何非法使用造成的后果负责。
"""

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("awvs_scheduler.log"),
        logging.StreamHandler()
    ]
)

def get_running_scans(BASE_URL, HEADERS):
    
    url = f"{BASE_URL}/scans"
    r = requests.get(url, headers=HEADERS, verify=False, timeout=30)

    scans = r.json().get("scans", [])

    running_status = ["processing", "starting", "queued"]

    count = 0
    for s in scans:
        status = s.get("current_session", {}).get("status")
        if status in running_status:
            count += 1

    return count


def get_targets(BASE_URL, HEADERS):
    url = f"{BASE_URL}/targets"
    r = requests.get(url, headers=HEADERS, verify=False, timeout=30)
    return r.json().get("targets", [])


def filter_targets(targets):
    """
    只筛选：
    - 从未扫描
    - 扫描失败（允许重试）
    """
    result = []

    for t in targets:
        last_status = t.get("last_scan_session_status")

        if last_status in [None]:
            result.append(t)

    return result


def start_scan(target_id, BASE_URL, HEADERS):
    url = f"{BASE_URL}/scans"

    payload = {
        "target_id": target_id,
        "profile_id": PROFILE_ID,
        "schedule": {
            "disable": False
        }
    }

    try:
        r = requests.post(url, json=payload, headers=HEADERS, verify=False, timeout=30)

        if r.status_code in [200, 201]:
            logging.info(f"[+] 启动扫描成功: {target_id}")
        else:
            logging.error(f"[!] 启动扫描失败: {target_id} -> {r.text}")

    except Exception as e:
        logging.error(f"[!] 请求异常: {target_id} -> {e}")


# ================== 主调度 ==================

def main(api_url, headers,MAX_RUNNING=5, MAX_SAFE=10, SLEEP_TIME=60):
    print("============================== AWVS自动化任务调度v1.0 ==============================")
    while True:
        try:
            running = get_running_scans(api_url, headers)
            logging.info(f"当前真实扫描数: {running}")

            # 安全保护（非常关键）
            if running > MAX_SAFE:
                logging.error(f"检测到异常扫描数量 ({running})，暂停调度！")
                time.sleep(SLEEP_TIME)
                continue

            if running < MAX_RUNNING:
                need = MAX_RUNNING - running
                logging.info(f"需要补充扫描任务: {need}")

                targets = get_targets(api_url, headers)
                candidates = filter_targets(targets)

                if not candidates:
                    logging.warning("没有可用目标（全部已扫描完成）")
                else:
                    for t in candidates[:need]:
                        start_scan(t["target_id"], api_url, headers)

            else:
                logging.info("扫描池已满，无需补充")

        except Exception as e:
            logging.exception(f"调度异常: {e}")

        time.sleep(SLEEP_TIME)


if __name__ == "__main__":
    print(logo)
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--time', type=int, default=60, help="检测间隔（默认60秒）")
    parser.add_argument('--target',help="AWVS主机地址")
    parser.add_argument('-p', '--port', type=int, default=3443, help="AWVS端口（默认3443）")
    parser.add_argument('-k', '--key', help="AWVS API Key")
    parser.add_argument('--threads', type=int, default=5, help="目标并发扫描数（默认5）")
    parser.add_argument('--size', type=int, default=10, help="扫描目标数量上限（默认10）")
    args = parser.parse_args()
    api_url = f"https://{args.target}:{args.port}/api/v1"
    
    MAX_RUNNING = args.threads          # 目标并发数
    MAX_SAFE = args.size            # 目标提交上限
    SLEEP_TIME = args.time           # 检测间隔
    PROFILE_ID = "11111111-1111-1111-1111-111111111111"
    HEADERS = {
        "X-Auth": args.key,
        "Content-Type": "application/json"
    }
    main(api_url, HEADERS, MAX_RUNNING, MAX_SAFE, SLEEP_TIME)
