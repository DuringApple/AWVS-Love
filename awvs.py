import requests
import time
import logging
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 禁用SSL警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logo = r"""
  ____  __    __  __ __   _____
 /    ||  |__|  ||  |  | / ___/
|  o  ||  |  |  ||  |  |(   \_ 
|     ||  |  |  ||  |  | \__  |
|  _  ||  `  '  ||  :  | /  \ |
|C |C | \ L  O /  \ V /  \  E | v2.0 - 2025-03-19
|__|__|  \_/\_/    \_/    \___| 若似月轮终皎洁，不辞冰雪为君热
------------------------------------------------------------
Author: 小猫之神在哭泣 (https://github.com/DuringApple)

一款基于AWVS API的自动化扫描任务调度工具，支持定时检测扫描状态并自动补充扫描任务，适用于大规模资产管理和持续安全监测。
仅用于合法授权的环境，使用前请确保已获得相关权限。作者不对任何非法使用造成的后果负责。
"""

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("awvs_scheduler.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)

def get_all_scans(BASE_URL, HEADERS):

    all_scans = []
    cursor = None
    limit = 100
    page = 1
    
    while True:
        try:
            params = {"l": limit}
            if cursor:
                params["c"] = cursor
                
            url = f"{BASE_URL}/scans"
            r = requests.get(
                url, 
                headers=HEADERS, 
                params=params,
                verify=False, 
                timeout=30
            )
            r.raise_for_status()
            
            response_data = r.json()
            current_scans = response_data.get("scans", [])
            all_scans.extend(current_scans)
            
            pagination = response_data.get("pagination", {})
            next_cursor = pagination.get("next") or pagination.get("cursor")
            if not next_cursor or len(current_scans) < limit:
                break
                
            cursor = next_cursor
            page += 1
            time.sleep(0.5)
            
        except Exception as e:
            logging.error(f"获取扫描列表失败（第{page}页）: {e}")
            break
    
    running_status = ["processing", "starting", "queued"]
    running_target_ids = set()
    for scan in all_scans:
        if scan.get("target_id"):
            status = scan.get("current_session", {}).get("status") or scan.get("status")
            if status in running_status:
                running_target_ids.add(scan["target_id"])
    
    return len(running_target_ids), running_target_ids

def get_targets(BASE_URL, HEADERS):

    all_targets = []
    cursor = None  # 分页游标
    limit = 100    # 每页数量
    page = 1
    
    while True:
        try:
            params = {"l": limit}
            if cursor:
                params["c"] = cursor
            
            url = f"{BASE_URL}/targets"
            r = requests.get(
                url, 
                headers=HEADERS, 
                params=params,
                verify=False, 
                timeout=30
            )
            r.raise_for_status()
            
            response_data = r.json()
            current_page_targets = response_data.get("targets", [])
            current_count = len(current_page_targets)
            

            all_targets.extend(current_page_targets)
            logging.info(f"第{page}页获取到 {current_count} 个目标，累计 {len(all_targets)} 个")
            

            pagination = response_data.get("pagination", {})
            next_cursor = pagination.get("next") or pagination.get("cursor")
            
            if not next_cursor and current_count < limit:
                break
            

            if next_cursor:
                cursor = next_cursor
            else:
                cursor = str(page * limit)
            
            page += 1
            time.sleep(0.5)
            
        except requests.exceptions.RequestException as e:
            logging.error(f"获取目标失败（第{page}页）: {e}")
            break
        except Exception as e:
            logging.error(f"解析目标失败（第{page}页）: {e}")
            break
    
    logging.info(f"最终获取到所有目标总数: {len(all_targets)}")
    return all_targets

def filter_targets(targets, running_target_ids):

    result = []
    retry_status = [None]
    #retry_status = [None, "failed", "aborted", "canceled", "timeout"]
    
    for t in targets:
        target_id = t.get("target_id")
        target_name = t.get("address", "未知目标")
        last_status = t.get("last_scan_session_status")
        
        if target_id in running_target_ids:
            logging.debug(f"目标 {target_name} ({target_id}) 正在扫描，跳过")
            continue
        
        if last_status in retry_status:
            result.append(t)
            logging.debug(f"目标 {target_name} ({target_id}) 加入队列，状态: {last_status or '从未扫描'}")
    
    logging.info(f"筛选出需要扫描的目标总数: {len(result)} (已排除 {len(running_target_ids)} 个正在扫描的目标)")
    return result

def start_scan(target_id, BASE_URL, HEADERS, PROFILE_ID):
    """启动单个目标的扫描任务"""
    url = f"{BASE_URL}/scans"
    payload = {
        "target_id": target_id,
        "profile_id": PROFILE_ID,
        "schedule": {
            "disable": False,
            "start_date": None,
            "time_sensitive": False
        }
    }

    try:
        r = requests.post(url, json=payload, headers=HEADERS, verify=False, timeout=60)
        
        if r.status_code in [200, 201]:
            logging.info(f"[+] 启动扫描成功: {target_id} ({r.json().get('scan_id', '未知扫描ID')})")
            return True
        else:
            logging.error(f"[!] 启动扫描失败: {target_id} -> 状态码: {r.status_code}, 响应: {r.text}")
            return False
    except requests.exceptions.RequestException as e:
        logging.error(f"[!] 请求异常: {target_id} -> {e}")
        return False
    except Exception as e:
        logging.error(f"[!] 启动扫描异常: {target_id} -> {e}")
        return False

# ================== 主调度 ==================
def main(api_url, headers, profile_id, MAX_RUNNING=5, MAX_SAFE=5, SLEEP_TIME=60):
    print("============================== AWVS自动化任务调度v2.0 ==============================")
    logging.info("AWVS自动化调度程序启动")
    logging.info(f"配置参数 - 最大并发扫描数: {MAX_RUNNING}, 安全上限: {MAX_SAFE}, 检测间隔: {SLEEP_TIME}秒")
    
    while True:
        try:

            running_count, running_target_ids = get_all_scans(api_url, headers)
            
            if running_count == -1:
                logging.warning("获取扫描状态失败，跳过本次检测")
                time.sleep(SLEEP_TIME)
                continue
            
            logging.info(f"当前运行中的扫描数: {running_count}")

            if running_count > MAX_SAFE:
                logging.error(f"检测到异常扫描数量 ({running_count} > {MAX_SAFE})，暂停调度！")
                time.sleep(SLEEP_TIME)
                continue

            if running_count < MAX_RUNNING:
                need = MAX_RUNNING - running_count
                logging.info(f"需要补充 {need} 个扫描任务")

                targets = get_targets(api_url, headers)
                if not targets:
                    logging.warning("未获取到任何目标")
                    time.sleep(SLEEP_TIME)
                    continue
                    
                candidates = filter_targets(targets, running_target_ids)

                if not candidates:
                    logging.info("没有需要扫描的目标（全部已扫描完成/无失败任务）")
                else:
                    for t in candidates[:need]:
                        start_scan(t["target_id"], api_url, headers, profile_id)
            else:
                logging.info(f"当前扫描数 ({running_count}) 已达上限 ({MAX_RUNNING})，无需补充")

        except Exception as e:
            logging.exception(f"调度主循环异常: {e}")

        time.sleep(SLEEP_TIME)

if __name__ == "__main__":
    print(logo)
    parser = argparse.ArgumentParser(description="AWVS API 自动化扫描任务调度工具")
    parser.add_argument('-t', '--time', type=int, default=60, help="检测间隔（秒），默认60秒")
    parser.add_argument('--target', required=True, help="AWVS主机地址（必填）")
    parser.add_argument('-p', '--port', type=int, default=3443, help="AWVS端口，默认3443")
    parser.add_argument('-k', '--key', required=True, help="AWVS API Key（必填）")
    parser.add_argument('--threads', type=int, default=5, help="最大并发扫描数，默认5")
    parser.add_argument('--size', type=int, default=5, help="扫描数量安全上限（超过则暂停），默认5")
    parser.add_argument('--profile-id', default="11111111-1111-1111-1111-111111111111", 
                        help="扫描配置文件ID，默认全扫描(11111111-1111-1111-1111-111111111111)")
    
    args = parser.parse_args()
    
    api_url = f"https://{args.target}:{args.port}/api/v1"
    
    MAX_RUNNING = args.threads          
    MAX_SAFE = args.size          
    SLEEP_TIME = args.time              
    PROFILE_ID = args.profile_id        
    
    HEADERS = {
        "X-Auth": args.key,
        "Content-Type": "application/json"
    }
    
    main(api_url, HEADERS, PROFILE_ID, MAX_RUNNING, MAX_SAFE, SLEEP_TIME)
