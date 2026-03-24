import requests
import time
import logging
import argparse
import threading
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import os,signal
from datetime import datetime, timezone
# 禁用SSL警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logo = r"""
  ____  __    __  __ __   _____
 /    ||  |__|  ||  |  | / ___/
|  o  ||  |  |  ||  |  |(   \_ 
|     ||  |  |  ||  |  | \__  |
|  _  ||  `  '  ||  :  | /  \ |
|C |C | \ L  O /  \ V /  \  E | v3.0 - 2025-03-20
|__|__|  \_/\_/    \_/    \___| 若似月轮终皎洁，不辞冰雪为君热
------------------------------------------------------------
Author: 小猫之神在哭泣 (https://github.com/DuringApple)

一款基于AWVS API的自动化扫描任务调度工具，支持定时检测扫描状态并自动补充扫描任务，适用于大规模资产管理和持续安全监测。
新增了高危漏洞监控功能，配合钉钉机器人实现实时通知。还增加了服务器内存监控模式，防止过度扫描导致系统资源耗尽。
仅用于合法授权的环境，使用前请确保已获得相关权限。作者不对任何非法使用造成的后果负责。
"""

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
    cursor = None
    limit = 100   
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

def safe_mode_monitor(jc_time,occupancy):
    import psutil,os,ctypes,signal
    
    while True:
        mem = psutil.virtual_memory()
        print(f"[*] 当前内存使用率: {mem.percent}%")
        if mem.percent > occupancy:
            logging.warning(f"内存使用率过高: {mem.percent}%，终止调度！")
            pid = os.getppid()
            if os.name == 'nt':
                handle = ctypes.windll.kernel32.OpenProcess(1, False, pid)
            if handle:
                ctypes.windll.kernel32.TerminateProcess(handle, -1)
                ctypes.windll.kernel32.CloseHandle(handle)
            else:
                os.kill(pid, signal.SIGKILL)
                os.kill(os.getppid(), signal.SIGTERM) 
        else:
            time.sleep(jc_time)

def dingding_robot(api, headers, access_token, jc_time):

    record_file = "vuln_ids.txt"

    def load_old_ids():
        if os.path.exists(record_file):
            with open(record_file, "r") as f:
                return set(f.read().splitlines())
        return set()

    def save_ids(ids):
        with open(record_file, "w") as f:
            f.write("\n".join(ids))

    while True:
        try:
            r = requests.get(api, headers=headers, verify=False, timeout=30)
            data = r.json()

            vulns = data.get("vulnerabilities", [])

            current_ids = set()
            new_vulns = []

            for v in vulns:
                vid = v.get("vuln_id")
                if vid:
                    current_ids.add(vid)

            old_ids = load_old_ids()

            # 新增漏洞
            diff_ids = current_ids - old_ids

            if diff_ids:
                for v in vulns:
                    if v.get("vuln_id") in diff_ids:
                        new_vulns.append(v)

                type_counter = {}
                detail_lines = []

                for v in new_vulns:
                    name = v.get("vt_name", "未知漏洞")
                    url = v.get("affects_url", "未知URL")

                    type_counter[name] = type_counter.get(name, 0) + 1

                    detail_lines.append(f"- {name}\n  ↳ {url}")

                summary = "\n".join([f"{k}: {v}个" for k, v in type_counter.items()])
                details = "\n".join(detail_lines[:10])

                msg = f""""✨[+] 主人ちゃん～快看过来ヾ(≧∇≦)ﾉ！\n新发现了{len(diff_ids)}个高危漏洞哦～💥  要赶紧处理掉才行哦🥺

🚨新增漏洞总数：{len(diff_ids)}
📊 类型统计：
{summary}

📌 漏洞详情：
{details}
(仅展示前10条，更多请登录AWVS查看哦主人~~~❤)"""

                url = f"https://oapi.dingtalk.com/robot/send?access_token={access_token}"

                payload = {
                    "msgtype": "text",
                    "text": {"content": msg}
                }

                requests.post(url, json=payload)
                logging.info("钉钉通知发送成功")

            else:
                print("没有新增漏洞")

            save_ids(current_ids)

        except Exception as e:
            logging.error(f"钉钉机器人异常: {e}")

        time.sleep(jc_time)

from datetime import datetime

def parse_time(timestr):
    try:
        if timestr.endswith("Z"):
            timestr = timestr.replace("Z", "+00:00")
        return datetime.fromisoformat(timestr)
    except Exception as e:
        logging.warning(f"时间解析失败: {timestr} -> {e}")
        return None

def zombie_task(BASE_URL, HEADERS, access_token=None, jc_time=600):
    """
    僵尸任务监控线程（仅告警模式）
    - 监控超过阈值的长时间扫描任务
    - 只发送日志和钉钉告警，不删除扫描
    """

    logging.info("[*] 僵尸任务监控线程已启动（仅告警模式）")

    RUNNING_STATUS = ["processing"]
    ALERT_THRESHOLD = 6 * 3600  # 6小时

    notified = set()  # 已通知的扫描ID，避免重复告警

    def send_dingtalk(msg):
        """发送钉钉告警"""
        if not access_token:
            return
        try:
            url = f"https://oapi.dingtalk.com/robot/send?access_token={access_token}"
            payload = {
                "msgtype": "text",
                "text": {"content": msg}
            }
            requests.post(url, json=payload, timeout=10)
        except Exception as e:
            logging.error(f"钉钉发送失败: {e}")

    while True:
        try:
            all_scans = []
            cursor = None

            # 分页获取扫描列表
            while True:
                params = {"l": 100}
                if cursor:
                    params["c"] = cursor

                url = f"{BASE_URL}/scans"
                r = requests.get(url, headers=HEADERS, params=params, verify=False, timeout=30)
                r.raise_for_status()

                data = r.json()
                current = data.get("scans", [])
                all_scans.extend(current)

                pagination = data.get("pagination", {})
                next_cursor = pagination.get("next") or pagination.get("cursor")
                if not next_cursor:
                    break
                cursor = next_cursor
                time.sleep(0.2)  # 防止请求过快

            now = datetime.now(timezone.utc)

            for scan in all_scans:
                scan_id = scan.get("scan_id")
                session = scan.get("current_session") or {}
                status = session.get("status")

                # 只处理正在扫描的任务
                if status not in RUNNING_STATUS:
                    continue

                start_date = session.get("start_date")
                if not scan_id or not start_date:
                    continue

                start_time = parse_time(start_date)
                if not start_time:
                    continue

                duration = (now - start_time).total_seconds()
                if duration < ALERT_THRESHOLD:
                    continue

                if scan_id in notified:
                    continue  # 已通知过，不重复发送

                progress = session.get("progress", 0)
                target = scan.get("target", {}).get("address", "未知目标")

                msg = f"""⚠️ AWVS疑似僵尸扫描任务提醒！

🆔 Scan ID: {scan_id}
🎯 目标: {target}
📊 当前进度: {progress}%
⏱ 已运行时间: {int(duration/60)} 分钟
📌 状态: {status}

⚠️ 该任务运行时间较长，可能存在卡死或低效扫描，请确认是否需要人工干预。
"""

                logging.warning(f"[Zombie Alert] {scan_id} 运行{int(duration/60)}分钟，进度{progress}%")
                send_dingtalk(msg)
                notified.add(scan_id)

        except Exception as e:
            logging.error(f"僵尸任务检测异常: {e}")

        time.sleep(jc_time) 

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
                        time.sleep(1) # 启动扫描后稍作等待，避免过快触发API限制
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
    parser.add_argument('--safe-mode', action='store_true', default=False, help="启用内存监控模式")
    parser.add_argument('--dingtalk-robot', action='store_true',default=False,help="钉钉机器人启用后会在高危漏洞数量增加时发送通知")
    
    args = parser.parse_args()
    
    api_url = f"https://{args.target}:{args.port}/api/v1"
    loudong_api_url = f"https://{args.target}:{args.port}/api/v1/vulnerabilities?q=severity:3"
    zombie_task_api = f"https://{args.target}:{args.port}/api/v1"

    MAX_RUNNING = args.size          
    MAX_SAFE = args.size          
    SLEEP_TIME = args.time              
    PROFILE_ID = args.profile_id  
    safe_mode = args.safe_mode
    robot = args.dingtalk_robot      
    
    HEADERS = {
        "X-Auth": args.key,
        "Content-Type": "application/json"
    }


    def robot_pd(robot):
        if robot:
            access_token = input("[*] 请输入钉钉机器人Access_Token: ")
            print("\n+--------------------------------------------------------------+")
            print("| 钉钉机器人已启用 将在高危漏洞增加或疑似僵尸线程触发时发送通知 |")
            print("+--------------------------------------------------------------+\n")
            dingding_thread = threading.Thread(target=dingding_robot, args=(loudong_api_url, HEADERS, access_token,SLEEP_TIME), daemon=True)
            zombie_thread = threading.Thread(
            target=zombie_task,
            args=(zombie_task_api, HEADERS, access_token, 300),
            daemon=True
            )
            zombie_thread.start()
            dingding_thread.start()



    if safe_mode:
        occupancy = int(input("[*] 请输入内存占用安全上限（百分比，默认80）: ") or 80)
        robot_pd(robot)
        monitor_thread = threading.Thread(target=safe_mode_monitor, args=(SLEEP_TIME, occupancy), daemon=True)
        print("\n+-----------------------------------------+")
        print("| 内存监控线程启动 正在监测内存占用...... |")
        print("+-----------------------------------------+\n")
        monitor_thread.start()
        main(api_url, HEADERS, PROFILE_ID, MAX_RUNNING, MAX_SAFE, SLEEP_TIME)
    else:
        robot_pd(robot)
        main(api_url, HEADERS, PROFILE_ID, MAX_RUNNING, MAX_SAFE, SLEEP_TIME)
