import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import urllib3
from tqdm import tqdm
import time
import sys
import random
import socket
from ipaddress import ip_network, IPv4Address, IPv6Address
import argparse
import threading
from queue import Queue, Empty

# 解决requests请求出现的InsecureRequestWarning错误
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 定义颜色
GREEN, RED, YELLOW, BLUE, MAGENTA, CYAN, RESET = "\033[92m", "\033[91m", "\033[93m", "\033[94m", "\033[95m", "\033[96m", "\033[0m"

# 随机 User-Agent 列表
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/114.0.1823.58",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]

def get_random_headers():
    """随机生成请求头"""
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "Cache-Control": "max-age=0",
    }

# --- 代理获取与验证 ---

def fetch_proxy_pool(proxy_urls):
    """从多个远程地址获取代理池"""
    all_proxies = []
    for url in proxy_urls:
        try:
            # 特殊处理 spys.one，因为它需要爬虫而不是直接文本文件
            if "spys.one" in url:
                print(f"[*] 正在从 spys.one 爬取代理列表...")
                # 简化的 HTML 解析逻辑 (需要 BeautifulSoup 或 Selenium 进行更准确的解析)
                # 这里只是一个示例，实际应用中可能需要更复杂的解析
                headers = get_random_headers()
                response = requests.get(url, headers=headers, timeout=15)
                if response.status_code == 200:
                    # 基于正则表达式提取 IP 和端口
                    pattern = r'<font class=spy14>(\d+\.\d+\.\d+\.\d+)</font>\s*<font class=spy14>:</font>\s*<font class=spy14>(\d+)</font>'
                    matches = re.findall(pattern, response.text)
                    proxies_from_spys = [f"{ip}:{port}" for ip, port in matches]
                    all_proxies.extend(proxies_from_spys)
                    print(f"[+] 从 spys.one 成功爬取到 {len(proxies_from_spys)} 个代理")
                else:
                    print(f"{RED}[-] 从 spys.one 爬取失败，HTTP 状态码: {response.status_code}{RESET}")
                continue # 跳过标准的文本文件处理

            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                proxies = response.text.strip().splitlines()
                cleaned_proxies = [p.strip() for p in proxies if p.strip()]
                all_proxies.extend(cleaned_proxies)
                print(f"[+] 从 {url} 成功拉取 {len(cleaned_proxies)} 个代理")
            else:
                print(f"{RED}[-] 从 {url} 拉取失败，HTTP 状态码: {response.status_code}{RESET}")
        except Exception as e:
            print(f"{RED}[-] 从 {url} 拉取失败: {str(e)}{RESET}")
    return all_proxies

def test_proxy_alive(proxy):
    """测试代理是否存活"""
    test_url = "http://www.baidu.com"  # 测试目标
    try:
        headers = get_random_headers()
        response = requests.get(
            test_url,
            proxies={"http": f"http://{proxy}", "https": f"https://{proxy}"},
            headers=headers,
            timeout=5,  # 超时时间
            verify=False
        )
        if response.status_code == 200:
            print(f"{GREEN}[+] 代理存活: {proxy}{RESET}")
            return proxy
    except Exception:
        pass  # 不输出代理不可用的信息
    return None

# --- 线程安全的代理池 ---

class SafeProxyPool:
    def __init__(self):
        self._lock = threading.Lock()
        self._pool = []

    def put(self, proxy):
        """将一个代理放入池中"""
        with self._lock:
            if proxy not in self._pool: # 简单去重
                 self._pool.append(proxy)
            # 可选：限制池子大小
            # MAX_POOL_SIZE = 1000
            # if len(self._pool) > MAX_POOL_SIZE:
            #     self._pool.pop(0)

    def get(self):
        """从池中随机取出一个代理，如果没有则返回 None"""
        with self._lock:
            if self._pool:
                return random.choice(self._pool)
            return None

    def size(self):
        """获取池中代理数量"""
        with self._lock:
            return len(self._pool)

# --- 后台代理验证器 ---

class BackgroundProxyValidator:
    def __init__(self, proxy_urls, safe_pool, stop_event):
        self.proxy_urls = proxy_urls
        self.safe_pool = safe_pool
        self.stop_event = stop_event
        self.validator_thread = None

    def _fetch_all_proxies(self):
        """从所有URL获取原始代理列表"""
        return fetch_proxy_pool(self.proxy_urls)

    def _validate_and_store(self, proxy):
        """验证单个代理并存入安全池"""
        if self.stop_event.is_set():
            return
        result = test_proxy_alive(proxy)
        if result and not self.stop_event.is_set():
            self.safe_pool.put(result)
            print(f"{GREEN}[+] 代理 {result} 已加入可用池 (当前池大小: {self.safe_pool.size()}){RESET}")

    def run_validation(self):
        """运行后台验证的主要逻辑"""
        print("[*] 启动后台代理验证器...")
        all_proxies = self._fetch_all_proxies()
        print(f"[+] 总共拉取到 {len(all_proxies)} 个原始代理")
        # 使用 ThreadPoolExecutor 进行并发验证
        with ThreadPoolExecutor(max_workers=100) as pool:
            # 提交所有验证任务
            futures = [pool.submit(self._validate_and_store, proxy) for proxy in all_proxies]
            # 等待所有任务完成或收到停止信号
            for future in as_completed(futures):
                if self.stop_event.is_set():
                    # 如果收到停止信号，取消未完成的任务（可选）
                    for f in futures:
                        f.cancel()
                    break
                # 获取结果（虽然是 None，但 as_completed 会等待）
                try:
                    future.result(timeout=0.1) # 短超时检查
                except:
                    pass # 忽略单个任务的异常
        print(f"[*] 后台代理验证完成。最终可用池大小: {self.safe_pool.size()}")

    def start(self):
        """启动后台验证线程"""
        self.validator_thread = threading.Thread(target=self.run_validation, daemon=True)
        self.validator_thread.start()

    def stop(self):
        """停止后台验证（通过事件）"""
        self.stop_event.set()
        if self.validator_thread:
            self.validator_thread.join()


# --- 核心功能函数 ---

def extract_domains(text):
    """从文本中提取域名"""
    return list(set(re.findall(r'(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})*)', text)))

def is_valid_ip(address):
    """检查是否为有效的 IPv4 或 IPv6 地址"""
    try:
        IPv4Address(address) or IPv6Address(address)
        return True
    except Exception:
        return False

def expand_ip_range(ip_range):
    """展开 IP 范围（如 154.86.30.12-233）"""
    try:
        start_ip, end_suffix = ip_range.split("-")
        start_parts = list(map(int, start_ip.split(".")))
        end_suffix = int(end_suffix)
        return [f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.{i}" for i in range(start_parts[3], end_suffix + 1)]
    except Exception:
        return []

def expand_cidr(cidr):
    """展开 CIDR（如 154.86.32.0/24）"""
    try:
        network = ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except Exception:
        return []

def reverse_ip_lookup(ip, retries=5, proxy=None):
    """
    查询 IP 地址对应的域名。
    :param ip: 要查询的 IP 地址
    :param retries: 最大重试次数
    :param proxy: 使用的代理
    :return: 域名列表（可能为空）
    """
    for attempt in range(retries):
        try:
            headers = get_random_headers()
            proxies = {"http": f"http://{proxy}", "https": f"https://{proxy}"} if proxy else None
            response = requests.get(
                f"http://api.webscan.cc/?action=query&ip={ip}",
                headers=headers,
                proxies=proxies,
                timeout=60
            )
            if response.status_code == 200:
                try:
                    data = response.json()
                except ValueError:
                    print(f"{RED}[-] 无法解析 JSON 数据: {response.text}{RESET}")
                    return []
                if isinstance(data, list) and len(data) > 0:
                    domains = [item.get("domain", "未知域名") for item in data]
                    print(f"IP: {ip} 匹配到以下域名: {', '.join(domains)}")
                    return domains
                else:
                    return []
            elif response.status_code == 530:
                wait_time = (2 ** attempt) + random.uniform(0, 1)  # 指数退避 + 随机抖动
                time.sleep(wait_time)
                continue
            else:
                print(f"{RED}[*] IP反查错误 (IP: {ip}): 状态码 {response.status_code}{RESET}")
                return []
        except requests.exceptions.RequestException as e:
            print(f"{RED}[*] IP反查错误 (IP: {ip}): {str(e)}{RESET}")
            if attempt < retries - 1:
                wait_time = (2 ** attempt) + random.uniform(0, 1)  # 指数退避 + 随机抖动
                time.sleep(wait_time)
            else:
                print("达到最大重试次数，尝试使用本地 DNS 解析...")
                return reverse_ip_lookup_local(ip)

def reverse_ip_lookup_local(ip, retries=3):
    """
    使用本地 DNS 反向解析 IP 地址。
    :param ip: 要查询的 IP 地址
    :param retries: 最大重试次数
    :return: 域名列表（可能为空）
    """
    for attempt in range(retries):
        try:
            print(f"正在使用本地 DNS 解析 IP: {ip} (尝试 {attempt + 1}/{retries})")
            hostname, _, _ = socket.gethostbyaddr(ip)
            print(f"IP: {ip} 匹配到域名: {hostname}")
            return [hostname]
        except socket.herror as e:
            print(f"{RED}[*] 本地 DNS 解析失败 (IP: {ip}): {str(e)}{RESET}")
            if attempt < retries - 1:
                time.sleep(2)
            else:
                return []

def check_domain_alive(domain, proxy=None):
    """检查域名是否存活（状态码为200）"""
    try:
        for protocol in ["http", "https"]:
            headers = get_random_headers()
            proxies = {"http": f"http://{proxy}", "https": f"https://{proxy}"} if proxy else None
            response = requests.head(
                f"{protocol}://{domain}",
                timeout=10,
                verify=False,
                allow_redirects=True,
                proxies=proxies,
                headers=headers
            )
            if response.status_code == 200:
                print(f"{GREEN}[+] 域名存活: {domain}{RESET}")
                return domain
    except Exception:
        pass  # 不输出域名不可用的信息
    return None

def query_baidu_weight(domains, proxy=None):
    """主权重查询接口（爱站API）"""
    api_url = "https://apistore.aizhan.com/baidurank/siteinfos/da469aa5731b6837193e0e8c19bebb96"
    try:
        headers = get_random_headers()
        proxies = {"http": f"http://{proxy}", "https": f"https://{proxy}"} if proxy else None
        response = requests.get(
            api_url,
            params={"domains": "|".join(domains)},
            timeout=10,
            verify=False,
            proxies=proxies,
            headers=headers
        )
        if response.status_code == 200 and response.json().get("code") == 200000:
            return response.json()["data"]["success"]
    except Exception as e:
        print(f"{RED}[*] 百度权重查询错误: {str(e)}{RESET}")
    return []

def process_input_file(input_file):
    """处理输入文件，提取所有域名和 IP 地址"""
    domains, ips = [], []
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            lines = [line.strip().split("#")[0] for line in f if line.strip() and not line.strip().startswith("#")]
    except FileNotFoundError:
        print(f"{RED}[-] 错误：未找到文件 {input_file}{RESET}")
        return [], []

    for line in lines:
        # 如果是 URL（包含 http:// 或 https://），去掉协议部分并归类为域名
        if line.startswith("http://") or line.startswith("https://"):
            domain = re.sub(r'^https?://', '', line).split('/')[0]
            domains.append(domain)
            continue

        # 如果是 IP 地址或范围
        if "/" in line:  # CIDR 格式
            ips.extend(expand_cidr(line))
        elif "-" in line and "." in line:  # IP 范围格式
            ips.extend(expand_ip_range(line))
        elif is_valid_ip(line):  # 单个 IP 地址
            ips.append(line)
        else:  # 域名
            domains.extend(extract_domains(line))

    return list(set(domains)), list(set(ips))

def process_ips_and_domains(input_file):
    output_file, alive_file = "results.csv", "alive.txt"

    # --- 1. 初始化代理相关组件 ---
    proxy_urls = [
        "https://raw.githubusercontent.com/XiaomingX/proxy-pool/refs/heads/main/proxy.txt",
        "https://raw.githubusercontent.com/watchttvv/free-proxy-list/refs/heads/main/proxy.txt",
        "https://raw.githubusercontent.com/parserpp/ip_ports/main/proxyinfo.txt",
        "https://spys.one/en/free-proxy-list/" # 添加 spys.one
        # 可以在这里添加更多代理源URL
    ]
    safe_proxy_pool = SafeProxyPool()
    stop_background_validator = threading.Event()
    background_validator = BackgroundProxyValidator(proxy_urls, safe_proxy_pool, stop_background_validator)

    # --- 2. 启动后台代理验证 ---
    background_validator.start()

    # --- 3. 等待初始一批代理 (可选，非必需) ---
    initial_wait_time = 5 # 秒
    print(f"[*] 等待 {initial_wait_time} 秒获取初始代理...")
    time_to_wait = initial_wait_time
    while time_to_wait > 0 and safe_proxy_pool.size() == 0:
        time.sleep(1)
        time_to_wait -= 1
    print(f"[+] 初始等待结束/有代理可用，当前可用代理数: {safe_proxy_pool.size()}")

    # --- 4. 提取域名和 IP 地址 ---
    domains, ips = process_input_file(input_file)
    print(f"[+] 提取到 {len(domains)} 个域名和 {len(ips)} 个 IP 地址")

    # --- 5. 初始化 CSV 文件 ---
    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        csv.writer(csvfile).writerow(["查询域名", "百度权重", "移动权重", "预计来路", "PC预计来路", "移动预计来路", "百度收录数量", "备案号"])

    # --- 6. 主任务处理 ---
    results_to_save = []
    with ThreadPoolExecutor(max_workers=50) as pool, open(alive_file, "w", encoding="utf-8") as alive_file_handle:
        # --- IP 反查域名 (使用后台提供的代理) ---
        print("[*] 开始 IP 反查域名...")
        with tqdm(total=len(ips), desc=f"{YELLOW}IP反查进度{RESET}", colour="yellow") as pbar:
            futures = []
            for ip in ips:
                # 从安全池获取代理
                proxy = safe_proxy_pool.get()
                futures.append(pool.submit(reverse_ip_lookup, ip, proxy=proxy))

            for future in as_completed(futures):
                domains_resolved = future.result()
                if domains_resolved:
                    domains.extend(domains_resolved)
                pbar.update(1)

        domains = list(set(domains)) # 去重
        print(f"[+] IP 反查完成后共找到 {len(domains)} 个域名")

        # --- 存活探测与后续查询 (继续使用后台提供的代理) ---
        print("[*] 开始域名存活探测与后续查询...")
        with tqdm(total=len(domains), desc=f"{MAGENTA}存活与后续查询进度{RESET}", colour="magenta") as pbar:
            futures = {pool.submit(check_domain_alive, domain, proxy=safe_proxy_pool.get()): domain for domain in domains}

            for future in as_completed(futures):
                domain = future.result() # 获取 check_domain_alive 的结果
                if domain:
                    alive_file_handle.write(f"{domain}\n")

                    # 启动权重查询等后续任务
                    weight_future = pool.submit(query_baidu_weight, [domain], proxy=safe_proxy_pool.get())
                    # icp_future = pool.submit(query_icp, domain, proxy=safe_proxy_pool.get()) # 占位符
                    # shoulu_future = pool.submit(check_baidu_shoulu, domain, proxy=safe_proxy_pool.get()) # 占位符

                    # 收集结果 (简化处理)
                    try:
                        weight_data = weight_future.result(timeout=30) # 设置超时
                        if weight_data and isinstance(weight_data, list) and len(weight_data) > 0:
                            w_data = weight_data[0]
                            results_to_save.append({
                                "domain": domain,
                                "pc_br": w_data.get("pc_br", "未找到"),
                                "m_br": w_data.get("m_br", "未找到"),
                                "ip": w_data.get("ip", "未找到"),
                                "pc_ip": w_data.get("pc_ip", "未找到"),
                                "m_ip": w_data.get("m_ip", "未找到"),
                                "baidu_shoulu": "未实现",
                                "filingnumber": "未实现",
                                "cms": "未实现"
                            })
                        else:
                             results_to_save.append({
                                "domain": domain,
                                "pc_br": "未找到",
                                "m_br": "未找到",
                                "ip": "未找到",
                                "pc_ip": "未找到",
                                "m_ip": "未找到",
                                "baidu_shoulu": "未实现",
                                "filingnumber": "未实现",
                                "cms": "未实现"
                            })
                    except Exception as e:
                        print(f"{RED}[-] 权重查询或结果处理超时/失败 for {domain}: {e}{RESET}")
                        # 即使失败也保存域名
                        results_to_save.append({
                            "domain": domain,
                            "pc_br": "查询失败",
                            "m_br": "查询失败",
                            "ip": "查询失败",
                            "pc_ip": "查询失败",
                            "m_ip": "查询失败",
                            "baidu_shoulu": "未实现",
                            "filingnumber": "未实现",
                            "cms": "未实现"
                        })

                pbar.update(1)


    # --- 7. 停止后台验证并保存结果 ---
    print("[*] 停止后台代理验证器...")
    background_validator.stop() # 通知后台线程停止
    print(f"[+] 最终可用代理池大小: {safe_proxy_pool.size()}")

    print("[*] 写入最终结果到 CSV 文件...")
    with open(output_file, "a", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        for r in results_to_save:
            writer.writerow([
                r["domain"], r["pc_br"], r["m_br"], r["ip"],
                r["pc_ip"], r["m_ip"], r["baidu_shoulu"], r["filingnumber"], r["cms"]
            ])

    print(f"\n[+] 结果已保存到 {output_file}")
    print(f"[+] 存活域名已保存到 {alive_file}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="终极IP反查域名并检测存活脚本")
    parser.add_argument("-f", "--file", required=True, help="指定目标文件路径（如 targets.txt）")
    parser.add_argument("-o", "--output", default="results.csv", help="指定输出文件路径（默认: results.csv）")
    parser.add_argument("-a", "--alive", default="alive.txt", help="指定存活域名输出文件路径（默认: alive.txt）")

    args = parser.parse_args()

    input_file = args.file
    output_file = args.output
    alive_file = args.alive

    process_ips_and_domains(input_file)
