# main.py
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
import json
import hashlib
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup # 需要安装: pip install beautifulsoup4
import threading
from queue import Queue

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
    """
    测试代理是否存活 (HTTP & HTTPS)。
    返回支持 HTTPS 的代理，或者 None。
    """
    test_urls = [
        ("http://www.baidu.com", "HTTP"),
        ("https://httpbin.org/get", "HTTPS") # 添加 HTTPS 测试
    ]
    supports_https = False

    for test_url, proto_name in test_urls:
        try:
            headers = get_random_headers()
            # 关键修改：HTTPS 代理 URL 也使用 http:// 前缀
            proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
            response = requests.get(
                test_url,
                proxies=proxies,
                headers=headers,
                timeout=5,  # 超时时间
                verify=False # 忽略证书错误
            )
            if response.status_code == 200:
                if proto_name == "HTTPS":
                    supports_https = True
            else:
                # 如果任何一个测试失败，认为代理不可用
                return None
        except requests.exceptions.SSLError as ssl_err:
            # 如果是 HTTPS 测试失败，不支持 HTTPS
            if proto_name == "HTTPS":
                supports_https = False
            else:
                # 如果 HTTP 都 SSL 错误，可能代理本身有问题
                return None
            break # 跳出循环
        except requests.exceptions.RequestException as req_err:
            # 任何请求错误都认为代理不可用
            return None
        except Exception as e:
            return None

    if supports_https:
        # print(f"{GREEN}[+] 代理存活且支持 HTTPS: {proxy}{RESET}") # 可选：显示成功信息
        return proxy # 只返回支持 HTTPS 的代理
    else:
        return None # 过滤掉不支持 HTTPS 的代理

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
    :param proxy: 使用的代理 (必须是支持 HTTPS 的)
    :return: 域名列表（可能为空）
    """
    for attempt in range(retries):
        try:
            headers = get_random_headers()
            # 关键修改：确保代理 URL 使用 http:// 前缀
            proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None
            response = requests.get(
                f"http://api.webscan.cc/?action=query&ip={ip}",
                headers=headers,
                proxies=proxies,
                timeout=60  # 增加超时时间到 60 秒
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                except ValueError:
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
                return []
        except requests.exceptions.RequestException as e:
            if attempt < retries - 1:
                wait_time = (2 ** attempt) + random.uniform(0, 1)  # 指数退避 + 随机抖动
                time.sleep(wait_time)
            else:
                return reverse_ip_lookup_local(ip)
    return []

def reverse_ip_lookup_local(ip, retries=3):
    """
    使用本地 DNS 反向解析 IP 地址。
    :param ip: 要查询的 IP 地址
    :param retries: 最大重试次数
    :return: 域名列表（可能为空）
    """
    for attempt in range(retries):
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            print(f"IP: {ip} 匹配到域名: {hostname}")
            return [hostname]
        except socket.herror as e:
            if attempt < retries - 1:
                time.sleep(2)
            else:
                return []

def check_domain_alive(domain, proxy=None):
    """检查域名是否存活（状态码为200）"""
    try:
        for protocol in ["http", "https"]:
            headers = get_random_headers()
            # 关键修改：确保代理 URL 使用 http:// 前缀
            proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None
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
                return domain, protocol # 返回域名和协议
    except Exception:
        pass  # 不输出域名不可用的信息
    return None, None

def query_baidu_weight(domains, proxy=None):
    """主权重查询接口（爱站API）"""
    api_url = "https://apistore.aizhan.com/baidurank/siteinfos/da469aa5731b6837193e0e8c19bebb96"
    try:
        headers = get_random_headers()
        # 关键修改：确保代理 URL 使用 http:// 前缀
        proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None
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
        pass
    return []

def query_backup_weight_1(domain, proxy=None):
    """第一备选权重查询接口（api.pearktrue.cn）"""
    api_url = "https://api.pearktrue.cn/api/website/weight.php"
    try:
        headers = get_random_headers()
        # 关键修改：确保代理 URL 使用 http:// 前缀
        proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None
        response = requests.get(
            api_url,
            params={"domain": domain},
            timeout=10,
            verify=False,
            proxies=proxies,
            headers=headers
        )
        if response.status_code == 200 and response.json().get("code") == 200:
            data = response.json()["data"]
            return {
                "domain": domain,
                "pc_br": data.get("BaiDu_PC", "未找到"),
                "m_br": data.get("BaiDu_Mobile", "未找到"),
                "ip": "未找到",
                "pc_ip": "未找到",
                "m_ip": "未找到"
            }
    except Exception as e:
        pass
    return {
        "domain": domain,
        "pc_br": "未找到",
        "m_br": "未找到",
        "ip": "未找到",
        "pc_ip": "未找到",
        "m_ip": "未找到"
    }

def query_icp(domain, proxy=None):
    """通过 https://api.pearktrue.cn/api/icp/ 查询备案号"""
    api_url = "https://api.pearktrue.cn/api/icp/"
    try:
        headers = get_random_headers()
        # 关键修改：确保代理 URL 使用 http:// 前缀
        proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None
        response = requests.get(
            api_url,
            params={"domain": domain},
            timeout=10,
            verify=False,
            proxies=proxies,
            headers=headers
        )
        if response.status_code == 200 and response.json().get("code") == 200:
            filingnumber = response.json()["data"].get("filingnumber", "未备案")
            return filingnumber
    except Exception as e:
        pass
    return "未备案"

def check_baidu_shoulu(domain, proxy=None):
    """检查百度收录数量"""
    try:
        headers = get_random_headers()
        # 关键修改：确保代理 URL 使用 http:// 前缀
        proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None
        response = requests.get(
            f"https://api.pearktrue.cn/api/website/shoulu.php?url={domain}",
            timeout=10,
            verify=False,
            proxies=proxies,
            headers=headers
        )
        if response.status_code == 200 and response.json().get("code") == 200:
            return response.json()["data"].get("baidu", "未收录")
    except Exception as e:
        pass
    return "未收录"

def load_fingerprints(filename='fingers.json'):
    """加载指纹库"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get("fingerprint", [])
    except FileNotFoundError:
        print(f"{RED}[-] 指纹文件 {filename} 未找到。{RESET}")
        return []
    except json.JSONDecodeError:
        print(f"{RED}[-] 指纹文件 {filename} 格式错误。{RESET}")
        return []

def fingerprint_analysis(domain, protocol, fingerprints, proxy=None):
    """指纹识别"""
    url = f"{protocol}://{domain}"
    try:
        headers = get_random_headers()
        # 关键修改：确保代理 URL 使用 http:// 前缀
        proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None

        # 获取主页内容
        response = requests.get(url, timeout=10, verify=False, allow_redirects=True, headers=headers, proxies=proxies)
        content = response.text.lower()
        soup = BeautifulSoup(response.content, 'html.parser')

        for finger in fingerprints:
            location = finger.get('location', '').lower()
            keywords = finger.get('keyword', [])
            cms = finger.get('cms', 'Unknown CMS')

            if not keywords:
                continue

            found = False
            if location == 'body':
                if any(kw.lower() in content for kw in keywords):
                    found = True
            elif location == 'title':
                title_tag = soup.find('title')
                if title_tag and title_tag.string:
                    title_text = title_tag.string.lower()
                    if any(kw.lower() in title_text for kw in keywords):
                        found = True
            elif location == 'header':
                 # 检查响应头
                for k, v in response.headers.items():
                    header_line = f"{k}: {v}".lower()
                    if any(kw.lower() in header_line for kw in keywords):
                        found = True
                        break
            elif location == 'faviconhash':
                # 获取 favicon 并计算 hash
                try:
                    parsed_url = urlparse(url)
                    favicon_url = urljoin(url, '/favicon.ico')
                    fav_response = requests.get(favicon_url, timeout=10, verify=False, headers=headers, proxies=proxies)
                    if fav_response.status_code == 200:
                        favicon_hash = hashlib.md5(fav_response.content).hexdigest()
                        if favicon_hash in keywords:
                            found = True
                except Exception:
                    pass # 忽略 favicon 获取错误

            if found:
                print(f"{GREEN}[+] 指纹识别成功: {domain} -> {cms}{RESET}")
                return cms

    except requests.exceptions.SSLError:
        pass
    except requests.exceptions.ConnectionError:
        pass
    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.RequestException:
        pass
    except Exception as e:
        pass

    return "未识别"

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
        elif "-" in line:  # IP 范围格式
            ips.extend(expand_ip_range(line))
        elif is_valid_ip(line):  # 单个 IP 地址
            ips.append(line)
        else:  # 域名
            domains.extend(extract_domains(line))

    return list(set(domains)), list(set(ips))

def get_user_proxy_choice():
    """获取用户是否使用代理的选择"""
    while True:
        print("\n请选择是否使用代理:")
        print("1. 使用代理")
        print("2. 不使用代理")
        choice = input("请输入选择 (1 或 2): ").strip()
        if choice == "1":
            return True
        elif choice == "2":
            return False
        else:
            print(f"{RED}无效输入，请输入 1 或 2{RESET}")

def process_ips_and_domains(input_file, output_file="results.csv", alive_file="alive.txt", use_proxy=True):
    """主处理函数"""
    # 加载指纹库
    fingerprints = load_fingerprints()
    print(f"[+] 成功加载 {len(fingerprints)} 个指纹规则")

    # 初始化代理相关组件（如果使用代理）
    safe_proxy_pool = None
    stop_background_validator = None
    background_validator = None
    
    if use_proxy:
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
    else:
        print("[*] 未使用代理模式")

    # --- 4. 提取域名和 IP 地址 ---
    domains, ips = process_input_file(input_file)
    print(f"[+] 提取到 {len(domains)} 个域名和 {len(ips)} 个 IP 地址")

    # --- 5. 初始化 CSV 文件 ---
    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        csv.writer(csvfile).writerow(["查询域名", "百度权重", "移动权重", "预计来路", "PC预计来路", "移动预计来路", "百度收录数量", "备案号", "指纹识别"])

    # --- 6. 主任务处理 ---
    results_to_save = []
    
    # 使用上下文管理器确保文件正确关闭
    with ThreadPoolExecutor(max_workers=50) as pool:
        # 使用文件句柄，手动控制刷新
        alive_file_handle = open(alive_file, "w", encoding="utf-8")
        try:
            # --- IP 反查域名 (使用后台提供的代理) ---
            print("[*] 开始 IP 反查域名...")
            with tqdm(total=len(ips), desc=f"{YELLOW}IP反查进度{RESET}", colour="yellow") as pbar:
                futures = []
                for ip in ips:
                    # 根据是否使用代理选择代理
                    proxy = None
                    if use_proxy and safe_proxy_pool:
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
                futures = {}
                for domain in domains:
                    # 根据是否使用代理选择代理
                    proxy = None
                    if use_proxy and safe_proxy_pool:
                        proxy = safe_proxy_pool.get()
                    futures[pool.submit(check_domain_alive, domain, proxy=proxy)] = domain

                for future in as_completed(futures):
                    domain, protocol = future.result() # 获取 check_domain_alive 的结果
                    if domain:
                        # 立即写入 alive.txt 并刷新
                        alive_file_handle.write(f"{domain}\n")
                        alive_file_handle.flush() # 强制刷新缓冲区

                        # 启动权重查询等后续任务
                        # 根据是否使用代理选择代理
                        proxy = None
                        if use_proxy and safe_proxy_pool:
                            proxy = safe_proxy_pool.get()
                        
                        weight_future = pool.submit(query_baidu_weight, [domain], proxy=proxy)
                        icp_future = pool.submit(query_icp, domain, proxy=proxy)
                        shoulu_future = pool.submit(check_baidu_shoulu, domain, proxy=proxy)
                        fingerprint_future = pool.submit(fingerprint_analysis, domain, protocol, fingerprints, proxy=proxy)

                        # 收集结果 (简化处理)
                        weight_data = weight_future.result()
                        if not weight_data:  # 如果主API失败，使用备选API
                            # 根据是否使用代理选择代理
                            proxy_for_backup = None
                            if use_proxy and safe_proxy_pool:
                                proxy_for_backup = safe_proxy_pool.get()
                            weight_data = [query_backup_weight_1(domain, proxy=proxy_for_backup)]

                        icp_data = icp_future.result()
                        shoulu_data = shoulu_future.result()
                        fingerprint_data = fingerprint_future.result()

                        result_dict = {
                            "domain": domain,
                            "pc_br": weight_data[0].get("pc_br", "未找到") if isinstance(weight_data[0], dict) else "未找到",
                            "m_br": weight_data[0].get("m_br", "未找到") if isinstance(weight_data[0], dict) else "未找到",
                            "ip": weight_data[0].get("ip", "未找到") if isinstance(weight_data[0], dict) else "未找到",
                            "pc_ip": weight_data[0].get("pc_ip", "未找到") if isinstance(weight_data[0], dict) else "未找到",
                            "m_ip": weight_data[0].get("m_ip", "未找到") if isinstance(weight_data[0], dict) else "未找到",
                            "baidu_shoulu": shoulu_data,
                            "filingnumber": icp_data,
                            "cms": fingerprint_data
                        }
                        
                        # 立即写入 CSV 文件并刷新
                        with open(output_file, "a", newline="", encoding="utf-8") as csvfile:
                            writer = csv.writer(csvfile)
                            writer.writerow([
                                result_dict["domain"], 
                                result_dict["pc_br"], 
                                result_dict["m_br"], 
                                result_dict["ip"],
                                result_dict["pc_ip"], 
                                result_dict["m_ip"], 
                                result_dict["baidu_shoulu"], 
                                result_dict["filingnumber"], 
                                result_dict["cms"]
                            ])
                        # 将结果保存到内存中用于最终显示
                        results_to_save.append(result_dict)

                    pbar.update(1)
        finally:
            # 确保文件关闭
            alive_file_handle.close()

    # --- 7. 停止后台验证并保存结果 ---
    if use_proxy and background_validator:
        print("[*] 停止后台代理验证器...")
        background_validator.stop() # 通知后台线程停止
        print(f"[+] 最终可用代理池大小: {safe_proxy_pool.size()}")
    else:
        print("[*] 未使用代理，跳过后台验证器停止")

    print(f"\n[+] 结果已保存到 {output_file}")
    print(f"[+] 存活域名已保存到 {alive_file}")

if __name__ == '__main__':
    # 首先询问用户是否使用代理
    use_proxy = get_user_proxy_choice()
    
    # 添加命令行参数解析
    parser = argparse.ArgumentParser(description="终极IP反查域名并检测存活脚本")
    parser.add_argument("-f", "--file", required=True, help="指定目标文件路径（如 targets.txt）")
    parser.add_argument("-o", "--output", default="results.csv", help="指定输出文件路径（默认: results.csv）")
    parser.add_argument("-a", "--alive", default="alive.txt", help="指定存活域名输出文件路径（默认: alive.txt）")

    args = parser.parse_args()

    input_file = args.file
    output_file = args.output
    alive_file = args.alive

    process_ips_and_domains(input_file, output_file, alive_file, use_proxy)
