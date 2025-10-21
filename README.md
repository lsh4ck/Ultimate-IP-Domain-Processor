# Ultimate IP/Domain Processor

一个强大的 Python 脚本，用于批量处理 IP 地址和域名。该脚本能够从多种来源获取免费代理，验证其有效性，并利用这些代理池来执行一系列网络信息搜集任务，包括但不限于 IP 反向域名查询 (Reverse DNS Lookup)、域名存活检测、网站权重查询等。

## 功能特性

*   **多源代理池聚合**:
    *   从多个公开的 GitHub 仓库 (如 `XiaomingX/proxy-pool`, `watchttvv/free-proxy-list`, `parserpp/ip_ports`) 拉取 HTTP/HTTPS 代理列表。
    *   **计划中/可扩展**: 可轻松扩展以支持从其他来源（如 `spys.one` 网页爬取）获取代理。
*   **智能代理验证**:
    *   并发测试代理的存活状态，快速过滤出可用代理。
    *   **计划中/可扩展**: 可区分并验证不同类型代理 (HTTP, HTTPS, SOCKS5)。
*   **灵活的输入处理**:
    *   支持读取包含以下内容的文本文件作为输入：
        *   单个 IPv4/IPv6 地址 (e.g., `192.168.1.1`)
        *   CIDR 网络范围 (e.g., `192.168.1.0/24`)
        *   IP 范围 (e.g., `192.168.1.1-100`)
        *   域名 (e.g., `example.com`)
        *   完整 URL (e.g., `http://example.com/path`)
*   **高效的并发执行**:
    *   利用 `ThreadPoolExecutor` 实现多线程并发处理，大幅提升任务执行效率。
*   **核心信息搜集任务**:
    *   **IP 反向域名查询 (Reverse DNS Lookup)**:
        *   对输入的 IP 地址或范围进行反向 DNS 查询，获取关联的域名。
        *   支持调用在线 API (如 `api.webscan.cc`) 和本地 DNS 解析作为备用方案。
    *   **域名存活检测**:
        *   检查解析出的或直接输入的域名是否可以通过 HTTP/HTTPS 访问 (状态码 200)。
    *   **网站权重查询**:
        *   调用第三方 API (如 爱站网) 查询域名的百度权重、移动权重等信息。
    *   **计划中/可扩展**:
        *   查询百度收录数量。
        *   查询 ICP 备案信息。
        *   网站指纹识别 (CMS, Framework)。

## 工作流程

1.  **初始化**: 脚本启动，准备所需库和常量。
2.  **加载输入**: 读取用户指定的输入文件。
3.  **解析输入**: 从输入文件中提取并标准化 IP 地址、CIDR 范围、IP 范围和域名。
4.  **获取代理**: 从预设的多个 GitHub URL 并发下载代理列表。
5.  **验证代理**: 并发测试所有下载的代理，建立一个初始的存活代理池。
6.  **执行核心任务**:
    *   **IP 反查**: 使用存活代理池中的代理，并发执行 IP 反向域名查询。
    *   **合并域名**: 将反查得到的域名与直接输入的域名合并去重。
    *   **存活探测**: 使用代理池，并发检查所有域名的可访问性。
    *   **信息查询**: 对存活的域名，并发调用 API 查询权重等信息。
7.  **输出结果**:
    *   将所有存活的域名保存到 `alive.txt` 文件。
    *   将详细的查询结果（域名、权重等）保存到 `results.csv` 文件。

## 依赖库

*   `requests`: 用于发送 HTTP 请求。
*   `tqdm`: 用于在终端显示美观的进度条。
*   `ipaddress`: 用于处理和解析 IP 地址及网络。
*   `concurrent.futures`: 用于实现多线程并发。
*   `urllib3`: 用于处理 HTTP 相关的底层操作 (禁用不安全请求警告)。
*   `argparse`: 用于解析命令行参数。
*   `csv`: 用于将结果写入 CSV 文件。
*   `re`: 用于正则表达式匹配和提取。
*   `socket`: 用于本地 DNS 反向解析。
*   `random`, `time`, `sys`: 用于通用操作 (随机数、延时、系统交互)。

## 安装

1.  确保您已安装 Python 3.6 或更高版本。
2.  克隆或下载此仓库。
3.  (推荐) 创建并激活一个虚拟环境：
    ```bash
    python -m venv venv
    source venv/bin/activate  # Linux/macOS
    # 或
    venv\Scripts\activate     # Windows
    ```
4.  安装所需的 Python 包：
    ```bash
    pip install requests tqdm urllib3
    ```

## 使用方法

在终端中运行脚本，并使用 `-f` 参数指定包含目标的输入文件：

```bash
python main.py -f targets.txt
可选参数:

-o OUTPUT_FILE, --output OUTPUT_FILE: 指定输出 CSV 文件的路径 (默认: results.csv)。
-a ALIVE_FILE, --alive ALIVE_FILE: 指定输出存活域名文件的路径 (默认: alive.txt)。
输入文件格式 (targets.txt)

文件应包含每行一个目标，支持以下格式：
# 这是一条注释，会被忽略
154.86.32.0/24         # CIDR 网络范围
maiuedu.com            # 域名
154.86.30.12-233       # IP 范围
http://xawsjsxy.com    # 完整 URL (协议会被剥离，域名被提取)
https://xawsjsxy.com   # 完整 URL
192.168.1.100          # 单个 IP 地址

配置
代理源: 可以在 process_ips_and_domains 函数内的 proxy_urls 列表中添加或删除代理池的 URL。
API 密钥: 如果使用的权重查询 API 需要认证，请在 query_baidu_weight 函数中添加相应的认证头信息。
线程数: 可以调整 ThreadPoolExecutor 的 max_workers 参数来改变并发线程数，以适应您的硬件和网络环境。
