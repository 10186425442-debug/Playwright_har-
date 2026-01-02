import socket
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
import time
from pathlib import Path
from typing import Any, List, Dict, Optional, Callable
from datetime import datetime
import logging
import subprocess
import platform
import threading
import json
import hashlib

from .result import TestResult, TestSession
from .har_manager import HARManager
from .blacklist_manager import BlacklistManager
from .request_interceptor import RequestInterceptor
from .simple_route_interceptor import setup_route_interceptor
from vpn.vpn_manager import VPNManager, VPNConfig
from utils.har_parser import HARParser
from utils.file_utils import get_app_base_dir
from utils.playwright_path_helper import setup_playwright_environment, get_chromium_launch_args


class PageLoadTester:
    def __init__(self, logger: Optional[logging.Logger] = None, wait_for_network_idle: bool = False, config_manager=None):
        """
        网页性能测试器

        Args:
            logger: 日志记录器
            wait_for_network_idle: 是否等待网络空闲
            config_manager: 配置管理器（可选）
        """
        self.timeout = 30000  # 默认30秒超时（毫秒）
        self.headless = True
        self.logger = logger or logging.getLogger(__name__)
        self.wait_for_network_idle = wait_for_network_idle
        self.config_manager = config_manager
        
        # VPN相关配置
        self.vpn_manager: Optional[VPNManager] = None
        self.vpn_config: Optional[VPNConfig] = None
        self.enable_vpn_testing = False
        self.stage_timeouts = {
            "stage1": 8000,   # HTTP连接测试（默认8秒）
            "stage2": 30000,  # DOM事件监听（默认30秒，非阻塞，获取到就记录）
            "stage3": 60000,  # Load事件测试（默认60秒，主要等待，总超时时间）
        }
        self.har_options = {
            "enable_har_capture": True,  # 默认启用HAR捕获
            "save_har_files": True,
            "extract_hostnames": True,
            "max_har_size_mb": 50,
        }
        self.session_output_dir: Optional[Path] = None
        self.current_session_name: Optional[str] = None
        self.har_manager: Optional[HARManager] = None
        self.blacklist_manager: Optional[BlacklistManager] = None
        self.blocked_requests: List[str] = []  # 记录本次测试中被拦截的请求
        self.failed_vpns: set = set()  # 记录本次测试任务中连接失败的VPN，自动跳过
        
        # URL测试状态跟踪（用于卡死检测）
        self.active_url_tests: Dict = {}  # {future: (url, start_time, vpn_name, original_position)}
        self.url_test_lock = threading.Lock()  # 保护active_url_tests的锁
        self.monitor_thread: Optional[threading.Thread] = None  # 监控线程
        self.monitor_running = False  # 监控线程运行标志
        # 存储future_to_url字典的引用，供监控线程访问（线程安全）
        self.future_to_url_registry: Dict[str, dict] = {}  # {vpn_name: future_to_url}
        self.future_to_url_lock = threading.Lock()  # 保护future_to_url_registry的锁
        # 任务取消标志字典（用于标记需要取消的任务）
        self.cancelled_urls: Dict[str, set] = {}  # {vpn_name: {url}}
        self.cancelled_urls_lock = threading.Lock()  # 保护cancelled_urls的锁
        # 停止控制（用于优雅关闭时不再提交新任务）
        self.stop_event = threading.Event()

    def initialize_vpn_support(self, enable_vpn: bool = True):
        """
        初始化VPN支持
        
        Args:
            enable_vpn: 是否启用VPN测试
        """
        self.enable_vpn_testing = enable_vpn
        if enable_vpn:
            self.vpn_manager = VPNManager(logger=self.logger)
            self.vpn_config = VPNConfig()
            self.logger.info("VPN支持已启用")
        else:
            self.vpn_manager = None
            self.vpn_config = None
            self.logger.info("VPN支持已禁用")

    def configure_vpn_testing(self, vpn_names: List[str], vpn_credentials: Dict[str, Dict[str, str]] = None):
        """
        配置VPN测试
        
        Args:
            vpn_names: VPN名称列表
            vpn_credentials: VPN凭据字典 {vpn_name: {"username": "", "password": ""}}
        """
        if not self.vpn_config:
            self.initialize_vpn_support(True)
        
        # 清空现有配置
        self.vpn_config.config["selected_vpns"] = []
        self.vpn_config.config["vpn_credentials"] = {}
        
        # 添加新的VPN配置
        for vpn_name in vpn_names:
            credentials = vpn_credentials.get(vpn_name, {}) if vpn_credentials else {}
            self.vpn_config.add_vpn(
                vpn_name,
                credentials.get("username", ""),
                credentials.get("password", "")
            )
        
        self.vpn_config.save_config()
        self.logger.info(f"已配置VPN测试: {vpn_names}")

    @staticmethod
    def _convert_vpn_name_to_english(vpn_name: str) -> str:
        """
        将VPN名称转换为英文标识符
        例如：B沈阳 -> 2SY, A北京 -> 1BJ, 上海 -> SH
        
        Args:
            vpn_name: VPN名称，可能包含A/B前缀和地区名
            
        Returns:
            转换后的英文标识符
        """
        from .har_manager import HARManager
        
        # 尝试使用HARManager的转换方法
        region_id = HARManager._convert_region_identifier(vpn_name)
        if region_id:
            return region_id
        
        # 如果没有匹配，尝试直接转换地区名
        # 移除A/B前缀
        clean_name = vpn_name.lstrip('ABab')
        
        # 查找地区名映射
        if clean_name in HARManager.REGION_PINYIN_MAP:
            pinyin = HARManager.REGION_PINYIN_MAP[clean_name]
            # 检查是否有A/B前缀
            if vpn_name.startswith(('A', 'a')):
                return f"1{pinyin}"
            elif vpn_name.startswith(('B', 'b')):
                return f"2{pinyin}"
            else:
                return pinyin
        
        # 如果都不匹配，使用清理后的名称（移除特殊字符）
        safe = "".join(c for c in vpn_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
        return safe.replace(' ', '_') if safe else "vpn"
    
    @staticmethod
    def _sanitize_session_name(name: str) -> str:
        """
        清理会话名称，如果是VPN名称格式则转换为英文
        
        Args:
            name: 会话名称，可能是VPN名称格式（如"B沈阳_20251203_141930"）
            
        Returns:
            清理后的名称，VPN名称会被转换为英文
        """
        # 检查是否是VPN名称格式（包含A/B前缀和地区名）
        from .har_manager import HARManager
        
        # 尝试提取VPN名称部分（去除时间戳）
        import re
        # 匹配格式：VPN名称_时间戳（支持旧格式 YYYYMMDD_HHMMSS 和新格式 YYYYMMDDTHHMMSS）
        # 匹配旧格式：_YYYYMMDD_HHMMSS
        match_old = re.match(r'^(.+?)(_\d{8}_\d{6})$', name)
        if match_old:
            vpn_part = match_old.group(1)
            timestamp_part = match_old.group(2)
            # 转换VPN名称为英文
            english_vpn = PageLoadTester._convert_vpn_name_to_english(vpn_part)
            # 转换时间戳为ISO 8601格式
            timestamp_iso = timestamp_part.replace('_', 'T', 1)  # 只替换第一个下划线
            return f"{english_vpn}{timestamp_iso}"
        
        # 匹配新格式：_YYYYMMDDTHHMMSS
        match_new = re.match(r'^(.+?)(_\d{8}T\d{6})$', name)
        if match_new:
            vpn_part = match_new.group(1)
            timestamp_part = match_new.group(2)
            # 转换VPN名称为英文
            english_vpn = PageLoadTester._convert_vpn_name_to_english(vpn_part)
            return f"{english_vpn}{timestamp_part}"
        
        # 如果不是VPN名称格式，尝试直接转换
        region_id = HARManager._convert_region_identifier(name)
        if region_id:
            return region_id
        
        # 普通清理
        safe = "".join(c for c in name if c.isalnum() or c in (' ', '-', '_')).rstrip()
        return safe.replace(' ', '_') if safe else "unnamed_test"

    def update_har_options(self, options: Optional[Dict[str, Any]]) -> None:
        if not options:
            return
        for key in ("enable_har_capture", "save_har_files", "extract_hostnames", "max_har_size_mb"):
            if key in options and options[key] is not None:
                self.har_options[key] = options[key]

    def _extract_timestamp_from_test_name(self, test_name: str) -> str | None:
        """
        从测试名称中提取时间戳（支持旧格式 YYYYMMDD_HHMMSS 和新格式 YYYYMMDDTHHMMSS）
        测试名称格式通常是：{name}_{YYYYMMDDTHHMMSS} 或 {name}_{YYYYMMDD_HHMMSS}
        
        Args:
            test_name: 测试名称
            
        Returns:
            时间戳字符串（旧格式返回 YYYYMMDD_HHMMSS，新格式返回 YYYYMMDDTHHMMSS），如果未找到则返回None
        """
        import re
        # 优先匹配新格式：YYYYMMDDTHHMMSS（ISO 8601格式）
        pattern_new = r'(\d{8}T\d{6})'
        match_new = re.search(pattern_new, test_name)
        if match_new:
            return match_new.group(1)
        
        # 匹配旧格式：YYYYMMDD_HHMMSS
        pattern_old = r'(\d{8}_\d{6})'
        match_old = re.search(pattern_old, test_name)
        if match_old:
            return match_old.group(1)
        
        return None

    def prepare_session_directory(self, session: TestSession, base_dir: Path, vpn_name: Optional[str] = None) -> Path:
        """
        准备会话目录
        
        Args:
            session: 测试会话
            base_dir: 基础目录
            vpn_name: VPN名称（如果提供，会在base_dir下创建VPN名称的文件夹）
        """
        safe_name = self._sanitize_session_name(session.test_name)
        
        # 从测试名称中提取时间戳（用于HAR文件命名，避免定时任务多次执行时覆盖）
        timestamp = self._extract_timestamp_from_test_name(session.test_name)

        # 如果base_dir已经是最终目录（定时任务的VPN子目录），直接使用
        # 注意：该分支仅适用于带有vpn_name的场景（例如定时任务的VPN子目录），
        # 普通测试（不带vpn_name）应始终在base_dir下再创建一层以测试名称命名的子目录。
        # 否则，普通测试会直接把HAR/hostname生成在results根目录下，导致不同测试结果混在一起。
        if vpn_name and base_dir.exists() and base_dir.is_dir() and base_dir.name != safe_name:
            # 定时任务的VPN子目录，直接使用
            session_dir = base_dir.resolve()
        elif vpn_name:
            # 如果有VPN名称，在base_dir下创建VPN名称的文件夹，然后在VPN文件夹下创建测试名称文件夹
            vpn_safe_name = self._sanitize_session_name(vpn_name)
            vpn_dir = (base_dir / vpn_safe_name).resolve()
            session_dir = (vpn_dir / safe_name).resolve()
        else:
            # 普通情况，创建子目录
            session_dir = (base_dir / safe_name).resolve()
        
        session_dir.mkdir(parents=True, exist_ok=True)

        session.session_directory = str(session_dir)
        self.session_output_dir = session_dir
        self.current_session_name = safe_name

        if self.har_options.get("enable_har_capture"):
            # HAR管理器初始化
            # 如果session_dir是VPN子目录（定时任务的情况），直接使用session_dir作为base_dir
            # 否则使用session_dir的父目录作为base_dir，session_name作为子目录名
            if base_dir.exists() and base_dir.is_dir() and base_dir.name != safe_name:
                # 定时任务的VPN子目录，直接使用session_dir作为base_dir，session_name作为子目录
                # 但我们需要har_files和hostnames直接在VPN子目录下，所以传入空字符串作为session_name
                self.har_manager = HARManager("", session_dir, timestamp=timestamp)
            elif vpn_name:
                # VPN测试：har_files和hostnames保存在VPN文件夹下
                vpn_safe_name = self._sanitize_session_name(vpn_name)
                vpn_dir = (base_dir / vpn_safe_name).resolve()
                self.har_manager = HARManager(safe_name, vpn_dir, timestamp=timestamp)
            else:
                # 普通情况：session_dir = base_dir / safe_name
                # HARManager(session_name, base_dir) 会在 base_dir / session_name 下创建 har 和 hostname
                # 所以应该传入 base_dir 作为 base_results_dir，safe_name 作为 session_name
                # 但 session_dir.parent 就是 base_dir，所以使用 session_dir.parent
                # 确保 base_results_dir 是 session_dir 的父目录（即 base_dir）
                if session_dir.parent != session_dir:
                    base_results_dir = session_dir.parent
                else:
                    # 如果 session_dir.parent == session_dir（理论上不应该发生），使用 base_dir
                    base_results_dir = base_dir
                # 确保传入的 session_name 不为空，这样 HARManager 会在 base_results_dir / session_name 下创建 har 和 hostname
                # 添加日志以便调试
                self.logger.debug(f"初始化HARManager: session_name={safe_name}, base_results_dir={base_results_dir}")
                self.har_manager = HARManager(safe_name, base_results_dir, timestamp=timestamp)
                self.logger.debug(f"HARManager初始化完成: har_dir={self.har_manager.har_dir}, hostname_dir={self.har_manager.hostname_dir}")
        else:
            self.har_manager = None

        return session_dir

    def _should_capture_har(self) -> bool:
        return bool(self.har_manager and self.har_options.get("enable_har_capture"))

    def apply_har_metadata(self, session: TestSession) -> None:
        # 如果session.session_directory已经设置（在prepare_session_directory中设置），则不再覆盖
        # 只有在未设置时才从self.session_output_dir计算
        if not session.session_directory and self.session_output_dir:
            results_base = (get_app_base_dir() / "results").resolve()
            session_path = self.session_output_dir.resolve()
            try:
                relative_path = session_path.relative_to(results_base)
                session.session_directory = str((get_app_base_dir() / "results") / relative_path)
            except ValueError:
                session.session_directory = str(session_path)
        if self.har_manager:
            stats = self.har_manager.get_stats()
            session.har_files_count = stats.get("har_files_count", 0)
            session.total_unique_domains = stats.get("total_unique_domains", 0)

    def _cleanup_temp_files(self, *paths: Optional[Path]) -> None:
        for path in paths:
            if path and path.exists():
                try:
                    path.unlink()
                except Exception:
                    pass

    def _close_browser_resources(self, browser, context, page=None) -> None:
        """
        关闭浏览器资源，确保所有资源都被正确释放
        
        Args:
            browser: 浏览器实例
            context: 浏览器上下文
            page: 页面实例（可选）
        """
        # 先关闭页面（如果提供）
        if page:
            try:
                page.close()
            except Exception:
                pass

    def _create_placeholder_har(self, har_path: Path, url: str) -> None:
        """
        创建一个最小的占位HAR文件，保证即使在阶段1就失败的URL也有对应的HAR文件。

        结构符合HAR 1.2的基本格式，但不包含任何entries，仅用于占位和后续流程兼容。
        """
        try:
            har_path.parent.mkdir(parents=True, exist_ok=True)
            if har_path.exists():
                return

            placeholder = {
                "log": {
                    "version": "1.2",
                    "creator": {
                        "name": "WebPerformanceTester",
                        "version": "2.x"
                    },
                    "browser": {
                        "name": "unknown",
                        "version": ""
                    },
                    "pages": [],
                    "entries": [],
                    "comment": f"Placeholder HAR for URL (no network activity recorded): {url}"
                }
            }

            with har_path.open("w", encoding="utf-8") as f:
                json.dump(placeholder, f, ensure_ascii=False, indent=2)
        except Exception as exc:
            # 不因为占位HAR失败而中断整体流程，只记录日志
            self.logger.warning(f"创建占位HAR文件失败 ({har_path}): {exc}")

    def _close_browser_resources(self, browser, context, page=None) -> None:
        """
        关闭浏览器资源，确保所有资源都被正确释放
        
        Args:
            browser: 浏览器实例
            context: 浏览器上下文
            page: 页面实例（可选）
        """
        # 先关闭页面（如果提供）
        if page:
            try:
                page.close()
            except Exception:
                pass
        
        # 关闭上下文
        if context:
            try:
                context.close()
            except Exception:
                pass
        
        # 关闭浏览器
        if browser:
            try:
                browser.close()
            except Exception:
                pass

    def _remove_har_content(self, har_path: Path) -> None:
        """
        移除HAR文件中的所有content内容（请求体和响应体）
        
        Args:
            har_path: HAR文件路径
        """
        if not har_path or not har_path.exists():
            return
        
        try:
            # 读取HAR文件
            with har_path.open("r", encoding="utf-8") as f:
                har_data = json.load(f)
            
            # 获取entries
            log = har_data.get("log", {})
            entries = log.get("entries", [])
            
            # 移除所有entries中的content内容
            for entry in entries:
                # 移除请求体内容
                request = entry.get("request", {})
                if "postData" in request:
                    post_data = request["postData"]
                    if "text" in post_data:
                        del post_data["text"]
                
                # 移除响应体内容
                response = entry.get("response", {})
                if "content" in response:
                    content = response["content"]
                    if "text" in content:
                        del content["text"]
            
            # 写回HAR文件
            with har_path.open("w", encoding="utf-8") as f:
                json.dump(har_data, f, ensure_ascii=False, indent=2)
            
            self.logger.debug(f"已移除HAR文件中的content内容: {har_path}")
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.warning(f"移除HAR文件content内容失败: {exc}")

    def _add_ip_addresses_to_har(self, har_path: Path) -> None:
        """
        为HAR文件中的每个entry添加IP地址信息
        
        Args:
            har_path: HAR文件路径
        """
        if not har_path or not har_path.exists():
            return
        
        try:
            # 读取HAR文件
            with har_path.open("r", encoding="utf-8") as f:
                har_data = json.load(f)
            
            # 获取entries
            log = har_data.get("log", {})
            entries = log.get("entries", [])
            
            # 用于缓存已解析的域名IP地址，避免重复解析
            domain_ip_cache = {}
            
            # 为每个entry添加IP地址
            for entry in entries:
                request = entry.get("request", {})
                request_url = request.get("url", "")
                
                if not request_url:
                    continue
                
                try:
                    # 从URL中提取域名
                    from urllib.parse import urlparse
                    parsed = urlparse(request_url)
                    domain = parsed.hostname
                    
                    if not domain:
                        continue
                    
                    # 检查缓存
                    if domain in domain_ip_cache:
                        ip_address = domain_ip_cache[domain]
                    else:
                        # 解析域名获取IP地址
                        ip_address = self._get_ip_address(request_url)
                        if ip_address:
                            domain_ip_cache[domain] = ip_address
                    
                    # 将IP地址添加到request对象中（HAR标准字段）
                    if ip_address:
                        request["serverIPAddress"] = ip_address
                    # 同时添加到entry级别，方便某些工具读取
                    if ip_address:
                        entry["_serverIPAddress"] = ip_address
                except Exception as e:
                    self.logger.debug(f"为URL添加IP地址失败: {request_url}, 错误: {e}")
                    continue
            
            # 保存更新后的HAR文件
            with har_path.open("w", encoding="utf-8") as f:
                json.dump(har_data, f, ensure_ascii=False, indent=2)
            
            self.logger.debug(f"已为HAR文件添加IP地址信息: {har_path}")
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.warning(f"为HAR文件添加IP地址失败: {exc}")
    
    def _mark_blocked_requests_in_har(self, har_path: Path) -> None:
        """
        为HAR文件中被黑名单拦截的请求设置标准的_failureText字段。
        
        标记规则：
        - 只有当 entry.request.url 在 self.blocked_requests 中 **且** HAR文件中显示请求被中止时，才标记为拦截
        - 检查条件：
          1. URL在blocked_requests列表中（表示应该被拦截）
          2. HAR文件中response._wasAborted = true（表示请求确实被中止）
          3. 或者response.status = -1 且 response._failureText 存在（表示请求失败）
        - 设置 response._failureText = "net::ERR_BLOCKED_BY_CLIENT"（Chrome标准错误代码）
        - 使用原生HAR格式，不添加自定义字段
        """
        if not har_path or not har_path.exists():
            return
        # 没有拦截记录则无需处理
        if not self.blocked_requests:
            return
        
        try:
            with har_path.open("r", encoding="utf-8") as f:
                har_data = json.load(f)
            
            log = har_data.get("log", {})
            entries = log.get("entries", [])
            
            # 使用set加速匹配
            blocked_set = set(self.blocked_requests)
            marked_count = 0
            skipped_count = 0  # 记录跳过的请求数（URL在拦截列表中但实际已成功）
            
            for entry in entries:
                request = entry.get("request", {})
                request_url = request.get("url", "")
                if not request_url:
                    continue
                
                # 只处理在拦截列表中的URL
                if request_url not in blocked_set:
                    continue
                
                response = entry.get("response", {})
                if not response:
                    continue
                
                # 检查请求是否真的被中止或失败
                was_aborted = response.get("_wasAborted", False)
                status = response.get("status", 0)
                failure_text = response.get("_failureText", "")
                
                # 判断是否为真正的拦截：
                # 1. _wasAborted = true（明确表示被中止）
                # 2. 或者 status = -1 且存在 _failureText（表示请求失败）
                # 3. 如果 status >= 200 且 status < 400，说明请求成功了，不应该标记为拦截
                is_actually_blocked = False
                
                if was_aborted:
                    # 明确被中止，肯定是拦截
                    is_actually_blocked = True
                elif status == -1 and failure_text:
                    # 状态为-1且有错误信息，可能是拦截或网络错误
                    # 如果已经是 ERR_BLOCKED_BY_CLIENT，说明之前已经标记过
                    if failure_text == "net::ERR_BLOCKED_BY_CLIENT":
                        is_actually_blocked = True
                    # 如果是 ERR_FAILED 且没有 _wasAborted，可能是拦截（旧格式）
                    elif failure_text == "net::ERR_FAILED":
                        is_actually_blocked = True
                elif status >= 200 and status < 400:
                    # 请求成功（2xx或3xx），这是一个严重问题！
                    # 如果URL在拦截列表中，说明应该被拦截，但请求却成功了
                    # 这可能是因为：
                    # 1. 拦截器设置时机太晚（在请求发起之后）
                    # 2. 拦截器没有正确生效
                    # 3. 请求来自Service Worker缓存或其他缓存机制
                    # 4. 请求在页面创建时就已经预加载完成
                    is_actually_blocked = False
                    skipped_count += 1
                    # 记录严重警告，这是一个拦截失效的问题
                    from urllib.parse import urlparse
                    parsed_url = urlparse(request_url)
                    domain = parsed_url.netloc or parsed_url.path
                    self.logger.error(
                        f"[拦截失效] ❌ 严重问题：URL {request_url} (域名: {domain}) "
                        f"应该在黑名单中被拦截，但请求却成功了（status={status}）！"
                        f"这表示拦截器可能没有正确生效。请检查："
                        f"1. 拦截器是否在页面导航前设置"
                        f"2. 黑名单域名是否正确匹配"
                        f"3. 是否有缓存或其他机制绕过了拦截器"
                    )
                
                if is_actually_blocked:
                    # 设置response._failureText为标准错误代码（Chrome原生格式）
                    response["_failureText"] = "net::ERR_BLOCKED_BY_CLIENT"
                    # 确保status为-1（表示失败）
                    if status != -1:
                        response["status"] = -1
                        response["statusText"] = ""
                    marked_count += 1
            
            # 只有在确实有标记变更时才写回文件
            if marked_count > 0:
                with har_path.open("w", encoding="utf-8") as f:
                    json.dump(har_data, f, ensure_ascii=False, indent=2)
                self.logger.debug(f"已在HAR文件中为 {marked_count} 个请求设置拦截标记（ERR_BLOCKED_BY_CLIENT）: {har_path}")
                if skipped_count > 0:
                    self.logger.info(f"[HAR标记] 跳过了 {skipped_count} 个请求（在拦截列表中但实际已成功）: {har_path}")
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.warning(f"为HAR文件设置拦截标记失败: {exc}")
    
    def _update_har_with_pages(
        self,
        har_path: Path,
        page_title: str,
        page_url: str,
        on_content_load: float,
        on_load: float,
        started_date_time: Optional[str] = None
    ) -> None:
        """
        更新HAR文件，添加pages信息
        
        Args:
            har_path: HAR文件路径
            page_title: 页面标题
            page_url: 页面URL
            on_content_load: DOMContentLoaded时间（毫秒）
            on_load: Load事件时间（毫秒）
            started_date_time: 页面开始时间（ISO格式），如果为None则使用当前时间
        """
        if not har_path or not har_path.exists():
            return
        
        try:
            # 读取HAR文件
            with har_path.open("r", encoding="utf-8") as f:
                har_data = json.load(f)
            
            # 检查是否已有pages信息
            log = har_data.get("log", {})
            if "pages" not in log or not log.get("pages"):
                # 生成页面ID（基于URL的哈希）
                import hashlib
                page_id = f"page@{hashlib.md5(page_url.encode()).hexdigest()}"
                
                # 如果没有提供开始时间，使用当前时间或从entries中获取最早的时间
                if not started_date_time:
                    entries = log.get("entries", [])
                    if entries:
                        # 从第一个entry获取开始时间
                        first_entry = entries[0]
                        started_date_time = first_entry.get("startedDateTime", datetime.utcnow().isoformat() + "Z")
                    else:
                        started_date_time = datetime.utcnow().isoformat() + "Z"
                
                # 创建pages数组
                pages = [{
                    "startedDateTime": started_date_time,
                    "id": page_id,
                    "title": page_title or page_url,
                    "pageTimings": {
                        "onContentLoad": int(on_content_load) if on_content_load > 0 else -1,
                        "onLoad": int(on_load) if on_load > 0 else -1,
                        "comment": ""
                    }
                }]
                
                # 更新HAR数据
                log["pages"] = pages
                har_data["log"] = log
            
            # 写回HAR文件（先保存pages信息）
            with har_path.open("w", encoding="utf-8") as f:
                json.dump(har_data, f, ensure_ascii=False, indent=2)
            
            # 移除content内容
            self._remove_har_content(har_path)
            
            self.logger.debug(f"已更新HAR文件的pages信息: {har_path}")
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.warning(f"更新HAR文件pages信息失败: {exc}")

    def _finalize_test_result(
        self,
        result: TestResult,
        url: str,
        har_path: Optional[Path],
        hostname_path: Optional[Path],
        page_title: Optional[str] = None,
        page_url: Optional[str] = None
    ) -> TestResult:
        if not self._should_capture_har() or not har_path:
            return result

        if not har_path.exists():
            # 等待片刻，确保HAR写入完成
            for _ in range(10):
                time.sleep(0.2)
                if har_path.exists():
                    break
            if not har_path.exists():
                # 如果仍未生成HAR文件，则创建一个占位HAR，保证每个URL至少有一个HAR文件
                self.logger.warning(f"HAR文件未生成: {har_path}，将创建占位HAR文件")
                try:
                    self._create_placeholder_har(har_path, url)
                except Exception as exc:
                    self.logger.error(f"创建占位HAR文件失败: {exc}")
                    return result

        max_size = self.har_options.get("max_har_size_mb") or 0
        har_saved = self.har_options.get("save_har_files", True)
        hostnames: List[str] = []

        try:
            if max_size > 0:
                max_bytes = max_size * 1024 * 1024
                if har_path.stat().st_size > max_bytes:
                    self.logger.warning(f"HAR文件超过大小限制({max_size}MB)，跳过解析: {har_path}")
                    if not har_saved:
                        self._cleanup_temp_files(har_path)
                    return result

            # 先提取hostnames（在更新HAR文件之前），并保存到hostname目录
            if self.har_options.get("extract_hostnames", True):
                hostnames = HARParser.extract_hostnames(har_path)
                if hostname_path:
                    metadata = {
                        "timestamp": datetime.now().isoformat(),
                        "source_url": url,
                    }
                    HARParser.save_hostnames_to_txt(hostnames, hostname_path, metadata)
                    result.hostname_file_path = str(hostname_path)

            result.domain_count = len(hostnames)

            # ===== 通过HAR文件获取加载时间（作为权威来源） =====
            # 优先从HAR中解析pageTimings / entries来反推DOMContentLoaded和Load时间，
            # 然后再写回到TestResult对象中，标记来源为"har"。
            on_content_ms, on_load_ms = HARParser.get_page_timings(har_path)
            # DOM Ready 时间
            if on_content_ms is not None:
                result.dom_ready_time = on_content_ms / 1000.0
                result.dom_time_source = "har"
            # 完全加载时间（Load）
            if on_load_ms is not None:
                result.full_load_time = on_load_ms / 1000.0
                result.full_load_time_source = "har"

            # 更新HAR文件，添加pages信息（如果提供了页面信息）
            if page_title is not None and page_url is not None:
                # 将秒转换为毫秒写入pageTimings；如果仍为None，用-1表示未记录
                on_content_load = int(result.dom_ready_time * 1000) if result.dom_ready_time and result.dom_ready_time > 0 else -1
                on_load = int(result.full_load_time * 1000) if result.full_load_time and result.full_load_time > 0 else -1
                self._update_har_with_pages(har_path, page_title, page_url, on_content_load, on_load)
            else:
                # 即使不需要更新pages，也要移除content内容
                self._remove_har_content(har_path)
            
            # 为HAR文件中的每个URL添加IP地址
            self._add_ip_addresses_to_har(har_path)
            # 为被黑名单拦截的请求添加标记字段，便于后续区分统计
            self._mark_blocked_requests_in_har(har_path)

            if har_saved:
                result.har_file_path = str(har_path)
            else:
                self._cleanup_temp_files(har_path)

            if self.har_manager:
                self.har_manager.register_artifact(hostnames, har_saved)

            return result
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.error(f"HAR处理失败: {exc}")
            if not har_saved:
                self._cleanup_temp_files(har_path)
            return result

    def _validate_and_normalize_url(self, url: str) -> str:
        """
        验证和规范化URL

        Args:
            url: 原始URL

        Returns:
            规范化后的URL
        """
        url = url.strip()

        # 自动添加https://协议头
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        return url

    def _get_ip_address(self, url: str) -> Optional[str]:
        """
        获取URL对应的IPv4地址

        Args:
            url: 目标URL

        Returns:
            IPv4地址或None
        """
        try:
            # 提取域名部分
            domain = url.replace('https://', '').replace('http://', '').split('/')[0]

            # 解析域名获取IP地址
            ip_list = socket.getaddrinfo(domain, None)

            # 提取IPv4地址
            for ip in ip_list:
                if ip[0] == socket.AF_INET:  # IPv4
                    return ip[4][0]
            return None
        except Exception as e:
            self.logger.warning(f"无法解析 {url} 的IP地址: {e}")
            return None

    def _clear_dns_cache(self):
        """
        清除系统DNS缓存（跨平台支持）
        注意：此方法已被 _clear_all_caches 替代，保留用于向后兼容
        """
        self._flush_dns_cache()
    
    def _clear_all_caches(self, reason: str = ""):
        """
        统一清理所有缓存和存储状态
        包括：DNS缓存、浏览器缓存、Cookie、LocalStorage、HTTP缓存等
        
        Args:
            reason: 清理原因（用于日志记录）
        """
        reason_text = f" ({reason})" if reason else ""
        self.logger.info(f"开始统一清理所有缓存和存储状态{reason_text}")
        
        # 清除DNS缓存
        self._flush_dns_cache()
        
        # 浏览器缓存、Cookie、LocalStorage等通过 storage_state=None 在创建浏览器上下文时清除
        # 这里只记录日志，实际的浏览器存储清理在 _measure_single_page 中通过 storage_state=None 实现
        self.logger.info("已清除DNS缓存，浏览器存储状态将在创建浏览器上下文时清除")

    def _measure_single_page(self, url: str, url_index: int, original_position: int,
                             round_num: int = 0) -> TestResult:
        """三阶段测试逻辑 - 同步版本"""
        start_time = time.time()
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

        # 创建任务标识
        task_id = f"{original_position}-{round_num}"
        
        # 创建请求拦截器
        interceptor = RequestInterceptor(
            blacklist_manager=self.blacklist_manager,
            logger=self.logger
        )
        
        # 检查主URL是否被黑名单拦截（在浏览器启动前检查）
        is_blocked, intercept_record = interceptor.check_main_url(url)
        if is_blocked:
            # 获取IP地址（即使被拦截也记录IP）
            ip_address = self._get_ip_address(url)
            self.logger.info(
                f"[拦截完成] URL已被黑名单拦截 [{task_id}]: {url} "
                f"(IP: {ip_address if ip_address else '无法解析'}, "
                f"匹配规则: {intercept_record.matched_rule if intercept_record else '未知'})"
            )
            # 黑名单拦截场景下，不会生成 HAR / hostname 文件，
            # 因此这里直接返回结果对象，而不再调用 _finalize_test_result（该方法依赖 HAR 相关路径）。
            return TestResult(
                url=url,
                status="blocked",  # 新增拦截状态
                status_code=None,  # 状态码设为None，在显示时显示"拦截"
                error_type="blacklist_blocked",
                error_message=f"URL在黑名单中，已被拦截（匹配规则: {intercept_record.matched_rule if intercept_record else '未知'}）",
                test_round=round_num,
                url_index=url_index,
                original_position=original_position,
                ip_address=ip_address,
                response_time=-1,
                final_url=url,
            )
        
        # 如果logger支持任务日志，使用任务日志方法
        if hasattr(self.logger, 'log_task_start'):
            self.logger.log_task_start(url, original_position, round_num)
        else:
            self.logger.info(f"[开始] 测试URL [{task_id}]: {url}")

        # 获取IP地址
        ip_address = self._get_ip_address(url)
        if ip_address:
            if hasattr(self.logger, 'log_task_stage'):
                self.logger.log_task_stage("解析IP", url, original_position, round_num, f"-> {ip_address}")
            else:
                self.logger.info(f"解析IP地址 [{task_id}]: {url} -> {ip_address}")

        try:
            # 验证和规范化URL
            normalized_url = self._validate_and_normalize_url(url)

            # 在测试开始前检查浏览器是否已安装
            try:
                from utils.playwright_checker import check_playwright_browser_installed
                if not check_playwright_browser_installed("chromium"):
                    self.logger.error(f"Playwright 浏览器未安装，无法运行测试")
                    return TestResult(
                        url=url,
                        status="error",
                        error_type="browser_not_installed",
                        error_message="Playwright 浏览器未安装，请运行 'playwright install chromium' 安装浏览器",
                        test_round=round_num,
                        url_index=url_index,
                        original_position=original_position,
                        ip_address=ip_address,
                        response_time=-1,
                        final_url=normalized_url
                    )
            except Exception as e:
                self.logger.warning(f"检查浏览器安装状态时出错: {e}")

            # 在 exe 环境中设置 Playwright 环境变量
            setup_playwright_environment(self.config_manager)

            with sync_playwright() as p:
                # 只使用chromium浏览器（支持HAR录制）
                browser_name = "chromium"
                browser_type = p.chromium
                browser_start_time = time.time()
                context = None

                # 用于保存阶段1获取的数据
                stage1_status_code = None
                stage1_final_url = None
                stage1_successful = False
                # 用于保存阶段2获取的DOM时间（如果30秒内获取到）
                dom_ready_time = None

                self.logger.info(f"使用 {browser_name} 开始测试 [{original_position}-{round_num}]: {url}")

                har_path: Optional[Path] = None
                hostname_path: Optional[Path] = None
                if self._should_capture_har():
                    # 检查是否有VPN上下文信息
                    test_mode = getattr(self, '_current_test_mode', None)
                    vpn_name = getattr(self, '_current_vpn_name', None)
                    
                    # 使用original_position而不是url_index，避免批处理时文件覆盖
                    # original_position从1开始，需要减1作为文件索引
                    har_path = self.har_manager.get_har_file_path(
                        url, round_num, original_position - 1, 0, test_mode, vpn_name
                    )
                    hostname_path = self.har_manager.get_hostname_file_path(
                        url, round_num, original_position - 1, 0, test_mode, vpn_name
                    )
                    # 确保HAR/hostname路径存在，如有历史残留先清理
                    self._cleanup_temp_files(har_path, hostname_path)

                def finalize_result(test_result: TestResult, page_title: Optional[str] = None, page_url: Optional[str] = None) -> TestResult:
                    return self._finalize_test_result(test_result, url, har_path, hostname_path, page_title, page_url)

                try:
                    # 获取启动参数（在 exe 环境中会包含可执行文件路径）
                    launch_args = get_chromium_launch_args(self.config_manager)
                    launch_args.update({
                        "headless": self.headless,
                        "args": [
                            '--no-sandbox',
                            '--disable-dev-shm-usage',
                            '--disable-web-security',
                            '--disable-features=VizDisplayCompositor',
                            '--disable-blink-features=AutomationControlled',
                            '--disable-http-cache',  # 禁用HTTP缓存，确保每次测试都重新请求资源
                            '--disable-background-networking',  # 禁用后台网络请求
                            '--disable-background-timer-throttling',  # 禁用后台定时器节流
                            '--disable-backgrounding-occluded-windows',  # 禁用后台窗口
                            '--disable-breakpad',  # 禁用崩溃报告
                            '--disable-client-side-phishing-detection',  # 禁用客户端钓鱼检测
                            '--disable-component-update',  # 禁用组件更新
                            '--disable-default-apps',  # 禁用默认应用
                            '--disable-domain-reliability',  # 禁用域名可靠性
                            '--disable-features=TranslateUI',  # 禁用翻译UI
                            '--disable-hang-monitor',  # 禁用挂起监控
                            '--disable-ipc-flooding-protection',  # 禁用IPC洪水保护
                            '--disable-popup-blocking',  # 禁用弹窗阻止
                            '--disable-prompt-on-repost',  # 禁用重新提交提示
                            '--disable-renderer-backgrounding',  # 禁用渲染器后台
                            '--disable-sync',  # 禁用同步
                            '--disable-translate',  # 禁用翻译
                            '--metrics-recording-only',  # 仅记录指标
                            '--no-first-run',  # 不首次运行
                            '--safebrowsing-disable-auto-update',  # 禁用安全浏览自动更新
                            '--enable-automation',  # 启用自动化
                            '--password-store=basic',  # 基本密码存储
                            '--use-mock-keychain',  # 使用模拟密钥链
                            '--disable-features=PreloadMediaEngagementData,AutofillServerCommunication',  # 禁用预加载和自动填充服务器通信
                        ]
                    })
                    browser = browser_type.launch(**launch_args)

                    # 配置浏览器上下文
                    # 使用空的storage_state确保每次测试都使用全新的浏览器上下文，清除缓存和存储
                    context_kwargs = dict(
                            viewport={'width': 1920, 'height': 1080},
                            user_agent=user_agent,
                            ignore_https_errors=True,
                            java_script_enabled=True,
                            bypass_csp=True,
                            storage_state=None,  # 清除所有存储状态（包括缓存、Cookie、LocalStorage等）
                            service_workers='block'  # 禁用Service Worker，防止缓存绕过拦截器
                        )

                    if har_path:
                        context_kwargs.update(
                            record_har_path=str(har_path),
                            record_har_mode="full",
                            record_har_content="embed"  # 嵌入内容，生成最完整的HAR文件
                        )

                    # 记录浏览器上下文创建（包含缓存清理信息）
                    test_mode_info = ""
                    if hasattr(self, '_current_test_mode') and self._current_test_mode:
                        test_mode_info = f" [{self._current_test_mode}模式]"
                    self.logger.info(f"创建浏览器上下文{test_mode_info}，已清除缓存、Cookie和存储状态，已禁用HTTP缓存")
                    
                    # 创建浏览器上下文
                    context = browser.new_context(**context_kwargs)
                    
                    # 【使用新的简单可靠拦截器】参考简易脚本的实现方式
                    # 在 context 级别设置拦截器，确保拦截所有请求（包括预加载和重定向）
                    setup_route_interceptor(
                        context=context,
                        blacklist_manager=self.blacklist_manager,
                        logger=self.logger,
                        disable_cache=True,
                        blocked_requests_list=self.blocked_requests
                    )

                    # 隐藏自动化特征
                    context.add_init_script("""
                        Object.defineProperty(navigator, 'webdriver', {
                            get: () => undefined,
                        });
                    """)
                    
                    # 注入性能指标收集脚本
                    context.add_init_script("""
                            // 创建全局对象存储性能指标
                            window.__performanceMetrics = {
                                lcp: null,
                                cls: 0,
                                tbt: 0,
                                inp: null,
                                si: null,
                                lcpEntries: [],
                                clsEntries: [],
                                longTasks: [],
                                interactions: []
                            };
                            
                            // LCP - Largest Contentful Paint Observer
                            if ('PerformanceObserver' in window) {
                                try {
                                    const lcpObserver = new PerformanceObserver((list) => {
                                        const entries = list.getEntries();
                                        entries.forEach(entry => {
                                            window.__performanceMetrics.lcpEntries.push(entry);
                                            // 更新最新的LCP值
                                            window.__performanceMetrics.lcp = entry.renderTime || entry.loadTime;
                                        });
                                    });
                                    lcpObserver.observe({ entryTypes: ['largest-contentful-paint'] });
                                } catch (e) {
                                    console.warn('LCP Observer not supported:', e);
                                }
                                
                                // CLS - Cumulative Layout Shift Observer
                                try {
                                    const clsObserver = new PerformanceObserver((list) => {
                                        const entries = list.getEntries();
                                        entries.forEach(entry => {
                                            if (!entry.hadRecentInput) {
                                                window.__performanceMetrics.cls += entry.value || 0;
                                                window.__performanceMetrics.clsEntries.push(entry);
                                            }
                                        });
                                    });
                                    clsObserver.observe({ entryTypes: ['layout-shift'] });
                                } catch (e) {
                                    console.warn('CLS Observer not supported:', e);
                                }
                                
                                // TBT - Total Blocking Time (Long Tasks Observer)
                                try {
                                    const longTaskObserver = new PerformanceObserver((list) => {
                                        const entries = list.getEntries();
                                        entries.forEach(entry => {
                                            const duration = entry.duration || 0;
                                            if (duration > 50) {
                                                const blockingTime = duration - 50;
                                                window.__performanceMetrics.tbt += blockingTime;
                                                window.__performanceMetrics.longTasks.push(entry);
                                            }
                                        });
                                    });
                                    longTaskObserver.observe({ entryTypes: ['longtask'] });
                                } catch (e) {
                                    console.warn('Long Task Observer not supported:', e);
                                }
                                
                                // INP - Interaction to Next Paint (需要监听交互事件)
                                // 监听常见的交互事件
                                ['click', 'keydown', 'pointerdown'].forEach(eventType => {
                                    document.addEventListener(eventType, (event) => {
                                        const interaction = {
                                            type: eventType,
                                            time: performance.now(),
                                            target: event.target ? event.target.tagName : 'unknown'
                                        };
                                        window.__performanceMetrics.interactions.push(interaction);
                                        
                                        // 使用requestAnimationFrame来测量到下一帧的时间
                                        requestAnimationFrame(() => {
                                            const paintTime = performance.now();
                                            const inpValue = paintTime - interaction.time;
                                            
                                            // 只保留最差的INP值（最大的延迟）
                                            if (!window.__performanceMetrics.inp || inpValue > window.__performanceMetrics.inp) {
                                                window.__performanceMetrics.inp = inpValue;
                                            }
                                        });
                                    }, { passive: true });
                                });
                            }
                        """)
                    
                    # 【简化实现】创建页面，context级别的拦截器已经设置，无需在页面级别重复设置
                    # context级别的拦截器会拦截所有请求，包括重定向后的请求
                    page = context.new_page()

                    # 读取阶段超时时间（毫秒）
                    stage1_timeout = max(1000, int(self.stage_timeouts.get("stage1", 8000)))
                    stage2_timeout = max(1000, int(self.stage_timeouts.get("stage2", 15000)))
                    stage3_timeout = max(1000, int(self.stage_timeouts.get("stage3", 30000)))

                    # ==================== 阶段1: HTTP连接测试 ====================
                    page.set_default_timeout(stage1_timeout)

                    if hasattr(self.logger, 'log_task_stage'):
                        self.logger.log_task_stage("阶段1-HTTP", url, original_position, round_num)
                    else:
                        self.logger.info(f"[阶段1-HTTP] [{task_id}]: {url}")

                    try:
                        response = page.goto(
                            normalized_url,
                            wait_until="commit",  # 只等待HTTP响应
                            timeout=stage1_timeout
                        )

                        status_code = response.status if response else 0
                        final_url = page.url

                        # 保存阶段1获取的数据
                        stage1_status_code = status_code
                        stage1_final_url = final_url
                        stage1_successful = True

                        stage1_time = time.time() - browser_start_time
                        if hasattr(self.logger, 'log_task_stage'):
                            self.logger.log_task_stage("阶段1完成", url, original_position, round_num, 
                                                     f"状态码 {status_code}, 用时 {stage1_time:.1f}s")
                        else:
                            self.logger.info(f"[阶段1完成] [{task_id}]: 状态码 {status_code}, 用时 {stage1_time:.1f}s")

                        # HTTP错误检查
                        if status_code >= 400:
                            self._close_browser_resources(browser, context)
                            return finalize_result(TestResult(
                                url=url,
                                status="error",
                                status_code=status_code,
                                error_type="http_error",
                                error_message=f"HTTP错误: {status_code}",
                                test_round=round_num,
                                url_index=url_index,
                                original_position=original_position,
                                ip_address=ip_address,
                                response_time=-1,
                                final_url=final_url
                            ))

                    except PlaywrightTimeoutError:
                        # 阶段1失败：HTTP连接超时
                        stage1_time = time.time() - browser_start_time
                        stage1_timeout_seconds = stage1_timeout / 1000.0  # 转换为秒
                        self.logger.error(f"阶段1失败-HTTP超时 [{original_position}-{round_num}]: {url} (超时设置: {stage1_timeout_seconds:.1f}秒)")
                        self._close_browser_resources(browser, context)
                        return finalize_result(TestResult(
                            url=url,
                            status="timeout",
                            error_type="connection_timeout",
                            error_message=f"HTTP连接超时（{stage1_timeout_seconds:.1f}秒内无响应）",
                            test_round=round_num,
                            url_index=url_index,
                            original_position=original_position,
                            ip_address=ip_address,
                            response_time=-1,
                            final_url=normalized_url
                        ))
                    except Exception as e:
                        # 处理重定向循环等特殊错误
                        error_message = str(e)
                        stage1_time = time.time() - browser_start_time

                        # 判断是否为重定向错误
                        is_redirect_error = any(keyword in error_message for keyword in
                                                ['REDIRECT_LOOP', 'redirections', 'redirect'])

                        if is_redirect_error:
                            self.logger.error(
                                f"阶段1失败-重定向错误 [{original_position}-{round_num}]: {browser_name} - {error_message}")
                            self._close_browser_resources(browser, context)
                            return finalize_result(TestResult(
                                url=url,
                                status="error",
                                error_type="redirect_error",
                                error_message=f"重定向错误: {error_message}",
                                test_round=round_num,
                                url_index=url_index,
                                original_position=original_position,
                                ip_address=ip_address,
                                response_time=-1,
                                final_url=normalized_url,
                                is_redirect_loop=True,
                                redirect_count=20  # 假设达到最大重定向次数
                            ))
                        else:
                            # 其他异常，直接返回错误
                            self.logger.error(
                                f"阶段1异常 [{original_position}-{round_num}]: {browser_name} - {error_message}")
                            self._close_browser_resources(browser, context)
                            self._cleanup_temp_files(har_path, hostname_path)
                            return finalize_result(TestResult(
                                url=url,
                                status="error",
                                error_type="browser_error",
                                error_message=f"浏览器错误: {error_message}",
                                test_round=round_num,
                                url_index=url_index,
                                original_position=original_position,
                                ip_address=ip_address,
                                response_time=-1,
                                final_url=normalized_url
                            ))

                    # ==================== 阶段2: DOM事件监听（非阻塞） ====================
                    # DOMContentLoaded作为事件监听，30秒内获取到就记录，获取不到也不阻塞
                    if hasattr(self.logger, 'log_task_stage'):
                        self.logger.log_task_stage("阶段2-DOM", url, original_position, round_num)
                    else:
                        self.logger.info(f"[阶段2-DOM] [{task_id}]: {url} (事件监听模式，不阻塞)")

                    # 尝试等待DOMContentLoaded，但设置超时后不阻塞，继续执行
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=stage2_timeout)
                        # 如果30秒内获取到，记录时间
                        dom_ready_time = time.time() - browser_start_time
                        if hasattr(self.logger, 'log_task_stage'):
                            self.logger.log_task_stage("阶段2完成", url, original_position, round_num, 
                                                     f"DOM事件触发 (用时: {dom_ready_time:.1f}s)")
                        else:
                            self.logger.info(f"[阶段2完成] [{task_id}]: DOM事件触发 (用时: {dom_ready_time:.1f}s)")
                    except PlaywrightTimeoutError:
                        # DOM在30秒内未触发，但不阻塞，继续执行
                        stage2_timeout_seconds = stage2_timeout / 1000.0
                        self.logger.info(f"[阶段2-DOM] [{task_id}]: DOM事件在{stage2_timeout_seconds:.1f}秒内未触发，继续等待Load事件")
                        # dom_ready_time保持为None，表示未在30秒内获取到
                    except Exception as e:
                        # 其他异常也不阻塞
                        self.logger.warning(f"[阶段2-DOM] [{task_id}]: DOM事件监听异常: {e}，继续执行")
                        # dom_ready_time保持为None

                except Exception as e:
                    # 浏览器启动异常
                    browser_time = time.time() - browser_start_time
                    error_message = str(e)

                    # 检查是否为网络相关错误
                    if any(keyword in error_message for keyword in ['UNKNOWN_HOST', 'resolve hostname']):
                        self.logger.error(
                            f"DNS解析失败 [{original_position}-{round_num}]: {browser_name} - {error_message}")
                        self._close_browser_resources(browser, context)
                        return finalize_result(TestResult(
                            url=url,
                            status="error",
                            error_type="dns_error",
                            error_message=f"DNS解析失败: {error_message}",
                            test_round=round_num,
                            url_index=url_index,
                            original_position=original_position,
                            ip_address=ip_address,
                            response_time=-1,
                            final_url=normalized_url
                        ))
                    else:
                        self.logger.error(
                            f"浏览器启动失败 [{original_position}-{round_num}]: {browser_name} - {error_message}")
                        self._close_browser_resources(browser, context)
                        self._cleanup_temp_files(har_path, hostname_path)
                        return finalize_result(TestResult(
                            url=url,
                            status="error",
                            error_type="browser_error",
                            error_message=f"浏览器启动失败: {error_message}",
                            test_round=round_num,
                            url_index=url_index,
                            original_position=original_position,
                            ip_address=ip_address,
                            response_time=-1,
                            final_url=normalized_url
                        ))

                # ==================== 阶段3: Load事件测试（主要等待，60秒） ====================
                page.set_default_timeout(stage3_timeout)

                if hasattr(self.logger, 'log_task_stage'):
                    self.logger.log_task_stage("阶段3-Load", url, original_position, round_num)
                else:
                    self.logger.info(f"[阶段3-Load] [{task_id}]: {url}")

                try:
                    page.wait_for_load_state("load", timeout=stage3_timeout)

                    stage3_time = time.time() - browser_start_time
                    total_time = time.time() - start_time

                    if hasattr(self.logger, 'log_task_stage'):
                        self.logger.log_task_stage("阶段3完成", url, original_position, round_num, 
                                                 f"Load成功 (总用时: {total_time:.1f}s)")
                    else:
                        self.logger.info(f"[阶段3完成] [{task_id}]: Load成功 (总用时: {total_time:.1f}s)")
                    
                    # 记录任务完成
                    if hasattr(self.logger, 'log_task_complete'):
                        self.logger.log_task_complete(url, original_position, round_num, "成功", total_time)

                    # 获取完整性能数据（包括Lighthouse指标）
                    performance_data = page.evaluate("""() => {
                        const getTimingData = () => {
                            const navEntries = performance.getEntriesByType('navigation');
                            if (navEntries && navEntries.length > 0) {
                                const nav = navEntries[0];
                                return {
                                    domReady: nav.domContentLoadedEventEnd,
                                    fullLoad: nav.loadEventEnd
                                };
                            }

                            const timing = performance.timing;
                            if (timing) {
                                return {
                                    domReady: timing.domContentLoadedEventEnd - timing.navigationStart,
                                    fullLoad: timing.loadEventEnd - timing.navigationStart
                                };
                            }
                            return { domReady: 0, fullLoad: 0 };
                        };

                        const { domReady, fullLoad } = getTimingData();
                        
                        // FCP - First Contentful Paint
                        let fcp = 0;
                        const fcpEntry = performance.getEntriesByName('first-contentful-paint')[0];
                        if (fcpEntry) {
                            fcp = fcpEntry.startTime;
                        }
                        
                        // 从注入的脚本中获取性能指标
                        const metrics = window.__performanceMetrics || {};
                        
                        // LCP - Largest Contentful Paint
                        let lcp = 0;
                        if (metrics.lcp !== null && metrics.lcp !== undefined) {
                            lcp = metrics.lcp;
                        } else {
                            // 备用方法：从PerformanceEntry获取
                            const lcpEntries = performance.getEntriesByType('largest-contentful-paint');
                            if (lcpEntries && lcpEntries.length > 0) {
                                lcp = lcpEntries[lcpEntries.length - 1].renderTime || lcpEntries[lcpEntries.length - 1].loadTime;
                            }
                        }
                        
                        // CLS - Cumulative Layout Shift
                        let cls = metrics.cls || 0;
                        if (cls === 0) {
                            // 备用方法：从PerformanceEntry获取
                            const clsEntries = performance.getEntriesByType('layout-shift');
                            if (clsEntries && clsEntries.length > 0) {
                                cls = clsEntries.reduce((sum, entry) => {
                                    if (!entry.hadRecentInput) {
                                        return sum + (entry.value || 0);
                                    }
                                    return sum;
                                }, 0);
                            }
                        }
                        
                        // TBT - Total Blocking Time
                        let tbt = metrics.tbt || 0;
                        if (tbt === 0) {
                            // 备用方法：从PerformanceEntry获取
                            const longTaskEntries = performance.getEntriesByType('longtask');
                            if (longTaskEntries && longTaskEntries.length > 0) {
                                tbt = longTaskEntries.reduce((sum, entry) => {
                                    const duration = entry.duration || 0;
                                    return duration > 50 ? sum + (duration - 50) : sum;
                                }, 0);
                            }
                        }
                        
                        // INP - Interaction to Next Paint
                        let inp = metrics.inp || 0;
                        
                        // SI - Speed Index (需要特殊计算，这里先返回0)
                        // Speed Index需要计算页面加载过程中视觉进度的变化
                        // 这是一个复杂的指标，通常需要专门的库来计算
                        // 可以通过计算资源加载时间或使用估算方法
                        let si = 0;
                        // 简单的SI估算：基于FCP和LCP
                        if (fcp > 0 && lcp > 0) {
                            // SI的简单估算：FCP和LCP的平均值
                            si = (fcp + lcp) / 2;
                        } else if (fcp > 0) {
                            si = fcp * 1.5; // 如果只有FCP，估算SI
                        }
                        
                        return { 
                            domReady, 
                            fullLoad, 
                            fcp,
                            lcp,
                            cls,
                            tbt,
                            si,
                            inp
                        };
                    }""")

                    # 在关闭context前获取页面信息
                    page_title = page.title() if page else None
                    page_url = page.url if page else stage1_final_url

                    self._close_browser_resources(browser, context)

                    # 处理性能数据
                    # 优先使用阶段2记录的实际DOM时间（如果30秒内获取到），否则使用性能API数据
                    if dom_ready_time is not None:
                        dom_ready_seconds = dom_ready_time
                    else:
                        dom_ready_seconds = performance_data.get("domReady", 0) / 1000.0
                        if dom_ready_seconds <= 0:
                            dom_ready_seconds = None  # 如果性能API也没有数据，设为None
                    
                    full_load_seconds = performance_data.get("fullLoad", 0) / 1000.0
                    fcp_seconds = performance_data.get("fcp", 0) / 1000.0
                    
                    # Lighthouse性能指标（转换为秒）
                    lcp_seconds = performance_data.get("lcp", 0) / 1000.0 if performance_data.get("lcp", 0) > 0 else None
                    inp_seconds = performance_data.get("inp", 0) / 1000.0 if performance_data.get("inp", 0) > 0 else None
                    cls_value = performance_data.get("cls", 0) if performance_data.get("cls", 0) > 0 else None
                    tbt_seconds = performance_data.get("tbt", 0) / 1000.0 if performance_data.get("tbt", 0) > 0 else None
                    si_value = performance_data.get("si", 0) / 1000.0 if performance_data.get("si", 0) > 0 else None

                    # 如果性能API数据异常，使用实际测试时间
                    if full_load_seconds <= 0:
                        full_load_seconds = stage3_time

                    return finalize_result(TestResult(
                        url=url,
                        status="success",
                        status_code=stage1_status_code,  # ✅ 使用阶段1获取的状态码
                        response_time=total_time,
                        dom_ready_time=dom_ready_seconds,
                        full_load_time=full_load_seconds,
                        fcp_time=fcp_seconds,
                        lcp_time=lcp_seconds,
                        inp_time=inp_seconds,
                        cls_score=cls_value,
                        tbt_time=tbt_seconds,
                        si_score=si_value,
                        test_round=round_num,
                        url_index=url_index,
                        original_position=original_position,
                        ip_address=ip_address,
                        final_url=stage1_final_url,  # ✅ 使用阶段1获取的最终URL
                        load_event_triggered=True
                    ), page_title=page_title, page_url=page_url)

                except PlaywrightTimeoutError:
                    # 阶段3失败：Load事件超时，但页面已打开
                    stage3_time = time.time() - browser_start_time
                    total_time = time.time() - start_time

                    self.logger.warning(
                        f"阶段3失败-Load超时 [{original_position}-{round_num}]: {url} (总用时: {total_time:.1f}s)")

                    # 立即关闭浏览器资源，避免后续操作阻塞
                    # 先尝试快速获取页面信息（带超时保护）
                    page_title = None
                    page_url = stage1_final_url
                    
                    try:
                        # 使用线程超时来强制结束可能阻塞的操作
                        from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
                        
                        def get_page_info():
                            try:
                                if page:
                                    title = page.title()
                                    url = page.url
                                    return title, url
                            except:
                                pass
                            return None, stage1_final_url
                        
                        # 使用线程池执行，设置2秒超时
                        with ThreadPoolExecutor(max_workers=1) as executor:
                            future = executor.submit(get_page_info)
                            try:
                                page_title, page_url = future.result(timeout=2.0)
                            except FutureTimeoutError:
                                self.logger.warning(f"获取页面信息超时 [{original_position}-{round_num}]，跳过")
                                page_title = None
                                page_url = stage1_final_url
                    except Exception as e:
                        self.logger.warning(f"获取页面信息失败 [{original_position}-{round_num}]: {e}")
                    
                    # 立即关闭浏览器资源，避免阻塞
                    try:
                        self._close_browser_resources(browser, context, page)
                    except Exception as e:
                        self.logger.warning(f"关闭浏览器资源时出错 [{original_position}-{round_num}]: {e}")
                    
                    # 使用默认性能数据（不再尝试获取，避免阻塞）
                    performance_data = {"domReady": 0, "fullLoad": 0, "fcp": 0, "lcp": 0, "inp": 0, "cls": 0, "tbt": 0, "si": 0}

                    # 使用-1标记超时情况
                    # 优先使用阶段2记录的实际DOM时间（如果30秒内获取到），否则使用性能API数据
                    if dom_ready_time is not None:
                        dom_ready_seconds = dom_ready_time
                    else:
                        dom_ready_seconds = performance_data.get("domReady", 0) / 1000.0 if performance_data.get("domReady", 0) > 0 else -1
                    full_load_seconds = -1  # 完全加载时间设为-1（Load超时）
                    fcp_seconds = performance_data.get("fcp", 0) / 1000.0 if performance_data.get("fcp", 0) > 0 else -1
                    
                    # Lighthouse性能指标（超时情况下，如果有数据就使用，否则为None）
                    lcp_seconds = performance_data.get("lcp", 0) / 1000.0 if performance_data.get("lcp", 0) > 0 else None
                    inp_seconds = performance_data.get("inp", 0) / 1000.0 if performance_data.get("inp", 0) > 0 else None
                    cls_value = performance_data.get("cls", 0) if performance_data.get("cls", 0) > 0 else None
                    tbt_seconds = performance_data.get("tbt", 0) / 1000.0 if performance_data.get("tbt", 0) > 0 else None
                    si_value = performance_data.get("si", 0) / 1000.0 if performance_data.get("si", 0) > 0 else None

                    return finalize_result(TestResult(
                        url=url,
                        status="partial_success",  # 部分成功
                        status_code=stage1_status_code,  # ✅ 使用阶段1获取的状态码
                        response_time=total_time,
                        dom_ready_time=dom_ready_seconds,
                        full_load_time=full_load_seconds,  # 记录为-1
                        fcp_time=fcp_seconds,
                        lcp_time=lcp_seconds,
                        inp_time=inp_seconds,
                        cls_score=cls_value,
                        tbt_time=tbt_seconds,
                        si_score=si_value,
                        test_round=round_num,
                        url_index=url_index,
                        original_position=original_position,
                        ip_address=ip_address,
                        final_url=stage1_final_url,  # ✅ 使用阶段1获取的最终URL
                        error_type="load_timeout",
                        error_message=f"页面DOM已加载但资源加载超时（总超时: {stage3_timeout / 1000.0:.1f}秒）",
                        load_event_triggered=False
                    ), page_title=page_title, page_url=page_url)

        except PlaywrightTimeoutError as e:
            end_time = time.time()
            response_time = end_time - start_time
            self.logger.error(f"全局超时 [{original_position}-{round_num}]: {url} - 实际等待: {response_time:.2f}s")
            return self._finalize_test_result(TestResult(
                url=url,
                status="timeout",
                error_type="global_timeout",
                error_message="全局测试超时",
                test_round=round_num,
                url_index=url_index,
                original_position=original_position,
                ip_address=ip_address,
                response_time=-1,
                final_url=normalized_url
            ), url, None, None)
        except Exception as e:
            end_time = time.time()
            response_time = end_time - start_time
            error_message = str(e)

            self.logger.error(f"测试失败 [{original_position}-{round_num}]: {url} - 错误: {error_message}")
            return self._finalize_test_result(TestResult(
                url=url,
                status="error",
                error_type="exception",
                error_message=error_message,
                test_round=round_num,
                url_index=url_index,
                original_position=original_position,
                ip_address=ip_address,
                response_time=response_time,
                final_url=normalized_url
            ), url, None, None)

    def run_direct_only_tests(self, urls: List[str], vpn_name: str, concurrency: int = 3, 
                              rounds: int = 1, test_name: str = "", base_output_dir: Optional[Path] = None,
                              progress_callback: Optional[Callable[[int, int], None]] = None) -> TestSession:
        """
        运行直连模式测试（不连接VPN，只测试直连通道）
        
        Args:
            urls: URL列表
            vpn_name: VPN名称（用于标识和文件命名）
            concurrency: 并发数
            rounds: 测试轮次
            test_name: 测试名称
            base_output_dir: 基础输出目录（可选）
            progress_callback: 进度回调函数
            
        Returns:
            测试会话对象
        """
        # 清空本次测试的拦截记录
        self.blocked_requests.clear()
        
        # 如果指定了基础输出目录（定时任务），使用它；否则使用默认的results目录
        output_base_dir = base_output_dir if base_output_dir else (get_app_base_dir() / "results")
        
        # 创建测试会话
        session = TestSession(
            test_name=test_name or f"DirectTest_{datetime.now().strftime('%Y%m%dT%H%M%S')}",
            test_rounds=rounds,
            total_urls=len(urls)
        )
        # 为直连测试准备会话目录，使用VPN名称标识
        self.prepare_session_directory(session, output_base_dir, vpn_name=vpn_name)
        
        self.logger.info(f"开始直连模式测试 '{session.test_name}' (VPN标识: {vpn_name}): {len(urls)} 个URL (并发数: {concurrency}, 轮次: {rounds})")
        self.logger.info(f"注意：此测试不连接VPN，只测试直连通道")
        
        # 使用线程池实现真正的并发
        from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
        actual_concurrency = min(concurrency, len(urls))  # 实际并发数不超过URL数量
        
        self.logger.info(f"实际并发数: {actual_concurrency} (配置: {concurrency}, URL数: {len(urls)})")
        
        completed_count = 0
        
        # 多轮次测试
        for round_num in range(rounds):
            if self.stop_event.is_set():
                self.logger.info("检测到停止信号，提前结束直连模式测试")
                break
            # 每轮测试开始前统一清理一次
            self._clear_all_caches(f"第 {round_num + 1} 轮直连测试开始前")
            
            self.logger.info(f"=== 开始第 {round_num + 1}/{rounds} 轮测试 ===")
            self.logger.info(f"本轮将并发执行 {min(actual_concurrency, len(urls))} 个任务")
            
            # 准备所有测试任务队列
            from queue import Queue
            task_queue = Queue()
            for url_index, url in enumerate(urls):
                original_position = url_index + 1
                task_queue.put((url, url_index, original_position, round_num))
            
            # 使用线程池动态调度执行
            future_to_task = {}
            
            with ThreadPoolExecutor(max_workers=actual_concurrency) as executor:
                # 初始提交：提交与并发数相等的任务
                initial_tasks = min(actual_concurrency, len(urls))
                self.logger.info(f"初始提交 {initial_tasks} 个并发任务")
                for _ in range(initial_tasks):
                    if not task_queue.empty():
                        url, url_index, original_position, _ = task_queue.get()
                        self.logger.info(f"提交任务 [{original_position}-{round_num}]: {url} 到线程池")
                        future = executor.submit(
                            self._run_single_direct_test_in_thread, url, url_index, original_position, round_num, vpn_name
                        )
                        future_to_task[future] = (url, url_index, original_position)
                
                # 动态调度：当任务完成时，立即提交下一个任务
                while future_to_task:
                    if self.stop_event.is_set():
                        self.logger.info("检测到停止信号，停止提交新的直连任务")
                        # 取消未完成任务
                        for f in not_done:
                            f.cancel()
                        break
                    # 等待任意一个任务完成
                    done, not_done = wait(future_to_task.keys(), return_when=FIRST_COMPLETED)
                    
                    # 处理完成的任务
                    for future in done:
                        url, url_index, original_position = future_to_task.pop(future)
                        
                        try:
                            result = future.result()
                            # 处理结果，按URL分组存储
                            key = f"{url}_direct_{vpn_name}"
                            if key not in session.results:
                                session.results[key] = []
                            session.results[key].append(result)
                            
                            completed_count += 1
                            if progress_callback:
                                progress_callback(completed_count, len(urls) * rounds)
                                
                        except Exception as exc:
                            self.logger.error(f"测试URL [{original_position}-{round_num}] {url} 时发生异常: {exc}", exc_info=True)
                            # 创建错误结果
                            error_result = TestResult(
                                url=url,
                                status="error",
                                error_type="exception",
                                error_message=str(exc),
                                test_round=round_num,
                                url_index=url_index,
                                original_position=original_position,
                                response_time=-1,
                                test_mode="direct",
                                vpn_name=vpn_name
                            )
                            key = f"{url}_direct_{vpn_name}"
                            if key not in session.results:
                                session.results[key] = []
                            session.results[key].append(error_result)
                            
                            completed_count += 1
                            if progress_callback:
                                progress_callback(completed_count, len(urls) * rounds)
                        
                        # 立即提交下一个任务（如果有）
                        if not task_queue.empty() and not self.stop_event.is_set():
                            next_url, next_url_index, next_original_position, _ = task_queue.get()
                            self.logger.info(f"任务完成，立即提交下一个任务 [{next_original_position}-{round_num}]: {next_url}")
                            future = executor.submit(
                                self._run_single_direct_test_in_thread, next_url, next_url_index, next_original_position, round_num, vpn_name
                            )
                            future_to_task[future] = (next_url, next_url_index, next_original_position)
            
            self.logger.info(f"=== 第 {round_num + 1}/{rounds} 轮测试完成 ===")
        
        self.logger.info(f"直连模式测试完成 '{session.test_name}': 共测试 {len(urls) * rounds} 个URL")
        return session
    
    def _run_single_direct_test_in_thread(self, url: str, url_index: int, original_position: int, 
                                          round_num: int, vpn_name: str) -> TestResult:
        """
        在线程中运行单个直连测试
        
        Args:
            url: URL地址
            url_index: URL索引
            original_position: 原始位置
            round_num: 轮次
            vpn_name: VPN名称（用于标识）
            
        Returns:
            测试结果
        """
        # 为每个线程创建独立的测试器实例
        thread_tester = PageLoadTester(logger=self.logger, wait_for_network_idle=self.wait_for_network_idle, config_manager=self.config_manager)
        thread_tester.timeout = self.timeout
        thread_tester.stage_timeouts = self.stage_timeouts.copy()
        thread_tester.headless = self.headless
        thread_tester.update_har_options(self.har_options)
        if self.blacklist_manager:
            thread_tester.blacklist_manager = self.blacklist_manager
        # 共享拦截请求列表（线程安全）
        thread_tester.blocked_requests = self.blocked_requests
        
        # 设置会话目录（共享同一个会话）
        if self.current_session_name:
            thread_tester.current_session_name = self.current_session_name
            thread_tester.session_output_dir = self.session_output_dir
            if self.har_manager:
                thread_tester.har_manager = self.har_manager
        
        # 设置VPN上下文信息（用于HAR文件命名）
        thread_tester._current_test_mode = "direct"
        thread_tester._current_vpn_name = vpn_name
        
        # 执行测试（不连接VPN，使用当前网络环境）
        result = thread_tester._measure_single_page(url, url_index, original_position, round_num)
        
        # 设置测试模式和VPN名称
        result.test_mode = "direct"
        result.vpn_name = vpn_name
        
        return result
    
    def run_tests(self, urls: List[str], concurrency: int = 3, rounds: int = 1, test_name: str = "") -> TestSession:
        """
        运行批量测试，支持多轮次

        Args:
            urls: URL列表
            concurrency: 并发数
            rounds: 测试轮次
            test_name: 测试名称

        Returns:
            测试会话对象
        """
        # 清空本次测试的拦截记录
        self.blocked_requests.clear()
        
        # 输出黑名单状态
        if self.blacklist_manager:
            blocked_count = len(self.blacklist_manager.get_blocked_domains())
            self.logger.info(f"[黑名单状态] 已加载 {blocked_count} 个黑名单域名，测试过程中将自动拦截匹配的请求")
        else:
            self.logger.info("[黑名单状态] 黑名单管理器未启用")

        # 创建测试会话
        session = TestSession(
            test_name=test_name or f"Test_{datetime.now().strftime('%Y%m%dT%H%M%S')}",
            test_rounds=rounds,
            total_urls=len(urls)
        )
        self.prepare_session_directory(session, get_app_base_dir() / "results")

        self.logger.info(f"开始测试 '{session.test_name}': {len(urls)} 个URL (并发数: {concurrency}, 轮次: {rounds})")

        # 使用线程池实现真正的并发
        from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
        actual_concurrency = min(concurrency, len(urls))  # 实际并发数不超过URL数量
        
        self.logger.info(f"实际并发数: {actual_concurrency} (配置: {concurrency}, URL数: {len(urls)})")
        self.logger.info(f"每个线程将创建独立的Playwright实例以确保真正的并发执行")

        # 多轮次测试
        for round_num in range(rounds):
            if self.stop_event.is_set():
                self.logger.info("检测到停止信号，提前结束测试")
                break
            # 每轮测试开始前统一清理一次
            self._clear_all_caches(f"第 {round_num + 1} 轮测试开始前")
            
            self.logger.info(f"=== 开始第 {round_num + 1}/{rounds} 轮测试 ===")
            self.logger.info(f"本轮将并发执行 {min(actual_concurrency, len(urls))} 个任务")

            # 准备所有测试任务队列
            from queue import Queue
            task_queue = Queue()
            for url_index, url in enumerate(urls):
                original_position = url_index + 1
                task_queue.put((url, url_index, original_position, round_num))

            # 使用线程池动态调度执行
            future_to_task = {}
            
            with ThreadPoolExecutor(max_workers=actual_concurrency) as executor:
                # 初始提交：提交与并发数相等的任务
                initial_tasks = min(actual_concurrency, len(urls))
                self.logger.info(f"初始提交 {initial_tasks} 个并发任务")
                for _ in range(initial_tasks):
                    if not task_queue.empty():
                        url, url_index, original_position, _ = task_queue.get()
                        self.logger.info(f"提交任务 [{original_position}-{round_num}]: {url} 到线程池")
                        future = executor.submit(
                            self._run_single_test_in_thread, url, url_index, original_position, round_num
                        )
                        future_to_task[future] = (url, url_index, original_position)

                # 动态调度：当任务完成时，立即提交下一个任务
                while future_to_task:
                    if self.stop_event.is_set():
                        self.logger.info("检测到停止信号，停止提交新的任务")
                        for f in not_done:
                            f.cancel()
                        break
                    # 等待任意一个任务完成
                    done, not_done = wait(future_to_task.keys(), return_when=FIRST_COMPLETED)
                    
                    # 处理完成的任务
                    for future in done:
                        url, url_index, original_position = future_to_task.pop(future)

                        try:
                            result = future.result()
                            # 处理结果，按URL分组存储
                            if result.url not in session.results:
                                session.results[result.url] = []
                            session.results[result.url].append(result)

                        except Exception as exc:
                            self.logger.error(f"测试URL [{original_position}-{round_num}] {url} 时发生异常: {exc}", exc_info=True)
                            # 创建错误结果
                            error_result = TestResult(
                                url=url,
                                status="error",
                                error_type="exception",
                                error_message=str(exc),
                                test_round=round_num,
                                url_index=url_index,
                                original_position=original_position,
                                response_time=-1
                            )
                            if error_result.url not in session.results:
                                session.results[error_result.url] = []
                            session.results[error_result.url].append(error_result)

                        # 立即提交下一个任务（如果有）
                        if not task_queue.empty() and not self.stop_event.is_set():
                            next_url, next_url_index, next_original_position, _ = task_queue.get()
                            self.logger.info(f"任务完成，立即提交下一个任务 [{next_original_position}-{round_num}]: {next_url}")
                            next_future = executor.submit(
                                self._run_single_test_in_thread, next_url, next_url_index, next_original_position, round_num
                            )
                            future_to_task[next_future] = (next_url, next_url_index, next_original_position)

            self.logger.info(f"第 {round_num + 1}/{rounds} 轮测试完成")

            # 轮次之间暂停（可选）
            if round_num < rounds - 1:
                self.logger.info(f"等待 {5} 秒后开始下一轮测试...")
                time.sleep(5)

        self.apply_har_metadata(session)

        # 计算测试会话的元数据统计
        session.calculate_metadata()

        self.logger.info(
            f"测试 '{session.test_name}' 完成: "
            f"总请求 {session.metadata['total_requests']}, "
            f"成功 {session.metadata['successful_requests']}, "
            f"成功率 {session.metadata['success_rate']}%"
        )
        
        # 输出拦截统计
        if self.blocked_requests:
            unique_blocked = len(set(self.blocked_requests))
            # 统计每个被拦截域名的拦截次数
            from collections import Counter
            blocked_counter = Counter(self.blocked_requests)
            # 提取域名并统计
            domain_counter = {}
            for url, count in blocked_counter.items():
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    domain = parsed.hostname or url
                    if domain not in domain_counter:
                        domain_counter[domain] = 0
                    domain_counter[domain] += count
                except:
                    domain_counter[url] = count
            
            self.logger.info(f"本次测试拦截了 {unique_blocked} 个不同的请求 (总计 {len(self.blocked_requests)} 次拦截)")
            # 显示被拦截的域名详情（最多显示前20个）
            if domain_counter:
                sorted_domains = sorted(domain_counter.items(), key=lambda x: x[1], reverse=True)
                top_domains = sorted_domains[:20]
                self.logger.info(f"[拦截详情] 被拦截的域名列表 (显示前{min(20, len(sorted_domains))}个):")
                for domain, count in top_domains:
                    self.logger.info(f"  - {domain} (拦截 {count} 次)")
                if len(sorted_domains) > 20:
                    self.logger.info(f"  ... 还有 {len(sorted_domains) - 20} 个域名被拦截")
        else:
            self.logger.info("本次测试未拦截任何请求")

        return session

    def request_stop(self):
        """外部请求停止，避免继续提交新任务"""
        self.stop_event.set()

    def _run_single_test_in_thread(self, url: str, url_index: int, original_position: int, round_num: int) -> TestResult:
        """
        在单独线程中运行单个URL测试
        
        注意：每个线程需要创建自己的测试器实例和Playwright实例，因为Playwright的同步API不是线程安全的
        """
        task_id = f"{original_position}-{round_num}"
        
        # 为每个线程创建任务专用的日志适配器
        from utils.logger import create_task_logger
        task_logger = create_task_logger(self.logger, task_id, f"URL-{original_position}")
        
        # 为每个线程创建独立的测试器实例
        thread_tester = PageLoadTester(logger=task_logger, wait_for_network_idle=self.wait_for_network_idle, config_manager=self.config_manager)
        thread_tester.timeout = self.timeout
        thread_tester.stage_timeouts = self.stage_timeouts.copy()
        thread_tester.headless = self.headless
        thread_tester.update_har_options(self.har_options)
        thread_tester.blacklist_manager = self.blacklist_manager
        # 共享拦截请求列表（线程安全）
        thread_tester.blocked_requests = self.blocked_requests
        
        # 设置会话目录（共享同一个会话）
        if self.current_session_name:
            thread_tester.current_session_name = self.current_session_name
            thread_tester.session_output_dir = self.session_output_dir
            if self.har_manager:
                thread_tester.har_manager = self.har_manager
        
        try:
            # 执行测试
            result = thread_tester._measure_single_page_with_retry(
                url, url_index, original_position, round_num, max_retries=1
            )
            
            # 记录任务完成状态
            if hasattr(task_logger, 'log_task_complete'):
                status = result.status if hasattr(result, 'status') else "未知"
                duration = result.response_time if hasattr(result, 'response_time') and result.response_time > 0 else -1
                task_logger.log_task_complete(url, original_position, round_num, status, duration)
            
            return result
        except Exception as e:
            # 记录任务错误
            if hasattr(task_logger, 'log_task_error'):
                task_logger.log_task_error(url, original_position, round_num, str(e))
            else:
                task_logger.error(f"任务执行失败: {e}")
            raise

    def save_results(self, session: TestSession, output_dir: Path) -> Path:
        """
        （已简化）保存测试结果相关信息

        当前版本不再生成独立的JSON结果文件，测试数据以 HAR 和 hostname 文件形式保存。

        Args:
            session: 测试会话对象
            output_dir: 输出目录

        Returns:
            会话目录路径（包含本次测试生成的HAR/hostname子目录）
        """
        target_dir = Path(session.session_directory) if session.session_directory else output_dir
        if not target_dir.exists():
            target_dir.mkdir(parents=True)

        # 不再生成JSON结果文件，所有可用信息均已通过 HAR / hostname 输出。
        # 这里仅记录一次信息性日志，方便用户在日志中找到会话目录位置。
        self.logger.info(f"本次测试结果以 HAR/hostname 形式保存在目录: {target_dir}")
        return target_dir

    def load_results(self, file_path: Path) -> TestSession:
        """
        从JSON文件加载测试结果

        Args:
            file_path: JSON文件路径

        Returns:
            测试会话对象
        """
        import json

        if not file_path.exists():
            raise FileNotFoundError(f"结果文件不存在: {file_path}")

        if file_path.stat().st_size == 0:
            raise ValueError(f"结果文件为空: {file_path}")

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()

            if not content:
                raise ValueError(f"结果文件内容为空: {file_path}")

            data = json.loads(content)
            return TestSession.from_dict(data)

        except json.JSONDecodeError as e:
            self.logger.error(f"JSON解析错误: {file_path} - {str(e)}")
            # 尝试读取文件内容用于调试
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    file_content = f.read()
                    self.logger.debug(f"文件内容: {file_content[:200]}...")  # 只记录前200个字符
            except:
                pass
            raise e
        except Exception as e:
            self.logger.error(f"加载结果文件失败: {file_path} - {str(e)}")
            raise e

    def _measure_single_page_with_retry(self, url: str, url_index: int, original_position: int,
                                        round_num: int = 0, max_retries: int = 2) -> TestResult:
        """带重试机制的页面测试"""
        for attempt in range(max_retries + 1):
            result = self._measure_single_page(url, url_index, original_position, round_num)

            # 如果是HTTP/2错误，尝试重试
            if (result.status == "error" and
                    result.error_type == "http2_error" and
                    attempt < max_retries):
                self.logger.info(f"HTTP/2错误，第{attempt + 1}次重试: {url}")
                time.sleep(1)  # 重试前等待1秒
                continue

            return result

        return result  # 返回最后一次尝试的结果

    def run_vpn_tests(self, urls: List[str], vpn_names: List[str], concurrency: int = 3, 
                      rounds: int = 1, test_name: str = "", base_output_dir: Optional[Path] = None,
                      progress_callback: Optional[Callable[[int, int], None]] = None,
                      enable_vpn_test: bool = True, enable_direct_test: bool = True) -> TestSession:
        """
        运行VPN测试，根据配置测试VPN模式和/或直连模式
        Windows上L2TP VPN不支持同时连接多个，所以VPN是顺序连接的
        每个VPN连接后，使用并发来测试多个URL
        
        Args:
            urls: URL列表
            vpn_names: VPN名称列表（会自动排序以保持固定顺序）
            concurrency: 并发数（同时测试的URL数量，不是VPN数量）
            rounds: 测试轮次
            test_name: 测试名称
            base_output_dir: 基础输出目录（可选）
            progress_callback: 进度回调函数（可选）
            enable_vpn_test: 是否启用VPN模式测试（默认True）
            enable_direct_test: 是否启用直连模式测试（默认True）
            
        Returns:
            测试会话对象
        """
        # 对VPN列表进行排序，确保每次执行顺序一致
        vpn_names = sorted(vpn_names)
        self.logger.info(f"VPN列表已排序: {vpn_names}")
        if not self.enable_vpn_testing or not self.vpn_manager:
            raise ValueError("VPN测试未启用，请先调用 initialize_vpn_support(True)")
        
        # 检查管理员权限
        if not self.vpn_manager.check_admin_privileges():
            raise PermissionError("VPN测试需要管理员权限，请以管理员身份运行程序")
        
        # 清空本次测试的拦截记录
        self.blocked_requests.clear()
        
        # 输出黑名单状态
        if self.blacklist_manager:
            blocked_count = len(self.blacklist_manager.get_blocked_domains())
            self.logger.info(f"[黑名单状态] 已加载 {blocked_count} 个黑名单域名，测试过程中将自动拦截匹配的请求")
        else:
            self.logger.info("[黑名单状态] 黑名单管理器未启用")
        
        # 清空本次测试的VPN连接失败记录（每次测试任务开始时重置）
        self.failed_vpns.clear()
        self.logger.info("已重置VPN连接失败记录，本次测试将重新尝试连接所有VPN")

        # 如果指定了基础输出目录（定时任务），使用它；否则使用默认的results目录
        output_base_dir = base_output_dir if base_output_dir else (get_app_base_dir() / "results")
        
        # 如果只有一个VPN，创建单个会话；如果有多个VPN，需要为每个VPN创建独立会话
        # 但为了保持兼容性，如果只有一个VPN，仍然使用单个会话
        if len(vpn_names) == 1:
            # 单个VPN：在VPN文件夹下创建测试会话
            session = TestSession(
                test_name=test_name or f"VPNTest_{datetime.now().strftime('%Y%m%dT%H%M%S')}",
                test_rounds=rounds,
                total_urls=len(urls)
            )
            self.prepare_session_directory(session, output_base_dir, vpn_name=vpn_names[0])
        else:
            # 多个VPN：先创建会话，但目录会在每个VPN测试时单独创建
            session = TestSession(
                test_name=test_name or f"VPNTest_{datetime.now().strftime('%Y%m%dT%H%M%S')}",
                test_rounds=rounds,
                total_urls=len(urls)
            )
            # 暂时不创建目录，每个VPN会单独创建

        self.logger.info(f"开始VPN测试 '{session.test_name}': {len(urls)} 个URL, {len(vpn_names)} 个VPN (URL并发数: {concurrency}, 轮次: {rounds})")
        self.logger.info(f"注意：Windows上L2TP VPN不支持同时连接多个，VPN将顺序连接，但每个VPN内会并发测试多个URL")

        # 获取网络信息
        if not self.vpn_manager.get_network_gateways():
            raise RuntimeError("无法获取网络网关信息")

        # 线程安全的会话结果存储
        session_lock = threading.Lock()
        
        # 实际并发数不超过URL数量
        actual_concurrency = min(concurrency, len(urls))
        self.logger.info(f"实际URL并发数: {actual_concurrency} (配置: {concurrency}, URL数: {len(urls)})")

        # 用于存储多个VPN的会话（如果有多个VPN）
        vpn_sessions = []
        current_session = session  # 默认使用共享会话

        try:
            # 顺序连接每个VPN（Windows不支持同时连接多个VPN）
            for vpn_index, vpn_name in enumerate(vpn_names):
                # 检查该VPN是否在失败列表中（之前连接失败过）
                if vpn_name in self.failed_vpns:
                    self.logger.warning(f"⚠️ VPN {vpn_name} 在本次测试任务中连接失败过，自动跳过该VPN的所有测试任务")
                    continue
                
                self.logger.info(f"=== 开始测试VPN: {vpn_name} ({vpn_index + 1}/{len(vpn_names)}) ===")
                
                # 如果有多个VPN，为每个VPN创建独立的会话和目录
                if len(vpn_names) > 1:
                    # 为当前VPN创建独立的会话
                    vpn_session = TestSession(
                        test_name=test_name or f"VPNTest_{datetime.now().strftime('%Y%m%dT%H%M%S')}",
                        test_rounds=rounds,
                        total_urls=len(urls)
                    )
                    # 为当前VPN创建独立的目录
                    self.prepare_session_directory(vpn_session, output_base_dir, vpn_name=vpn_name)
                    # 更新HAR管理器
                    if self.har_options.get("enable_har_capture"):
                        # 为当前VPN创建HAR管理器
                        vpn_safe_name = self._sanitize_session_name(vpn_name)
                        vpn_dir = (output_base_dir / vpn_safe_name).resolve()
                        safe_name = self._sanitize_session_name(vpn_session.test_name)
                        # 从测试名称中提取时间戳
                        timestamp = self._extract_timestamp_from_test_name(vpn_session.test_name)
                        self.har_manager = HARManager(safe_name, vpn_dir, timestamp=timestamp)
                    current_session = vpn_session
                    vpn_sessions.append((vpn_name, vpn_session))
                else:
                    # 单个VPN，使用共享会话
                    current_session = session
                
                # 获取VPN凭据
                credentials = self.vpn_config.get_vpn_credentials(vpn_name)
                username = credentials.get("username", "")
                password = credentials.get("password", "")
                
                # 连接VPN（只有在启用VPN测试时才连接）
                if enable_vpn_test:
                    # 传递vpn_config用于容错机制（连接其他VPN节点）
                    if not self.vpn_manager.connect_vpn(vpn_name, username, password, vpn_config=self.vpn_config):
                        self.logger.error(f"❌ 无法连接VPN: {vpn_name}，将该VPN添加到失败列表，本次测试任务中将自动跳过该VPN的所有测试")
                        # 将失败的VPN添加到失败列表，本次任务中不再尝试
                        self.failed_vpns.add(vpn_name)
                        self.logger.info(f"📋 当前失败VPN列表: {list(self.failed_vpns)}")
                        continue
                else:
                    self.logger.info(f"VPN模式测试已禁用，不连接VPN: {vpn_name}")
                
                try:
                    # 等待VPN连接稳定
                    wait_time = self.vpn_config.get_test_settings().get("wait_after_vpn_connect", 3)
                    self.logger.debug(f"等待VPN连接稳定 {wait_time} 秒...")
                    time.sleep(wait_time)
                    
                    # 更新网关信息（如果连接了VPN）
                    if enable_vpn_test:
                        self.logger.debug(f"开始获取网络网关信息...")
                        self.vpn_manager.get_network_gateways()
                        self.logger.debug(f"网络网关信息获取完成")
                    
                    # 使用线程池并发测试多个URL
                    self.logger.debug(f"开始调用_run_concurrent_url_tests_for_vpn...")
                    self._run_concurrent_url_tests_for_vpn(
                        vpn_name, urls, current_session, session_lock, actual_concurrency,
                        progress_callback, enable_vpn_test, enable_direct_test
                    )
                
                finally:
                    # 断开VPN连接（如果连接了VPN，添加超时保护）
                    # 注意：如果VPN已经在批次处理中断开（例如在直连测试前断开），这里不需要再次断开
                    if enable_vpn_test:
                        # 检查VPN是否仍然连接
                        if self.vpn_manager.connected_vpn_name == vpn_name:
                            self.logger.info(f"准备断开VPN连接: {vpn_name}")
                            self._safe_disconnect_vpn(vpn_name)
                            self.logger.info(f"VPN {vpn_name} 已断开")
                        else:
                            self.logger.debug(f"VPN {vpn_name} 已经断开，跳过断开操作")
                    
                    # VPN之间的间隔
                    if vpn_index < len(vpn_names) - 1:
                        self.logger.info("等待3秒后连接下一个VPN...")
                        time.sleep(3)

        finally:
            # 停止监控线程
            self._stop_monitor_thread()
            
            # 清空活动URL测试列表
            with self.url_test_lock:
                self.active_url_tests.clear()
            
            # 清理future_to_url_registry
            with self.future_to_url_lock:
                self.future_to_url_registry.clear()
            
            # 清理取消标志
            with self.cancelled_urls_lock:
                self.cancelled_urls.clear()
            
            # 确保清理所有路由
            try:
                self.logger.info("清理所有路由...")
                self.vpn_manager.cleanup_routes()
            except Exception as e:
                self.logger.error(f"清理路由时发生错误: {e}", exc_info=True)
            
            # 确保断开所有VPN连接（添加超时保护）
            self.logger.info("确保断开所有VPN连接...")
            for vpn_name in vpn_names:
                try:
                    self._safe_disconnect_vpn(vpn_name)
                except Exception as e:
                    self.logger.error(f"断开VPN {vpn_name} 时发生错误: {e}", exc_info=True)

        # 如果有多个VPN，需要处理多个会话；如果只有一个VPN，处理单个会话
        if len(vpn_names) > 1:
            # 多个VPN：处理所有VPN的会话
            for vpn_name, vpn_session in vpn_sessions:
                self.apply_har_metadata(vpn_session)
                vpn_session.calculate_metadata()
                self.logger.info(
                    f"VPN测试 '{vpn_session.test_name}' (VPN: {vpn_name}) 完成: "
                    f"总请求 {vpn_session.metadata['total_requests']}, "
                    f"成功 {vpn_session.metadata['successful_requests']}, "
                    f"成功率 {vpn_session.metadata['success_rate']}%"
                )
            # 返回最后一个会话（为了保持接口兼容性）
            final_session = vpn_sessions[-1][1] if vpn_sessions else session
        else:
            # 单个VPN：处理共享会话
            final_session = session
            self.apply_har_metadata(final_session)
            final_session.calculate_metadata()
            self.logger.info(
                f"VPN测试 '{final_session.test_name}' 完成: "
                f"总请求 {final_session.metadata['total_requests']}, "
                f"成功 {final_session.metadata['successful_requests']}, "
                f"成功率 {final_session.metadata['success_rate']}%"
            )
        
        # 输出拦截统计
        if self.blocked_requests:
            unique_blocked = len(set(self.blocked_requests))
            # 统计每个被拦截域名的拦截次数
            from collections import Counter
            blocked_counter = Counter(self.blocked_requests)
            # 提取域名并统计
            domain_counter = {}
            for url, count in blocked_counter.items():
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    domain = parsed.hostname or url
                    if domain not in domain_counter:
                        domain_counter[domain] = 0
                    domain_counter[domain] += count
                except:
                    domain_counter[url] = count
            
            self.logger.info(f"本次VPN测试拦截了 {unique_blocked} 个不同的请求 (总计 {len(self.blocked_requests)} 次拦截)")
            # 显示被拦截的域名详情（最多显示前20个）
            if domain_counter:
                sorted_domains = sorted(domain_counter.items(), key=lambda x: x[1], reverse=True)
                top_domains = sorted_domains[:20]
                self.logger.info(f"[拦截详情] 被拦截的域名列表 (显示前{min(20, len(sorted_domains))}个):")
                for domain, count in top_domains:
                    self.logger.info(f"  - {domain} (拦截 {count} 次)")
                if len(sorted_domains) > 20:
                    self.logger.info(f"  ... 还有 {len(sorted_domains) - 20} 个域名被拦截")
        else:
            self.logger.info("本次VPN测试未拦截任何请求")


        return final_session
    
    def _run_concurrent_url_tests_for_vpn(self, vpn_name: str, urls: List[str], session: TestSession, 
                                          session_lock: threading.Lock, concurrency: int,
                                          progress_callback: Optional[Callable[[int, int], None]] = None,
                                          enable_vpn_test: bool = True, enable_direct_test: bool = True):
        """
        在VPN连接状态下，并发测试多个URL
        根据配置决定测试VPN模式和/或直连模式
        
        Args:
            vpn_name: VPN名称
            urls: URL列表
            session: 测试会话对象（线程安全访问）
            session_lock: 会话锁，用于线程安全的结果存储
            concurrency: 并发数（同时测试的URL数量）
            progress_callback: 进度回调函数（可选）
            enable_vpn_test: 是否启用VPN模式测试（默认True）
            enable_direct_test: 是否启用直连模式测试（默认True）
        """
        from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
        from queue import Queue
        
        # 将future_to_url注册到全局注册表，供监控线程访问
        with self.future_to_url_lock:
            self.future_to_url_registry[vpn_name] = {}
        
        # 启动监控线程（如果还没启动）
        self._start_monitor_thread()
        
        # 计算最大超时时间（所有阶段超时时间总和 + 缓冲时间60秒）
        max_timeout_seconds = (self.stage_timeouts.get("stage1", 8000) + 
                               self.stage_timeouts.get("stage2", 15000) + 
                               self.stage_timeouts.get("stage3", 30000)) / 1000.0 + 60
        
        # 初始化取消标志
        with self.cancelled_urls_lock:
            if vpn_name not in self.cancelled_urls:
                self.cancelled_urls[vpn_name] = set()
        
        # 每批处理的URL数量（从配置获取）
        batch_size = self.vpn_config.get_test_settings().get("vpn_batch_size", 10)
        if hasattr(self, 'config_manager') and self.config_manager:
            config = self.config_manager.get_config()
            batch_size = config.get("vpn_batch_size", batch_size)
        
        # 获取VPN凭据（用于重连）
        credentials = self.vpn_config.get_vpn_credentials(vpn_name)
        username = credentials.get("username", "")
        password = credentials.get("password", "")
        
        try:
            # 将URL列表分批处理
            total_batches = (len(urls) + batch_size - 1) // batch_size
            self.logger.info(f"[VPN-{vpn_name}] 总共 {len(urls)} 个URL，将分为 {total_batches} 批处理（每批 {batch_size} 个URL）")
            
            for batch_index in range(total_batches):
                start_idx = batch_index * batch_size
                end_idx = min(start_idx + batch_size, len(urls))
                batch_urls = urls[start_idx:end_idx]
                batch_num = batch_index + 1
                
                self.logger.info(f"[VPN-{vpn_name}] ========== 开始处理第 {batch_num}/{total_batches} 批URL ({len(batch_urls)} 个) ==========")
                
                # ========== 第一阶段：测试这批URL的VPN模式（如果启用） ==========
                if enable_vpn_test:
                    # 批次开始前统一清理一次（连接VPN后）
                    self._clear_all_caches(f"批次 {batch_num} VPN模式测试开始前")
                    
                    self.logger.info(f"[VPN-{vpn_name}] [批次 {batch_num}] 开始VPN模式测试...")
                    self._run_url_tests_phase(vpn_name, batch_urls, session, session_lock, concurrency, 
                                             "vpn", max_timeout_seconds, progress_callback, start_idx)
                else:
                    self.logger.info(f"[VPN-{vpn_name}] [批次 {batch_num}] VPN模式测试已禁用，跳过")
                
                # ========== 断开VPN并清除缓存（仅在同时启用VPN和直连测试时才需要） ==========
                # 优化逻辑：如果只选择了VPN模式或只选择了直连模式，不需要断开VPN
                # 1. 只选择VPN模式：不需要断开，继续测试下一批
                # 2. 只选择直连模式：不需要断开（因为没有连接VPN），直接测试直连
                # 3. 同时选择VPN和直连：需要断开VPN，测试直连，然后重新连接VPN
                if enable_direct_test:
                    # 只有在同时启用VPN和直连测试时，才需要断开VPN
                    if enable_vpn_test:
                        # 同时启用VPN和直连：需要断开VPN并测试直连
                        self.logger.info(f"[VPN-{vpn_name}] [批次 {batch_num}] VPN模式测试完成，准备断开VPN并清除缓存...")
                        self._safe_disconnect_vpn(vpn_name)
                        self.logger.info(f"[VPN-{vpn_name}] [批次 {batch_num}] VPN已断开")
                        
                        # 切换到直连模式前统一清理一次
                        self._clear_all_caches(f"批次 {batch_num} 切换到直连模式前")
                        
                        # 等待系统恢复网络配置（VPN断开后，系统会自动恢复原始网关和DNS）
                        wait_time = self.vpn_config.get_test_settings().get("wait_after_disconnect", 5)
                        if hasattr(self, 'config_manager') and self.config_manager:
                            config = self.config_manager.get_config()
                            wait_time = config.get("wait_after_disconnect", wait_time)
                        self.logger.info(f"[VPN-{vpn_name}] [批次 {batch_num}] 等待 {wait_time} 秒，确保系统网络配置恢复...")
                        time.sleep(wait_time)
                    else:
                        # 只启用直连模式：不需要断开VPN（因为没有连接VPN），直接测试直连
                        # 批次开始前统一清理一次
                        self._clear_all_caches(f"批次 {batch_num} 直连模式测试开始前")
                        self.logger.info(f"[VPN-{vpn_name}] [批次 {batch_num}] 只启用直连模式，无需断开VPN，直接开始直连模式测试...")
                    
                    # ========== 第二阶段：测试这批URL的直连模式 ==========
                    self.logger.info(f"[VPN-{vpn_name}] [批次 {batch_num}] 开始直连模式测试...")
                    self._run_url_tests_phase(vpn_name, batch_urls, session, session_lock, concurrency, 
                                             "direct", max_timeout_seconds, progress_callback, start_idx)
                    
                    # ========== 重新连接VPN（如果不是最后一批且同时启用了VPN和直连测试） ==========
                    if batch_num < total_batches and enable_vpn_test and enable_direct_test:
                        self.logger.info(f"[VPN-{vpn_name}] [批次 {batch_num}] 直连模式测试完成，准备重新连接VPN...")
                        # 传递vpn_config用于容错机制（连接其他VPN节点）
                        if self.vpn_manager.connect_vpn(vpn_name, username, password, vpn_config=self.vpn_config):
                            self.logger.info(f"[VPN-{vpn_name}] [批次 {batch_num}] VPN已重新连接")
                            # 等待VPN连接稳定
                            wait_time = self.vpn_config.get_test_settings().get("wait_after_vpn_connect", 3)
                            time.sleep(wait_time)
                            # 更新网关信息
                            self.vpn_manager.get_network_gateways()
                        else:
                            self.logger.error(f"[VPN-{vpn_name}] [批次 {batch_num}] 重新连接VPN失败，后续批次将无法继续")
                            break
                    else:
                        self.logger.info(f"[VPN-{vpn_name}] [批次 {batch_num}] 直连模式测试完成（最后一批或VPN测试已禁用，不重新连接VPN）")
                elif enable_vpn_test and batch_num < total_batches:
                    # 如果只启用VPN测试，且不是最后一批，需要保持VPN连接
                    self.logger.info(f"[VPN-{vpn_name}] [批次 {batch_num}] VPN模式测试完成，直连模式已禁用，保持VPN连接继续下一批")
                
                self.logger.info(f"[VPN-{vpn_name}] [批次 {batch_num}] 处理完成")
        finally:
            # 清理注册表
            with self.future_to_url_lock:
                self.future_to_url_registry.pop(vpn_name, None)
            # 清理取消标志
            with self.cancelled_urls_lock:
                self.cancelled_urls.pop(vpn_name, None)
    
    def _run_url_tests_phase(self, vpn_name: str, urls: List[str], session: TestSession, 
                            session_lock: threading.Lock, concurrency: int, test_mode: str,
                            max_timeout_seconds: float, progress_callback: Optional[Callable[[int, int], None]] = None,
                            url_start_index: int = 0):
        """
        执行一个测试阶段（VPN模式或直连模式）
        
        Args:
            vpn_name: VPN名称
            urls: URL列表
            session: 测试会话对象
            session_lock: 会话锁
            concurrency: 并发数
            test_mode: 测试模式 ("vpn" 或 "direct")
            max_timeout_seconds: 最大超时时间
            progress_callback: 进度回调函数
            url_start_index: URL的起始索引（用于计算original_position）
        """
        from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
        from queue import Queue
        
        # 准备URL任务队列
        url_queue = Queue()
        for url_index, url in enumerate(urls):
            # original_position 需要加上 url_start_index，以保持全局位置
            original_position = url_start_index + url_index + 1
            url_queue.put((url, url_index, original_position))
        
        # 使用线程池并发处理URL
        future_to_url = {}
        
        # 更新全局注册表
        with self.future_to_url_lock:
            if vpn_name in self.future_to_url_registry:
                self.future_to_url_registry[vpn_name] = future_to_url
        
        try:
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                # 初始提交：提交与并发数相等的URL任务
                for _ in range(min(concurrency, len(urls))):
                    if not url_queue.empty():
                        url, url_index, original_position = url_queue.get()
                        self.logger.info(f"[VPN-{vpn_name}] [{test_mode.upper()}] 提交URL任务 [{original_position}]: {url} 到线程池")
                        future = executor.submit(
                            self._run_single_url_test_phase,
                            vpn_name, url, url_index, original_position, session, session_lock, test_mode
                        )
                        future_to_url[future] = (url, url_index, original_position)
                        # 记录URL测试开始时间
                        with self.url_test_lock:
                            self.active_url_tests[future] = (url, time.time(), vpn_name, original_position)
                
                # 动态调度：当URL任务完成时，立即提交下一个URL任务
                while future_to_url:
                    # 在等待之前，先检查是否有卡死的任务
                    self._check_and_kill_stuck_tasks(future_to_url, max_timeout_seconds, url_queue, executor, 
                                                     vpn_name, session, session_lock, progress_callback, len(urls), test_mode)
                    
                    # 如果所有任务都被终止了，退出循环
                    if not future_to_url:
                        break
                    
                    # 等待任意一个URL任务完成
                    # 等待超时时间设置为 max_timeout_seconds 的 1/10，但最小30秒，最大120秒
                    # 这样当测试超时时间很长时（如600秒），等待超时也会相应调整，避免频繁触发警告
                    wait_timeout = max(30, min(120, max_timeout_seconds / 10))
                    done, not_done = wait(future_to_url.keys(), return_when=FIRST_COMPLETED, timeout=wait_timeout)
                    
                    # 如果超时（没有任务完成），再次检查卡死任务
                    if not done:
                        self.logger.warning(f"[VPN-{vpn_name}] [{test_mode.upper()}] 等待任务完成超时（{wait_timeout:.1f}秒），检查是否有卡死任务...")
                        self._check_and_kill_stuck_tasks(future_to_url, max_timeout_seconds, url_queue, executor, 
                                                         vpn_name, session, session_lock, progress_callback, len(urls), test_mode)
                        continue
                    
                    # 处理完成的URL任务
                    for future in done:
                        url, url_index, original_position = future_to_url.pop(future)
                        # 从活动测试中移除
                        with self.url_test_lock:
                            self.active_url_tests.pop(future, None)
                        
                        try:
                            future.result()  # 获取结果（如果有异常会抛出）
                            # 计算已完成的URL数量：总数 - 剩余任务 - 队列中任务
                            completed_count = len(urls) - len(future_to_url) - url_queue.qsize()
                            self.logger.info(f"[VPN-{vpn_name}] [{test_mode.upper()}] URL任务完成 [{original_position}]: {url} ({completed_count}/{len(urls)})")
                            
                            # 更新进度
                            if progress_callback:
                                progress_callback(completed_count, len(urls))
                        except Exception as exc:
                            # 即使失败也计算进度
                            completed_count = len(urls) - len(future_to_url) - url_queue.qsize()
                            self.logger.error(f"[VPN-{vpn_name}] [{test_mode.upper()}] URL任务 [{original_position}] {url} 执行失败: {exc}", exc_info=True)
                            
                            # 更新进度
                            if progress_callback:
                                progress_callback(completed_count, len(urls))
                        
                        # 立即提交下一个URL任务（如果有）
                        if not url_queue.empty():
                            next_url, next_url_index, next_original_position = url_queue.get()
                            self.logger.info(f"[VPN-{vpn_name}] [{test_mode.upper()}] URL任务完成，立即提交下一个URL任务 [{next_original_position}]: {next_url}")
                            next_future = executor.submit(
                                self._run_single_url_test_phase,
                                vpn_name, next_url, next_url_index, next_original_position, session, session_lock, test_mode
                            )
                            future_to_url[next_future] = (next_url, next_url_index, next_original_position)
                            # 记录新URL测试开始时间
                            with self.url_test_lock:
                                self.active_url_tests[next_future] = (next_url, time.time(), vpn_name, next_original_position)
                    
                    # 检查是否有卡死的任务（在等待期间）
                    self._check_and_kill_stuck_tasks(future_to_url, max_timeout_seconds, url_queue, executor, 
                                                     vpn_name, session, session_lock, progress_callback, len(urls), test_mode)
        except Exception as e:
            self.logger.error(f"[VPN-{vpn_name}] [{test_mode.upper()}] 测试阶段发生错误: {e}", exc_info=True)
    
    def _start_monitor_thread(self):
        """启动监控线程，每30秒检查一次卡死的URL测试"""
        if self.monitor_thread is None or not self.monitor_thread.is_alive():
            self.monitor_running = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            self.logger.info("已启动URL测试监控线程，每30秒检查一次卡死状态")
    
    def _stop_monitor_thread(self):
        """停止监控线程"""
        self.monitor_running = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.logger.info("正在停止URL测试监控线程...")
    
    def _monitor_loop(self):
        """监控循环，每30秒检查一次卡死的URL测试"""
        while self.monitor_running:
            try:
                time.sleep(30)  # 每30秒检查一次，提高响应速度
                if not self.monitor_running:
                    break
                
                # 计算最大超时时间
                max_timeout_seconds = (self.stage_timeouts.get("stage1", 8000) + 
                                       self.stage_timeouts.get("stage2", 15000) + 
                                       self.stage_timeouts.get("stage3", 30000)) / 1000.0 + 60
                
                # 检查卡死的任务
                with self.url_test_lock:
                    current_time = time.time()
                    stuck_futures = []
                    for future, (url, start_time, vpn_name, original_position) in list(self.active_url_tests.items()):
                        elapsed = current_time - start_time
                        if elapsed > max_timeout_seconds:
                            stuck_futures.append((future, url, vpn_name, original_position, elapsed))
                
                if stuck_futures:
                    self.logger.warning(f"⚠️ 检测到 {len(stuck_futures)} 个卡死的URL测试任务")
                    for future, url, vpn_name, original_position, elapsed in stuck_futures:
                        self.logger.error(f"🔴 卡死任务: [VPN-{vpn_name}] [URL-{original_position}] {url} (运行时间: {elapsed:.1f}秒, 超过最大超时时间: {max_timeout_seconds:.1f}秒)")
                        
                        # 标记URL为已取消
                        with self.cancelled_urls_lock:
                            if vpn_name not in self.cancelled_urls:
                                self.cancelled_urls[vpn_name] = set()
                            self.cancelled_urls[vpn_name].add(url)
                        
                        # 尝试取消future
                        if not future.done():
                            cancelled = future.cancel()
                            if cancelled:
                                self.logger.warning(f"已尝试取消卡死的future: {url}")
                            else:
                                self.logger.warning(f"无法取消正在运行的future: {url}，任务可能正在执行中")
                        
                        # 从活动列表中移除
                        with self.url_test_lock:
                            self.active_url_tests.pop(future, None)
                        
                        # 尝试从future_to_url_registry中移除（如果存在）
                        with self.future_to_url_lock:
                            if vpn_name in self.future_to_url_registry:
                                future_to_url = self.future_to_url_registry[vpn_name]
                                if future in future_to_url:
                                    future_to_url.pop(future)
                                    self.logger.info(f"已从future_to_url中移除卡死任务: {url}")
            except Exception as e:
                self.logger.error(f"监控线程错误: {e}", exc_info=True)
    
    def _check_and_kill_stuck_tasks(self, future_to_url: dict, max_timeout_seconds: float, 
                                     url_queue, executor, vpn_name: str, session: TestSession, 
                                     session_lock: threading.Lock, progress_callback, total_urls: int, 
                                     test_mode: str = "vpn"):
        """检查并终止卡死的URL测试任务"""
        current_time = time.time()
        stuck_futures = []
        
        with self.url_test_lock:
            for future in list(future_to_url.keys()):
                if future in self.active_url_tests:
                    url, start_time, _, original_position = self.active_url_tests[future]
                    elapsed = current_time - start_time
                    if elapsed > max_timeout_seconds:
                        stuck_futures.append((future, url, original_position, elapsed))
        
        # 处理卡死的任务
        for future, url, original_position, elapsed in stuck_futures:
            self.logger.error(f"🔴 [VPN-{vpn_name}] 检测到卡死的URL测试任务 [{original_position}]: {url} (运行时间: {elapsed:.1f}秒)")
            
            # 标记URL为已取消
            with self.cancelled_urls_lock:
                if vpn_name not in self.cancelled_urls:
                    self.cancelled_urls[vpn_name] = set()
                self.cancelled_urls[vpn_name].add(url)
            
            # 尝试取消future
            if not future.done():
                cancelled = future.cancel()
                if cancelled:
                    self.logger.warning(f"✅ 已成功取消卡死的URL测试任务 [{original_position}]: {url}")
                else:
                    self.logger.warning(f"⚠️ 无法取消正在运行的URL测试任务 [{original_position}]: {url}，任务可能正在执行中（已标记为取消，任务会在下次检查时退出）")
            
            # 从future_to_url中移除
            if future in future_to_url:
                future_to_url.pop(future)
            
            # 从活动测试中移除
            with self.url_test_lock:
                self.active_url_tests.pop(future, None)
            
            # 创建超时错误结果
            try:
                from .result import TestResult
                timeout_result = TestResult(
                    url=url,
                    status="timeout",
                    error_type="stuck_timeout",
                    error_message=f"URL测试任务卡死，运行时间超过 {max_timeout_seconds:.1f} 秒（实际运行: {elapsed:.1f}秒），已强制终止",
                    test_round=0,
                    url_index=original_position - 1,
                    original_position=original_position,
                    timestamp=datetime.now().isoformat()
                )
                # 添加到会话结果中
                with session_lock:
                    session_key = f"{url}_{test_mode}_{vpn_name}"
                    if session_key not in session.results:
                        session.results[session_key] = []
                    session.results[session_key].append(timeout_result)
                self.logger.info(f"已为卡死的URL测试任务创建超时结果: {url}")
            except Exception as e:
                self.logger.error(f"创建超时结果失败: {e}", exc_info=True)
            
            # 更新进度
            completed_count = total_urls - len(future_to_url) - url_queue.qsize()
            if progress_callback:
                progress_callback(completed_count, total_urls)
            
            # 如果队列中还有任务，立即提交下一个
            if not url_queue.empty():
                next_url, next_url_index, next_original_position = url_queue.get()
                self.logger.info(f"[VPN-{vpn_name}] [{test_mode.upper()}] 卡死任务已处理，立即提交下一个URL任务 [{next_original_position}]: {next_url}")
                next_future = executor.submit(
                    self._run_single_url_test_phase,
                    vpn_name, next_url, next_url_index, next_original_position, session, session_lock, test_mode
                )
                future_to_url[next_future] = (next_url, next_url_index, next_original_position)
                # 记录新URL测试开始时间
                with self.url_test_lock:
                    self.active_url_tests[next_future] = (next_url, time.time(), vpn_name, next_original_position)

    def _is_url_cancelled(self, vpn_name: str, url: str) -> bool:
        """检查URL是否已被取消"""
        with self.cancelled_urls_lock:
            if vpn_name in self.cancelled_urls:
                return url in self.cancelled_urls[vpn_name]
            return False
    
    def _flush_dns_cache(self) -> bool:
        """
        清除DNS缓存（内部方法，由 _clear_all_caches 调用）
        
        Returns:
            bool: 是否成功清除DNS缓存
        """
        try:
            system = platform.system()
            if system == "Windows":
                # Windows系统使用 ipconfig /flushdns
                result = subprocess.run(
                    ["ipconfig", "/flushdns"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    encoding='gbk' if platform.system() == "Windows" else 'utf-8'
                )
                if result.returncode == 0:
                    self.logger.debug("DNS缓存清除成功")
                    return True
                else:
                    self.logger.warning(f"DNS缓存清除失败: {result.stderr}")
                    return False
            elif system == "Linux":
                # Linux系统使用 systemd-resolve 或 resolvectl
                # 先尝试使用 resolvectl
                result = subprocess.run(
                    ["resolvectl", "flush-caches"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    self.logger.debug("DNS缓存清除成功 (resolvectl)")
                    return True
                # 如果失败，尝试使用 systemd-resolve
                result = subprocess.run(
                    ["systemd-resolve", "--flush-caches"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    self.logger.debug("DNS缓存清除成功 (systemd-resolve)")
                    return True
                self.logger.warning(f"DNS缓存清除失败: {result.stderr}")
                return False
            elif system == "Darwin":  # macOS
                # macOS使用 dscacheutil -flushcache
                result = subprocess.run(
                    ["dscacheutil", "-flushcache"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    self.logger.debug("DNS缓存清除成功")
                    return True
                else:
                    self.logger.warning(f"DNS缓存清除失败: {result.stderr}")
                    return False
            else:
                self.logger.warning(f"不支持的操作系统: {system}")
                return False
        except subprocess.TimeoutExpired:
            self.logger.warning("DNS缓存清除超时")
            return False
        except Exception as e:
            self.logger.warning(f"清除DNS缓存时发生错误: {e}")
            return False
    
    def _run_single_url_test_phase(self, vpn_name: str, url: str, url_index: int, original_position: int,
                                   session: TestSession, session_lock: threading.Lock, test_mode: str):
        """
        测试单个URL的一个阶段（VPN模式或直连模式）
        
        Args:
            vpn_name: VPN名称
            url: URL地址
            url_index: URL索引
            original_position: 原始位置
            session: 测试会话对象（线程安全访问）
            session_lock: 会话锁，用于线程安全的结果存储
            test_mode: 测试模式 ("vpn" 或 "direct")
        """
        # 为每个URL线程创建独立的测试器实例
        thread_tester = PageLoadTester(logger=self.logger, wait_for_network_idle=self.wait_for_network_idle, config_manager=self.config_manager)
        thread_tester.timeout = self.timeout
        thread_tester.stage_timeouts = self.stage_timeouts.copy()
        thread_tester.headless = self.headless
        thread_tester.update_har_options(self.har_options)
        # 确保黑名单管理器被正确传递
        if self.blacklist_manager:
            thread_tester.blacklist_manager = self.blacklist_manager
        # 共享拦截请求列表（线程安全）
        thread_tester.blocked_requests = self.blocked_requests
        thread_tester.vpn_manager = self.vpn_manager
        thread_tester.vpn_config = self.vpn_config
        thread_tester.enable_vpn_testing = True
        
        # 设置会话目录（共享同一个会话）
        if self.current_session_name:
            thread_tester.current_session_name = self.current_session_name
            thread_tester.session_output_dir = self.session_output_dir
            if self.har_manager:
                thread_tester.har_manager = self.har_manager
        
        try:
            self.logger.info(f"[VPN-{vpn_name}] [{test_mode.upper()}] [URL-{original_position}] 开始测试: {url}")
            
            # 检查任务是否已被取消
            if self._is_url_cancelled(vpn_name, url):
                self.logger.warning(f"[VPN-{vpn_name}] [{test_mode.upper()}] [URL-{original_position}] 任务已被取消，提前退出: {url}")
                return
            
            # 检查主URL是否被黑名单拦截（在测试开始前检查）
            interceptor = RequestInterceptor(
                blacklist_manager=self.blacklist_manager,
                logger=self.logger
            )
            is_blocked, intercept_record = interceptor.check_main_url(url)
            if is_blocked:
                # 获取IP地址（即使被拦截也记录IP）
                ip = self.vpn_manager.resolve_domain_ip(url) if self.vpn_manager else None
                self.logger.info(
                    f"[VPN-{vpn_name}] [{test_mode.upper()}] [URL-{original_position}] [拦截完成] URL已被黑名单拦截: {url} "
                    f"(IP: {ip if ip else '无法解析'}, 匹配规则: {intercept_record.matched_rule if intercept_record else '未知'})"
                )
                # 创建拦截状态的结果
                blocked_result = TestResult(
                    url=url,
                    status="blocked",
                    status_code=None,
                    error_type="blacklist_blocked",
                    error_message=f"URL在黑名单中，已被拦截（匹配规则: {intercept_record.matched_rule if intercept_record else '未知'}）",
                    test_round=0,
                    url_index=url_index,
                    original_position=original_position,
                    ip_address=ip,
                    response_time=-1,
                    final_url=url,
                    test_mode=test_mode,
                    vpn_name=vpn_name
                )
                # 存储测试结果
                result_key = f"{url}_{test_mode}_{vpn_name}"
                with session_lock:
                    if result_key not in session.results:
                        session.results[result_key] = []
                    session.results[result_key].append(blocked_result)
                return
            
            # 解析域名IP
            ip = None
            if self.vpn_manager:
                ip = self.vpn_manager.resolve_domain_ip(url)
            if not ip:
                self.logger.error(f"[VPN-{vpn_name}] [{test_mode.upper()}] [URL-{original_position}] 无法解析域名 {url}，跳过测试")
                # 创建错误结果并存储
                error_result = TestResult(
                    url=url,
                    status="error",
                    error_type="dns_error",
                    error_message=f"无法解析域名: {url}",
                    test_round=0,
                    url_index=url_index,
                    original_position=original_position,
                    response_time=-1,
                    final_url=url,
                    test_mode=test_mode,
                    vpn_name=vpn_name
                )
                result_key = f"{url}_{test_mode}_{vpn_name}"
                with session_lock:
                    if result_key not in session.results:
                        session.results[result_key] = []
                    session.results[result_key].append(error_result)
                return
            
            # 执行测试（缓存已在批次开始前统一清理，这里不再清理）
            if test_mode == "direct":
                # 直连模式：VPN已断开，系统已自动恢复原始网关，直接测试即可
                self.logger.info(f"[VPN-{vpn_name}] [{test_mode.upper()}] [URL-{original_position}] VPN已断开，使用系统默认网关进行直连测试")
                # 执行直连测试（VPN已断开，系统已自动恢复原始网关）
                result = thread_tester._measure_single_page_with_vpn_context(
                    url, url_index, original_position, 0, "direct", vpn_name
                )
                
                # 线程安全地存储测试结果
                result_key = f"{url}_{test_mode}_{vpn_name}"
                with session_lock:
                    if result_key not in session.results:
                        session.results[result_key] = []
                    session.results[result_key].append(result)
            else:
                # VPN模式：直接测试
                result = thread_tester._measure_single_page_with_vpn_context(
                    url, url_index, original_position, 0, "vpn", vpn_name
                )
                
                # 线程安全地存储测试结果
                result_key = f"{url}_{test_mode}_{vpn_name}"
                with session_lock:
                    if result_key not in session.results:
                        session.results[result_key] = []
                    session.results[result_key].append(result)
            
            self.logger.info(f"[VPN-{vpn_name}] [{test_mode.upper()}] [URL-{original_position}] 测试完成: {url}")
        
        except Exception as e:
            self.logger.error(f"[VPN-{vpn_name}] [{test_mode.upper()}] [URL-{original_position}] URL测试过程中发生错误: {e}", exc_info=True)
    
    def _run_single_url_test_for_vpn(self, vpn_name: str, url: str, url_index: int, original_position: int,
                                     session: TestSession, session_lock: threading.Lock):
        """
        在VPN连接状态下，测试单个URL的VPN通道和正常通道
        测试顺序：先测试VPN通道，再测试正常通道
        
        Args:
            vpn_name: VPN名称
            url: URL地址
            url_index: URL索引
            original_position: 原始位置
            session: 测试会话对象（线程安全访问）
            session_lock: 会话锁，用于线程安全的结果存储
        """
        # 为每个URL线程创建独立的测试器实例
        thread_tester = PageLoadTester(logger=self.logger, wait_for_network_idle=self.wait_for_network_idle, config_manager=self.config_manager)
        thread_tester.timeout = self.timeout
        thread_tester.stage_timeouts = self.stage_timeouts.copy()
        thread_tester.headless = self.headless
        thread_tester.update_har_options(self.har_options)
        # 确保黑名单管理器被正确传递
        if self.blacklist_manager:
            thread_tester.blacklist_manager = self.blacklist_manager
            self.logger.debug(f"[VPN-{vpn_name}] [URL-{original_position}] 黑名单管理器已传递，黑名单域名数: {len(self.blacklist_manager.get_blocked_domains())}")
        else:
            self.logger.warning(f"[VPN-{vpn_name}] [URL-{original_position}] 黑名单管理器未初始化")
        # 共享拦截请求列表（线程安全）
        thread_tester.blocked_requests = self.blocked_requests
        thread_tester.vpn_manager = self.vpn_manager  # 共享VPN管理器（因为VPN已经连接）
        thread_tester.vpn_config = self.vpn_config
        thread_tester.enable_vpn_testing = True
        
        # 设置会话目录（共享同一个会话）
        if self.current_session_name:
            thread_tester.current_session_name = self.current_session_name
            thread_tester.session_output_dir = self.session_output_dir
            if self.har_manager:
                thread_tester.har_manager = self.har_manager
        
        try:
            self.logger.info(f"[VPN-{vpn_name}] [URL-{original_position}] 开始测试: {url}")
            
            # 检查任务是否已被取消
            if self._is_url_cancelled(vpn_name, url):
                self.logger.warning(f"[VPN-{vpn_name}] [URL-{original_position}] 任务已被取消，提前退出: {url}")
                return
            
            # 检查主URL是否被黑名单拦截（在测试开始前检查）
            interceptor = RequestInterceptor(
                blacklist_manager=self.blacklist_manager,
                logger=self.logger
            )
            is_blocked, intercept_record = interceptor.check_main_url(url)
            if is_blocked:
                # 获取IP地址（即使被拦截也记录IP）
                ip = self.vpn_manager.resolve_domain_ip(url)
                self.logger.info(
                    f"[VPN-{vpn_name}] [URL-{original_position}] [拦截完成] URL已被黑名单拦截: {url} "
                    f"(IP: {ip if ip else '无法解析'}, 匹配规则: {intercept_record.matched_rule if intercept_record else '未知'})"
                )
                # 创建拦截状态的结果
                blocked_result = TestResult(
                    url=url,
                    status="blocked",
                    status_code=None,
                    error_type="blacklist_blocked",
                    error_message=f"URL在黑名单中，已被拦截（匹配规则: {intercept_record.matched_rule if intercept_record else '未知'}）",
                    test_round=0,
                    url_index=url_index,
                    original_position=original_position,
                    ip_address=ip,
                    response_time=-1,
                    final_url=url,
                    test_mode="vpn",
                    vpn_name=vpn_name
                )
                # 存储VPN测试结果
                vpn_key = f"{url}_vpn_{vpn_name}"
                with session_lock:
                    if vpn_key not in session.results:
                        session.results[vpn_key] = []
                    session.results[vpn_key].append(blocked_result)
                
                # 创建直连测试的拦截结果
                direct_blocked_result = TestResult(
                    url=url,
                    status="blocked",
                    status_code=None,
                    error_type="blacklist_blocked",
                    error_message=f"URL在黑名单中，已被拦截（匹配规则: {intercept_record.matched_rule if intercept_record else '未知'}）",
                    test_round=0,
                    url_index=url_index,
                    original_position=original_position,
                    ip_address=ip,
                    response_time=-1,
                    final_url=url,
                    test_mode="direct",
                    vpn_name=vpn_name
                )
                # 存储直连测试结果
                direct_key = f"{url}_direct_{vpn_name}"
                with session_lock:
                    if direct_key not in session.results:
                        session.results[direct_key] = []
                    session.results[direct_key].append(direct_blocked_result)
                
                self.logger.info(f"[VPN-{vpn_name}] [URL-{original_position}] 拦截测试完成（VPN和直连结果已创建）: {url}")
                return
            
            # 解析域名IP
            ip = self.vpn_manager.resolve_domain_ip(url)
            if not ip:
                self.logger.error(f"[VPN-{vpn_name}] [URL-{original_position}] 无法解析域名 {url}，跳过测试")
                # 创建错误结果并存储
                error_result = TestResult(
                    url=url,
                    status="error",
                    error_type="dns_error",
                    error_message=f"无法解析域名: {url}",
                    test_round=0,
                    url_index=url_index,
                    original_position=original_position,
                    response_time=-1,
                    final_url=url,
                    test_mode="vpn",
                    vpn_name=vpn_name
                )
                vpn_key = f"{url}_vpn_{vpn_name}"
                with session_lock:
                    if vpn_key not in session.results:
                        session.results[vpn_key] = []
                    session.results[vpn_key].append(error_result)
                return
            
            # 1. VPN模式测试
            self.logger.info(f"[VPN-{vpn_name}] [URL-{original_position}] 执行VPN模式测试: {url}")
            
            # 检查任务是否已被取消
            if self._is_url_cancelled(vpn_name, url):
                self.logger.warning(f"[VPN-{vpn_name}] [URL-{original_position}] 任务已被取消，跳过VPN测试: {url}")
                return
            
            # 执行VPN测试（缓存已在批次开始前统一清理，这里不再清理）
            vpn_result = thread_tester._measure_single_page_with_vpn_context(
                url, url_index, original_position, 0, "vpn", vpn_name
            )
            
            # 线程安全地存储VPN测试结果
            vpn_key = f"{url}_vpn_{vpn_name}"
            with session_lock:
                if vpn_key not in session.results:
                    session.results[vpn_key] = []
                session.results[vpn_key].append(vpn_result)
            
            # 等待一下
            time.sleep(2)
            
            # 检查任务是否已被取消
            if self._is_url_cancelled(vpn_name, url):
                self.logger.warning(f"[VPN-{vpn_name}] [URL-{original_position}] 任务已被取消，跳过直连测试: {url}")
                return
            
            # 2. 直连模式测试
            self.logger.info(f"[VPN-{vpn_name}] [URL-{original_position}] 执行直连模式测试: {url}")
            
            # 执行直连测试（缓存已在切换到直连模式前统一清理，这里不再清理）
            
            # 使用全局网关模式：直接修改默认网关，让所有流量（包括DNS）都走直连通道
            # 这样不需要为每个IP添加路由，更简单且可靠
            gateway_switched = False
            try:
                with session_lock:  # 网关切换需要全局锁，确保同一时间只有一个线程在切换
                    gateway_switched = self.vpn_manager.switch_to_direct_gateway()
                
                if gateway_switched:
                    # 等待网关切换生效
                    wait_time = self.vpn_config.get_test_settings().get("wait_after_route_change", 2)
                    time.sleep(wait_time)
                    
                    # 执行直连测试（此时所有流量包括DNS都会走直连通道）
                    direct_result = thread_tester._measure_single_page_with_vpn_context(
                        url, url_index, original_position, 0, "direct", vpn_name
                    )
                    
                    # 线程安全地存储直连测试结果
                    direct_key = f"{url}_direct_{vpn_name}"
                    with session_lock:
                        if direct_key not in session.results:
                            session.results[direct_key] = []
                        session.results[direct_key].append(direct_result)
                    
                    # 恢复VPN网关（需要线程安全）
                    with session_lock:
                        self.vpn_manager.restore_vpn_gateway()
                else:
                    self.logger.error(f"[VPN-{vpn_name}] [URL-{original_position}] 无法切换到直连网关，跳过直连测试: {url}")
            
            except Exception as e:
                self.logger.error(f"[VPN-{vpn_name}] [URL-{original_position}] 直连测试时发生错误: {e}", exc_info=True)
                # 确保恢复VPN网关（即使出错）
                if gateway_switched:
                    try:
                        with session_lock:
                            self.vpn_manager.restore_vpn_gateway()
                    except:
                        pass
            
            self.logger.info(f"[VPN-{vpn_name}] [URL-{original_position}] 测试完成: {url}")
        
        except Exception as e:
            self.logger.error(f"[VPN-{vpn_name}] [URL-{original_position}] URL测试过程中发生错误: {e}", exc_info=True)
    
    def _safe_disconnect_vpn(self, vpn_name: str, timeout: int = 10):
        """
        安全断开VPN连接，带超时保护
        
        Args:
            vpn_name: VPN名称
            timeout: 超时时间（秒）
        """
        try:
            import signal
            
            def timeout_handler(signum, frame):
                raise TimeoutError(f"断开VPN {vpn_name} 超时")
            
            # 设置超时（仅Unix系统支持signal）
            if hasattr(signal, 'SIGALRM'):
                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(timeout)
            
            try:
                self.vpn_manager.disconnect_vpn(vpn_name)
                time.sleep(1)  # 等待断开完成
            finally:
                if hasattr(signal, 'SIGALRM'):
                    signal.alarm(0)  # 取消超时
        except TimeoutError:
            self.logger.warning(f"断开VPN {vpn_name} 超时，继续执行")
        except Exception as e:
            self.logger.error(f"断开VPN {vpn_name} 时发生错误: {e}", exc_info=True)
    
    def _safe_disconnect_vpn_for_manager(self, vpn_manager, vpn_name: str, timeout: int = 10):
        """
        安全断开VPN连接（使用指定的VPN管理器），带超时保护
        
        Args:
            vpn_manager: VPN管理器实例
            vpn_name: VPN名称
            timeout: 超时时间（秒）
        """
        try:
            # 使用线程超时机制（Windows兼容）
            import threading
            import subprocess
            
            disconnect_success = threading.Event()
            disconnect_error = [None]
            
            def disconnect_thread():
                try:
                    # 直接使用subprocess调用rasdial，避免阻塞
                    result = subprocess.run(
                        ['rasdial', vpn_name, '/disconnect'],
                        capture_output=True,
                        text=True,
                        encoding='gbk',
                        timeout=timeout,
                        stdin=subprocess.DEVNULL
                    )
                    if result.returncode == 0:
                        disconnect_success.set()
                    else:
                        disconnect_error[0] = f"断开失败: {result.stderr}"
                        disconnect_success.set()
                except subprocess.TimeoutExpired:
                    disconnect_error[0] = f"断开超时（{timeout}秒）"
                    disconnect_success.set()
                except Exception as e:
                    disconnect_error[0] = e
                    disconnect_success.set()
            
            thread = threading.Thread(target=disconnect_thread, daemon=True)
            thread.start()
            thread.join(timeout=timeout + 2)  # 给额外2秒缓冲时间
            
            if not disconnect_success.is_set():
                self.logger.warning(f"断开VPN {vpn_name} 超时（{timeout}秒），强制继续执行")
                # 尝试强制终止rasdial进程（如果存在）
                try:
                    subprocess.run(['taskkill', '/F', '/IM', 'rasdial.exe'], 
                                 capture_output=True, timeout=2)
                except:
                    pass
            elif disconnect_error[0]:
                self.logger.error(f"断开VPN {vpn_name} 时发生错误: {disconnect_error[0]}", exc_info=True)
            else:
                self.logger.info(f"VPN {vpn_name} 断开成功")
        except Exception as e:
            self.logger.error(f"断开VPN {vpn_name} 时发生错误: {e}", exc_info=True)
    

    def _measure_single_page_with_vpn_context(self, url: str, url_index: int, original_position: int,
                                              round_num: int, test_mode: str, vpn_name: str) -> TestResult:
        """
        在VPN上下文中测试单个页面
        
        Args:
            url: 目标URL
            url_index: URL索引
            original_position: 原始位置
            round_num: 轮次编号
            test_mode: 测试模式 ("vpn" 或 "direct")
            vpn_name: VPN名称
            
        Returns:
            测试结果
        """
        # 为VPN测试创建独立的测试器实例
        vpn_tester = PageLoadTester(logger=self.logger, wait_for_network_idle=self.wait_for_network_idle)
        vpn_tester.timeout = self.timeout
        vpn_tester.stage_timeouts = self.stage_timeouts.copy()
        vpn_tester.headless = self.headless
        vpn_tester.update_har_options(self.har_options)
        vpn_tester.blacklist_manager = self.blacklist_manager
        vpn_tester.config_manager = self.config_manager
        # 共享拦截请求列表（确保拦截统计正确）
        vpn_tester.blocked_requests = self.blocked_requests
        
        # 设置会话目录（共享同一个会话）
        if self.current_session_name:
            vpn_tester.current_session_name = self.current_session_name
            vpn_tester.session_output_dir = self.session_output_dir
            
            # 为VPN测试创建专用的HAR管理器
            if self.har_manager:
                vpn_tester.har_manager = self.har_manager
        
        # 设置VPN上下文信息
        vpn_tester._current_test_mode = test_mode
        vpn_tester._current_vpn_name = vpn_name
        
        # 调用原有的测试方法
        result = vpn_tester._measure_single_page(url, url_index, original_position, round_num)
        
        # 添加VPN相关信息
        result.test_mode = test_mode
        result.vpn_name = vpn_name
        
        return result