from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Set, List
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


class BlacklistManager:
    """黑名单管理器：管理拦截域名列表、对比hostname文件、持久化存储（线程安全）"""

    def __init__(self, blacklist_file: Path | None = None):
        if blacklist_file is None:
            from utils.file_utils import get_app_base_dir
            self.blacklist_file = get_app_base_dir() / "config" / "blacklist.json"
        else:
            self.blacklist_file = blacklist_file
        self.blocked_domains: Set[str] = set()
        self._lock = threading.RLock()  # 使用可重入锁，支持同一线程多次获取
        self._load_blacklist()

    def _load_blacklist(self) -> None:
        """从文件加载黑名单"""
        if self.blacklist_file.exists():
            try:
                with self.blacklist_file.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.blocked_domains = set(data.get("domains", []))
                logger.info(f"已加载黑名单: {len(self.blocked_domains)} 个域名")
            except Exception as exc:
                logger.error(f"加载黑名单失败: {exc}")
                self.blocked_domains = set()
        else:
            # 尝试从旧位置迁移配置文件
            from utils.file_utils import get_app_base_dir
            old_blacklist_file = get_app_base_dir() / "blacklist.json"
            if old_blacklist_file.exists() and old_blacklist_file != self.blacklist_file:
                try:
                    # 确保新目录存在
                    self.blacklist_file.parent.mkdir(parents=True, exist_ok=True)
                    # 复制文件
                    import shutil
                    shutil.copy2(old_blacklist_file, self.blacklist_file)
                    # 重新加载
                    with self.blacklist_file.open("r", encoding="utf-8") as f:
                        data = json.load(f)
                        self.blocked_domains = set(data.get("domains", []))
                    logger.info(f"已从旧位置迁移黑名单文件: {old_blacklist_file} -> {self.blacklist_file}")
                    logger.info(f"已加载黑名单: {len(self.blocked_domains)} 个域名")
                except Exception as exc:
                    logger.warning(f"迁移黑名单文件失败: {exc}")
                    self.blocked_domains = set()

    def _save_blacklist(self) -> None:
        """保存黑名单到文件"""
        try:
            self.blacklist_file.parent.mkdir(parents=True, exist_ok=True)
            with self.blacklist_file.open("w", encoding="utf-8") as f:
                json.dump({"domains": sorted(self.blocked_domains)}, f, indent=2, ensure_ascii=False)
            logger.info(f"已保存黑名单: {len(self.blocked_domains)} 个域名")
        except Exception as exc:
            logger.error(f"保存黑名单失败: {exc}")

    def add_domains(self, domains: List[str]) -> None:
        """添加域名到黑名单（线程安全）"""
        added = []
        with self._lock:
            for domain in domains:
                clean_domain = self._normalize_domain(domain)
                if clean_domain and clean_domain not in self.blocked_domains:
                    self.blocked_domains.add(clean_domain)
                    added.append(clean_domain)
        if added:
            self._save_blacklist()
            logger.info(f"已添加 {len(added)} 个域名到黑名单: {added}")

    def remove_domain(self, domain: str) -> None:
        """从黑名单移除域名（线程安全）"""
        clean_domain = self._normalize_domain(domain)
        with self._lock:
            if clean_domain in self.blocked_domains:
                self.blocked_domains.remove(clean_domain)
                removed = True
            else:
                removed = False
        if removed:
            self._save_blacklist()
            logger.info(f"已从黑名单移除: {clean_domain}")

    def clear_blacklist(self) -> None:
        """清空黑名单（线程安全）"""
        with self._lock:
            count = len(self.blocked_domains)
            self.blocked_domains.clear()
        self._save_blacklist()
        logger.info(f"已清空黑名单 ({count} 个域名)")

    def is_blocked(self, url: str) -> bool:
        """检查URL是否在黑名单中（支持子域名匹配，与对比逻辑保持一致）"""
        try:
            # 如果URL没有协议，尝试添加http://以便解析
            if not url.startswith(('http://', 'https://')):
                test_url = f"http://{url}"
            else:
                test_url = url
            
            parsed = urlparse(test_url)
            domain = parsed.hostname or url  # 如果解析失败，使用原始URL
            clean_domain = self._normalize_domain(domain)
            
            # 如果规范化后为空，尝试直接规范化原始URL
            if not clean_domain:
                clean_domain = self._normalize_domain(url)
            
            # 首先尝试精确匹配（使用锁保护）
            matched_domain = None
            match_type = None
            
            with self._lock:
                if clean_domain in self.blocked_domains:
                    matched_domain = clean_domain
                    match_type = "精确匹配"
            
            # 如果精确匹配失败，进行子域名匹配
            if not matched_domain:
                # 使用锁保护集合访问，避免迭代时集合被修改
                with self._lock:
                    # 创建集合的副本进行迭代，避免迭代时集合被修改导致的异常
                    blocked_domains_copy = set(self.blocked_domains)
                
                # 在锁外进行迭代，避免长时间持有锁
                for blocked_domain in blocked_domains_copy:
                    # 精确匹配（再次检查，虽然理论上不会发生）
                    if clean_domain == blocked_domain:
                        matched_domain = blocked_domain
                        match_type = "精确匹配"
                        break
                    # 检查请求的域名是否是黑名单域名的子域名
                    # 例如：fonts.googleapis.com 是 googleapis.com 的子域名
                    # 现实语义：拉黑 googleapis.com，则其所有子域名（如 fonts.googleapis.com）也应被拦截；
                    # 但拉黑某个具体子域名（如 scratch.mit.edu），不应反向把父域名 mit.edu 一起拉黑，
                    # 所以这里只保留“请求域名是黑名单域名的子域名”这一方向的匹配。
                    if clean_domain.endswith('.' + blocked_domain):
                        matched_domain = blocked_domain
                        match_type = "子域名匹配（请求域名是黑名单域名的子域名）"
                        break
            
            if matched_domain:
                # 记录详细的拦截信息（使用根logger确保日志能传播）
                root_logger = logging.getLogger()
                root_logger.info(
                    f"[黑名单拦截] URL: {url} | "
                    f"解析hostname: {domain} | "
                    f"规范化hostname: {clean_domain} | "
                    f"匹配黑名单域名: {matched_domain} | "
                    f"匹配类型: {match_type}"
                )
                return True
            
            return False
        except Exception as e:
            logger.error(f"检查URL是否在黑名单中时出错: {url}, 错误: {e}")
            return False

    def get_blocked_domains(self) -> List[str]:
        """获取所有被拦截的域名列表（排序，线程安全）"""
        with self._lock:
            return sorted(self.blocked_domains)

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        """规范化域名：去除www、端口号、转换为小写"""
        if not domain:
            return ""
        domain = domain.lower().strip()
        # 去除www前缀
        if domain.startswith("www."):
            domain = domain[4:]
        # 去除端口号
        if ":" in domain:
            domain = domain.split(":")[0]
        return domain

    @staticmethod
    def load_hostnames_from_file(file_path: Path) -> Set[str]:
        """从hostname文件加载域名列表（跳过注释行）"""
        hostnames = set()
        if not file_path.exists():
            return hostnames
        try:
            with file_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        clean = BlacklistManager._normalize_domain(line)
                        if clean:
                            hostnames.add(clean)
        except Exception as exc:
            logger.error(f"读取hostname文件失败 ({file_path}): {exc}")
        return hostnames

    @staticmethod
    def load_reference_file(file_path: Path) -> Set[str]:
        """从参考对比文件加载域名列表"""
        return BlacklistManager.load_hostnames_from_file(file_path)

    @staticmethod
    def compare_hostnames(test_hostnames: Set[str], reference_hostnames: Set[str], match_level: str = '2', return_base_urls: bool = False) -> Set[str]:
        """
        对比测试hostname与参考文件，返回匹配的域名
        
        Args:
            test_hostnames: 测试中的hostname集合
            reference_hostnames: 参考文件中的hostname集合
            match_level: 匹配级别
                '1' - 精确匹配
                '2' - 子域名匹配（默认，支持子域名关系）
                '3' - 二级域名匹配
            return_base_urls: 是否返回基准URL（参考文件中的URL），默认False返回测试中的hostname
        Returns:
            匹配的域名集合（如果return_base_urls=True，返回参考文件中的基准URL；否则返回测试中的hostname）
        """
        if match_level == '1':
            # 级别1: 精确匹配
            if return_base_urls:
                # 返回参考文件中匹配的基准URL
                return test_hostnames & reference_hostnames
            else:
                return test_hostnames & reference_hostnames
        elif match_level == '2':
            # 级别2: 子域名匹配（支持子域名关系）
            if return_base_urls:
                # 返回参考文件中匹配的基准URL
                matched_base_urls = set()
                for ref_domain in reference_hostnames:
                    for test_domain in test_hostnames:
                        # 精确匹配
                        if test_domain == ref_domain:
                            matched_base_urls.add(ref_domain)
                            break
                        # 检查是否是子域名关系
                        # test_domain 是 ref_domain 的子域名
                        if test_domain.endswith('.' + ref_domain):
                            matched_base_urls.add(ref_domain)
                            break
                        # ref_domain 是 test_domain 的子域名
                        if ref_domain.endswith('.' + test_domain):
                            matched_base_urls.add(ref_domain)
                            break
                return matched_base_urls
            else:
                # 返回测试中匹配的hostname（原有逻辑）
                matched = set()
                for test_domain in test_hostnames:
                    for ref_domain in reference_hostnames:
                        # 精确匹配
                        if test_domain == ref_domain:
                            matched.add(test_domain)
                            break
                        # 检查是否是子域名关系
                        # test_domain 是 ref_domain 的子域名
                        if test_domain.endswith('.' + ref_domain):
                            matched.add(test_domain)
                            break
                        # ref_domain 是 test_domain 的子域名
                        if ref_domain.endswith('.' + test_domain):
                            matched.add(test_domain)
                            break
                return matched
        elif match_level == '3':
            # 级别3: 二级域名匹配
            def get_second_level(domain: str) -> str:
                """提取二级域名"""
                parts = domain.split('.')
                if len(parts) >= 2:
                    return '.'.join(parts[-2:])
                return domain
            
            matched = set()
            for test_domain in test_hostnames:
                test_2nd = get_second_level(test_domain)
                for ref_domain in reference_hostnames:
                    ref_2nd = get_second_level(ref_domain)
                    if test_2nd == ref_2nd:
                        matched.add(test_domain)
                        break
            return matched
        else:
            # 默认使用精确匹配
            return test_hostnames & reference_hostnames

