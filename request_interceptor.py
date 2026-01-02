"""
请求拦截器：基于 Playwright Route API 实现网络请求拦截
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional, Callable, List, Dict, Set
from urllib.parse import urlparse
from datetime import datetime

from .blacklist_manager import BlacklistManager


logger = logging.getLogger(__name__)


@dataclass
class InterceptRecord:
    """拦截记录"""
    url: str                          # 请求URL
    hostname: str                     # 主机名
    is_blocked: bool                  # 是否被拦截
    block_reason: Optional[str] = None       # 拦截原因
    matched_rule: Optional[str] = None       # 匹配的黑名单规则
    block_type: Optional[str] = None  # 拦截类型（main_url/resource）
    resource_type: Optional[str] = None      # 资源类型（document/image/script等）
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())  # 时间戳


class RequestInterceptor:
    """请求拦截器：基于 Playwright Route API 实现网络请求拦截"""
    
    def __init__(
        self,
        blacklist_manager: Optional[BlacklistManager] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        初始化请求拦截器
        
        Args:
            blacklist_manager: 黑名单管理器
            logger: 日志记录器
        """
        self.blacklist_manager = blacklist_manager
        self.logger = logger or logging.getLogger(__name__)
        
        # 拦截记录列表
        self._blocked_records: List[InterceptRecord] = []
        self._all_records: List[InterceptRecord] = []
        
        # 统计信息
        self._stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "loaded_requests": 0,
            "unique_hostnames": set(),
            "blocked_hostnames": set(),
        }
    
    def check_main_url(self, url: str) -> tuple[bool, Optional[InterceptRecord]]:
        """
        检查主URL是否被黑名单拦截（在浏览器启动前检查）
        
        Args:
            url: 要检查的URL
            
        Returns:
            (is_blocked, record): 是否被拦截和拦截记录
        """
        if not self.blacklist_manager:
            return False, None
        
        try:
            # 提取hostname
            hostname = self._extract_hostname(url)
            
            # 检查是否被拦截
            is_blocked = self.blacklist_manager.is_blocked(url)
            
            # 创建拦截记录
            record = InterceptRecord(
                url=url,
                hostname=hostname,
                is_blocked=is_blocked,
                block_type="main_url",
                block_reason="blacklist_match" if is_blocked else None,
                matched_rule=self._find_matched_rule(hostname) if is_blocked else None
            )
            
            if is_blocked:
                self._blocked_records.append(record)
                self.logger.info(
                    f"[主URL拦截] URL已被黑名单拦截: {url} "
                    f"(hostname: {hostname}, 匹配规则: {record.matched_rule})"
                )
            
            self._all_records.append(record)
            return is_blocked, record
            
        except Exception as e:
            self.logger.error(f"检查主URL时出错: {url}, 错误: {e}", exc_info=True)
            return False, None
    
    def create_route_handler(self, disable_cache: bool = True) -> Callable:
        """
        创建 Playwright route handler
        
        Args:
            disable_cache: 是否禁用缓存（添加缓存禁用请求头）
        
        Returns:
            route handler函数
        """
        def handler(route):
            """路由处理函数"""
            request = route.request
            request_url = request.url
            request_method = request.method
            resource_type = request.resource_type
            
            # 更新统计
            self._stats["total_requests"] += 1
            
            try:
                # 提取hostname（提前提取，用于日志记录和后续处理）
                hostname = self._extract_hostname(request_url)
                self._stats["unique_hostnames"].add(hostname)
                
                # 【关键修复】记录所有经过拦截器的黑名单域名请求，包括重定向请求
                # 这对于调试非常重要，可以确认请求是否真的经过了拦截器
                if self.blacklist_manager:
                    try:
                        clean_hostname = BlacklistManager._normalize_domain(hostname)
                        blocked_domains = self.blacklist_manager.get_blocked_domains()
                        # 检查是否是黑名单域名（精确匹配或子域名匹配）
                        is_potential_block = clean_hostname in blocked_domains or any(
                            clean_hostname.endswith('.' + blocked_domain) 
                            for blocked_domain in blocked_domains
                        )
                        if is_potential_block:
                            # 对于黑名单域名，使用info级别记录，确保能看到
                            # 这个日志会在拦截器的最开始就记录，确保所有经过拦截器的请求都被记录
                            self.logger.info(f"[拦截器入口] {request_method} {request_url} (hostname: {clean_hostname}, resource_type: {resource_type})")
                    except Exception as e:
                        # 日志记录失败不应该影响拦截逻辑
                        pass
                
                # 检查黑名单拦截
                is_blocked = False
                matched_rule = None
                block_reason = None
                
                if self.blacklist_manager:
                    try:
                        is_blocked = self.blacklist_manager.is_blocked(request_url)
                        if is_blocked:
                            matched_rule = self._find_matched_rule(hostname)
                            block_reason = "blacklist_match"
                            self._stats["blocked_requests"] += 1
                            self._stats["blocked_hostnames"].add(hostname)
                        else:
                            self._stats["loaded_requests"] += 1
                    except Exception as e:
                        # 如果拦截检查出错，为了安全起见，中止请求
                        self.logger.error(
                            f"[拦截错误] 黑名单拦截检查出错: {request_url}, 错误: {e}，为安全起见中止请求",
                            exc_info=True
                        )
                        is_blocked = True
                        block_reason = "check_error"
                        matched_rule = None
                        self._stats["blocked_requests"] += 1
                        self._stats["blocked_hostnames"].add(hostname)
                
                # 创建拦截记录
                record = InterceptRecord(
                    url=request_url,
                    hostname=hostname,
                    is_blocked=is_blocked,
                    block_type="resource",
                    block_reason=block_reason,
                    matched_rule=matched_rule,
                    resource_type=resource_type
                )
                
                self._all_records.append(record)
                
                # 执行拦截或放行
                if is_blocked:
                    self._blocked_records.append(record)
                    self.logger.info(
                        f"[请求拦截] ✓ {request_method} {request_url} "
                        f"已被黑名单拦截 (hostname: {hostname}, 匹配规则: {matched_rule})"
                    )
                    # 【关键修复】使用route.abort()拦截请求
                    # 这应该能拦截所有请求，包括重定向后的请求
                    route.abort("blockedbyclient")
                else:
                    # 未被拦截，继续请求
                    if disable_cache:
                        # 添加禁用缓存的请求头
                        headers = route.request.headers.copy()
                        headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
                        headers['Pragma'] = 'no-cache'
                        headers['Expires'] = '0'
                        # 【关键修复】使用route.continue_()继续请求
                        # 这应该能处理所有请求，包括重定向后的请求
                        route.continue_(headers=headers)
                    else:
                        route.continue_()
                    
            except Exception as e:
                self.logger.error(f"处理路由请求时出错: {request_url}, 错误: {e}", exc_info=True)
                # 出错时为了安全起见，中止请求
                route.abort("blockedbyclient")
        
        return handler
    
    def _extract_hostname(self, url: str) -> str:
        """
        从URL中提取hostname
        
        Args:
            url: 请求URL
            
        Returns:
            hostname
        """
        try:
            # 如果URL没有协议，尝试添加http://以便解析
            if not url.startswith(('http://', 'https://')):
                test_url = f"http://{url}"
            else:
                test_url = url
            
            parsed = urlparse(test_url)
            hostname = parsed.hostname or parsed.path.split("/")[0]
            
            if not hostname:
                return url
            
            # 规范化hostname
            if self.blacklist_manager:
                return self.blacklist_manager._normalize_domain(hostname)
            else:
                return hostname.lower().strip()
                
        except Exception as e:
            self.logger.warning(f"提取hostname失败: {url}, 错误: {e}")
            return url
    
    def _find_matched_rule(self, hostname: str) -> Optional[str]:
        """
        查找匹配的黑名单规则
        
        Args:
            hostname: 主机名
            
        Returns:
            匹配的黑名单域名，如果没有匹配则返回None
        """
        if not self.blacklist_manager:
            return None
        
        try:
            # 获取所有黑名单域名
            blocked_domains = self.blacklist_manager.get_blocked_domains()
            
            # 精确匹配
            if hostname in blocked_domains:
                return hostname
            
            # 子域名匹配：检查hostname是否是黑名单域名的子域名
            for blocked_domain in blocked_domains:
                if hostname.endswith('.' + blocked_domain):
                    return blocked_domain
            
            return None
            
        except Exception as e:
            self.logger.warning(f"查找匹配规则失败: {hostname}, 错误: {e}")
            return None
    
    def get_blocked_records(self) -> List[InterceptRecord]:
        """
        获取所有被拦截的记录
        
        Returns:
            拦截记录列表
        """
        return self._blocked_records.copy()
    
    def get_all_records(self) -> List[InterceptRecord]:
        """
        获取所有记录（包括被拦截和未拦截的）
        
        Returns:
            所有记录列表
        """
        return self._all_records.copy()
    
    def get_stats(self) -> Dict:
        """
        获取统计信息
        
        Returns:
            统计信息字典
        """
        return {
            "total_requests": self._stats["total_requests"],
            "blocked_requests": self._stats["blocked_requests"],
            "loaded_requests": self._stats["loaded_requests"],
            "unique_hostnames": len(self._stats["unique_hostnames"]),
            "blocked_hostnames": len(self._stats["blocked_hostnames"]),
        }
    
    def reset(self):
        """重置拦截器状态（清空记录和统计）"""
        self._blocked_records.clear()
        self._all_records.clear()
        self._stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "loaded_requests": 0,
            "unique_hostnames": set(),
            "blocked_hostnames": set(),
        }

