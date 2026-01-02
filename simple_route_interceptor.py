"""
简单可靠的路由拦截器
参考简易脚本的实现方式，使用最直接的方式实现拦截功能
"""
from __future__ import annotations

import logging
from typing import Optional, Callable, List
from urllib.parse import urlparse

from .blacklist_manager import BlacklistManager


logger = logging.getLogger(__name__)


def create_simple_route_handler(
    blacklist_manager: Optional[BlacklistManager] = None,
    logger: Optional[logging.Logger] = None,
    disable_cache: bool = True,
    blocked_requests_list: Optional[List[str]] = None
) -> Callable:
    """
    创建简单的路由拦截器处理函数
    
    参考简易脚本的实现方式：
    1. 直接在拦截函数中提取 hostname
    2. 检查是否在黑名单中
    3. 如果匹配就 abort，否则 continue
    
    Args:
        blacklist_manager: 黑名单管理器
        logger: 日志记录器
        disable_cache: 是否禁用缓存
        blocked_requests_list: 用于记录被拦截请求的列表（可选）
    
    Returns:
        route handler 函数
    """
    log = logger or logging.getLogger(__name__)
    
    def handle_route(route):
        """
        路由拦截处理函数
        参考简易脚本：直接在函数中处理，简单可靠
        """
        request = route.request
        request_url = request.url
        request_method = request.method
        resource_type = request.resource_type
        
        try:
            # 提取 hostname（参考简易脚本的方式）
            try:
                url_obj = urlparse(request_url)
                hostname = url_obj.hostname or ""
            except Exception:
                # 如果 URL 解析失败，继续请求（参考简易脚本的错误处理）
                if disable_cache:
                    headers = request.headers.copy()
                    headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
                    headers['Pragma'] = 'no-cache'
                    headers['Expires'] = '0'
                    route.continue_(headers=headers)
                else:
                    route.continue_()
                return
            
            # 如果没有 hostname，继续请求
            if not hostname:
                if disable_cache:
                    headers = request.headers.copy()
                    headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
                    headers['Pragma'] = 'no-cache'
                    headers['Expires'] = '0'
                    route.continue_(headers=headers)
                else:
                    route.continue_()
                return
            
            # 规范化 hostname 用于检查
            clean_hostname = BlacklistManager._normalize_domain(hostname)
            
            # 【关键修复】检查是否在黑名单中（使用 BlacklistManager.is_blocked() 确保逻辑一致）
            # 这个方法已经处理了规范化、精确匹配、子域名匹配等所有情况
            is_blocked = False
            if blacklist_manager:
                # 使用 BlacklistManager.is_blocked() 方法，确保检查逻辑与系统其他部分一致
                is_blocked = blacklist_manager.is_blocked(request_url)
                
                # 【调试日志】记录所有经过拦截器的请求（特别是黑名单域名的请求）
                # 这样可以确认拦截器是否真的被调用了
                blocked_domains = blacklist_manager.get_blocked_domains()
                is_potential_block = clean_hostname in blocked_domains or any(
                    clean_hostname.endswith('.' + blocked_domain) 
                    for blocked_domain in blocked_domains
                )
                if is_potential_block:
                    log.info(f"[拦截器检查] {request_method} {request_url} (hostname: {clean_hostname}, resource_type: {resource_type}, is_blocked: {is_blocked})")
                
                # 如果被拦截，记录日志和请求
                if is_blocked:
                    log.info(f"[拦截请求] ✓ {request_method} {request_url} (hostname: {clean_hostname})")
                    # 记录到 blocked_requests_list（如果提供）
                    if blocked_requests_list is not None and request_url not in blocked_requests_list:
                        blocked_requests_list.append(request_url)
            
            # 执行拦截或放行（参考简易脚本：route.abort() 或 route.continue()）
            if is_blocked:
                route.abort("blockedbyclient")
            else:
                # 继续请求（参考简易脚本：route.continue()）
                if disable_cache:
                    headers = request.headers.copy()
                    headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
                    headers['Pragma'] = 'no-cache'
                    headers['Expires'] = '0'
                    route.continue_(headers=headers)
                else:
                    route.continue_()
                    
        except Exception as error:
            # 如果出错，继续请求（参考简易脚本的错误处理）
            log.error(f"处理路由请求时出错: {request_url}, 错误: {error}", exc_info=True)
            try:
                if disable_cache:
                    headers = request.headers.copy()
                    headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
                    headers['Pragma'] = 'no-cache'
                    headers['Expires'] = '0'
                    route.continue_(headers=headers)
                else:
                    route.continue_()
            except:
                # 如果 continue 也失败，则 abort
                route.abort("blockedbyclient")
    
    return handle_route


def setup_route_interceptor(
    context,
    blacklist_manager: Optional[BlacklistManager] = None,
    logger: Optional[logging.Logger] = None,
    disable_cache: bool = True,
    blocked_requests_list: Optional[List[str]] = None
) -> None:
    """
    在 context 上设置路由拦截器
    
    参考简易脚本的方式：
    - 在 context 级别设置拦截器
    - 使用通配符 "**/*" 匹配所有请求
    - 简单直接，可靠牢固
    
    Args:
        context: Playwright BrowserContext 对象
        blacklist_manager: 黑名单管理器
        logger: 日志记录器
        disable_cache: 是否禁用缓存
        blocked_requests_list: 用于记录被拦截请求的列表（可选）
    """
    log = logger or logging.getLogger(__name__)
    
    # 创建拦截器处理函数
    route_handler = create_simple_route_handler(
        blacklist_manager=blacklist_manager,
        logger=log,
        disable_cache=disable_cache,
        blocked_requests_list=blocked_requests_list
    )
    
    # 【关键】在 context 级别设置拦截器（参考简易脚本：page.route('**/*', ...)）
    # context 级别的拦截器会拦截所有请求，包括重定向后的请求
    # 【重要】必须在 context 创建后、任何页面创建前设置，确保拦截所有请求
    context.route("**/*", route_handler)
    
    if blacklist_manager:
        blocked_count = len(blacklist_manager.get_blocked_domains())
        blocked_domains = blacklist_manager.get_blocked_domains()[:5]  # 只显示前5个
        log.info(f"[路由拦截器] ✓ 已设置路由拦截器，黑名单域名数: {blocked_count}")
        if blocked_count > 0:
            log.info(f"[路由拦截器] 黑名单域名示例: {', '.join(blocked_domains)}{'...' if blocked_count > 5 else ''}")
    else:
        log.debug("[路由拦截器] 黑名单管理器未设置，仅应用缓存禁用")

