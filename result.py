from dataclasses import dataclass, asdict
from typing import Optional, Dict, List, Any, Tuple
from datetime import datetime
from collections import defaultdict


@dataclass
class TestResult:
    """单个测试结果"""
    url: str
    status: str
    status_code: Optional[int] = None
    response_time: Optional[float] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None

    # 性能指标 - 使用特殊值表示超时
    dom_ready_time: Optional[float] = None
    full_load_time: Optional[float] = None
    fcp_time: Optional[float] = None  # First Contentful Paint
    
    # Lighthouse性能指标
    lcp_time: Optional[float] = None  # Largest Contentful Paint (最大内容绘制)
    inp_time: Optional[float] = None  # Interaction to Next Paint (交互到下次绘制)
    cls_score: Optional[float] = None  # Cumulative Layout Shift (累积布局偏移)
    tbt_time: Optional[float] = None  # Total Blocking Time (总阻塞时间)
    si_score: Optional[float] = None  # Speed Index (速度指数)

    # 测试信息
    test_round: Optional[int] = None
    url_index: Optional[int] = None
    original_position: Optional[int] = None

    # 网络信息
    ip_address: Optional[str] = None
    final_url: Optional[str] = None  # 最终重定向后的URL
    timestamp: str = None

    # 重定向信息
    redirect_count: int = 0
    redirect_chain: List[str] = None
    is_redirect_loop: bool = False

    # 性能指标来源标记
    dom_time_source: str = "measured"  # measured, timeout_fallback, not_available
    full_load_time_source: str = "measured"  # measured, timeout_fallback, not_available

    # 新增：load事件触发标记
    load_event_triggered: bool = False

    # HAR相关信息
    har_file_path: Optional[str] = None
    hostname_file_path: Optional[str] = None
    domain_count: int = 0

    # VPN相关信息
    test_mode: Optional[str] = None  # "vpn", "direct", 或 None (普通测试)
    vpn_name: Optional[str] = None   # VPN连接名称

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
        if self.redirect_chain is None:
            self.redirect_chain = []

        # 确保final_url有值，默认为原始URL
        if self.final_url is None:
            self.final_url = self.url

        # 如果是重定向错误，设置相应的标记
        if self.error_type == "redirect_error" and self.redirect_count == 0:
            self.redirect_count = 20  # 默认最大重定向次数
            self.is_redirect_loop = True

    def to_dict(self) -> dict:
        """将TestResult对象转换为字典"""
        result_dict = asdict(self)
        # 如果URL被拦截，将status_code设置为"拦截"字符串（而不是None）
        if self.status == "blocked" or self.error_type == "blacklist_blocked":
            result_dict['status_code'] = "拦截"
        return result_dict

    @classmethod
    def from_dict(cls, data: dict) -> 'TestResult':
        """从字典创建TestResult对象"""
        return cls(**data)


@dataclass
class AverageResult:
    """按URL+IP分组的平均结果"""
    url: str
    ip_address: str
    avg_response_time: float
    avg_dom_ready_time: float
    avg_full_load_time: float
    avg_fcp_time: float
    test_count: int
    success_count: int  # 新增：成功次数
    success_rate: float
    original_positions: List[int]  # 保留原始位置信息用于排序
    position_range: str  # 新增：位置范围显示


@dataclass
class TestSession:
    """测试会话完整信息"""
    test_name: str  # 测试名称
    test_rounds: int  # 测试轮次
    timestamp: str = None  # 测试开始时间戳
    total_urls: int = 0  # 总URL数量
    session_directory: Optional[str] = None  # 会话结果目录
    har_files_count: int = 0
    total_unique_domains: int = 0

    # 按URL分组的结果
    results: Dict[str, List[TestResult]] = None

    # 元数据
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if self.results is None:
            self.results = {}
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self) -> dict:
        """将TestSession对象转换为字典"""
        # 转换results中的TestResult对象为字典
        results_dict = {}
        for url, result_list in self.results.items():
            results_dict[url] = [result.to_dict() for result in result_list]

        return {
            "test_name": self.test_name,
            "test_rounds": self.test_rounds,
            "timestamp": self.timestamp,
            "total_urls": self.total_urls,
            "session_directory": self.session_directory,
            "har_files_count": self.har_files_count,
            "total_unique_domains": self.total_unique_domains,
            "results": results_dict,
            "metadata": self.metadata
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'TestSession':
        """从字典创建TestSession对象"""
        # 转换results字典为TestResult对象
        results_dict = {}
        for url, result_list in data.get('results', {}).items():
            results_dict[url] = [TestResult.from_dict(result) for result in result_list]

        return cls(
            test_name=data['test_name'],
            test_rounds=data['test_rounds'],
            timestamp=data.get('timestamp'),
            total_urls=data.get('total_urls', 0),
            session_directory=data.get('session_directory'),
            har_files_count=data.get('har_files_count', 0),
            total_unique_domains=data.get('total_unique_domains', 0),
            results=results_dict,
            metadata=data.get('metadata', {})
        )

    def calculate_metadata(self):
        """计算测试会话的元数据"""
        total_requests = 0
        successful_requests = 0
        total_response_time = 0.0
        response_time_count = 0

        for url_results in self.results.values():
            for result in url_results:
                total_requests += 1
                if result.status == "success":
                    successful_requests += 1
                    if result.response_time is not None and result.response_time != -1:
                        total_response_time += result.response_time
                        response_time_count += 1

        # 计算统计数据
        success_rate = (successful_requests / total_requests * 100) if total_requests > 0 else 0
        average_response_time = (total_response_time / response_time_count) if response_time_count > 0 else 0

        self.metadata = {
            "total_requests": total_requests,
            "successful_requests": successful_requests,
            "failed_requests": total_requests - successful_requests,
            "success_rate": round(success_rate, 2),
            "average_response_time": round(average_response_time, 3),
            "data_version": "1.0",
            "unique_urls": len(self.results),
            "unique_ips": len(set(
                result.ip_address
                for url_results in self.results.values()
                for result in url_results
                if result.ip_address
            )),
            "har_files_count": self.har_files_count,
            "total_unique_domains": self.total_unique_domains
        }

    def calculate_average_results(self) -> List[AverageResult]:
        """按URL+IP分组计算平均值"""
        # 按 (url, ip_address) 分组
        grouped_results = defaultdict(list)

        for url_results in self.results.values():
            for result in url_results:
                key = (result.url, result.ip_address or "未知IP")
                grouped_results[key].append(result)

        average_results = []

        for (url, ip_address), results in grouped_results.items():
            # 计算成功和总测试次数
            successful_results = [r for r in results if r.status == "success"]
            total_count = len(results)
            success_count = len(successful_results)

            # 计算成功率：成功次数 / 总测试次数 × 100%
            success_rate = (success_count / total_count * 100) if total_count > 0 else 0

            # 计算各项指标的平均值（只基于成功的结果）
            if successful_results:
                avg_response_time = sum(
                    r.response_time for r in successful_results if
                    r.response_time is not None and r.response_time != -1) / len(successful_results)
                # 处理可能为None的性能指标
                dom_times = [r.dom_ready_time for r in successful_results if
                             r.dom_ready_time is not None and r.dom_ready_time != -1]
                avg_dom_ready_time = sum(dom_times) / len(dom_times) if dom_times else 0.0

                full_load_times = [r.full_load_time for r in successful_results if
                                   r.full_load_time is not None and r.full_load_time != -1]
                avg_full_load_time = sum(full_load_times) / len(full_load_times) if full_load_times else 0.0

                fcp_times = [r.fcp_time for r in successful_results if r.fcp_time is not None and r.fcp_time != -1]
                avg_fcp_time = sum(fcp_times) / len(fcp_times) if fcp_times else 0.0
            else:
                avg_response_time = avg_dom_ready_time = avg_full_load_time = avg_fcp_time = 0.0

            # 收集原始位置信息用于排序和显示
            original_positions = list(set(r.original_position for r in results if r.original_position is not None))
            original_positions.sort()

            # 生成位置范围显示
            if original_positions:
                if len(original_positions) == 1:
                    position_range = str(original_positions[0])
                else:
                    position_range = f"{min(original_positions)}-{max(original_positions)}"
            else:
                position_range = "-"

            average_results.append(AverageResult(
                url=url,
                ip_address=ip_address,
                avg_response_time=round(avg_response_time, 2),
                avg_dom_ready_time=round(avg_dom_ready_time, 2),
                avg_full_load_time=round(avg_full_load_time, 2),
                avg_fcp_time=round(avg_fcp_time, 2),
                test_count=total_count,
                success_count=success_count,  # 新增成功次数
                success_rate=round(success_rate, 2),
                original_positions=original_positions,
                position_range=position_range  # 新增位置范围
            ))

        # 按URL和原始位置排序
        average_results.sort(key=lambda x: (min(x.original_positions) if x.original_positions else float('inf'), x.url))

        return average_results