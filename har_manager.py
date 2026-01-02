from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Set, Optional, Tuple
from urllib.parse import urlparse


class HARManager:
    """负责管理HAR与hostname文件的目录及统计信息"""
    
    # 地区名称到拼音首字母的映射表
    REGION_PINYIN_MAP = {
        "重庆": "CQ", "北京": "BJ", "上海": "SH", "广州": "GZ", "深圳": "SZ",
        "杭州": "HZ", "成都": "CD", "武汉": "WH", "西安": "XA", "南京": "NJ",
        "天津": "TJ", "苏州": "SZ", "长沙": "CS", "郑州": "ZZ", "青岛": "QD",
        "大连": "DL", "东莞": "DG", "宁波": "NB", "厦门": "XM", "福州": "FZ",
        "无锡": "WX", "合肥": "HF", "昆明": "KM", "哈尔滨": "HEB", "济南": "JN",
        "佛山": "FS", "长春": "CC", "温州": "WZ", "石家庄": "SJZ", "南宁": "NN",
        "常州": "CZ", "南昌": "NC", "贵阳": "GY", "太原": "TY", "嘉兴": "JX",
        "珠海": "ZH", "中山": "ZS", "台州": "TZ", "惠州": "HZ", "金华": "JH",
        "镇江": "ZJ", "扬州": "YZ", "盐城": "YC", "湖州": "HZ", "泰州": "TZ",
        "宿迁": "SQ", "淮安": "HA", "连云港": "LYG", "徐州": "XZ", "南通": "NT",
        "沈阳": "SY",  # 添加沈阳
    }

    def __init__(self, session_name: str, base_results_dir: Path | None = None, timestamp: str | None = None):
        base_results_dir = base_results_dir or Path("results")
        self.session_name = session_name
        # 如果session_name为空，说明是定时任务的VPN子目录，直接使用base_results_dir
        if not session_name:
            self.base_dir = base_results_dir.resolve()
        else:
            # 确保session_name不为空时，在base_results_dir下创建以session_name命名的子目录
            self.base_dir = (base_results_dir / session_name).resolve()
        
        # 保存时间戳，用于文件命名（避免定时任务多次执行时覆盖文件）
        self.timestamp = timestamp
        
        # 从时间戳中提取时间（HH:MM格式），用于创建时间子文件夹
        self.time_folder = self._extract_time_folder(timestamp)
        
        # 如果有时间文件夹，在har和hostname目录下创建时间子文件夹
        if self.time_folder:
            self.har_dir = self.base_dir / "har" / self.time_folder
            self.hostname_dir = self.base_dir / "hostname" / self.time_folder
        else:
            self.har_dir = self.base_dir / "har"
            self.hostname_dir = self.base_dir / "hostname"
        
        self._ensure_directories()

        self.har_files_captured: int = 0
        self.unique_domains: Set[str] = set()

    def _extract_time_folder(self, timestamp: str | None) -> str | None:
        """
        从时间戳中提取日期和时间（YYYYMMDD-HH-MM格式），用于创建时间子文件夹
        
        Args:
            timestamp: 时间戳，格式为 YYYYMMDDTHHMMSS 或 YYYYMMDD_HHMMSS
            
        Returns:
            时间字符串（YYYYMMDD-HH-MM格式），如果无法提取则返回None
            注意：使用连字符而不是冒号，因为Windows不允许文件夹名包含冒号
            包含日期可以避免不同日期的同一时间点使用同一个文件夹
        """
        if not timestamp:
            return None
        
        try:
            # 处理新格式：YYYYMMDDTHHMMSS
            if 'T' in timestamp:
                parts = timestamp.split('T')
                if len(parts) >= 2:
                    date_part = parts[0]  # YYYYMMDD
                    time_part = parts[1]  # HHMMSS
                    if len(date_part) == 8 and len(time_part) >= 4:
                        hour = time_part[0:2]
                        minute = time_part[2:4]
                        return f"{date_part}-{hour}-{minute}"  # YYYYMMDD-HH-MM
            # 处理旧格式：YYYYMMDD_HHMMSS
            elif '_' in timestamp:
                parts = timestamp.split('_')
                if len(parts) >= 2:
                    date_part = parts[0]  # YYYYMMDD
                    time_part = parts[1]  # HHMMSS
                    if len(date_part) == 8 and len(time_part) >= 4:
                        hour = time_part[0:2]
                        minute = time_part[2:4]
                        return f"{date_part}-{hour}-{minute}"  # YYYYMMDD-HH-MM
        except Exception:
            pass
        
        return None

    def _ensure_directories(self) -> None:
        self.har_dir.mkdir(parents=True, exist_ok=True)
        self.hostname_dir.mkdir(parents=True, exist_ok=True)
    
    def _extract_domain_and_service(self, url: str) -> Tuple[str, str]:
        """
        从URL中提取域名和服务名
        
        注意：域名中的点号（.）会保留，不会被替换为下划线
        下划线仅用于分隔不同的字段（域名、服务名、代理类型等）
        
        Args:
            url: 原始URL，例如 "https://apple.com/health" 或 "www.ted.com" 或 "apple.com"
            
        Returns:
            (域名, 服务名) 元组，服务名可能为空字符串
            例如：("apple.com", "health") 或 ("apple.com", "")
        """
        try:
            # 如果URL没有协议前缀，先规范化（添加https://）
            normalized_url = url.strip()
            if not normalized_url.startswith(('http://', 'https://')):
                normalized_url = 'https://' + normalized_url
            
            parsed = urlparse(normalized_url)
            # 提取域名（保留点号，不替换为下划线）
            domain = parsed.netloc.split(":")[0] if parsed.netloc else ""
            
            # 如果netloc为空，尝试从path中提取（处理没有协议的URL）
            if not domain and parsed.path:
                # 可能是 "www.ted.com" 这样的格式，path会是 "www.ted.com"
                path_start = parsed.path.split("/")[0]
                if path_start and '.' in path_start:
                    domain = path_start
            
            # 如果还是没有域名，尝试从原始URL中提取
            if not domain:
                # 移除协议前缀
                temp = normalized_url.replace('https://', '').replace('http://', '')
                # 取第一个斜杠之前的部分作为域名
                domain = temp.split('/')[0].split('?')[0].split('#')[0]
            
            if domain.startswith("www."):
                domain = domain[4:]
            
            # 域名中的点号保留，只清理Windows不允许的特殊字符（但不包括点号）
            # 点号是域名的一部分，应该保留
            domain = re.sub(r'[<>:"/\\|?*]', "_", domain)
            
            # 如果域名仍然为空，返回unknown
            if not domain:
                return "unknown", ""
            
            # 提取服务名（从URL路径的第一段，如果有的话）
            service_name = ""
            if parsed.path:
                path_parts = [p for p in parsed.path.strip("/").split("/") if p]
                if path_parts:
                    # 取第一段作为服务名，清理特殊字符（但保留点号，因为服务名可能包含点号）
                    service_name = path_parts[0]
                    # 只替换Windows不允许的字符，保留点号
                    service_name = re.sub(r'[<>:"/\\|?*]', "_", service_name)
                    # 限制长度
                    if len(service_name) > 30:
                        service_name = service_name[:30]
            
            return domain, service_name
        except Exception:
            # 如果解析失败，返回默认值
            return "unknown", ""
    
    @staticmethod
    def _convert_region_identifier(vpn_name: str) -> str:
        """
        转换区域标识：A重庆 → 1CQ, B北京 → 2BJ
        
        Args:
            vpn_name: VPN名称，可能包含A/B前缀和地区名
            
        Returns:
            转换后的区域标识，如 "1CQ", "2BJ"，如果没有匹配则返回空字符串
        """
        if not vpn_name:
            return ""
        
        # 匹配A或B前缀
        match = re.match(r'^([AB])(.+)$', vpn_name)
        if not match:
            return ""
        
        prefix = match.group(1)
        region_name = match.group(2)
        
        # 转换前缀：A → 1, B → 2
        prefix_num = "1" if prefix == "A" else "2"
        
        # 查找地区名的拼音首字母
        pinyin_code = HARManager.REGION_PINYIN_MAP.get(region_name, "")
        if not pinyin_code:
            # 如果没有找到，尝试从地区名中提取（简单处理）
            # 这里可以扩展更多规则
            return ""
        
        return f"{prefix_num}{pinyin_code}"
    
    def _convert_timestamp_format(self, timestamp: str) -> str:
        """
        转换时间戳格式：20251130_122913 → 20251130T122913 (ISO 8601基本格式)
        如果已经是ISO 8601格式（包含T），则直接返回
        
        Args:
            timestamp: 原始时间戳，格式为 YYYYMMDD_HHMMSS 或 YYYYMMDDTHHMMSS
            
        Returns:
            转换后的时间戳，格式为 YYYYMMDDTHHMMSS
        """
        if not timestamp:
            return ""
        
        # 如果已经是ISO 8601格式（包含T），直接返回
        if 'T' in timestamp:
            return timestamp
        
        # 替换下划线为T（ISO 8601格式）
        return timestamp.replace("_", "T", 1)  # 只替换第一个下划线

    def _sanitize_filename(self, url: str, max_length: int = 200) -> str:
        """
        将URL转换为安全的文件名
        
        Args:
            url: 原始URL
            max_length: 最大文件名长度
        
        Returns:
            安全的文件名
        """
        try:
            # 解析URL
            parsed = urlparse(url)
            
            # 构建文件名：域名_路径（不包含协议和www）
            parts = []
            if parsed.netloc:
                # 移除端口号
                domain = parsed.netloc.split(":")[0]
                # 移除www前缀
                if domain.startswith("www."):
                    domain = domain[4:]
                parts.append(domain)
            if parsed.path:
                # 清理路径，移除开头的斜杠和特殊字符
                path = parsed.path.strip("/")
                if path:
                    # 替换路径分隔符和特殊字符
                    path = path.replace("/", "_").replace("\\", "_")
                    parts.append(path)
            
            # 如果没有查询参数，可以添加
            if parsed.query:
                # 简化查询参数，只取前几个字符
                query = parsed.query[:20].replace("&", "_").replace("=", "_")
                parts.append(query)
            
            # 组合所有部分
            filename = "_".join(parts) if parts else "unknown"
            
            # 移除或替换Windows不允许的字符
            invalid_chars = r'[<>:"/\\|?*]'
            filename = re.sub(invalid_chars, "_", filename)
            
            # 移除连续的下划线和点
            filename = re.sub(r'_{2,}', '_', filename)
            filename = re.sub(r'\.{2,}', '.', filename)
            
            # 移除开头和结尾的下划线、点和空格
            filename = filename.strip('_. ')
            
            # 限制长度
            if len(filename) > max_length:
                filename = filename[:max_length]
            
            # 如果文件名为空，使用默认值
            if not filename:
                filename = "unknown"
            
            return filename
        except Exception:
            # 如果解析失败，使用简单的清理方法
            filename = url.replace("https://", "").replace("http://", "")
            # 移除www前缀
            if filename.startswith("www."):
                filename = filename[4:]
            filename = re.sub(r'[<>:"/\\|?*]', "_", filename)
            filename = re.sub(r'_{2,}', '_', filename)
            filename = filename.strip('_. ')[:max_length] or "unknown"
            return filename

    def get_har_file_path(self, url: str, test_round: int, url_index: int, attempt: int = 0, 
                          test_mode: str = None, vpn_name: str = None) -> Path:
        """
        获取HAR文件路径，使用新的命名规则：
        [索引]_[域名].[服务名]_[代理类型]_[区域标识]_[时间戳].har
        
        Args:
            url: 测试的URL
            test_round: 测试轮次
            url_index: URL索引
            attempt: 尝试次数（用于重试）
            test_mode: 测试模式 ("vpn" 或 "direct")
            vpn_name: VPN名称
        
        Returns:
            HAR文件路径
        """
        # 提取域名和服务名
        domain, service_name = self._extract_domain_and_service(url)

        # 域名.服务名 部分（服务名可能为空）
        if service_name:
            domain_service = f"{domain}.{service_name}"
        else:
            domain_service = domain

        parts = [domain_service]

        # 代理类型（vpn / direct）
        if test_mode:
            parts.append(test_mode)
        else:
            parts.append("vpn" if vpn_name else "direct")

        # 区域标识（根据VPN名称转换）
        if vpn_name:
            region_id = HARManager._convert_region_identifier(vpn_name)
            if region_id:
                parts.append(region_id)

        # 时间戳（如果有）—— 已在构造HARManager时传入原始时间戳
        if self.timestamp:
            converted_timestamp = self._convert_timestamp_format(self.timestamp)
            if converted_timestamp:
                parts.append(converted_timestamp)

        # 组合除索引外的主体部分
        core_name = "_".join(parts)

        # 最终文件名格式：[索引]_[域名].[服务名]_[代理类型]_[区域标识]_[时间戳].har
        filename = f"{url_index}_{core_name}.har"
        return self.har_dir / filename

    def get_hostname_file_path(self, url: str, test_round: int, url_index: int, attempt: int = 0,
                               test_mode: str = None, vpn_name: str = None) -> Path:
        """
        获取hostname文件路径，使用新的命名规则（与HAR文件命名规则一致）
        
        Args:
            url: 测试的URL
            test_round: 测试轮次
            url_index: URL索引
            attempt: 尝试次数（用于重试）
            test_mode: 测试模式 ("vpn" 或 "direct")
            vpn_name: VPN名称
        
        Returns:
            hostname文件路径
        """
        # 使用与HAR文件相同的命名逻辑
        har_path = self.get_har_file_path(url, test_round, url_index, attempt, test_mode, vpn_name)
        # 将.har扩展名替换为_hostnames.txt
        hostname_filename = har_path.name.replace(".har", "_hostnames.txt")
        return self.hostname_dir / hostname_filename

    def register_artifact(self, hostnames: Iterable[str], har_saved: bool) -> None:
        if har_saved:
            self.har_files_captured += 1
        self.unique_domains.update(hostnames)

    def convert_json_filename(self, test_name: str) -> str:
        """
        转换JSON文件名：A北京_20251202_203940 -> 1BJ_20251202T203940
        
        Args:
            test_name: 原始测试名称，格式如 "A北京_20251202_203940" 或 "B沈阳_20251203_141930"
            
        Returns:
            转换后的文件名（不含扩展名），格式如 "1BJ_20251202T203940"
            如果无法转换，返回清理后的原始名称
        """
        import re
        
        # 匹配格式：A/B + 地区名 + _ + 时间戳
        # 例如：A北京_20251202_203940, B沈阳_20251203_141930
        pattern = r'^([AB])(.+?)_(\d{8}_\d{6})$'
        match = re.match(pattern, test_name)
        
        if match:
            prefix = match.group(1)  # A 或 B
            region_name = match.group(2)  # 地区名，如 "北京"、"沈阳"
            timestamp = match.group(3)  # 时间戳，如 "20251202_203940"
            
            # 转换前缀：A -> 1, B -> 2
            prefix_num = "1" if prefix == "A" else "2"
            
            # 查找地区名的拼音首字母
            pinyin_code = self.REGION_PINYIN_MAP.get(region_name, "")
            
            if pinyin_code:
                # 转换时间戳格式：20251202_203940 -> 20251202T203940
                converted_timestamp = timestamp.replace("_", "T", 1)
                return f"{prefix_num}{pinyin_code}_{converted_timestamp}"
        
        # 如果无法匹配，尝试只转换时间戳格式
        timestamp_pattern = r'(\d{8}_\d{6})'
        timestamp_match = re.search(timestamp_pattern, test_name)
        if timestamp_match:
            timestamp = timestamp_match.group(1)
            converted_timestamp = timestamp.replace("_", "T", 1)
            # 替换时间戳部分
            return re.sub(timestamp_pattern, converted_timestamp, test_name)
        
        # 如果都不匹配，返回清理后的原始名称
        return re.sub(r'[<>:"/\\|?*]', "_", test_name)
    
    def get_stats(self) -> dict:
        return {
            "har_files_count": self.har_files_captured,
            "total_unique_domains": len(self.unique_domains)
        }


