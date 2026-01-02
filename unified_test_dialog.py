#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统一测试配置对话框
合并了原来的配置测试和VPN测试功能
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

from vpn.vpn_manager import VPNConfig
from vpn.vpn_detector import VPNDetector
from utils.config_manager import ConfigManager


class UnifiedTestDialog:
    """统一测试配置对话框"""
    
    def __init__(self, parent, config_manager: ConfigManager, logger: Optional[logging.Logger] = None):
        self.parent = parent
        self.config_manager = config_manager
        self.logger = logger or logging.getLogger(__name__)
        self.result = None
        
        # VPN相关
        self.vpn_config = VPNConfig()
        self.vpn_detector = VPNDetector(self.logger)
        self.available_vpns = []
        self.vpn_items = {}  # 存储VPN的勾选变量和UI元素
        
        # 创建对话框
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("测试配置")
        self.dialog.geometry("900x700")
        self.dialog.resizable(True, True)
        self.dialog.minsize(800, 600)
        
        # 设置模态
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # 居中显示
        self.dialog.geometry("+%d+%d" % (parent.winfo_rootx() + 50, parent.winfo_rooty() + 50))
        
        self.create_widgets()
        self.load_current_config()
        self.detect_vpns()
        
        # 绑定关闭事件
        self.dialog.protocol("WM_DELETE_WINDOW", self.on_cancel)
    
    def create_widgets(self):
        """创建UI组件"""
        # 创建笔记本控件
        notebook = ttk.Notebook(self.dialog)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 基本配置标签页
        self.create_basic_config_tab(notebook)
        
        # URL配置标签页
        self.create_url_config_tab(notebook)
        
        # VPN配置标签页
        self.create_vpn_config_tab(notebook)
        
        # 高级配置标签页
        self.create_advanced_config_tab(notebook)
        
        # 定时任务标签页
        self.create_schedule_config_tab(notebook)
        
        # 按钮区域
        self.create_buttons()
    
    def create_basic_config_tab(self, notebook: ttk.Notebook):
        """创建基本配置标签页"""
        basic_frame = ttk.Frame(notebook)
        notebook.add(basic_frame, text="基本配置")
        
        # 测试名称
        name_frame = ttk.LabelFrame(basic_frame, text="测试名称", padding="10")
        name_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(name_frame, text="测试名称:").pack(anchor=tk.W)
        self.test_name_var = tk.StringVar()
        test_name_entry = ttk.Entry(name_frame, textvariable=self.test_name_var, font=("Arial", 10))
        test_name_entry.pack(fill=tk.X, pady=(5, 0))
        
        # 自动生成按钮
        ttk.Button(name_frame, text="自动生成", 
                  command=self.generate_test_name).pack(anchor=tk.E, pady=(5, 0))
        
        # 测试设置
        settings_frame = ttk.LabelFrame(basic_frame, text="测试设置", padding="10")
        settings_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 测试模式选择
        test_mode_frame = ttk.LabelFrame(settings_frame, text="测试模式", padding="5")
        test_mode_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.test_mode_var = tk.StringVar(value="single")
        ttk.Radiobutton(test_mode_frame, text="单次执行", variable=self.test_mode_var, 
                       value="single", command=self.on_test_mode_changed).pack(side=tk.LEFT, padx=(0, 20))
        ttk.Radiobutton(test_mode_frame, text="按次数执行", variable=self.test_mode_var, 
                       value="repeat", command=self.on_test_mode_changed).pack(side=tk.LEFT)
        
        # 按次数执行配置
        self.repeat_config_frame = ttk.LabelFrame(settings_frame, text="按次数执行配置", padding="5")
        self.repeat_config_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 执行次数
        repeat_count_frame = ttk.Frame(self.repeat_config_frame)
        repeat_count_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(repeat_count_frame, text="执行次数:").pack(side=tk.LEFT)
        self.repeat_count_var = tk.IntVar(value=5)
        ttk.Spinbox(repeat_count_frame, from_=1, to=100, textvariable=self.repeat_count_var, 
                   width=10).pack(side=tk.RIGHT)
        
        # 开始时间选择
        start_time_frame = ttk.Frame(self.repeat_config_frame)
        start_time_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.start_time_mode_var = tk.StringVar(value="immediate")
        ttk.Radiobutton(start_time_frame, text="立即开始", variable=self.start_time_mode_var, 
                       value="immediate", command=self.on_start_time_mode_changed).pack(side=tk.LEFT, padx=(0, 20))
        ttk.Radiobutton(start_time_frame, text="定时开始", variable=self.start_time_mode_var, 
                       value="scheduled", command=self.on_start_time_mode_changed).pack(side=tk.LEFT)
        
        # 定时开始配置
        self.scheduled_start_frame = ttk.Frame(self.repeat_config_frame)
        self.scheduled_start_frame.pack(fill=tk.X, pady=(5, 0))
        
        # 日期选择
        date_frame = ttk.Frame(self.scheduled_start_frame)
        date_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(date_frame, text="开始日期:").pack(side=tk.LEFT)
        self.start_date_var = tk.StringVar()
        from datetime import datetime, timedelta
        default_date = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")
        self.start_date_var.set(default_date)
        ttk.Entry(date_frame, textvariable=self.start_date_var, width=12).pack(side=tk.LEFT, padx=(10, 0))
        ttk.Label(date_frame, text="(格式: YYYY-MM-DD)", foreground="gray", font=("Arial", 8)).pack(side=tk.LEFT, padx=(5, 0))
        
        # 时间选择
        time_frame = ttk.Frame(self.scheduled_start_frame)
        time_frame.pack(fill=tk.X)
        ttk.Label(time_frame, text="开始时间:").pack(side=tk.LEFT)
        self.start_hour_var = tk.StringVar(value="09")
        self.start_minute_var = tk.StringVar(value="00")
        ttk.Combobox(time_frame, textvariable=self.start_hour_var, values=[f"{i:02d}" for i in range(24)], 
                    width=5, state="readonly").pack(side=tk.LEFT, padx=(10, 5))
        ttk.Label(time_frame, text=":").pack(side=tk.LEFT)
        ttk.Combobox(time_frame, textvariable=self.start_minute_var, values=[f"{i:02d}" for i in range(60)], 
                    width=5, state="readonly").pack(side=tk.LEFT, padx=(5, 0))
        
        # 初始状态：按次数执行模式默认隐藏，单次执行模式显示
        self.repeat_config_frame.pack_forget()
        
        # 并发数
        self.concurrent_frame = ttk.Frame(settings_frame)
        self.concurrent_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(self.concurrent_frame, text="并发数:").pack(side=tk.LEFT)
        self.concurrent_var = tk.IntVar(value=3)
        ttk.Spinbox(self.concurrent_frame, from_=1, to=10, textvariable=self.concurrent_var, 
                   width=10).pack(side=tk.RIGHT)
        
        # 阶段超时时间
        timeout_label_frame = ttk.LabelFrame(settings_frame, text="阶段超时时间(秒)", padding="5")
        timeout_label_frame.pack(fill=tk.X, pady=(0, 5))
        
        # 阶段1 HTTP超时
        timeout1_frame = ttk.Frame(timeout_label_frame)
        timeout1_frame.pack(fill=tk.X, pady=(0, 2))
        ttk.Label(timeout1_frame, text="阶段1-HTTP:").pack(side=tk.LEFT)
        self.timeout_stage1_var = tk.IntVar(value=8)
        ttk.Spinbox(timeout1_frame, from_=5, to=60, textvariable=self.timeout_stage1_var, 
                   width=8).pack(side=tk.RIGHT)
        
        # 阶段2 DOM超时（事件监听，非阻塞）
        timeout2_frame = ttk.Frame(timeout_label_frame)
        timeout2_frame.pack(fill=tk.X, pady=(0, 2))
        ttk.Label(timeout2_frame, text="阶段2-DOM(事件监听):").pack(side=tk.LEFT)
        self.timeout_stage2_var = tk.IntVar(value=30)
        ttk.Spinbox(timeout2_frame, from_=5, to=120, textvariable=self.timeout_stage2_var, 
                   width=8).pack(side=tk.RIGHT)
        
        # 阶段3 Load超时（主要等待，总超时时间）
        timeout3_frame = ttk.Frame(timeout_label_frame)
        timeout3_frame.pack(fill=tk.X, pady=(0, 2))
        ttk.Label(timeout3_frame, text="阶段3-Load(总超时):").pack(side=tk.LEFT)
        self.timeout_stage3_var = tk.IntVar(value=60)
        ttk.Spinbox(timeout3_frame, from_=5, to=300, textvariable=self.timeout_stage3_var, 
                   width=8).pack(side=tk.RIGHT)
        
        # HAR采集
        self.har_enabled_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="启用HAR文件采集", 
                       variable=self.har_enabled_var).pack(anchor=tk.W, pady=(5, 0))
        
        # Hostname采集
        self.hostname_enabled_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="启用Hostname文件采集", 
                       variable=self.hostname_enabled_var).pack(anchor=tk.W, pady=(5, 0))
        
        # 黑名单
        self.blacklist_enabled_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="启用黑名单过滤", 
                       variable=self.blacklist_enabled_var).pack(anchor=tk.W, pady=(5, 0))
        
        # 结果存放位置
        output_dir_frame = ttk.LabelFrame(basic_frame, text="结果存放位置", padding="10")
        output_dir_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 存放位置选择
        dir_select_frame = ttk.Frame(output_dir_frame)
        dir_select_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.use_custom_output_dir_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(dir_select_frame, text="使用自定义存放位置", 
                       variable=self.use_custom_output_dir_var,
                       command=self.on_output_dir_option_changed).pack(anchor=tk.W)
        
        # 自定义路径输入框和选择按钮
        custom_dir_frame = ttk.Frame(output_dir_frame)
        custom_dir_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.custom_output_dir_var = tk.StringVar()
        custom_dir_entry = ttk.Entry(custom_dir_frame, textvariable=self.custom_output_dir_var, 
                                     state="disabled", font=("Arial", 9))
        custom_dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        ttk.Button(custom_dir_frame, text="选择文件夹", 
                  command=self.select_output_directory).pack(side=tk.RIGHT)
        
        # 默认路径显示
        from utils.file_utils import get_app_base_dir
        default_dir = get_app_base_dir() / "results"
        default_info = ttk.Label(output_dir_frame, 
                                text=f"默认位置: {default_dir}",
                                foreground="gray", font=("Arial", 8))
        default_info.pack(anchor=tk.W, pady=(5, 0))
        
        # 保存自定义路径输入框的引用，以便后续启用/禁用
        self.custom_dir_entry = custom_dir_entry
    
    def create_url_config_tab(self, notebook: ttk.Notebook):
        """创建URL配置标签页"""
        url_frame = ttk.Frame(notebook)
        notebook.add(url_frame, text="测试URL")
        
        # URL输入区域
        input_frame = ttk.LabelFrame(url_frame, text="URL输入", padding="10")
        input_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # 输入方式选择
        method_frame = ttk.Frame(input_frame)
        method_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.url_method_var = tk.StringVar(value="manual")
        ttk.Radiobutton(method_frame, text="手动输入", variable=self.url_method_var, 
                       value="manual", command=self.on_url_method_changed).pack(side=tk.LEFT, padx=(0, 20))
        ttk.Radiobutton(method_frame, text="从文件导入", variable=self.url_method_var, 
                       value="file", command=self.on_url_method_changed).pack(side=tk.LEFT)
        
        # 手动输入区域
        self.manual_frame = ttk.Frame(input_frame)
        self.manual_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(self.manual_frame, text="请输入测试URL（每行一个）:").pack(anchor=tk.W)
        self.url_text = tk.Text(self.manual_frame, height=10, wrap=tk.WORD)
        url_scrollbar = ttk.Scrollbar(self.manual_frame, orient=tk.VERTICAL, command=self.url_text.yview)
        self.url_text.configure(yscrollcommand=url_scrollbar.set)
        self.url_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        url_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 文件导入区域
        self.file_frame = ttk.Frame(input_frame)
        
        file_select_frame = ttk.Frame(self.file_frame)
        file_select_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.file_path_var = tk.StringVar()
        ttk.Entry(file_select_frame, textvariable=self.file_path_var, state="readonly").pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        ttk.Button(file_select_frame, text="选择文件", command=self.select_url_file).pack(side=tk.RIGHT)
        
        # URL预览
        preview_frame = ttk.LabelFrame(url_frame, text="URL预览", padding="10")
        preview_frame.pack(fill=tk.X)
        
        self.url_count_var = tk.StringVar(value="URL数量: 0")
        ttk.Label(preview_frame, textvariable=self.url_count_var).pack(anchor=tk.W)
        
        self.url_preview = tk.Listbox(preview_frame, height=6)
        preview_scrollbar = ttk.Scrollbar(preview_frame, orient=tk.VERTICAL, command=self.url_preview.yview)
        self.url_preview.configure(yscrollcommand=preview_scrollbar.set)
        self.url_preview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        preview_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 绑定文本变化事件
        self.url_text.bind('<KeyRelease>', self.update_url_preview)
        self.url_text.bind('<Button-1>', self.update_url_preview)
    
    def create_vpn_config_tab(self, notebook: ttk.Notebook):
        """创建VPN配置标签页"""
        vpn_frame = ttk.Frame(notebook)
        notebook.add(vpn_frame, text="VPN配置")
        
        # 添加提示信息
        info_frame = ttk.LabelFrame(vpn_frame, text="提示", padding="10")
        info_frame.pack(fill=tk.X, padx=10, pady=(10, 5))
        info_label = ttk.Label(info_frame, 
                              text="VPN是可选的。如果不选择任何VPN，将直接使用当前网络环境进行测试（不添加路由，不连接VPN）。",
                              foreground="gray", wraplength=800, justify=tk.LEFT)
        info_label.pack(anchor=tk.W)
        
        # 测试模式选择
        mode_frame = ttk.LabelFrame(vpn_frame, text="测试模式（选择VPN后生效）", padding="10")
        mode_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # VPN模式测试选项
        self.enable_vpn_test_var = tk.BooleanVar(value=True)
        vpn_mode_check = ttk.Checkbutton(
            mode_frame,
            text="启用VPN模式测试（连接VPN并测试VPN通道）",
            variable=self.enable_vpn_test_var
        )
        vpn_mode_check.pack(anchor=tk.W)
        
        # 直连模式测试选项
        self.enable_direct_test_var = tk.BooleanVar(value=True)
        direct_mode_check = ttk.Checkbutton(
            mode_frame,
            text="启用直连模式测试（测试直连通道，不连接VPN）",
            variable=self.enable_direct_test_var
        )
        direct_mode_check.pack(anchor=tk.W, pady=(5, 0))
        
        # 添加说明
        mode_help = ttk.Label(
            mode_frame,
            text="说明：可以单独选择VPN模式或直连模式，也可以同时选择两者。如果只选择直连模式，系统不会连接VPN。HAR文件会根据选择的模式包含相应的标识。",
            foreground="gray",
            wraplength=800,
            justify=tk.LEFT
        )
        mode_help.pack(anchor=tk.W, pady=(5, 0))
        
        # 说明和刷新按钮
        control_frame = ttk.Frame(vpn_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        ttk.Label(control_frame, text="请选择VPN进行测试（可选，支持多个VPN顺序执行）:", 
                 foreground="blue").pack(side=tk.LEFT)
        ttk.Button(control_frame, text="刷新VPN列表", command=self.detect_vpns).pack(side=tk.RIGHT)
        
        # VPN选择区域
        self.vpn_selection_frame = ttk.LabelFrame(vpn_frame, text="VPN选择（可选）", padding="10")
        self.vpn_selection_frame.pack(fill=tk.BOTH, expand=True)
        
        # 创建可滚动的VPN列表
        canvas = tk.Canvas(self.vpn_selection_frame)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        vpn_scrollbar = ttk.Scrollbar(self.vpn_selection_frame, orient=tk.VERTICAL, command=canvas.yview)
        vpn_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        canvas.configure(yscrollcommand=vpn_scrollbar.set)
        canvas.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        
        self.scrollable_vpn_frame = ttk.Frame(canvas)
        canvas.create_window((0, 0), window=self.scrollable_vpn_frame, anchor="nw")
        
        # 标题行
        header_frame = ttk.Frame(self.scrollable_vpn_frame)
        header_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(header_frame, text="选择", width=8).pack(side=tk.LEFT, padx=2)
        ttk.Label(header_frame, text="VPN名称", width=20, anchor=tk.W).pack(side=tk.LEFT, padx=2)
        ttk.Label(header_frame, text="状态", width=12, anchor=tk.W).pack(side=tk.LEFT, padx=2)
        ttk.Label(header_frame, text="用户名", width=15, anchor=tk.W).pack(side=tk.LEFT, padx=2)
        ttk.Label(header_frame, text="操作", width=10, anchor=tk.W).pack(side=tk.LEFT, padx=2)
        
        # VPN选择区域始终启用
    
    def create_advanced_config_tab(self, notebook: ttk.Notebook):
        """创建高级配置标签页"""
        advanced_frame = ttk.Frame(notebook)
        notebook.add(advanced_frame, text="高级配置")
        
        # 浏览器配置
        browser_frame = ttk.LabelFrame(advanced_frame, text="浏览器配置", padding="10")
        browser_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 浏览器类型
        browser_type_frame = ttk.Frame(browser_frame)
        browser_type_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(browser_type_frame, text="浏览器类型:").pack(side=tk.LEFT)
        self.browser_type_var = tk.StringVar(value="chromium")
        browser_combo = ttk.Combobox(browser_type_frame, textvariable=self.browser_type_var,
                                   values=["chromium", "firefox", "webkit"], state="readonly", width=15)
        browser_combo.pack(side=tk.RIGHT)
        
        # 无头模式
        self.headless_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(browser_frame, text="无头模式（后台运行）", 
                       variable=self.headless_var).pack(anchor=tk.W, pady=(5, 0))
        
        # 网络配置
        network_frame = ttk.LabelFrame(advanced_frame, text="网络配置", padding="10")
        network_frame.pack(fill=tk.X, pady=(0, 10))
        
        # DNS配置
        dns_frame = ttk.Frame(network_frame)
        dns_frame.pack(fill=tk.X, pady=(0, 5))
        self.use_system_dns_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(dns_frame, text="使用系统默认DNS（VPN通道使用VPN DNS，直连使用默认DNS）", 
                       variable=self.use_system_dns_var).pack(anchor=tk.W)
        
        # 用户代理
        ua_frame = ttk.Frame(network_frame)
        ua_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(ua_frame, text="用户代理:").pack(anchor=tk.W)
        self.user_agent_var = tk.StringVar(value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        ttk.Entry(ua_frame, textvariable=self.user_agent_var).pack(fill=tk.X, pady=(5, 0))
        
        # 其他选项
        other_frame = ttk.LabelFrame(advanced_frame, text="其他选项", padding="10")
        other_frame.pack(fill=tk.X)
        
        # 清除DNS缓存
        self.clear_dns_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(other_frame, text="测试前清除DNS缓存", 
                       variable=self.clear_dns_var).pack(anchor=tk.W)
        
        # 自动断开VPN
        self.auto_disconnect_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(other_frame, text="测试完成后自动断开VPN", 
                       variable=self.auto_disconnect_var).pack(anchor=tk.W, pady=(5, 0))
        
        # VPN测试配置
        vpn_test_frame = ttk.LabelFrame(advanced_frame, text="VPN测试配置", padding="10")
        vpn_test_frame.pack(fill=tk.X, pady=(10, 0))
        
        # 每批URL数量
        batch_size_frame = ttk.Frame(vpn_test_frame)
        batch_size_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(batch_size_frame, text="每批URL数量（测试多少个URL后断开VPN）:").pack(side=tk.LEFT)
        self.batch_size_var = tk.IntVar(value=10)
        ttk.Spinbox(batch_size_frame, from_=1, to=100, textvariable=self.batch_size_var, 
                   width=10).pack(side=tk.RIGHT)
        
        # 断开VPN后等待时间
        wait_after_disconnect_frame = ttk.Frame(vpn_test_frame)
        wait_after_disconnect_frame.pack(fill=tk.X)
        ttk.Label(wait_after_disconnect_frame, text="断开VPN后等待时间（秒）:").pack(side=tk.LEFT)
        self.wait_after_disconnect_var = tk.IntVar(value=5)
        ttk.Spinbox(wait_after_disconnect_frame, from_=1, to=60, textvariable=self.wait_after_disconnect_var, 
                   width=10).pack(side=tk.RIGHT)
        
        # 黑名单对比文件选择
        blacklist_frame = ttk.LabelFrame(advanced_frame, text="黑名单对比", padding="10")
        blacklist_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Label(blacklist_frame, text="参考文件（用于黑名单对比，可选）:", 
                 font=("Arial", 9)).pack(anchor=tk.W, pady=(0, 5))
        
        ref_file_frame = ttk.Frame(blacklist_frame)
        ref_file_frame.pack(fill=tk.X)
        
        self.reference_file_var = tk.StringVar()
        ref_entry = ttk.Entry(ref_file_frame, textvariable=self.reference_file_var, width=50)
        ref_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        def select_reference_file():
            from utils.file_utils import get_app_base_dir
            file = filedialog.askopenfilename(
                title="选择参考文件（hostname.txt）",
                filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
                initialdir=get_app_base_dir()
            )
            if file:
                self.reference_file_var.set(file)
        
        ttk.Button(ref_file_frame, text="选择文件", command=select_reference_file).pack(side=tk.LEFT)
    
    def create_schedule_config_tab(self, notebook: ttk.Notebook):
        """创建定时任务配置标签页"""
        schedule_frame = ttk.Frame(notebook)
        notebook.add(schedule_frame, text="定时任务")
        
        # 启用定时任务
        enable_frame = ttk.LabelFrame(schedule_frame, text="定时任务设置", padding="10")
        enable_frame.pack(fill=tk.X, pady=(0, 10), padx=10)
        
        self.schedule_enabled_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(enable_frame, text="启用定时任务", 
                       variable=self.schedule_enabled_var,
                       command=self.on_schedule_enabled_changed).pack(anchor=tk.W)
        
        # 定时任务模式：按星期/时间点 或 按开始时间+间隔+次数
        mode_frame = ttk.Frame(enable_frame)
        mode_frame.pack(fill=tk.X, pady=(8, 0))
        
        ttk.Label(mode_frame, text="任务模式:").pack(side=tk.LEFT)
        self.schedule_mode_var = tk.StringVar(value="weekly")  # weekly / interval
        ttk.Radiobutton(
            mode_frame, text="按星期+时间点", value="weekly",
            variable=self.schedule_mode_var,
            command=self.on_schedule_mode_changed
        ).pack(side=tk.LEFT, padx=(10, 0))
        ttk.Radiobutton(
            mode_frame, text="按开始时间+间隔+次数", value="interval",
            variable=self.schedule_mode_var,
            command=self.on_schedule_mode_changed
        ).pack(side=tk.LEFT, padx=(10, 0))
        
        # 星期选择区域
        weekday_frame = ttk.LabelFrame(schedule_frame, text="选择执行日期（周一到周日）", padding="10")
        weekday_frame.pack(fill=tk.X, pady=(0, 10), padx=10)
        self.weekday_frame = weekday_frame  # 保存引用，便于启用/禁用
        
        weekday_names = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"]
        self.weekday_vars = {}
        weekday_buttons_frame = ttk.Frame(weekday_frame)
        weekday_buttons_frame.pack(fill=tk.X)
        
        for i, day_name in enumerate(weekday_names):
            var = tk.BooleanVar(value=False)
            self.weekday_vars[i] = var
            btn = ttk.Checkbutton(weekday_buttons_frame, text=day_name, variable=var)
            btn.pack(side=tk.LEFT, padx=5)
        
        # 时间设置区域（按星期+时间点模式使用）
        time_frame = ttk.LabelFrame(schedule_frame, text="执行时间（每行一个时间，格式：HH:MM，例如：09:00）", padding="10")
        time_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10), padx=10)
        self.time_frame = time_frame
        
        # 说明文字
        help_label = ttk.Label(time_frame, 
                               text="提示：每行输入一个时间，格式为 HH:MM（24小时制），例如：09:00、14:30、23:59",
                               foreground="gray", font=("Arial", 9))
        help_label.pack(anchor=tk.W, pady=(0, 5))
        
        # 时间输入文本框（多行）
        text_frame = ttk.Frame(time_frame)
        text_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.time_text = tk.Text(text_frame, height=8, wrap=tk.WORD, font=("Consolas", 10))
        time_text_scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.time_text.yview)
        self.time_text.configure(yscrollcommand=time_text_scrollbar.set)
        self.time_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        time_text_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 快速添加按钮区域
        quick_add_frame = ttk.Frame(time_frame)
        quick_add_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(quick_add_frame, text="快速添加:", font=("Arial", 9)).pack(side=tk.LEFT, padx=(0, 5))
        
        def add_quick_times():
            """快速添加常用时间"""
            common_times = ["09:00", "12:00", "15:00", "18:00", "21:00"]
            current_text = self.time_text.get("1.0", tk.END).strip()
            existing_times = set(line.strip() for line in current_text.split('\n') if line.strip())
            
            new_times = []
            for time_str in common_times:
                if time_str not in existing_times:
                    new_times.append(time_str)
            
            if new_times:
                if current_text:
                    self.time_text.insert(tk.END, "\n" + "\n".join(new_times))
                else:
                    self.time_text.insert(tk.END, "\n".join(new_times))
            else:
                messagebox.showinfo("提示", "所有常用时间已存在")
        
        ttk.Button(quick_add_frame, text="添加常用时间（9:00, 12:00, 15:00, 18:00, 21:00）", 
                  command=add_quick_times).pack(side=tk.LEFT, padx=(0, 5))
        
        def clear_all_times():
            """清空所有时间"""
            if messagebox.askyesno("确认", "确定要清空所有时间吗？"):
                self.time_text.delete("1.0", tk.END)
        
        ttk.Button(quick_add_frame, text="清空", command=clear_all_times).pack(side=tk.LEFT)
        
        # 存储时间列表（从文本框解析）
        self.schedule_times = []
        
        # 间隔模式配置区域
        interval_frame = ttk.LabelFrame(schedule_frame, text="按开始时间+间隔+次数", padding="10")
        interval_frame.pack(fill=tk.X, pady=(0, 10), padx=10)
        self.interval_frame = interval_frame
        
        # 开始日期（下拉选择，从当前日期开始）
        start_date_frame = ttk.Frame(interval_frame)
        start_date_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(start_date_frame, text="开始日期:").pack(side=tk.LEFT)
        self.interval_start_date_var = tk.StringVar()
        # 生成日期选项（从今天开始，未来30天）
        from datetime import datetime, timedelta
        date_options = []
        today = datetime.now()
        for i in range(30):  # 未来30天
            date = today + timedelta(days=i)
            date_str = date.strftime("%Y-%m-%d")
            display_str = date.strftime("%Y年%m月%d日")
            if i == 0:
                display_str += " (今天)"
            elif i == 1:
                display_str += " (明天)"
            date_options.append((date_str, display_str))
        # 设置默认值为今天（显示格式）
        self.interval_start_date_var.set(date_options[0][1])  # 使用显示格式
        date_combo = ttk.Combobox(start_date_frame, textvariable=self.interval_start_date_var, 
                                  values=[opt[1] for opt in date_options], state="readonly", width=20)
        date_combo.pack(side=tk.LEFT, padx=(5, 0))
        # 保存日期映射，用于获取实际日期值
        self.date_value_map = {opt[1]: opt[0] for opt in date_options}  # 显示格式 -> 实际日期值
        self.date_display_map = {opt[0]: opt[1] for opt in date_options}  # 实际日期值 -> 显示格式
        
        # 开始时间（小时和分钟下拉选择）
        start_time_frame = ttk.Frame(interval_frame)
        start_time_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(start_time_frame, text="开始时间:").pack(side=tk.LEFT)
        
        # 小时选择（00-23）
        self.interval_start_hour_var = tk.StringVar(value="09")
        hour_combo = ttk.Combobox(start_time_frame, textvariable=self.interval_start_hour_var,
                                  values=[f"{i:02d}" for i in range(24)], state="readonly", width=5)
        hour_combo.pack(side=tk.LEFT, padx=(5, 0))
        ttk.Label(start_time_frame, text="时").pack(side=tk.LEFT, padx=(2, 5))
        
        # 分钟选择（00, 05, 10, 15, ..., 55，每5分钟一个选项）
        self.interval_start_minute_var = tk.StringVar(value="00")
        minute_values = [f"{i:02d}" for i in range(0, 60, 5)]  # 每5分钟一个选项
        minute_combo = ttk.Combobox(start_time_frame, textvariable=self.interval_start_minute_var,
                                    values=minute_values, state="readonly", width=5)
        minute_combo.pack(side=tk.LEFT, padx=(0, 0))
        ttk.Label(start_time_frame, text="分").pack(side=tk.LEFT, padx=(2, 0))
        
        # 间隔与次数
        interval_conf_frame = ttk.Frame(interval_frame)
        interval_conf_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(interval_conf_frame, text="间隔(分钟):").pack(side=tk.LEFT)
        self.interval_minutes_var = tk.IntVar(value=30)
        ttk.Spinbox(interval_conf_frame, from_=1, to=1440, textvariable=self.interval_minutes_var, width=8).pack(side=tk.LEFT, padx=(5, 20))
        
        ttk.Label(interval_conf_frame, text="执行次数:").pack(side=tk.LEFT)
        self.interval_count_var = tk.IntVar(value=20)
        ttk.Spinbox(interval_conf_frame, from_=1, to=10000, textvariable=self.interval_count_var, width=8).pack(side=tk.LEFT, padx=(5, 0))
        
        # 更新UI状态
        self.on_schedule_enabled_changed()
    
    def on_schedule_enabled_changed(self):
        """定时任务启用状态改变"""
        enabled = self.schedule_enabled_var.get()
        # 根据启用状态和模式切换控件可用性
        state = "normal" if enabled else "disabled"
        
        # 启用/禁用模式选择
        for child in self.schedule_enabled_var._callbacks if hasattr(self.schedule_enabled_var, "_callbacks") else []:
            # 占位，防止潜在错误；真正的启用/禁用在下面的frame中完成
            pass
        
        # 星期/时间点模式相关
        for widget in self.weekday_frame.winfo_children():
            widget_state = state if self.schedule_mode_var.get() == "weekly" and enabled else "disabled"
            try:
                widget.configure(state=widget_state)
            except tk.TclError:
                pass
        for widget in self.time_frame.winfo_children():
            widget_state = state if self.schedule_mode_var.get() == "weekly" and enabled else "disabled"
            try:
                widget.configure(state=widget_state)
            except tk.TclError:
                pass
        
        # 间隔模式相关
        for widget in self.interval_frame.winfo_children():
            widget_state = state if self.schedule_mode_var.get() == "interval" and enabled else "disabled"
            try:
                widget.configure(state=widget_state)
            except tk.TclError:
                pass
    
    def on_schedule_mode_changed(self):
        """定时任务模式切换"""
        # 重新应用启用状态逻辑
        self.on_schedule_enabled_changed()
    
    def parse_schedule_times(self):
        """从文本框解析时间列表"""
        text_content = self.time_text.get("1.0", tk.END).strip()
        if not text_content:
            return []
        
        times = []
        import re
        for line in text_content.split('\n'):
            line = line.strip()
            if not line:
                continue
            # 验证时间格式 HH:MM
            if re.match(r'^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$', line):
                times.append(line)
            else:
                self.logger.warning(f"无效的时间格式: {line}，已跳过")
        
        # 去重并排序
        times = sorted(list(set(times)))
        return times
    
    def create_buttons(self):
        """创建按钮区域"""
        button_frame = ttk.Frame(self.dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        ttk.Button(button_frame, text="取消", command=self.on_cancel).pack(side=tk.RIGHT, padx=(10, 0))
        self.start_test_btn = ttk.Button(button_frame, text="开始测试", command=self.on_ok)
        self.start_test_btn.pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="保存配置", command=self.save_config).pack(side=tk.LEFT)
    
    def generate_test_name(self):
        """自动生成测试名称（英文格式，ISO 8601时间戳）"""
        from datetime import datetime
        # 使用ISO 8601基本格式：YYYYMMDDTHHMMSS
        timestamp = datetime.now().strftime("%Y%m%dT%H%M%S")
        # 使用英文测试名称
        self.test_name_var.set(f"Test_{timestamp}")
    
    def on_url_method_changed(self):
        """URL输入方式改变"""
        if self.url_method_var.get() == "manual":
            self.file_frame.pack_forget()
            self.manual_frame.pack(fill=tk.BOTH, expand=True)
        else:
            self.manual_frame.pack_forget()
            self.file_frame.pack(fill=tk.BOTH, expand=True)
        self.update_url_preview()
    
    def select_url_file(self):
        """选择URL文件"""
        file_path = filedialog.askopenfilename(
            title="选择URL文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if file_path:
            self.file_path_var.set(file_path)
            self.update_url_preview()
    
    def update_url_preview(self, event=None):
        """更新URL预览"""
        urls = self.get_urls()
        
        # 更新计数
        self.url_count_var.set(f"URL数量: {len(urls)}")
        
        # 更新预览列表
        self.url_preview.delete(0, tk.END)
        for i, url in enumerate(urls[:20]):  # 只显示前20个
            self.url_preview.insert(tk.END, f"{i+1}. {url}")
        
        if len(urls) > 20:
            self.url_preview.insert(tk.END, f"... 还有 {len(urls) - 20} 个URL")
    
    def get_urls(self) -> List[str]:
        """获取URL列表"""
        urls = []
        
        if self.url_method_var.get() == "manual":
            # 手动输入
            text_content = self.url_text.get("1.0", tk.END).strip()
            if text_content:
                urls = [line.strip() for line in text_content.split('\n') if line.strip()]
        else:
            # 文件导入
            file_path = self.file_path_var.get()
            if file_path and Path(file_path).exists():
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        urls = [line.strip() for line in f if line.strip()]
                except Exception as e:
                    self.logger.error(f"读取URL文件失败: {e}")
        
        return urls
    
    
    def detect_vpns(self):
        """检测可用VPN"""
        try:
            self.available_vpns = self.vpn_detector.get_vpn_connections()
            self.logger.info(f"检测到VPN连接: {self.available_vpns}")
            self.update_vpn_list()
        except Exception as e:
            self.logger.error(f"检测VPN失败: {e}")
            messagebox.showerror("错误", f"检测VPN失败:\n{e}")
    
    def update_vpn_list(self):
        """更新VPN列表显示"""
        # 清除现有项目
        for widget in self.scrollable_vpn_frame.winfo_children()[1:]:  # 保留标题行
            widget.destroy()
        
        self.vpn_items.clear()
        
        # 添加VPN项目
        for vpn_name in self.available_vpns:
            self.add_vpn_item(vpn_name)
    
    def add_vpn_item(self, vpn_name: str):
        """添加VPN项目"""
        item_frame = ttk.Frame(self.scrollable_vpn_frame)
        item_frame.pack(fill=tk.X, pady=2)
        
        # 选择框
        selected_var = tk.BooleanVar()
        checkbox = ttk.Checkbutton(item_frame, variable=selected_var, width=8)
        checkbox.pack(side=tk.LEFT, padx=2)
        
        # VPN名称
        name_label = ttk.Label(item_frame, text=vpn_name, width=20, anchor=tk.W)
        name_label.pack(side=tk.LEFT, padx=2)
        
        # 状态
        status_label = ttk.Label(item_frame, text="未连接", width=12, anchor=tk.W)
        status_label.pack(side=tk.LEFT, padx=2)
        
        # 用户名显示
        credentials = self.vpn_config.get_vpn_credentials(vpn_name)
        username = credentials.get("username", "") if credentials else ""
        username_label = ttk.Label(item_frame, text=username, width=15, anchor=tk.W)
        username_label.pack(side=tk.LEFT, padx=2)
        
        # 编辑按钮
        edit_btn = ttk.Button(item_frame, text="编辑", width=8,
                             command=lambda: self.edit_vpn_credentials(vpn_name))
        edit_btn.pack(side=tk.LEFT, padx=2)
        
        # 存储项目信息
        self.vpn_items[vpn_name] = {
            'selected_var': selected_var,
            'status_label': status_label,
            'username_label': username_label,
            'frame': item_frame
        }
    
    def edit_vpn_credentials(self, vpn_name: str):
        """编辑VPN凭据"""
        credentials = self.vpn_config.get_vpn_credentials(vpn_name)
        current_username = credentials.get("username", "") if credentials else ""
        current_password = credentials.get("password", "") if credentials else ""
        
        # 创建凭据编辑对话框
        cred_dialog = tk.Toplevel(self.dialog)
        cred_dialog.title(f"编辑VPN凭据 - {vpn_name}")
        cred_dialog.geometry("400x250")
        cred_dialog.resizable(True, True)
        cred_dialog.minsize(350, 200)
        cred_dialog.transient(self.dialog)
        cred_dialog.grab_set()
        
        # 居中显示
        cred_dialog.geometry("+%d+%d" % (
            self.dialog.winfo_rootx() + 100,
            self.dialog.winfo_rooty() + 100
        ))
        
        main_frame = ttk.Frame(cred_dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # VPN名称
        ttk.Label(main_frame, text=f"VPN: {vpn_name}", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        # 用户名
        ttk.Label(main_frame, text="用户名:").pack(anchor=tk.W)
        username_var = tk.StringVar(value=current_username)
        username_entry = ttk.Entry(main_frame, textvariable=username_var)
        username_entry.pack(fill=tk.X, pady=(5, 10))
        
        # 密码
        ttk.Label(main_frame, text="密码:").pack(anchor=tk.W)
        password_var = tk.StringVar(value=current_password)
        password_entry = ttk.Entry(main_frame, textvariable=password_var, show="*")
        password_entry.pack(fill=tk.X, pady=(5, 20))
        
        # 按钮
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        def save_credentials():
            username = username_var.get().strip()
            password = password_var.get().strip()
            
            if not username or not password:
                messagebox.showerror("错误", "用户名和密码不能为空")
                return
            
            # 保存凭据
            self.vpn_config.set_vpn_credentials(vpn_name, username, password)
            self.vpn_config.save_config()
            
            # 更新显示
            if vpn_name in self.vpn_items:
                self.vpn_items[vpn_name]['username_label'].config(text=username)
            
            cred_dialog.destroy()
        
        ttk.Button(button_frame, text="取消", command=cred_dialog.destroy).pack(side=tk.RIGHT, padx=(10, 0))
        ttk.Button(button_frame, text="保存", command=save_credentials).pack(side=tk.RIGHT)
        
        # 焦点设置
        username_entry.focus()
    
    def load_current_config(self):
        """加载当前配置"""
        try:
            config = self.config_manager.get_config()
            
            # 基本配置
            self.concurrent_var.set(config.get("max_concurrent_tests", 3))
            
            # 阶段超时配置
            stage_timeouts = config.get("stage_timeouts", {"stage1": 8, "stage2": 30, "stage3": 60})
            self.timeout_stage1_var.set(stage_timeouts.get("stage1", 8))
            self.timeout_stage2_var.set(stage_timeouts.get("stage2", 30))
            self.timeout_stage3_var.set(stage_timeouts.get("stage3", 60))
            
            self.har_enabled_var.set(config.get("enable_har_capture", True))
            self.hostname_enabled_var.set(config.get("enable_hostname_capture", True))
            self.blacklist_enabled_var.set(config.get("enable_blacklist", True))
            
            # 结果存放位置配置
            if hasattr(self, 'use_custom_output_dir_var'):
                results_path = self.config_manager.get_results_path()
                if results_path:
                    self.use_custom_output_dir_var.set(True)
                    self.custom_output_dir_var.set(results_path)
                    self.custom_dir_entry.config(state="normal")
                else:
                    self.use_custom_output_dir_var.set(False)
                    self.custom_output_dir_var.set("")
                    self.custom_dir_entry.config(state="disabled")
            
            # 高级配置
            self.browser_type_var.set(config.get("browser_type", "chromium"))
            self.headless_var.set(config.get("headless", False))
            self.use_system_dns_var.set(config.get("use_system_dns", True))
            self.user_agent_var.set(config.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"))
            self.clear_dns_var.set(config.get("clear_dns_cache", True))
            self.auto_disconnect_var.set(config.get("auto_disconnect_vpn", True))
            
            # VPN测试配置
            if hasattr(self, 'batch_size_var'):
                self.batch_size_var.set(config.get("vpn_batch_size", 10))
            if hasattr(self, 'wait_after_disconnect_var'):
                self.wait_after_disconnect_var.set(config.get("wait_after_disconnect", 5))
            
            # 加载参考文件路径
            if hasattr(self, 'reference_file_var'):
                self.reference_file_var.set(config.get("reference_file", ""))
            
            # 定时任务配置（如果有，且UI已创建）
            if hasattr(self, 'schedule_enabled_var'):
                schedule = config.get("schedule", {})
                if schedule:
                    self.schedule_enabled_var.set(schedule.get("enabled", False))
                    mode = schedule.get("mode", "weekly")
                    if hasattr(self, 'schedule_mode_var'):
                        self.schedule_mode_var.set(mode)
                    # 设置星期/时间点模式配置
                    if mode == "weekly":
                        if hasattr(self, 'weekday_vars'):
                            weekdays = schedule.get("weekdays", [])
                            for day, var in self.weekday_vars.items():
                                var.set(day in weekdays)
                        if hasattr(self, 'time_text'):
                            times = schedule.get("times", [])
                            self.time_text.delete("1.0", tk.END)
                            if times:
                                self.time_text.insert("1.0", "\n".join(times))
                    # 设置间隔模式配置
                    elif mode == "interval":
                        if hasattr(self, 'interval_start_date_var') and schedule.get("start_datetime"):
                            # 解析日期和时间
                            try:
                                dt_str = schedule["start_datetime"]
                                from datetime import datetime
                                dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M")
                                date_str = dt.strftime("%Y-%m-%d")
                                hour_str = dt.strftime("%H")
                                minute_str = dt.strftime("%M")
                                
                                # 设置日期下拉框（显示格式）
                                if hasattr(self, 'date_display_map') and date_str in self.date_display_map:
                                    display_str = self.date_display_map[date_str]
                                    self.interval_start_date_var.set(display_str)
                                else:
                                    self.interval_start_date_var.set(date_str)
                                
                                # 设置小时和分钟下拉框
                                if hasattr(self, 'interval_start_hour_var'):
                                    self.interval_start_hour_var.set(hour_str)
                                if hasattr(self, 'interval_start_minute_var'):
                                    # 分钟需要四舍五入到最近的5分钟
                                    minute_int = int(minute_str)
                                    rounded_minute = round(minute_int / 5) * 5
                                    if rounded_minute >= 60:
                                        rounded_minute = 55
                                    self.interval_start_minute_var.set(f"{rounded_minute:02d}")
                            except Exception:
                                # 格式不对就原样放到日期框
                                self.interval_start_date_var.set(schedule["start_datetime"])
                        if hasattr(self, 'interval_minutes_var'):
                            self.interval_minutes_var.set(schedule.get("interval_minutes", 30))
                        if hasattr(self, 'interval_count_var'):
                            self.interval_count_var.set(schedule.get("repeat_count", 1))
                    
                    # 根据模式刷新控件状态
                    self.on_schedule_mode_changed()
            
        except Exception as e:
            self.logger.error(f"加载配置失败: {e}")
    
    def on_output_dir_option_changed(self):
        """处理存放位置选项变化"""
        if self.use_custom_output_dir_var.get():
            self.custom_dir_entry.config(state="normal")
            # 如果没有设置路径，自动打开选择对话框
            if not self.custom_output_dir_var.get():
                self.select_output_directory()
        else:
            self.custom_dir_entry.config(state="disabled")
            self.custom_output_dir_var.set("")
    
    def on_test_mode_changed(self):
        """测试模式改变"""
        if hasattr(self, 'test_mode_var') and self.test_mode_var.get() == "repeat":
            # 确保在并发数之前显示
            if hasattr(self, 'concurrent_frame'):
                self.repeat_config_frame.pack(fill=tk.X, pady=(0, 10), before=self.concurrent_frame)
            else:
                self.repeat_config_frame.pack(fill=tk.X, pady=(0, 10))
        else:
            if hasattr(self, 'repeat_config_frame'):
                self.repeat_config_frame.pack_forget()
    
    def on_start_time_mode_changed(self):
        """开始时间模式改变"""
        if hasattr(self, 'start_time_mode_var') and self.start_time_mode_var.get() == "scheduled":
            if hasattr(self, 'scheduled_start_frame'):
                self.scheduled_start_frame.pack(fill=tk.X, pady=(5, 0))
        else:
            if hasattr(self, 'scheduled_start_frame'):
                self.scheduled_start_frame.pack_forget()
    
    def select_output_directory(self):
        """选择结果存放目录"""
        from utils.file_utils import get_app_base_dir
        default_dir = get_app_base_dir() / "results"
        
        # 如果已有路径，使用已有路径作为初始目录
        initial_dir = self.custom_output_dir_var.get() if self.custom_output_dir_var.get() else str(default_dir)
        
        selected_dir = filedialog.askdirectory(
            title="选择结果存放位置",
            initialdir=initial_dir
        )
        
        if selected_dir:
            self.custom_output_dir_var.set(selected_dir)
            # 保存到配置
            self.config_manager.set_results_path(selected_dir)
    
    def save_config(self):
        """保存配置"""
        try:
            config = {
                "max_concurrent_tests": self.concurrent_var.get(),
                "stage_timeouts": {
                    "stage1": self.timeout_stage1_var.get(),
                    "stage2": self.timeout_stage2_var.get(),
                    "stage3": self.timeout_stage3_var.get()
                },
                "enable_har_capture": self.har_enabled_var.get(),
                "enable_hostname_capture": self.hostname_enabled_var.get(),
                "enable_blacklist": self.blacklist_enabled_var.get(),
                "browser_type": self.browser_type_var.get(),
                "headless": self.headless_var.get(),
                "use_system_dns": self.use_system_dns_var.get(),
                "user_agent": self.user_agent_var.get(),
                "clear_dns_cache": self.clear_dns_var.get(),
                "auto_disconnect_vpn": self.auto_disconnect_var.get(),
                "vpn_batch_size": self.batch_size_var.get(),
                "wait_after_disconnect": self.wait_after_disconnect_var.get()
            }
            
            self.config_manager.update_config(config)
            messagebox.showinfo("成功", "配置已保存")
            
        except Exception as e:
            self.logger.error(f"保存配置失败: {e}")
            messagebox.showerror("错误", f"保存配置失败:\n{e}")
    
    def validate_config(self) -> bool:
        """验证配置"""
        # 检查测试名称
        if not self.test_name_var.get().strip():
            messagebox.showerror("错误", "请输入测试名称")
            return False
        
        # 检查URL
        urls = self.get_urls()
        if not urls:
            messagebox.showerror("错误", "请输入至少一个测试URL")
            return False
        
        # 检查VPN配置（可选）
        selected_vpns = self.get_selected_vpns()
        enable_vpn_test = self.enable_vpn_test_var.get()
        enable_direct_test = self.enable_direct_test_var.get()
        
        # 如果选择了VPN但没有选择任何测试模式
        if selected_vpns and not enable_vpn_test and not enable_direct_test:
            messagebox.showerror("错误", "请至少选择一种测试模式（VPN模式或直连模式）")
            return False
        
        # 如果选择了VPN且启用了VPN模式测试，需要验证VPN凭据
        if selected_vpns and enable_vpn_test:
            for vpn_name in selected_vpns:
                credentials = self.vpn_config.get_vpn_credentials(vpn_name)
                if not credentials or not credentials.get("username") or not credentials.get("password"):
                    messagebox.showerror("错误", f"VPN '{vpn_name}' 缺少用户名或密码（VPN模式测试需要）")
                    return False
        # 如果没有选择VPN，将使用当前网络环境进行测试（不需要VPN）
        
        return True
    
    def get_selected_vpns(self) -> List[str]:
        """获取选中的VPN列表（保持固定顺序）"""
        selected = []
        # 按照vpn_items的插入顺序遍历（保持UI显示顺序）
        for vpn_name, item in self.vpn_items.items():
            if item['selected_var'].get():
                selected.append(vpn_name)
        # 排序以保持固定顺序
        selected.sort()
        return selected
    
    def on_ok(self):
        """确定按钮"""
        if not self.validate_config():
            return
        
        # 保存参考文件路径到配置
        reference_file = self.reference_file_var.get().strip() if hasattr(self, 'reference_file_var') else ""
        if reference_file:
            self.config_manager.set_reference_file(reference_file)
        
        # 保存自定义输出目录（如果启用）
        if hasattr(self, 'use_custom_output_dir_var') and self.use_custom_output_dir_var.get():
            custom_output_dir = self.custom_output_dir_var.get().strip()
            if custom_output_dir:
                self.config_manager.set_results_path(custom_output_dir)
        
        # 构建结果
        result = {
            "test_name": self.test_name_var.get().strip(),
            "urls": self.get_urls(),
            "selected_vpns": self.get_selected_vpns(),
            "enable_vpn_test": self.enable_vpn_test_var.get(),
            "enable_direct_test": self.enable_direct_test_var.get(),
            "reference_file": reference_file,
            "custom_output_dir": self.custom_output_dir_var.get().strip() if (hasattr(self, 'use_custom_output_dir_var') and self.use_custom_output_dir_var.get()) else "",
            "test_mode": self.test_mode_var.get() if hasattr(self, 'test_mode_var') else "single",
            "repeat_count": self.repeat_count_var.get() if (hasattr(self, 'test_mode_var') and self.test_mode_var.get() == "repeat" and hasattr(self, 'repeat_count_var')) else 1,
            "start_time_mode": self.start_time_mode_var.get() if (hasattr(self, 'test_mode_var') and self.test_mode_var.get() == "repeat" and hasattr(self, 'start_time_mode_var')) else "immediate",
            "start_datetime": None,  # 将在下面设置
            "config": {
                "max_concurrent_tests": self.concurrent_var.get(),
                "stage_timeouts": {
                    "stage1": self.timeout_stage1_var.get(),
                    "stage2": self.timeout_stage2_var.get(),
                    "stage3": self.timeout_stage3_var.get()
                },
                "enable_har_capture": self.har_enabled_var.get(),
                "enable_hostname_capture": self.hostname_enabled_var.get(),
                "enable_blacklist": self.blacklist_enabled_var.get(),
                "browser_type": self.browser_type_var.get(),
                "headless": self.headless_var.get(),
                "use_system_dns": self.use_system_dns_var.get(),
                "user_agent": self.user_agent_var.get(),
                "clear_dns_cache": self.clear_dns_var.get(),
                "auto_disconnect_vpn": self.auto_disconnect_var.get(),
                "vpn_batch_size": self.batch_size_var.get(),
                "wait_after_disconnect": self.wait_after_disconnect_var.get()
            }
        }
        
        # 添加定时任务配置
        if self.schedule_enabled_var.get():
            mode = self.schedule_mode_var.get() if hasattr(self, 'schedule_mode_var') else "weekly"
            schedule: Dict[str, Any] = {
                "enabled": True,
                "mode": mode
            }
            if mode == "weekly":
                # 获取选中的星期
                selected_weekdays = [day for day, var in self.weekday_vars.items() if var.get()]
                
                if not selected_weekdays:
                    messagebox.showwarning("警告", "请至少选择一个执行日期")
                    return
                
                # 从文本框解析时间
                schedule_times = self.parse_schedule_times()
                if not schedule_times:
                    messagebox.showwarning("警告", "请至少输入一个执行时间（格式：HH:MM）")
                    return
                
                schedule.update({
                    "weekdays": selected_weekdays,
                    "times": schedule_times
                })
            else:
                # 间隔模式：开始时间 + 间隔 + 次数
                start_date = self.interval_start_date_var.get().strip() if hasattr(self, 'interval_start_date_var') else ""
                start_hour = self.interval_start_hour_var.get().strip() if hasattr(self, 'interval_start_hour_var') else "09"
                start_minute = self.interval_start_minute_var.get().strip() if hasattr(self, 'interval_start_minute_var') else "00"
                
                if not start_date:
                    messagebox.showwarning("警告", "请选择开始日期")
                    return False
                
                # 如果日期是显示格式，需要转换为实际日期值
                if hasattr(self, 'date_value_map') and start_date in self.date_value_map:
                    start_date = self.date_value_map[start_date]
                
                # 组合时间字符串
                start_time = f"{start_hour}:{start_minute}"
                
                from datetime import datetime
                try:
                    start_dt = datetime.strptime(f"{start_date} {start_time}", "%Y-%m-%d %H:%M")
                except ValueError:
                    messagebox.showwarning("警告", "开始日期或时间格式不正确")
                    return False
                interval_minutes = int(self.interval_minutes_var.get()) if hasattr(self, 'interval_minutes_var') else 0
                repeat_count = int(self.interval_count_var.get()) if hasattr(self, 'interval_count_var') else 0
                if interval_minutes <= 0:
                    messagebox.showwarning("警告", "间隔时间必须大于 0 分钟")
                    return
                if repeat_count <= 0:
                    messagebox.showwarning("警告", "执行次数必须大于 0")
                    return
                schedule.update({
                    "start_datetime": start_dt.strftime("%Y-%m-%d %H:%M"),
                    "interval_minutes": interval_minutes,
                    "repeat_count": repeat_count
                })
            result["schedule"] = schedule
        else:
            result["schedule"] = {
                "enabled": False,
                "mode": "weekly",
                "weekdays": [],
                "times": []
            }
        
        self.result = result
        self.dialog.destroy()
    
    def save_config_and_schedule(self):
        """保存配置和定时任务（用于编辑任务时）"""
        if not self.validate_config():
            return False
        
        # 保存参考文件路径到配置
        reference_file = self.reference_file_var.get().strip() if hasattr(self, 'reference_file_var') else ""
        if reference_file:
            self.config_manager.set_reference_file(reference_file)
        
        # 构建结果（与on_ok相同）
        result = {
            "test_name": self.test_name_var.get().strip(),
            "urls": self.get_urls(),
            "selected_vpns": self.get_selected_vpns(),
            "enable_vpn_test": self.enable_vpn_test_var.get(),
            "enable_direct_test": self.enable_direct_test_var.get(),
            "reference_file": reference_file,
            "config": {
                "max_concurrent_tests": self.concurrent_var.get(),
                "stage_timeouts": {
                    "stage1": self.timeout_stage1_var.get(),
                    "stage2": self.timeout_stage2_var.get(),
                    "stage3": self.timeout_stage3_var.get()
                },
                "enable_har_capture": self.har_enabled_var.get(),
                "enable_hostname_capture": self.hostname_enabled_var.get(),
                "enable_blacklist": self.blacklist_enabled_var.get(),
                "browser_type": self.browser_type_var.get(),
                "headless": self.headless_var.get(),
                "use_system_dns": self.use_system_dns_var.get(),
                "user_agent": self.user_agent_var.get(),
                "clear_dns_cache": self.clear_dns_var.get(),
                "auto_disconnect_vpn": self.auto_disconnect_var.get(),
                "vpn_batch_size": self.batch_size_var.get(),
                "wait_after_disconnect": self.wait_after_disconnect_var.get()
            }
        }
        
        # 添加定时任务配置
        if self.schedule_enabled_var.get():
            mode = self.schedule_mode_var.get() if hasattr(self, 'schedule_mode_var') else "weekly"
            schedule: Dict[str, Any] = {
                "enabled": True,
                "mode": mode
            }
            if mode == "weekly":
                selected_weekdays = [day for day, var in self.weekday_vars.items() if var.get()]
                if not selected_weekdays:
                    messagebox.showwarning("警告", "请至少选择一个执行日期")
                    return False
                # 从文本框解析时间
                schedule_times = self.parse_schedule_times()
                if not schedule_times:
                    messagebox.showwarning("警告", "请至少输入一个执行时间（格式：HH:MM）")
                    return False
                schedule.update({
                    "weekdays": selected_weekdays,
                    "times": schedule_times
                })
            else:
                # 间隔模式
                start_date = self.interval_start_date_var.get().strip() if hasattr(self, 'interval_start_date_var') else ""
                start_hour = self.interval_start_hour_var.get().strip() if hasattr(self, 'interval_start_hour_var') else "09"
                start_minute = self.interval_start_minute_var.get().strip() if hasattr(self, 'interval_start_minute_var') else "00"
                
                if not start_date:
                    messagebox.showwarning("警告", "请选择开始日期")
                    return False
                
                # 如果日期是显示格式，需要转换为实际日期值
                if hasattr(self, 'date_value_map') and start_date in self.date_value_map:
                    start_date = self.date_value_map[start_date]
                
                # 组合时间字符串
                start_time = f"{start_hour}:{start_minute}"
                
                from datetime import datetime
                try:
                    start_dt = datetime.strptime(f"{start_date} {start_time}", "%Y-%m-%d %H:%M")
                except ValueError:
                    messagebox.showwarning("警告", "开始日期或时间格式不正确")
                    return False
                interval_minutes = int(self.interval_minutes_var.get()) if hasattr(self, 'interval_minutes_var') else 0
                repeat_count = int(self.interval_count_var.get()) if hasattr(self, 'interval_count_var') else 0
                if interval_minutes <= 0:
                    messagebox.showwarning("警告", "间隔时间必须大于 0 分钟")
                    return False
                if repeat_count <= 0:
                    messagebox.showwarning("警告", "执行次数必须大于 0")
                    return False
                schedule.update({
                    "start_datetime": start_dt.strftime("%Y-%m-%d %H:%M"),
                    "interval_minutes": interval_minutes,
                    "repeat_count": repeat_count
                })
            result["schedule"] = schedule
        else:
            result["schedule"] = {
                "enabled": False,
                "mode": "weekly",
                "weekdays": [],
                "times": []
            }
        
        self.result = result
        return True
    
    def on_cancel(self):
        """取消按钮"""
        self.result = None
        self.dialog.destroy()


def show_unified_test_dialog(parent, config_manager: ConfigManager, logger: Optional[logging.Logger] = None) -> Optional[Dict[str, Any]]:
    """显示统一测试配置对话框"""
    dialog = UnifiedTestDialog(parent, config_manager, logger)
    parent.wait_window(dialog.dialog)
    return dialog.result
