"""
配置管理对话框
允许用户配置浏览器路径和其他设置
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
import logging
from typing import Optional, Callable

from utils.config_manager import ConfigManager
from utils.playwright_checker import check_playwright_browser_installed
from utils.playwright_path_helper import get_playwright_browser_path, get_chromium_executable_path


logger = logging.getLogger(__name__)


class ConfigDialog:
    """配置管理对话框"""
    
    def __init__(self, parent, config_manager: ConfigManager, on_config_changed: Optional[Callable] = None):
        """
        初始化配置对话框
        
        Args:
            parent: 父窗口
            config_manager: 配置管理器
            on_config_changed: 配置更改后的回调函数
        """
        self.parent = parent
        self.config_manager = config_manager
        self.on_config_changed = on_config_changed
        
        self.dialog = None
        self.browser_path_var = None
        self.auto_detect_var = None
        
    def show(self):
        """显示配置对话框"""
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("配置管理")
        self.dialog.geometry("700x600")
        self.dialog.resizable(True, True)
        self.dialog.minsize(600, 500)
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # 居中显示
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() - self.dialog.winfo_width()) // 2
        y = (self.dialog.winfo_screenheight() - self.dialog.winfo_height()) // 2
        self.dialog.geometry(f"+{x}+{y}")
        
        # 创建主框架（可滚动）
        canvas = tk.Canvas(self.dialog)
        scrollbar = ttk.Scrollbar(self.dialog, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # 绑定鼠标滚轮
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        main_frame = ttk.Frame(scrollable_frame, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 标题
        title_label = ttk.Label(
            main_frame,
            text="配置管理",
            font=("Arial", 14, "bold")
        )
        title_label.pack(pady=(0, 20))
        
        # ==================== 浏览器路径配置 ====================
        browser_frame = ttk.LabelFrame(main_frame, text="Playwright 浏览器路径", padding=10)
        browser_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 自动检测选项
        auto_detect_frame = ttk.Frame(browser_frame)
        auto_detect_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.auto_detect_var = tk.BooleanVar(value=self.config_manager.get("auto_detect_browser", True))
        auto_detect_check = ttk.Checkbutton(
            auto_detect_frame,
            text="自动检测浏览器路径（推荐）",
            variable=self.auto_detect_var,
            command=self._on_auto_detect_changed
        )
        auto_detect_check.pack(side=tk.LEFT)
        
        # 浏览器路径输入
        path_frame = ttk.Frame(browser_frame)
        path_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(path_frame, text="浏览器目录:").pack(side=tk.LEFT, padx=(0, 5))
        
        self.browser_path_var = tk.StringVar(value=self.config_manager.get("browser_path", ""))
        self.browser_path_entry = ttk.Entry(path_frame, textvariable=self.browser_path_var, width=50)
        self.browser_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        self.browse_btn = ttk.Button(
            path_frame,
            text="浏览...",
            command=self._browse_browser_path,
            width=10
        )
        self.browse_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(
            path_frame,
            text="自动检测",
            command=self._auto_detect_browser_path,
            width=10
        ).pack(side=tk.LEFT)
        
        # 当前检测到的路径显示
        current_path_frame = ttk.Frame(browser_frame)
        current_path_frame.pack(fill=tk.X, pady=(0, 10))
        
        detected_path = get_playwright_browser_path("chromium", self.config_manager)
        if detected_path:
            detected_text = f"当前检测到的路径: {detected_path.parent}"
        else:
            detected_text = "未检测到浏览器路径"
        
        ttk.Label(
            current_path_frame,
            text=detected_text,
            font=("Arial", 8),
            foreground="gray"
        ).pack(side=tk.LEFT)
        
        # 验证按钮
        verify_frame = ttk.Frame(browser_frame)
        verify_frame.pack(fill=tk.X)
        
        self.verify_status_var = tk.StringVar(value="")
        verify_status_label = ttk.Label(
            verify_frame,
            textvariable=self.verify_status_var,
            font=("Arial", 9)
        )
        verify_status_label.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            verify_frame,
            text="验证路径",
            command=self._verify_browser_path,
            width=12
        ).pack(side=tk.LEFT)
        
        # ==================== 其他配置 ====================
        other_frame = ttk.LabelFrame(main_frame, text="其他配置", padding=10)
        other_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # 结果存储路径
        results_path_frame = ttk.Frame(other_frame)
        results_path_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(results_path_frame, text="结果存储路径:").pack(side=tk.LEFT, padx=(0, 5))
        
        results_path = self.config_manager.get("results_path", "")
        self.results_path_var = tk.StringVar(value=results_path)
        results_path_entry = ttk.Entry(results_path_frame, textvariable=self.results_path_var, width=50)
        results_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(
            results_path_frame,
            text="浏览...",
            command=self._browse_results_path,
            width=10
        ).pack(side=tk.LEFT)
        
        ttk.Label(
            other_frame,
            text="（留空则使用默认路径：exe所在目录/results）",
            font=("Arial", 8),
            foreground="gray"
        ).pack(anchor=tk.W, pady=(0, 10))
        
        # ==================== 按钮 ====================
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(
            button_frame,
            text="确定",
            command=self._on_ok,
            width=12
        ).pack(side=tk.RIGHT, padx=(5, 0))
        
        ttk.Button(
            button_frame,
            text="取消",
            command=self._on_cancel,
            width=12
        ).pack(side=tk.RIGHT)
        
        ttk.Button(
            button_frame,
            text="恢复默认",
            command=self._reset_to_default,
            width=12
        ).pack(side=tk.LEFT)
        
        # 初始化UI状态
        self._on_auto_detect_changed()
        
        # 如果启用自动检测且没有配置路径，尝试自动检测并填充
        if self.auto_detect_var.get() and not self.browser_path_var.get():
            browser_path = get_playwright_browser_path("chromium", self.config_manager)
            if browser_path:
                detected_path = str(browser_path.parent)
                self.browser_path_var.set(detected_path)
        
    def _on_auto_detect_changed(self):
        """自动检测选项改变时的处理"""
        auto_detect = self.auto_detect_var.get()
        # 如果启用自动检测，禁用路径输入和浏览按钮
        if hasattr(self, 'browser_path_entry'):
            if auto_detect:
                self.browser_path_entry.config(state=tk.DISABLED)
                self.browse_btn.config(state=tk.DISABLED)
                # 清空手动输入的路径
                if self.browser_path_var.get():
                    self.browser_path_var.set("")
            else:
                self.browser_path_entry.config(state=tk.NORMAL)
                self.browse_btn.config(state=tk.NORMAL)
        
    def _browse_browser_path(self):
        """浏览浏览器路径"""
        initial_dir = self.browser_path_var.get() or str(Path.home())
        path = filedialog.askdirectory(
            title="选择 Playwright 浏览器目录（ms-playwright）",
            initialdir=initial_dir
        )
        if path:
            self.browser_path_var.set(path)
            self.verify_status_var.set("")
    
    def _auto_detect_browser_path(self):
        """自动检测浏览器路径"""
        browser_path = get_playwright_browser_path("chromium", self.config_manager)
        if browser_path:
            detected_path = str(browser_path.parent)  # ms-playwright 目录
            self.browser_path_var.set(detected_path)
            self.verify_status_var.set("已自动检测到路径")
            # 如果启用了自动检测，自动保存路径到配置
            if self.auto_detect_var.get():
                # 自动检测模式下，保存路径以便下次使用
                self.config_manager.set("browser_path", detected_path)
            messagebox.showinfo("检测成功", f"已检测到浏览器路径:\n{detected_path}\n\n路径已自动填充，点击'确定'保存配置。")
        else:
            self.verify_status_var.set("未检测到浏览器")
            messagebox.showwarning("检测失败", "未检测到浏览器路径，请手动选择或安装浏览器")
    
    def _verify_browser_path(self):
        """验证浏览器路径"""
        path_str = self.browser_path_var.get().strip()
        if not path_str:
            self.verify_status_var.set("路径不能为空")
            return
        
        path = Path(path_str)
        if not path.exists():
            self.verify_status_var.set("路径不存在")
            messagebox.showerror("验证失败", f"路径不存在:\n{path_str}")
            return
        
        # 检查是否是 ms-playwright 目录
        if path.name != "ms-playwright":
            # 检查是否是浏览器子目录
            if "chromium" in path.name.lower():
                # 可能是浏览器子目录，向上查找 ms-playwright
                parent = path.parent
                if parent.name == "ms-playwright":
                    path = parent
                    self.browser_path_var.set(str(path))
                else:
                    self.verify_status_var.set("请选择 ms-playwright 目录")
                    messagebox.showwarning("路径错误", "请选择包含所有浏览器的 ms-playwright 目录，而不是单个浏览器目录")
                    return
            else:
                self.verify_status_var.set("请选择 ms-playwright 目录")
                messagebox.showwarning("路径错误", "请选择包含所有浏览器的 ms-playwright 目录")
                return
        
        # 检查目录中是否有 chromium
        chromium_dirs = list(path.glob("chromium-*"))
        if not chromium_dirs:
            self.verify_status_var.set("未找到 chromium 浏览器")
            messagebox.showwarning("验证失败", "在指定路径中未找到 chromium 浏览器")
            return
        
        # 检查可执行文件
        chromium_path = chromium_dirs[0]
        exe_paths = [
            chromium_path / "chrome-win" / "chrome.exe",
            chromium_path / "chrome-win" / "headless_shell.exe",
        ]
        
        found_exe = None
        for exe_path in exe_paths:
            if exe_path.exists():
                found_exe = exe_path
                break
        
        if not found_exe:
            # 递归查找
            for exe_file in chromium_path.rglob("chrome.exe"):
                found_exe = exe_file
                break
        
        if found_exe:
            self.verify_status_var.set("验证成功")
            messagebox.showinfo("验证成功", f"浏览器路径验证成功！\n\n找到浏览器: {found_exe}")
        else:
            self.verify_status_var.set("未找到可执行文件")
            messagebox.showwarning("验证失败", "在指定路径中未找到浏览器可执行文件")
    
    def _browse_results_path(self):
        """浏览结果存储路径"""
        initial_dir = self.results_path_var.get() or str(Path.home())
        path = filedialog.askdirectory(
            title="选择结果存储目录",
            initialdir=initial_dir
        )
        if path:
            self.results_path_var.set(path)
    
    def _reset_to_default(self):
        """恢复默认设置"""
        if messagebox.askyesno("确认", "确定要恢复默认设置吗？"):
            self.auto_detect_var.set(True)
            self.browser_path_var.set("")
            self.results_path_var.set("")
            self.verify_status_var.set("")
            messagebox.showinfo("提示", "已恢复默认设置")
    
    def _on_ok(self):
        """确定按钮处理"""
        # 保存配置 - 无论是否自动检测，都要保存auto_detect_browser状态
        auto_detect = self.auto_detect_var.get()
        self.config_manager.set("auto_detect_browser", auto_detect)
        self.config_manager._save_config()  # 立即保存
        
        browser_path = self.browser_path_var.get().strip()
        if auto_detect:
            # 自动检测模式：如果路径为空，尝试自动检测并保存
            if not browser_path:
                browser_path_obj = get_playwright_browser_path("chromium", self.config_manager)
                if browser_path_obj:
                    browser_path = str(browser_path_obj.parent)
                    self.config_manager.set("browser_path", browser_path)
                    self.logger.info(f"自动检测并保存浏览器路径: {browser_path}")
            elif browser_path:
                # 有路径，保存它
                self.config_manager.set("browser_path", browser_path)
        else:
            # 手动模式：保存用户输入的路径
            if browser_path:
                self.config_manager.set("browser_path", browser_path)
            else:
                # 如果为空，删除配置
                if "browser_path" in self.config_manager.config:
                    del self.config_manager.config["browser_path"]
                    self.config_manager._save_config()
        
        results_path = self.results_path_var.get().strip()
        if results_path:
            self.config_manager.set("results_path", results_path)
        else:
            if "results_path" in self.config_manager.config:
                del self.config_manager.config["results_path"]
                self.config_manager._save_config()
        
        # 调用回调
        if self.on_config_changed:
            self.on_config_changed()
        
        self.dialog.destroy()
        messagebox.showinfo("保存成功", "配置已保存！\n\n部分配置需要重启程序才能生效。")
    
    def _on_cancel(self):
        """取消按钮处理"""
        self.dialog.destroy()

