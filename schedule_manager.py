"""
定时任务管理对话框
显示所有定时任务和执行历史
"""
import tkinter as tk
from tkinter import ttk, messagebox
from typing import List, Dict, Optional
from datetime import datetime
import logging


class ScheduleManagerDialog:
    """定时任务管理对话框"""
    
    def __init__(self, parent, scheduler, logger: Optional[logging.Logger] = None, execute_callback=None):
        self.parent = parent
        self.scheduler = scheduler
        self.logger = logger or logging.getLogger(__name__)
        self.execute_callback = execute_callback
        
        # 创建对话框
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("定时任务管理")
        self.dialog.geometry("900x600")
        self.dialog.resizable(True, True)
        self.dialog.minsize(800, 500)
        
        # 设置模态
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # 居中显示
        self.dialog.geometry("+%d+%d" % (parent.winfo_rootx() + 50, parent.winfo_rooty() + 50))
        
        self.create_widgets()
        self.refresh_task_list()
        
        # 绑定关闭事件
        self.dialog.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def create_widgets(self):
        """创建UI组件"""
        # 主框架
        main_frame = ttk.Frame(self.dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 任务列表区域
        list_frame = ttk.LabelFrame(main_frame, text="定时任务列表", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # 创建表格
        columns = ("任务名称", "状态", "执行日期", "执行时间", "上次执行", "操作")
        self.task_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=15)
        
        # 设置列标题和宽度
        self.task_tree.heading("任务名称", text="任务名称")
        self.task_tree.heading("状态", text="状态")
        self.task_tree.heading("执行日期", text="执行日期")
        self.task_tree.heading("执行时间", text="执行时间")
        self.task_tree.heading("上次执行", text="上次执行")
        self.task_tree.heading("操作", text="操作")
        
        self.task_tree.column("任务名称", width=200)
        self.task_tree.column("状态", width=80)
        self.task_tree.column("执行日期", width=150)
        self.task_tree.column("执行时间", width=200)
        self.task_tree.column("上次执行", width=150)
        self.task_tree.column("操作", width=100)
        
        # 滚动条
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.task_tree.yview)
        self.task_tree.configure(yscrollcommand=scrollbar.set)
        
        self.task_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 按钮区域
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(button_frame, text="刷新", command=self.refresh_task_list).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="编辑", command=self.edit_task).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="启用/禁用", command=self.toggle_task).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="删除", command=self.delete_task).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="查看详情", command=self.view_task_details).pack(side=tk.LEFT, padx=(0, 5))
        
        # 执行历史区域
        history_frame = ttk.LabelFrame(main_frame, text="执行历史", padding=10)
        history_frame.pack(fill=tk.BOTH, expand=True)
        
        # 历史记录文本框
        self.history_text = tk.Text(history_frame, height=8, wrap=tk.WORD, state=tk.DISABLED)
        history_scrollbar = ttk.Scrollbar(history_frame, orient=tk.VERTICAL, command=self.history_text.yview)
        self.history_text.configure(yscrollcommand=history_scrollbar.set)
        
        self.history_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        history_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 关闭按钮
        close_frame = ttk.Frame(main_frame)
        close_frame.pack(fill=tk.X)
        
        ttk.Button(close_frame, text="关闭", command=self.on_close).pack(side=tk.RIGHT)
    
    def refresh_task_list(self):
        """刷新任务列表"""
        # 清空现有项目
        for item in self.task_tree.get_children():
            self.task_tree.delete(item)
        
        # 获取所有任务
        tasks = self.scheduler.get_tasks()
        
        weekday_names = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"]
        
        for task in tasks:
            # 格式化执行日期
            weekdays = task.get('weekdays', [])
            days_str = ', '.join([weekday_names[d] for d in weekdays]) if weekdays else "无"
            
            # 格式化执行时间
            times = task.get('times', [])
            times_str = ', '.join(times) if times else "无"
            
            # 状态
            status = "已启用" if task.get('enabled', False) else "已禁用"
            
            # 上次执行时间
            last_run = task.get('last_run_time')
            if last_run:
                last_run_str = datetime.fromtimestamp(last_run).strftime("%Y-%m-%d %H:%M:%S")
            else:
                last_run_str = "从未执行"
            
            # 插入到树形视图
            item_id = self.task_tree.insert(
                "",
                tk.END,
                values=(
                    task.get('test_name', task.get('task_id', '未知')),
                    status,
                    days_str,
                    times_str,
                    last_run_str,
                    task.get('task_id', '')
                ),
                tags=(status,)
            )
            
            # 设置颜色
            if task.get('enabled', False):
                self.task_tree.set(item_id, "状态", "✓ 已启用")
            else:
                self.task_tree.set(item_id, "状态", "✗ 已禁用")
        
        # 更新执行历史
        self.update_history()
    
    def toggle_task(self):
        """启用/禁用任务"""
        selection = self.task_tree.selection()
        if not selection:
            messagebox.showwarning("警告", "请选择要操作的任务")
            return
        
        item = selection[0]
        task_id = self.task_tree.item(item, "values")[5]  # 操作列存储的是task_id
        
        if not task_id:
            messagebox.showerror("错误", "无法获取任务ID")
            return
        
        # 获取当前状态
        current_status = self.task_tree.item(item, "values")[1]
        is_enabled = "已启用" in current_status
        
        # 切换状态
        if self.scheduler.enable_task(task_id, not is_enabled):
            self.refresh_task_list()
            messagebox.showinfo("成功", f"任务已{'启用' if not is_enabled else '禁用'}")
        else:
            messagebox.showerror("错误", "操作失败")
    
    def delete_task(self):
        """删除任务"""
        selection = self.task_tree.selection()
        if not selection:
            messagebox.showwarning("警告", "请选择要删除的任务")
            return
        
        item = selection[0]
        task_name = self.task_tree.item(item, "values")[0]
        task_id = self.task_tree.item(item, "values")[5]
        
        if not task_id:
            messagebox.showerror("错误", "无法获取任务ID")
            return
        
        # 确认删除
        response = messagebox.askyesno(
            "确认删除",
            f"确定要删除定时任务 '{task_name}' 吗？\n\n此操作不可恢复。"
        )
        
        if response:
            if self.scheduler.remove_task(task_id):
                self.refresh_task_list()
                messagebox.showinfo("成功", "任务已删除")
            else:
                messagebox.showerror("错误", "删除失败")
    
    def view_task_details(self):
        """查看任务详情"""
        selection = self.task_tree.selection()
        if not selection:
            messagebox.showwarning("警告", "请选择要查看的任务")
            return
        
        item = selection[0]
        values = self.task_tree.item(item, "values")
        task_id = values[5]
        
        if not task_id:
            messagebox.showerror("错误", "无法获取任务ID")
            return
        
        # 获取任务详细信息
        tasks = self.scheduler.get_tasks()
        task_info = next((t for t in tasks if t.get('task_id') == task_id), None)
        
        if not task_info:
            messagebox.showerror("错误", "找不到任务信息")
            return
        
        # 获取任务配置
        task = self.scheduler.get_task(task_id)
        if not task:
            messagebox.showerror("错误", "找不到任务对象")
            return
        
        # 显示详情对话框
        detail_dialog = tk.Toplevel(self.dialog)
        detail_dialog.title(f"任务详情 - {values[0]}")
        detail_dialog.geometry("600x500")
        detail_dialog.transient(self.dialog)
        detail_dialog.grab_set()
        
        main_frame = ttk.Frame(detail_dialog, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 任务信息
        weekday_names = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"]
        weekdays = task_info.get('weekdays', [])
        days_str = ', '.join([weekday_names[d] for d in weekdays]) if weekdays else "无"
        times_str = ', '.join(task_info.get('times', [])) if task_info.get('times') else "无"
        
        # 获取VPN信息
        config = task.config
        selected_vpns = config.get('selected_vpns', [])
        vpn_str = ', '.join(selected_vpns) if selected_vpns else "无"
        
        # 获取URL信息
        urls = config.get('urls', [])
        url_count = len(urls)
        url_preview = ', '.join(urls[:3]) if urls else "无"
        if len(urls) > 3:
            url_preview += f" ... (共{url_count}个)"
        elif url_count == 0:
            url_preview = "无"
        
        # 获取执行历史统计
        execution_history = getattr(task, 'execution_history', [])
        success_count = sum(1 for r in execution_history if r.get('status') == 'success')
        failed_count = sum(1 for r in execution_history if r.get('status') == 'failed')
        total_executions = len(execution_history)
        
        info_text = f"""任务名称: {values[0]}
任务ID: {task_id}
状态: {values[1]}

执行日期: {days_str}
执行时间: {times_str}
上次执行: {values[4]}

选择的VPN: {vpn_str}
测试URL数量: {url_count}
URL预览: {url_preview}

并发数: {config.get('config', {}).get('max_concurrent_tests', 3)}
阶段超时:
  阶段1-HTTP: {config.get('config', {}).get('stage_timeouts', {}).get('stage1', 8)}秒
  阶段2-DOM: {config.get('config', {}).get('stage_timeouts', {}).get('stage2', 15)}秒
  阶段3-Load: {config.get('config', {}).get('stage_timeouts', {}).get('stage3', 30)}秒

执行统计:
  总执行次数: {total_executions}
  成功: {success_count}
  失败: {failed_count}

任务配置信息已保存，可在测试配置中查看完整配置。"""
        
        text_widget = tk.Text(main_frame, wrap=tk.WORD, state=tk.DISABLED, font=("Consolas", 9))
        text_widget.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        text_widget.config(state=tk.NORMAL)
        text_widget.insert("1.0", info_text)
        text_widget.config(state=tk.DISABLED)
        
        ttk.Button(main_frame, text="关闭", command=detail_dialog.destroy).pack()
    
    def edit_task(self):
        """编辑任务"""
        selection = self.task_tree.selection()
        if not selection:
            messagebox.showwarning("警告", "请选择要编辑的任务")
            return
        
        item = selection[0]
        values = self.task_tree.item(item, "values")
        task_id = values[5]
        
        if not task_id:
            messagebox.showerror("错误", "无法获取任务ID")
            return
        
        # 获取任务对象
        task = self.scheduler.get_task(task_id)
        if not task:
            messagebox.showerror("错误", "找不到任务对象")
            return
        
        # 打开编辑对话框（使用统一测试配置对话框，但预填充数据）
        from ui.unified_test_dialog import UnifiedTestDialog
        from utils.config_manager import ConfigManager
        
        # 创建编辑对话框
        edit_dialog = UnifiedTestDialog(self.dialog, ConfigManager(), self.logger)
        
        # 预填充任务配置
        config = task.config
        
        # 填充基本配置
        edit_dialog.test_name_var.set(config.get('test_name', ''))
        edit_dialog.concurrent_var.set(config.get('config', {}).get('max_concurrent_tests', 3))
        
        stage_timeouts = config.get('config', {}).get('stage_timeouts', {})
        edit_dialog.timeout_stage1_var.set(stage_timeouts.get('stage1', 8))
        edit_dialog.timeout_stage2_var.set(stage_timeouts.get('stage2', 15))
        edit_dialog.timeout_stage3_var.set(stage_timeouts.get('stage3', 30))
        
        # 填充其他配置
        config_data = config.get('config', {})
        edit_dialog.har_enabled_var.set(config_data.get('enable_har_capture', True))
        edit_dialog.hostname_enabled_var.set(config_data.get('enable_hostname_capture', True))
        edit_dialog.blacklist_enabled_var.set(config_data.get('enable_blacklist', True))
        edit_dialog.headless_var.set(config_data.get('headless', False))
        edit_dialog.browser_type_var.set(config_data.get('browser_type', 'chromium'))
        edit_dialog.use_system_dns_var.set(config_data.get('use_system_dns', True))
        edit_dialog.user_agent_var.set(config_data.get('user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'))
        edit_dialog.clear_dns_var.set(config_data.get('clear_dns_cache', True))
        edit_dialog.auto_disconnect_var.set(config_data.get('auto_disconnect_vpn', True))
        
        # 填充参考文件路径
        if hasattr(edit_dialog, 'reference_file_var'):
            edit_dialog.reference_file_var.set(config.get('reference_file', ''))
        
        # 填充URL
        urls = config.get('urls', [])
        edit_dialog.url_text.delete("1.0", tk.END)
        edit_dialog.url_text.insert("1.0", '\n'.join(urls))
        edit_dialog.update_url_preview()
        
        # 填充VPN选择（需要等待VPN列表加载完成）
        selected_vpns = config.get('selected_vpns', [])
        def fill_vpn_selection():
            for vpn_name, item_data in edit_dialog.vpn_items.items():
                if vpn_name in selected_vpns:
                    item_data['selected_var'].set(True)
        edit_dialog.dialog.after(200, fill_vpn_selection)
        
        # 填充定时任务配置
        schedule = config.get('schedule', {})
        if schedule:
            edit_dialog.schedule_enabled_var.set(schedule.get('enabled', False))
            weekdays = schedule.get('weekdays', [])
            for day, var in edit_dialog.weekday_vars.items():
                var.set(day in weekdays)
            edit_dialog.schedule_times = schedule.get('times', []).copy()
            edit_dialog.update_time_listbox()
        
        # 修改"开始测试"按钮为"保存"按钮，用于编辑模式
        if hasattr(edit_dialog, 'start_test_btn'):
            edit_dialog.start_test_btn.config(text='保存', command=lambda: self.save_edited_task(edit_dialog, task_id))
        else:
            # 如果按钮引用不存在，尝试查找按钮
            for widget in edit_dialog.dialog.winfo_children():
                if isinstance(widget, ttk.Frame):
                    for child in widget.winfo_children():
                        if isinstance(child, ttk.Button) and child.cget('text') == '开始测试':
                            child.config(text='保存', command=lambda: self.save_edited_task(edit_dialog, task_id))
                            break
        
        # 等待对话框关闭
        self.dialog.wait_window(edit_dialog.dialog)
    
    def save_edited_task(self, edit_dialog, task_id):
        """保存编辑后的任务配置"""
        # 验证配置
        if not edit_dialog.validate_config():
            return
        
        # 构建结果（使用save_config_and_schedule方法）
        if not edit_dialog.save_config_and_schedule():
            return
        
        if not edit_dialog.result:
            messagebox.showerror("错误", "保存配置失败")
            return
        
        # 删除旧任务
        self.scheduler.remove_task(task_id)
        
        # 如果定时任务已启用，添加新任务
        if edit_dialog.result.get('schedule', {}).get('enabled', False):
            if self.execute_callback:
                self.scheduler.add_task(
                    task_id=task_id,  # 使用相同的task_id以保持连续性
                    config=edit_dialog.result,
                    callback=lambda c=edit_dialog.result: self.execute_callback(c)
                )
                messagebox.showinfo("成功", "定时任务已更新")
                self.refresh_task_list()
                # 关闭编辑对话框
                edit_dialog.dialog.destroy()
            else:
                messagebox.showerror("错误", "无法执行任务回调")
        else:
            # 定时任务已禁用，只保存配置
            messagebox.showinfo("提示", "定时任务已禁用，配置已保存")
            self.refresh_task_list()
            # 关闭编辑对话框
            edit_dialog.dialog.destroy()
    
    def _execute_scheduled_test(self, config):
        """执行定时任务（使用回调函数）"""
        if self.execute_callback:
            self.execute_callback(config)
    
    def update_history(self):
        """更新执行历史（从内存和本地文件）"""
        self.history_text.config(state=tk.NORMAL)
        self.history_text.delete("1.0", tk.END)
        
        all_history = []
        
        # 1. 从内存中的任务获取执行历史
        tasks = self.scheduler.get_tasks()
        for task in tasks:
            task_name = task.get('test_name', task.get('task_id', '未知'))
            execution_history = task.get('execution_history', [])
            
            for record in execution_history:
                timestamp = record.get('timestamp', '')
                status = record.get('status', 'unknown')
                status_icon = "✓" if status == 'success' else "✗"
                all_history.append({
                    'time': record.get('time', 0),
                    'text': f"[{timestamp}] {status_icon} {task_name}"
                })
        
        # 2. 从本地文件（results文件夹）恢复执行历史
        try:
            from utils.file_utils import get_app_base_dir
            import json
            from datetime import datetime
            from pathlib import Path
            
            results_dir = get_app_base_dir() / "results"
            if results_dir.exists():
                # 获取所有任务名称（从定时任务配置中）
                task_names = set()
                for task in tasks:
                    task_name = task.get('test_name', '')
                    if task_name:
                        task_names.add(task_name)
                
                # 扫描results文件夹，查找属于定时任务的测试结果
                for json_file in results_dir.rglob("*.json"):
                    # 排除临时文件
                    if json_file.name.endswith('_comparison_temp.json'):
                        continue
                    
                    try:
                        # 读取JSON文件获取测试信息
                        with open(json_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        
                        test_name = data.get('test_name', '')
                        timestamp_str = data.get('timestamp', '')
                        
                        # 检查是否属于某个定时任务
                        # 通过检查test_name是否匹配任务名称，或者检查文件路径是否在任务目录下
                        is_scheduled_task = False
                        matched_task_name = test_name
                        
                        # 方法1: 检查test_name是否匹配任务名称
                        for task_name in task_names:
                            if test_name.startswith(task_name) or task_name in test_name:
                                is_scheduled_task = True
                                matched_task_name = task_name
                                break
                        
                        # 方法2: 检查文件路径是否在任务目录下（定时任务的文件在results/任务名称/下）
                        if not is_scheduled_task:
                            file_path = Path(json_file)
                            # 检查是否在results/任务名称/目录下
                            parts = file_path.parts
                            if len(parts) >= 3:  # results/任务名称/...
                                potential_task_name = parts[-2]  # 倒数第二层目录名
                                if potential_task_name in task_names:
                                    is_scheduled_task = True
                                    matched_task_name = potential_task_name
                        
                        if is_scheduled_task and timestamp_str:
                            # 解析时间戳
                            try:
                                # 尝试解析时间戳字符串
                                if ' ' in timestamp_str:
                                    dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                                else:
                                    dt = datetime.fromisoformat(timestamp_str.replace('T', ' ').split('.')[0])
                                
                                timestamp_float = dt.timestamp()
                                
                                # 检查是否已经存在于历史记录中（避免重复）
                                exists = False
                                for existing in all_history:
                                    if existing['time'] == timestamp_float and matched_task_name in existing['text']:
                                        exists = True
                                        break
                                
                                if not exists:
                                    all_history.append({
                                        'time': timestamp_float,
                                        'text': f"[{timestamp_str}] ✓ {matched_task_name}"
                                    })
                            except (ValueError, AttributeError):
                                # 时间戳解析失败，跳过
                                pass
                    except (json.JSONDecodeError, KeyError, Exception):
                        # 文件读取失败，跳过
                        continue
        except Exception as e:
            if self.logger:
                self.logger.error(f"从本地文件恢复执行历史失败: {e}", exc_info=True)
        
        # 按时间排序（最新的在前）
        all_history.sort(key=lambda x: x['time'], reverse=True)
        
        # 只显示最近100条
        history_lines = []
        for item in all_history[:100]:
            history_lines.append(item['text'])
        
        if history_lines:
            self.history_text.insert("1.0", "\n".join(history_lines))
        else:
            self.history_text.insert("1.0", "暂无执行历史")
        
        self.history_text.config(state=tk.DISABLED)
        self.history_text.see(tk.END)
    
    def on_close(self):
        """关闭对话框"""
        self.dialog.destroy()


def show_schedule_manager(parent, scheduler, logger: Optional[logging.Logger] = None, execute_callback=None):
    """显示定时任务管理对话框"""
    dialog = ScheduleManagerDialog(parent, scheduler, logger, execute_callback)
    parent.wait_window(dialog.dialog)

