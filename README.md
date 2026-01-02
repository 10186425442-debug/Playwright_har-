# 网页性能测试工具

一个功能强大的网页性能测试工具，支持VPN和直连通道的性能对比分析。

## 主要特性

### 🚀 VPN性能测试流程
- **VPN配置**：VPN为可选配置，支持多VPN顺序测试
- **多维度指标**：响应时间、首次内容绘制、DOM就绪时间、完整加载时间
- **独立结果管理**：每个VPN生成独立的测试会话和结果文件
- **普通测试模式**：支持不选择VPN的普通测试模式

### 🔧 高级功能
- **HAR文件采集**：完整的HTTP请求记录
- **主机名采集**：记录访问的所有域名
- **黑名单过滤**：智能过滤不需要的请求，支持参考文件对比
  - URL拦截检测：测试开始前检查URL是否在黑名单中
  - 拦截状态标记：被拦截的URL在结果中状态码显示为"拦截"
- **并发测试**：支持多线程并发测试（VPN顺序连接，URL并发测试）
- **定时任务**：支持按周一到周日设置执行日期，可设置多个具体时间点
- **状态码显示优化**：异常状态直观显示（超时、错误、拦截等）

### 🌐 VPN支持
- **多VPN顺序测试**：支持选择多个VPN进行顺序测试，每个VPN独立执行
- **自动检测**：自动检测系统中可用的VPN连接
- **凭据管理**：安全存储VPN用户名和密码
- **全局网关模式**（v2.2.12）：直连测试使用全局网关模式，所有流量（包括DNS）走直连通道
- **DNS缓存清除**（v2.2.12）：每次测试前自动清除DNS缓存，确保使用最新DNS解析结果
- **智能路由**：自动管理网关切换，测试完成后自动恢复
- **网络环境标识**：清楚区分VPN网络和直连网络环境

## 系统要求

- **操作系统**：Windows 10/11
- **Python**：3.8+ （如果从源码运行）
- **浏览器**：自动安装Playwright浏览器
- **网络**：支持VPN连接的网络环境

## 快速开始

### 方式一：使用预编译版本（推荐）
1. 下载最新的exe文件
2. 双击运行即可

### 方式二：从源码运行
1. 克隆仓库：
   ```bash
   git clone <repository-url>
   cd Playwright_test_clean
   ```

2. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```

3. 运行程序：
   ```bash
   python main.py
   ```

## 使用指南

### 1. 基本测试流程

1. **点击"开始测试"**
2. **配置基本信息**：
   - 输入测试名称（自动生成VPN测试名称）
   - 设置并发数和3阶段超时时间：
     - **阶段1-HTTP**：HTTP连接测试（默认8秒）
     - **阶段2-DOM**：DOM事件监听（默认30秒，非阻塞，获取到就记录）
     - **阶段3-Load**：Load事件测试（默认60秒，总超时时间）
   - 选择是否启用HAR采集、主机名采集、黑名单过滤

3. **配置测试URL**：
   - 手动输入URL（每行一个）
   - 或从文件导入URL列表

4. **VPN配置（必选）**：
   - 选择至少一个VPN进行测试（支持多选）
   - 配置VPN用户名和密码
   - 多个VPN将按顺序执行，每个生成独立结果

5. **高级配置（可选）**：
   - 选择浏览器类型
   - 设置用户代理
   - 使用系统默认DNS（VPN通道自动使用VPN DNS）
   - 选择参考文件（用于黑名单对比）

6. **定时任务（可选）**：
   - 启用定时任务
   - 选择执行日期（周一到周日）
   - 添加执行时间（可添加多个，精确到分钟）
   - 任务会自动保存并在指定时间执行

7. **开始测试**：点击"开始测试"按钮

### 2. 查看测试结果

测试完成后，系统会自动：
- 保存测试结果到`results`文件夹（以HAR文件形式保存）
- 在日志中输出测试完成信息

**查看历史测试结果**：
- 主界面左侧的"测试会话"区域提供两个选择框：
  - **选择文件夹**：选择包含测试结果的文件夹（results目录下的文件夹）
  - **选择文件**：在选中的文件夹中选择要查看的JSON文件
- 点击"重新加载会话"按钮可以手动选择文件夹和文件加载测试结果
- 点击"加载外部会话"按钮可以加载其他位置的测试结果文件（支持两步选择：先选文件夹，再选文件）

### 3. 结果文件说明

**当前版本（v2.2.17+）**：
- 测试完成后，仅在 `results/<会话>/har/` 目录下保留 HAR 文件
- 不再生成新的 JSON 结果文件和 hostname 文本文件
- 如需分析性能或域名，可使用外部工具或脚本直接读取 HAR 文件

**文件结构**：
- 单个VPN测试：`results/VPN名称/测试会话/har/`
- 多个VPN测试：每个VPN生成独立的文件夹
- 定时任务：`results/任务名称/VPN名称/测试会话/har/`（HAR文件按执行时间组织到子文件夹中）

### 4. 定时任务管理

1. **创建定时任务**：
   - 在测试配置中启用"定时任务"
   - 选择执行日期和时间
   - 点击"开始测试"保存任务

2. **管理定时任务**：
   - 点击主窗口的"定时任务"按钮
   - 查看所有已创建的任务
   - 支持编辑、启用/禁用、删除任务
   - 查看执行历史

3. **执行历史**：
   - 自动记录每次任务执行的时间戳和状态
   - 程序重启后自动从本地文件恢复历史记录
   - 支持查看最近100条执行记录

## 项目结构

```
Playwright_test_clean2/
├── main.py                 # 主程序入口
├── build_exe.py           # 打包脚本
├── requirements.txt       # 依赖列表
├── config/                # 配置文件目录
│   ├── config.json        # 主配置文件
│   ├── vpn_config.json    # VPN配置文件
│   ├── scheduled_tasks.json  # 定时任务配置文件
│   └── blacklist.json     # 黑名单配置文件
├── core/                 # 核心功能模块
│   ├── tester.py         # 测试引擎
│   ├── result.py         # 结果数据结构
│   ├── har_manager.py    # HAR文件管理
│   └── blacklist_manager.py  # 黑名单管理
├── ui/                   # 用户界面
│   ├── main_window.py    # 主窗口
│   ├── unified_test_dialog.py  # 统一测试配置对话框
│   ├── config_dialog.py  # 配置对话框
│   └── schedule_manager.py  # 定时任务管理
├── vpn/                  # VPN功能模块
│   ├── vpn_manager.py    # VPN管理器
│   ├── vpn_detector.py   # VPN检测器
│   └── vpn_config_dialog.py  # VPN配置对话框
├── utils/                # 工具模块
│   ├── config_manager.py # 配置管理
│   ├── file_utils.py     # 文件工具
│   ├── har_parser.py     # HAR解析器
│   ├── logger.py         # 日志工具
│   ├── scheduler.py      # 定时任务调度器
│   └── playwright_*.py   # Playwright相关工具
├── analysis/             # 数据分析模块
│   └── vpn_performance_analyzer.py  # VPN性能分析器
└── results/              # 测试结果目录
```

## 配置说明

所有配置文件都位于 `config/` 目录下。

### 主配置文件 (config/config.json)
```json
{
  "max_concurrent_tests": 3,     // 最大并发数
  "timeout": 30,                 // 超时时间（秒）
  "enable_har_capture": true,    // 启用HAR采集
  "enable_hostname_capture": true, // 启用主机名采集
  "enable_blacklist": true,      // 启用黑名单
  "browser_type": "chromium",    // 浏览器类型
  "headless": false,             // 无头模式
  "dns_server": "8.8.8.8",      // DNS服务器
  "user_agent": "Mozilla/5.0...", // 用户代理
  "clear_dns_cache": true,       // 清除DNS缓存
  "auto_disconnect_vpn": true    // 自动断开VPN
}
```

### VPN配置文件 (config/vpn_config.json)
```json
{
  "vpn_credentials": {
    "VPN名称": {
      "username": "用户名",
      "password": "密码"
    }
  },
  "test_settings": {
    "wait_after_vpn_connect": 3,
    "auto_disconnect_vpn": true
  }
}
```

### 定时任务配置文件 (config/scheduled_tasks.json)
定时任务配置会自动保存到此文件，包含任务配置、执行历史等信息：
```json
{
  "任务ID": {
    "config": {
      "test_name": "测试名称",
      "urls": ["URL列表"],
      "selected_vpns": ["VPN列表"],
      "reference_file": "参考文件路径（可选）",
      "config": { /* 测试配置 */ },
      "schedule": {
        "enabled": true,
        "weekdays": [0, 1, 2],
        "times": ["09:00", "14:00", "20:00"]
      }
    },
    "enabled": true,
    "last_run_time": 1234567890,
    "execution_history": [
      {
        "time": 1234567890,
        "status": "success",
        "timestamp": "2025-11-26 09:00:00"
      }
    ],
    "last_execution_by_time": {
      "2025-11-26_09:00": 1234567890
    }
  }
}
```

## 文件命名规则

### HAR文件命名规则

**基本格式**：
```
[域名].[服务名]_[代理类型]_[区域标识]_[时间戳]_[轮次]_[索引][重试标识].har
```

**字段说明**：
- **域名**：从URL中提取的域名（保留点号），如 `apple.com`、`music.apple.com`
- **服务名**：URL路径的第一段（可选），如 `health`、`store`
- **代理类型**：`vpn` 或 `direct`
- **区域标识**：VPN区域代码（仅VPN测试时），如 `1BJ`、`2SY`（格式：数字前缀+拼音首字母）
- **时间戳**：ISO 8601基本格式 `YYYYMMDDTHHMMSS`（定时任务时可选）
- **轮次**：测试轮次，如 `r0`、`r1`
- **索引**：URL索引，如 `i0`、`i35`
- **重试标识**：重试次数（仅重试时），如 `a1`、`a2`

**命名示例**：
- `apple.com.health_vpn_1BJ_20251202T203940_r0_i0.har`
- `music.apple.com.us_vpn_2SY_20251203T141930_r0_i0.har`
- `aboutamazon.com_direct_20251202T203940_r0_i35.har`

### Hostname文件命名规则

Hostname文件与HAR文件使用相同的命名规则，扩展名为 `_hostnames.txt`：
- `apple.com.health_vpn_1BJ_20251202T203940_r0_i0_hostnames.txt`
- `aboutamazon.com_direct_20251202T203940_r0_i35_hostnames.txt`

### JSON文件命名规则

**基本格式**：`[区域标识]_[时间戳].json`

**转换规则**：
- 原始格式：`A北京_20251202_203940`
- 转换后：`1BJ_20251202T203940.json`
- 前缀转换：`A` → `1`，`B` → `2`
- 地区名转换：地区名 → 拼音首字母（如：北京→BJ，沈阳→SY，重庆→CQ）
- 时间戳转换：`YYYYMMDD_HHMMSS` → `YYYYMMDDTHHMMSS`

### 区域标识转换规则

**前缀转换**：
- `A` → `1`
- `B` → `2`

**地区名到拼音首字母映射**（部分）：
- 北京 → BJ
- 上海 → SH
- 广州 → GZ
- 深圳 → SZ
- 重庆 → CQ
- 成都 → CD
- 武汉 → WH
- 西安 → XA
- 南京 → NJ
- 沈阳 → SY
- ...（完整映射表包含40+个城市，详见代码实现）

## 测试逻辑说明

### VPN测试模式（选择了VPN）

**分批处理流程**（每批10个URL）：
1. **VPN模式测试**：
   - 对这10个URL执行VPN模式测试（并发）
   - 每个URL测试前清除DNS缓存（确保使用最新DNS解析）
   - 使用VPN网关进行测试
   - 所有流量走VPN通道

2. **断开VPN并清除缓存**：
   - 断开VPN连接
   - 清除DNS缓存
   - 等待5秒，让系统自动恢复网络配置

3. **直连模式测试**：
   - 对这10个URL执行直连模式测试（并发）
   - 每个URL测试前清除DNS缓存（确保使用最新DNS解析）
   - 使用全局网关模式（修改默认网关指向原始网关）
   - 所有流量（包括DNS、CDN资源等）走直连通道
   - 测试完成后恢复VPN网关

4. **重新连接VPN**（最后一批除外）：
   - 测试完成后重新连接VPN，恢复网络环境
   - 等待VPN连接稳定

**结果**：包含VPN和直连对比数据

### 普通测试模式（未选择VPN）

- 不连接VPN
- 不添加路由
- 每个URL测试一次（使用当前网络）
- 结果只包含单次测试数据

### 三阶段测试机制

**阶段1-HTTP连接测试**（默认8秒）：
- 等待HTTP响应，获取状态码和最终URL
- 使用 `wait_until="commit"`，只等待HTTP响应，不等待页面内容加载
- 如果超时，直接返回连接超时错误

**阶段2-DOM事件监听**（默认30秒，非阻塞）：
- DOMContentLoaded作为事件监听，30秒内获取到就记录，获取不到也不阻塞
- 使用 `wait_for_load_state("domcontentloaded", timeout=stage2_timeout)`
- 如果30秒内获取到，记录DOM就绪时间
- 如果30秒内未获取到，记录日志但继续执行，不阻塞测试
- **关键改进**：无论DOM是否触发，都继续执行阶段3

**阶段3-Load事件测试**（默认60秒，总超时时间）：
- 等待Load事件，60秒内获取到就成功，否则超时
- 使用 `wait_for_load_state("load", timeout=stage3_timeout)`
- 这是主要的等待阶段，总超时时间由stage3超时时间决定
- 如果60秒内Load事件未触发，标记为超时

**测试时间控制**：
- 每个网站最多等待60秒（或配置的stage3超时时间）
- 不再因DOM超时而提前终止测试
- 总超时时间 = stage3超时时间（默认60秒）

## 黑名单拦截功能

### 功能概述

黑名单拦截功能用于在页面加载测试过程中自动拦截匹配黑名单域名的网络请求，有效阻止广告、追踪器等不必要的资源加载，提高测试的准确性和效率。

### 核心组件

**BlacklistManager（黑名单管理器）**：
- 管理域名黑名单列表
- 支持从 JSON/TXT 文件加载黑名单
- 提供域名匹配检查（精确匹配和子域名匹配）
- 线程安全的并发访问

**RequestInterceptor（请求拦截器）**：
- 基于 Playwright Route API 实现网络请求拦截
- 在浏览器发起请求前进行黑名单检查
- 记录所有请求的拦截日志

### 拦截策略

**精确匹配**：
- 黑名单中的 `example.com` 只拦截 `example.com`
- 不影响其他子域名

**子域名匹配（单向）**：
- 黑名单中的 `example.com` 会拦截：
  - `example.com`
  - `sub.example.com`
  - `api.sub.example.com`
  - 等所有子域名
- **不拦截反向情况**：黑名单 `fonts.googleapis.com`，请求 `googleapis.com` → 不拦截

### 拦截流程

1. **主URL检查阶段**：
   - 在浏览器启动前进行预检查
   - 如果URL在黑名单中，直接返回拦截结果，不启动浏览器

2. **资源请求拦截阶段**：
   - 浏览器运行时拦截所有请求
   - 使用 `route.abort("blockedbyclient")` 阻止被拦截的请求
   - 使用 `route.continue_()` 允许正常请求继续

### 黑名单文件格式

**JSON格式**：
```json
{
  "domains": [
    "example.com",
    "ads.google.com",
    "tracker.facebook.com"
  ]
}
```

**TXT格式**：
```
# 黑名单域名文件
example.com
ads.google.com
tracker.facebook.com
```

### HAR文件标记

拦截的请求会在 HAR 文件中标记：
- `response._failureText = "net::ERR_FAILED"`
- `response._wasAborted = true`
- `entry._blockedByBlacklist = true`（自定义标记字段）

详细说明请参考 [docs/黑名单拦截机制说明.md](docs/黑名单拦截机制说明.md)

## 性能指标说明

### Lighthouse性能指标

#### FCP (First Contentful Paint) - 首次内容绘制 ✅
- **字段名**: `fcp_time`
- **单位**: 秒
- **收集方式**: 从 `performance.getEntriesByName('first-contentful-paint')` 获取

#### LCP (Largest Contentful Paint) - 最大内容绘制 ✅
- **字段名**: `lcp_time`
- **单位**: 秒
- **收集方式**: 使用 Performance Observer 监听 `largest-contentful-paint` 事件

#### CLS (Cumulative Layout Shift) - 累积布局偏移 ✅
- **字段名**: `cls_score`
- **单位**: 无单位（分数）
- **收集方式**: 使用 Performance Observer 监听 `layout-shift` 事件

#### TBT (Total Blocking Time) - 总阻塞时间 ✅
- **字段名**: `tbt_time`
- **单位**: 秒
- **收集方式**: 使用 Performance Observer 监听 `longtask` 事件

#### INP (Interaction to Next Paint) - 交互到下次绘制 ✅
- **字段名**: `inp_time`
- **单位**: 秒
- **收集方式**: 监听用户交互事件，使用 `requestAnimationFrame` 测量

#### SI (Speed Index) - 速度指数 ✅
- **字段名**: `si_score`
- **单位**: 秒
- **收集方式**: 当前使用估算方法，基于FCP和LCP的平均值

### 数据存储

所有指标都保存在 `TestResult` 数据类中，时间类指标单位为秒，CLS为无单位分数。

### 收集机制

1. **页面加载前注入脚本**：在浏览器上下文创建时，通过 `context.add_init_script()` 注入性能指标收集脚本
2. **Performance Observer**：使用 Performance Observer API 实时监听性能事件
3. **页面加载后读取**：在页面加载完成后，通过 `page.evaluate()` 读取收集到的指标

## 文件夹层级结构

### 单个VPN测试

```
results/
└── 2SY/                        # VPN文件夹（B沈阳转换为2SY）
    ├── 2SY_20251203_141930/    # 测试会话文件夹（VPN名称和时间戳）
    │   └── 2SY_20251203T141930.json  # 测试结果JSON文件
    ├── har/                    # HAR文件目录
    │   └── ...
    └── hostname/               # 主机名文件目录
        └── ...
```

### 多个VPN测试

```
results/
├── 1BJ/                        # VPN1（A北京转换为1BJ）
│   ├── 1BJ_20251203_141930/
│   │   └── 1BJ_20251203T141930.json
│   ├── har/
│   └── hostname/
├── 2SY/                        # VPN2（B沈阳转换为2SY）
│   ├── 2SY_20251203_141930/
│   │   └── 2SY_20251203T141930.json
│   ├── har/
│   └── hostname/
└── 1CQ/                        # VPN3（A重庆转换为1CQ）
    └── ...
```

### 定时任务（多个VPN）

```
results/
└── Test_20251203T164315/       # 定时任务名称（测试名称，包含时间戳）
    ├── 1BJ/                    # 第一个VPN文件夹（A北京转换为1BJ）
    │   ├── 1BJ_20251203T141930/  # 测试会话文件夹（VPN名称_执行时间戳）
    │   │   └── 1BJ_20251203T141930.json
    │   ├── har/
    │   │   ├── 20251203-09-00/  # 时间子文件夹（按执行时间组织，格式：YYYYMMDD-HH-MM）
    │   │   │   └── ...
    │   │   ├── 20251203-09-30/  # 下一次执行的时间子文件夹
    │   │   │   └── ...
    │   │   └── 20251203-10-00/  # 再下一次执行的时间子文件夹
    │   │       └── ...
    │   └── hostname/
    ├── 2SY/                    # 第二个VPN文件夹（B沈阳转换为2SY）
    │   └── ...
    └── 1CQ/                    # 第三个VPN文件夹（A重庆转换为1CQ）
        └── ...
```

**说明**：
- 定时任务的基础目录名称使用测试名称（如 `Test_20251203T164315`）
- 每次执行定时任务时，会在基础目录下为每个VPN创建独立的文件夹
- 每个VPN文件夹下的测试会话文件夹名称格式为：`VPN英文名称_执行时间戳`（ISO 8601格式）
- **时间子文件夹**：对于定时任务，HAR和hostname文件会按执行时间组织到子文件夹中（格式：`YYYYMMDD-HH-MM`）

### 普通测试（未选择VPN）

```
results/
└── 测试名称/                   # 测试会话文件夹
    ├── 测试名称.json           # 测试结果JSON文件
    ├── har/                    # HAR文件目录
    └── hostname/               # 主机名文件目录
```

## 详细文档

更多详细信息请参考：
- **[更新日志.md](更新日志.md)** - 项目更新历史记录
- **[docs/黑名单拦截机制说明.md](docs/黑名单拦截机制说明.md)** - 黑名单拦截功能详细技术说明

## 打包说明

使用PyInstaller打包为独立可执行文件：

```bash
python build_exe.py
```

生成的exe文件位于`dist`目录中。

### 打包配置说明

**隐藏导入模块**：
- core模块：`core.tester`、`core.result`、`core.har_manager`、`core.blacklist_manager`
- utils模块：所有工具模块
- ui模块：所有UI模块
- vpn模块：VPN相关模块

**排除的模块**（减小体积）：
- matplotlib、scipy、IPython、jupyter
- numba、pyarrow、sqlalchemy
- chardet、PIL、cv2
- sklearn、torch、tensorflow

**优化选项**：
- 启用 `optimize=2`，对Python字节码进行优化
- 预期打包体积：约70-80MB（优化前约140MB）

**注意事项**：
- 脚本会自动清理之前的 build 和 dist 目录
- 程序启动时会自动检测 Playwright 浏览器是否已安装
- 如果未安装，程序会显示详细的安装说明

## 测试脚本

项目提供了两个测试脚本用于验证功能是否正常：

### 快速测试 (`quick_test.py`)
快速检查主要功能是否正常：
```bash
python quick_test.py
```

### 完整测试 (`test_functionality.py`)
使用unittest框架的完整测试套件：
```bash
python test_functionality.py
```

测试覆盖：
- VPN检测功能
- 配置管理功能
- 文件工具功能
- 黑名单管理功能
- 结果数据结构
- 定时任务调度器
- HAR管理功能
- 页面加载测试器
- 自动关闭消息框功能

## 常见问题

### Q: VPN连接失败怎么办？
A: 检查VPN用户名和密码是否正确，确保VPN服务正常运行。如果检测不到VPN，请查看日志文件中的DEBUG信息。

### Q: 测试结果不准确怎么办？
A: 建议在网络稳定的环境下进行测试，避免其他程序占用网络带宽。

### Q: 如何添加新的测试URL？
A: 在测试配置界面手动输入或从文本文件导入URL列表。

### Q: HAR文件有什么用？
A: HAR文件记录了完整的HTTP请求和响应，可用于详细的性能分析。

### Q: 如何查看历史测试结果？
A: 在主界面左侧的"测试会话"区域，先选择文件夹，再选择文件。如果文件很多，可以先选择文件夹快速定位。

### Q: 定时任务编辑后不生效？
A: 确保点击"保存"按钮（编辑模式下"开始测试"按钮会变为"保存"），而不是直接关闭对话框。

### Q: 测试完成的弹窗会自动关闭吗？
A: 根据最新版本（v2.2.17），测试完成后不再显示弹窗，仅通过日志输出完成信息。测试结果以HAR文件形式保存在 `results/.../har/` 中。

### Q: 如何查看测试结果？
A: 测试完成后，结果以HAR文件形式保存在 `results/<会话>/har/` 目录下。如需分析性能或域名，可使用外部工具或脚本直接读取HAR文件。

## 状态码说明

### 正常状态码
- **200**：成功访问
- **其他HTTP状态码**：如301、404、500等，显示实际状态码

### 异常状态码
- **拦截**：URL在黑名单中，已被拦截
- **超时**：页面加载超时（Load事件在60秒内未触发）
- **连接超时**：HTTP连接超时
- **重定向错误**：重定向循环或错误
- **DNS错误**：DNS解析失败
- **HTTP错误**：HTTP请求错误
- **错误**：其他错误
- **部分成功**：部分成功（如DOM加载完成但完整加载超时）

### 测试阶段说明

**三阶段测试机制**：
1. **阶段1-HTTP**：等待HTTP响应，获取状态码（默认8秒）
2. **阶段2-DOM**：监听DOMContentLoaded事件，30秒内获取到就记录，获取不到也不阻塞（默认30秒）
3. **阶段3-Load**：等待Load事件，60秒内获取到就成功，否则超时（默认60秒，总超时时间）

**测试时间**：每个网站最多等待60秒（或配置的stage3超时时间）

### 黑名单拦截
- 如果测试的URL在黑名单中，测试开始前会被拦截
- 拦截的URL在JSON结果中`status_code`字段显示为"拦截"
- 拦截的URL不会实际发起网络请求，节省测试时间

## 更新日志

详见 [更新日志.md](更新日志.md)

## 技术支持

如有问题或建议，请联系开发团队。

## 许可证

本项目采用MIT许可证，详见LICENSE文件。