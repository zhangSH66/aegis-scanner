# AEGIS 神盾扫描器

> 一个**只有扫描功能**的杀毒软件。纯 Python 标准库实现，**零第三方依赖**，带图形界面。
> 用大约 3000 行代码写清楚一个杀毒引擎到底是怎么工作的。

⚠️ **这是教学 / 玩具项目，不是可以替代真实杀毒软件的产品。** 它只扫描、只报告，
**不会**清除、隔离或修改任何文件。

---

## 特性

| | |
|---|---|
| **零依赖** | 只用 Python 标准库。不需要 pip install，不需要编译，不需要管理员权限 |
| **图形界面** | tkinter 手绘暗色主题，带进度条、结果列表、详情面板、运行日志、报告导出 |
| **命令行版** | 同一套引擎，支持 JSON / TXT 报告导出，方便接 CI |
| **手写 PE 解析器** | 不依赖 pefile，自己解析节区表、导入表、数字签名目录 |
| **四层检测** | 哈希信誉 → 特征规则 → 静态启发 → 文件名规则，加权汇总打分 |
| **规则可扩展** | 加一条规则只要往列表里追加一个字典，不用碰引擎代码 |
| **可选 YARA** | 装了 `yara-python` 就自动加载 `rules/` 目录下的 `.yar` 规则 |

---

## 界面

<!-- 建议在这里放一张截图：把图片存到 docs/screenshot.png，然后取消下面这行的注释 -->

<!-- ![界面截图](docs/screenshot.png) -->

```
┌──────────────────────────────────────────────────────────────┐
│  🛡  AEGIS 神盾扫描器                       引擎 1.0.0        │
│      纯 Python 杀毒扫描引擎 · 只扫描，不做清除   34条特征规则   │
├──────────────────────────────────────────────────────────────┤
│  扫描目标 [___________________________] [选择目录] [选择文件]  │
│  ☑启发式分析 ☑扫描压缩包 ☑Office宏 ☑报告灰色软件              │
│  线程[8]  跳过大于[64 MB]      [▶ 开始扫描] [■ 停止] [导出报告]│
├──────────────────────────────────────────────────────────────┤
│  ████████████████░░░░░░░░  62.4%   恶意 3  可疑 1  已扫 812/1300│
├───────────────────────────────┬──────────────────────────────┤
│  级别 │ 威胁名称      │ 路径  │  检出详情                     │
│  ─────┼──────────────┼───────│  ─────────────────────────    │
│  恶意 │ 加壳程序:UPX  │ ...   │  恶意　加壳程序：UPX           │
│  可疑 │ 双扩展名伪装  │ ...   │  文件　C:\...\发票.pdf.exe     │
│                               │  检出项（2）                  │
│                               │  [恶意 +28] 加壳程序：UPX      │
│                               │      依据　特征节区名 UPX0…    │
├───────────────────────────────┴──────────────────────────────┤
│  运行日志                                                     │
│  [12:03:41] 开始扫描：C:\Users\me\Downloads                   │
│  [12:03:42] [恶意] 加壳程序：UPX → C:\...\setup.exe           │
└──────────────────────────────────────────────────────────────┘
```

---

## 快速开始

需要 **Python 3.8 或更高版本**，没有其它任何依赖。

```bash
git clone https://github.com/<你的用户名>/aegis-scanner.git
cd aegis-scanner
```

**Windows** — 双击 `Aegis.pyw`（推荐，不弹控制台），或双击 `Aegis.py`。

**命令行**：

```bash
python Aegis.py                        # 启动图形界面
python aegis_cli.py <目标路径>          # 命令行扫描
python aegis_cli.py . --json out.json  # 顺便导出 JSON 报告
```

命令行参数：

```
--threads N        扫描线程数（默认 8）
--max-size N       跳过大于 N MB 的文件（默认 64）
--no-heuristics    只跑特征规则，跳过 PE 启发式分析
--no-archives      不递归扫描压缩包
--no-office        不分析 Office 宏
--no-pua           不报告灰色软件
--json FILE        导出 JSON 报告
--text FILE        导出文本报告
-q, --quiet        只输出检出结果
```

---

## 工作原理

一个文件进来，会依次过四层。每层可以独立贡献一个「威胁分值」，最后汇总判定。

### 第一层 · 哈希信誉

算文件 SHA-256 / MD5，查已知恶意样本库。

- 内置表在 `aegis_rules.py` 的 `KNOWN_BAD_HASHES`
- 外部表在 `signatures/blacklist.txt`（每行 `哈希  名称`，支持 `#` 注释）

这是置信度最高、成本最低的一层 —— 一个哈希查询就能定性，不用跑任何特征匹配。
真实杀毒软件也是这么做的，而且会把结果缓存在云端。

### 第二层 · 特征匹配（类 YARA）

34 条内置规则，覆盖：

| 类别 | 例子 |
|---|---|
| 脚本下载执行 | `DownloadString` + `Net.WebClient`、`IEX`、`-enc` |
| LOLBin 滥用 | `certutil -urlcache`、`mshta`、`regsvr32 scrobj.dll` |
| 反弹 Shell | `/dev/tcp/`、`nc -e /bin/sh`、`curl … \| bash` |
| 凭据窃取 | `sekurlsa::`、`reg save hklm\sam`、浏览器 `Login Data` |
| 勒索软件 | `vssadmin delete shadows`、勒索信话术 |
| 挖矿 | `stratum+tcp://`、`xmrig` |
| 键盘记录 | `GetAsyncKeyState` + `WH_KEYBOARD_LL` |
| Office 宏 | `AutoOpen`、`CreateObject("WScript.Shell")`、Excel 4.0 `=EXEC(` |
| WebShell | `eval($_POST`、`execute(request` |
| 持久化 / 免杀 | `CurrentVersion\Run`、`Set-MpPreference -DisableRealtimeMonitoring` |
| 网络特征 | IP 直连 URL、`.onion` 地址 |

**为什么要多模式组合（`condition: 2`）？**
单个字符串 `certutil` 满地都是，但 `certutil` + `-urlcache` 同时出现就基本只有一种用途。
多模式组合是压低误报的主要手段 —— 这也解释了为什么商业引擎的规则动辄几千条。

### 第三层 · 静态启发

**PE 结构分析**（手写解析器，不依赖 pefile）：

- 节区表、入口点、编译时间戳、数字签名目录
- **导入表解析** —— RVA 转文件偏移、遍历 `IMAGE_IMPORT_DESCRIPTOR`、还原函数名，
  再对照 90 多个高危 API 加权打分。
  例：`VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` = 进程注入三件套
- **节区熵值** —— 香农熵 > 7.2 说明内容被加密或压缩过
- **加壳识别** —— UPX / ASPack / Themida / VMProtect 等特征节区名
- W+X 节区、入口点落在节区外、Overlay 附加数据、导入表为空

**Office 文档分析**（OOXML 本质上就是个 zip）：

- `vbaProject.bin` 宏工程存在性，并把宏代码解出来**再过一遍完整分析链**
- 远程模板注入（`.rels` 里的 `TargetMode="External"`）
- 内嵌 OLE 对象、内嵌 PE 可执行体
- DDE / DDEAUTO 字段
- Excel 4.0（XLM）宏

**压缩包递归**：zip 成员逐个解出来重新走完整分析链，支持嵌套（默认深度 2），
带成员数和单成员解压尺寸上限，防止扫描时间被压缩炸弹拖死。

**文件名规则**：双扩展名（`发票.pdf.exe`）、RLO 字符伪装（U+202E）、
注册机/破解补丁、密码转储工具名。

### 第四层 · 判定打分

每条命中累加自己的 `score`，最后按下表折算：

| 条件 | 判定 |
|---|---|
| 有 `malicious` 级别命中，或总分 ≥ 70 | **恶意** |
| 有非 info 命中且总分 ≥ 20 | **可疑** |
| 其它 | 安全 |

带有效 Authenticode 签名的 PE 会得到 −15 分（减分参考 —— 签名也可能被盗用）。

---

## 自定义规则

规则全部写在 `aegis_rules.py`，加一条只要追加一个字典：

```python
{
    "id": "Script.PS.DownloadCradle",
    "name": "PowerShell 下载执行（Download Cradle）",
    "family": "Trojan.Downloader",
    "severity": "malicious",          # malicious / suspicious / pua / info
    "score": 55,
    "targets": ("any",),              # 适用类别；("any",) 表示所有文件
    "condition": 2,                   # 至少命中 2 个模式；"all" 表示全部命中
    "patterns": (
        ("ascii", b"DownloadString", "调用 DownloadString 下载远程内容"),
        ("ascii", b"Net.WebClient", "使用 Net.WebClient 发起网络请求"),
        ("regex", rb"-(?:enc|encodedcommand)\s+[A-Za-z0-9+/]{60,}", "超长 Base64 命令"),
    ),
    "desc": "会显示在界面详情面板里的说明文字",
}
```

`patterns` 支持三种类型：

- `ascii` —— 字节串，底层走 C 实现的 `bytes.find`，最快
- `hex` —— 十六进制串，写成 `"4D5A9000"` 这种
- `regex` —— 字节正则表达式

`targets` 可选值：`any` / `pe` / `office` / `script` / `text` / `binary` / `archive` / `pdf`。
`("any",)` 之外的取值会和文件实际类型求交集，用来跳过无关规则。

---

## 可选功能

### 接 YARA

```bash
python -m pip install yara-python
```

把 `.yar` / `.yara` 文件丢进 `rules/` 目录，引擎启动时会自动编译加载。
规则里可以用这些 meta 字段参与评分：

```yara
rule My_Rule
{
    meta:
        name        = "显示名称"
        family      = "家族"
        severity    = "malicious"
        score       = 60
        description = "说明文字"
    strings:
        $a = "some-bytes"
    condition:
        $a
}
```

没装 `yara-python` 时这部分**完全静默跳过**，不影响任何其它功能。
`rules/example.yar` 里有一个可直接跑的示例。

### 扩充哈希黑名单

编辑 `signatures/blacklist.txt`，每行 `哈希  名称`：

```
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f  EICAR-Test-File
44d88612fea8a8f36de82e1278abb02f  EICAR-Test-File（MD5）
```

哈希从哪来？用扫描器扫一遍，检出详情里的 SHA-256 直接复制过来。

---

## 关于 EICAR 检测

`aegis_rules.py` 里包含对 **EICAR 标准测试文件**的检测规则。
EICAR 是反病毒行业公认的**无害**测试串，所有杀毒软件都检测它，用来验证引擎是否在工作。

源码里这个字符串被**故意拆成两段拼接**：

```python
_EICAR_1 = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
_EICAR_2 = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
```

这样写不是为了隐藏什么，而是因为：如果你机器上装着真实杀毒软件，
**完整的字符串会让它把这份源码文件本身当成病毒删掉**。

如果你的 CI 或代码扫描工具对这个字符串有意见，直接删掉 `AV.Test.EICAR` 那条规则即可，
不影响任何其它功能。

---

## 想接真实引擎？

这个项目的引擎接口是模块化的，换成工业级引擎并不难：

- **ClamAV** —— 唯一成熟的开源全功能引擎。官方提供 Windows 安装包和便携 ZIP，
  跑 `clamd` 常驻进程，你的程序通过 TCP 的 `INSTREAM` 协议把文件流推过去。
  注意它是 **GPLv2**：要闭源发布就走进程隔离，别静态链接 `libclamav`。
- **YARA** —— 本项目已内置可选支持。
- **VirusTotal API** —— 免费公共 API 限 **4 请求/分钟**，而且**服务条款明确禁止用于商业产品，
  也不能当作杀毒产品的替代品**。个人自用可以，最省额度的用法是只查 SHA-256。

---

## 已知限制

这个项目是用来学原理的，下面这些限制是**设计上就存在**的，不是 bug：

- **不是实时防护** —— 没有文件系统过滤驱动，不会在你打开文件时自动拦截
- **不做清除** —— 只报告，不动你的文件
- **特征库很小** —— 34 条规则对比商业引擎的千万级签名，检出率不在一个量级
- **纯静态分析** —— 不执行样本，所以对加壳、混淆、无文件攻击的检出能力有限
- **压缩包支持不全** —— 只有 zip（Python 标准库的能力），rar / 7z 只能识别类型不能解包
- **熵值采样** —— 超大文件只取前 8 MB 计算熵值
- **误报** —— 静态启发式必然有误报，加壳的正常软件（很多安装包）会被标成「可疑」

## 免責 / Disclaimer

本项目**仅供学习研究**使用，作者不对其检出结果作任何保证。

它**不能**替代真实杀毒软件。请不要用它当作你唯一的防护手段。
使用者需自行承担使用风险，因使用本工具造成的任何后果由使用者自负。

## 许可

[MIT](LICENSE)
