# -*- coding: utf-8 -*-
"""AEGIS 神盾扫描器 · 内置特征规则库

纯 Python 实现，零第三方依赖。规则格式刻意做成类 YARA 的样子，
想加自己的规则直接往 RULES / FILENAME_RULES 里追加一条即可，不用改引擎。

单条规则字段说明
----------------
id         规则唯一标识
name       显示给人看的名字
family     家族/类别
severity   malicious（恶意）/ suspicious（可疑）/ pua（灰色软件）
score      命中后累加的威胁分值
targets    规则适用的文件类别，("any",) 表示所有文件
condition  需要命中的模式数量；给整数表示至少命中 N 个，"all" 表示全部命中
patterns   模式列表：(类型, 内容, 说明)，类型取 ascii / hex / regex
desc       规则说明，会显示在 UI 的详情面板里
"""

# ============================================================================
#  注意：EICAR 测试串在这里被故意拆成了两段
# ============================================================================
# EICAR 是反病毒行业标准的「无害测试文件」。你机器上装着卡巴斯基，
# 如果这段字符串以完整形态出现在源码里，保存 .py 的那一瞬间它就会被
# 卡巴斯基当成病毒当场删掉。拆开拼接后运行行为完全等价，但静态扫描
# 不会再误伤源码文件本身。
_EICAR_1 = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
_EICAR_2 = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# EICAR 文件的公开哈希（多年不变，可以放心写死）
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"

# 内置已知恶意哈希表（十六进制小写）
# 说明：这里只放公开可验证的测试样本哈希。真实的恶意软件哈希库请放到
# signatures/blacklist.txt 里（每行一个 SHA-256，可用 # 注释），引擎会自动加载。
KNOWN_BAD_HASHES = {
    EICAR_SHA256: "EICAR-Test-File（行业标准测试文件）",
    EICAR_MD5: "EICAR-Test-File（行业标准测试文件）",
}


# ============================================================================
#  内容特征规则
# ============================================================================
RULES = [
    # ------------------------------------------------------------------
    # 标准测试文件
    # ------------------------------------------------------------------
    {
        "id": "AV.Test.EICAR",
        "name": "EICAR 反病毒测试文件",
        "family": "EICAR",
        "severity": "malicious",
        "score": 100,
        "targets": ("any",),
        "condition": 2,
        "patterns": (
            ("ascii", _EICAR_1, "EICAR 标识串（前半段）"),
            ("ascii", _EICAR_2, "EICAR 标识串（后半段）"),
        ),
        "desc": "反病毒行业标准的无害测试文件，用来验证扫描引擎是否真的在工作。",
    },

    # ------------------------------------------------------------------
    # PowerShell / 脚本下载执行
    # ------------------------------------------------------------------
    {
        "id": "Script.PS.DownloadCradle",
        "name": "PowerShell 下载执行（Download Cradle）",
        "family": "Trojan.Downloader",
        "severity": "malicious",
        "score": 55,
        "targets": ("any",),
        "condition": 2,
        "patterns": (
            ("ascii", b"DownloadString", "调用 DownloadString 下载远程内容"),
            ("ascii", b"DownloadFile", "调用 DownloadFile 下载远程文件"),
            ("ascii", b"DownloadData", "调用 DownloadData 下载远程内容"),
            ("ascii", b"Net.WebClient", "使用 Net.WebClient 发起网络请求"),
            ("ascii", b"Invoke-WebRequest", "使用 Invoke-WebRequest 下载"),
            ("ascii", b"Start-BitsTransfer", "使用 BITS 后台传输下载"),
        ),
        "desc": "「下载 + 内存执行」是恶意 PowerShell 最典型的形态，常出现在钓鱼宏和快捷方式里。",
    },
    {
        "id": "Script.PS.EncodedCommand",
        "name": "PowerShell Base64 编码命令",
        "family": "Trojan.PowerShell",
        "severity": "malicious",
        "score": 45,
        "targets": ("any",),
        "condition": 1,
        "patterns": (
            ("regex", rb"-(?:enc|encodedcommand|e)\s+[A-Za-z0-9+/]{60,}={0,2}", "超长 Base64 编码命令参数"),
        ),
        "desc": "把整段脚本用 Base64 藏起来执行，是绕过静态检测的常规手法。",
    },
    {
        "id": "Script.PS.HiddenBypass",
        "name": "PowerShell 隐藏窗口 + 绕过执行策略",
        "family": "Trojan.PowerShell",
        "severity": "suspicious",
        "score": 30,
        "targets": ("any",),
        "condition": 2,
        "patterns": (
            ("ascii", b"-windowstyle hidden", "隐藏窗口运行"),
            ("ascii", b"-w hidden", "隐藏窗口运行（缩写）"),
            ("ascii", b"-ExecutionPolicy Bypass", "绕过 PowerShell 执行策略"),
            ("ascii", b"-ExecutionPolicy Unrestricted", "解除执行策略限制"),
            ("ascii", b"-noprofile", "跳过配置文件加载"),
            ("ascii", b"-nop ", "跳过配置文件加载（缩写）"),
        ),
        "desc": "单独看很常见，组合出现时基本可以确定是无人值守的恶意调用。",
    },
    {
        "id": "Script.PS.FromBase64Exec",
        "name": "Base64 解码后执行",
        "family": "Trojan.PowerShell",
        "severity": "malicious",
        "score": 45,
        "targets": ("any",),
        "condition": 2,
        "patterns": (
            ("ascii", b"FromBase64String", "Base64 解码"),
            ("ascii", b"Invoke-Expression", "动态执行字符串"),
            ("ascii", b"IEX", "动态执行字符串（缩写）"),
        ),
        "desc": "先解码再执行，是把 payload 藏进文本里的经典两步走。",
    },
    {
        "id": "Script.LOLBin.Certutil",
        "name": "滥用 certutil 下载/解码文件",
        "family": "Trojan.Downloader",
        "severity": "malicious",
        "score": 40,
        "targets": ("any",),
        "condition": 2,
        "patterns": (
            ("ascii", b"certutil", "调用系统自带 certutil"),
            ("ascii", b"-urlcache", "通过 urlcache 下载远程文件"),
            ("ascii", b"-decode", "解码文件"),
            ("ascii", b"-decodehex", "解码十六进制文件"),
        ),
        "desc": "certutil 是系统自带工具，常被用来「合法地」下载和解码恶意文件（LOLBin 手法）。",
    },
    {
        "id": "Script.LOLBin.MshtaRegsvr32",
        "name": "滥用 mshta / regsvr32 执行远程脚本",
        "family": "Trojan.Downloader",
        "severity": "malicious",
        "score": 50,
        "targets": ("any",),
        "condition": 2,
        "patterns": (
            ("ascii", b"mshta", "调用 mshta"),
            ("ascii", b"javascript:", "内联 javascript 协议"),
            ("ascii", b"vbscript:", "内联 vbscript 协议"),
            ("ascii", b"regsvr32", "调用 regsvr32"),
            ("ascii", b"scrobj.dll", "通过 scrobj.dll 执行远程脚本"),
        ),
        "desc": "mshta + script 协议、regsvr32 + scrobj.dll 都是绕过白名单的经典组合。",
    },
    {
        "id": "Script.VBS.WShellRun",
        "name": "VBScript 调用 WScript.Shell 执行命令",
        "family": "Trojan.Script",
        "severity": "suspicious",
        "score": 30,
        "targets": ("any",),
        "condition": 2,
        "patterns": (
            ("ascii", b"WScript.Shell", "创建 WScript.Shell 对象"),
            ("ascii", b".Run ", "执行外部命令"),
            ("ascii", b".Exec(", "执行外部程序"),
        ),
        "desc": "VBS/JS 脚本拉起外部进程，常用在钓鱼附件和 U 盘蠕虫里。",
    },

    # ------------------------------------------------------------------
    # Linux / 跨平台
    # ------------------------------------------------------------------
    {
        "id": "Script.Shell.ReverseShell",
        "name": "反弹 Shell 特征",
        "family": "Backdoor.Shell",
        "severity": "malicious",
        "score": 60,
        "targets": ("any",),
        "condition": 1,
        "patterns": (
            ("ascii", b"/dev/tcp/", "使用 bash 的 /dev/tcp 建立连接"),
            ("ascii", b"bash -i >&", "交互式 bash 反弹"),
            ("ascii", b"nc -e /bin/sh", "netcat 反弹 shell"),
            ("ascii", b"ncat -e /bin", "ncat 反弹 shell"),
            ("ascii", b"sh -i >&", "交互式 sh 反弹"),
        ),
        "desc": "把 shell 的控制权交给远程主机，是后门程序的核心动作。",
    },
    {
        "id": "Script.CurlPipeShell",
        "name": "curl/wget 管道执行",
        "family": "Trojan.Downloader",
        "severity": "malicious",
        "score": 50,
        "targets": ("any",),
        "condition": 1,
        "patterns": (
            ("regex", rb"(?:curl|wget)[^\r\n|]{0,120}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b", "下载内容直接交给 shell 执行"),
        ),
        "desc": "「下载即执行」，不落盘、不留痕。",
    },
    {
        "id": "Script.Base64.PE",
        "name": "Base64 编码的 PE 可执行体",
        "family": "Trojan.Dropper",
        "severity": "malicious",
        "score": 65,
        "targets": ("any",),
        "condition": 1,
        "patterns": (
            ("ascii", b"TVqQAAMAAAAEAAAA", "Base64 形式的 MZ/PE 文件头"),
            ("ascii", b"TVpQAAIAAAAEAA8A", "Base64 形式的 PE 文件头（变体）"),
        ),
        "desc": "文本里藏着一整个 Windows 可执行文件，几乎可以直接判定为投放器。",
    },

    # ------------------------------------------------------------------
    # 凭据窃取 / 黑客工具
    # ------------------------------------------------------------------
    {
        "id": "HackTool.Mimikatz",
        "name": "Mimikatz 凭据窃取工具",
        "family": "HackTool.Mimikatz",
        "severity": "malicious",
        "score": 80,
        "targets": ("any",),
        "condition": 1,
        "patterns": (
            ("ascii", b"sekurlsa::", "Mimikatz sekurlsa 模块命令"),
            ("ascii", b"lsadump::", "Mimikatz lsadump 模块命令"),
            ("ascii", b"kerberos::golden", "Mimikatz 黄金票据攻击"),
            ("ascii", b"privilege::debug", "Mimikatz 提权命令"),
            ("ascii", b"gentilkiwi", "Mimikatz 作者标识"),
        ),
        "desc": "直接从内存里抓 Windows 登录口令，是内网渗透的标配工具。",
    },
    {
        "id": "Cred.Theft.SAM",
        "name": "转储系统凭据数据库",
        "family": "Trojan.PasswordStealer",
        "severity": "malicious",
        "score": 55,
        "targets": ("any",),
        "condition": 2,
        "patterns": (
            ("ascii", b"reg save hklm\\sam", "导出 SAM 注册表配置单元"),
            ("ascii", b"reg save hklm\\system", "导出 SYSTEM 注册表配置单元"),
            ("ascii", b"NTDS.dit", "活动目录数据库文件"),
            ("ascii", b"procdump", "使用 procdump 转储进程内存"),
            ("ascii", b"lsass", "目标进程 lsass（存放凭据）"),
        ),
        "desc": "导出 SAM/SYSTEM 或转储 lsass 内存后离线破解口令。",
    },
    {
        "id": "Stealer.BrowserData",
        "name": "窃取浏览器保存的密码",
        "family": "Trojan.PasswordStealer",
        "severity": "suspicious",
        "score": 40,
        "targets": ("any",),
        "condition": 2,
        "patterns": (
            ("ascii", b"Login Data", "Chrome/Edge 密码数据库文件名"),
            ("ascii", b"Local State", "浏览器加密密钥文件"),
            ("ascii", b"\\User Data\\", "浏览器用户数据目录"),
            ("ascii", b"sqlite3", "读取 SQLite 数据库"),
            ("ascii", b"cookies", "Cookie 数据库"),
        ),
        "desc": "读取浏览器密码库文件并外传，是最常见的盗号木马行为。",
    },
    {
        "id": "Stealer.CryptoWallet",
        "name": "扫描加密货币钱包文件",
        "family": "Trojan.CoinStealer",
        "severity": "suspicious",
        "score": 35,
        "targets": ("any",),
        "condition": 2,
        "patterns": (
            ("ascii", b"wallet.dat", "Bitcoin Core 钱包文件"),
            ("ascii", b"Electrum", "Electrum 钱包"),
            ("ascii", b"Exodus", "Exodus 钱包"),
            ("ascii", b"MetaMask", "MetaMask 钱包"),
        ),
        "desc": "遍历本机钱包文件并回传，属于典型的加密货币窃取器。",
    },

    # ------------------------------------------------------------------
    # 勒索软件
    # ------------------------------------------------------------------
    {
        "id": "Ransom.ShadowCopyDelete",
        "name": "删除卷影副本（勒索前置动作）",
        "family": "Ransomware",
        "severity": "malicious",
        "score": 70,
        "targets": ("any",),
        "condition": 1,
        "patterns": (
            ("ascii", b"vssadmin delete shadows", "删除卷影副本"),
            ("ascii", b"vssadmin.exe delete shadows", "删除卷影副本"),
            ("ascii", b"wmic shadowcopy delete", "通过 WMI 删除卷影副本"),
            ("ascii", b"bcdedit /set recoveryenabled no", "关闭系统恢复"),
            ("ascii", b"wbadmin delete catalog", "删除备份目录"),
            ("ascii", b"bcdedit /set {default} recoveryenabled no", "关闭系统恢复"),
        ),
        "desc": "加密文件之前先毁掉备份，让受害者无法自行恢复 —— 勒索软件的标志性动作。",
    },
    {
        "id": "Ransom.Note",
        "name": "勒索信文本特征",
        "family": "Ransomware",
        "severity": "malicious",
        "score": 60,
        "targets": ("any",),
        "condition": 2,
        "patterns": (
            ("regex", rb"(?i)your files have been encrypted", "勒索信典型措辞"),
            ("regex", rb"(?i)all your files are encrypted", "勒索信典型措辞"),
            ("regex", rb"(?i)to decrypt your files", "勒索信典型措辞"),
            ("ascii", b"bitcoin", "要求比特币支付"),
            ("ascii", b"monero", "要求门罗币支付"),
            ("ascii", b".onion", "暗网支付页面"),
        ),
        "desc": "勒索说明文件的固定话术组合。",
    },

    # ------------------------------------------------------------------
    # 挖矿 / 灰色软件
    # ------------------------------------------------------------------
    {
        "id": "Miner.CoinMiner",
        "name": "加密货币挖矿程序",
        "family": "Riskware.Miner",
        "severity": "pua",
        "score": 45,
        "targets": ("any",),
        "condition": 1,
        "patterns": (
            ("ascii", b"stratum+tcp://", "矿池连接协议"),
            ("ascii", b"stratum+ssl://", "矿池连接协议（加密）"),
            ("ascii", b"xmrig", "XMRig 挖矿程序标识"),
            ("ascii", b"--donate-level", "XMRig 参数"),
            ("ascii", b"minerd", "cpuminer 标识"),
            ("ascii", b"--coin=", "挖矿命令行参数"),
        ),
        "desc": "挖矿程序本身未必是病毒，但它会吃满 CPU/GPU 并偷偷联网，通常按灰色软件处理。",
    },

    # ------------------------------------------------------------------
    # 间谍 / 后门
    # ------------------------------------------------------------------
    {
        "id": "Keylogger.API",
        "name": "键盘记录行为",
        "family": "Trojan.Spy",
        "severity": "malicious",
        "score": 55,
        "targets": ("pe", "binary", "text"),
        "condition": 2,
        "patterns": (
            ("ascii", b"GetAsyncKeyState", "轮询键盘按键状态"),
            ("ascii", b"GetKeyState", "查询按键状态"),
            ("ascii", b"WH_KEYBOARD_LL", "安装低级键盘钩子"),
            ("ascii", b"SetWindowsHookEx", "安装系统钩子"),
            ("ascii", b"GetForegroundWindow", "获取当前活动窗口标题"),
        ),
        "desc": "全局监听按键并记录窗口标题，是键盘记录器的标准实现方式。",
    },
    {
        "id": "RAT.FamilyStrings",
        "name": "远程控制木马（RAT）家族标识",
        "family": "Backdoor.RAT",
        "severity": "malicious",
        "score": 60,
        "targets": ("any",),
        "condition": 1,
        "patterns": (
            ("regex", rb"(?i)\b(?:AsyncRAT|QuasarRAT|njRAT|Remcos|DarkComet|NanoCore|Orcus|RevengeRAT|AgentTesla|Formbook|LokiBot)\b", "已知 RAT/窃密木马家族名出现在样本中"),
        ),
        "desc": "样本内部残留的家族标识字符串，是相当强的判定依据。",
    },

    # ------------------------------------------------------------------
    # 持久化 / 防御绕过
    # ------------------------------------------------------------------
    {
        "id": "Persist.RunKey",
        "name": "写入开机自启注册表项",
        "family": "Trojan.Persistence",
        "severity": "suspicious",
        "score": 30,
        "targets": ("any",),
        "condition": 2,
        "patterns": (
            ("ascii", b"CurrentVersion\\Run", "开机自启注册表路径"),
            ("ascii", b"reg add", "通过 reg 命令写入注册表"),
            ("ascii", b"RegSetValueEx", "写入注册表（API）"),
            ("ascii", b"SchTasks", "创建计划任务（API）"),
        ),
        "desc": "让程序在每次开机时自动运行，是最基础的持久化手段。",
    },
    {
        "id": "Persist.ScheduledTask",
        "name": "创建计划任务",
        "family": "Trojan.Persistence",
        "severity": "suspicious",
        "score": 25,
        "targets": ("any",),
        "condition": 1,
        "patterns": (
            ("ascii", b"schtasks /create", "命令行创建计划任务"),
            ("ascii", b"New-ScheduledTaskAction", "PowerShell 创建计划任务"),
            ("ascii", b"Register-ScheduledTask", "注册计划任务"),
        ),
        "desc": "计划任务常被用来做持久化和定时拉取 payload，单独出现只能算「值得看一眼」。",
    },
    {
        "id": "DefEvasion.DisableDefender",
        "name": "关闭 Windows Defender 防护",
        "family": "Trojan.DefenseEvasion",
        "severity": "malicious",
        "score": 60,
        "targets": ("any",),
        "condition": 2,
        "patterns": (
            ("ascii", b"Set-MpPreference", "修改 Defender 设置"),
            ("ascii", b"DisableRealtimeMonitoring", "关闭实时监控"),
            ("ascii", b"DisableAntiSpyware", "关闭反间谍软件"),
            ("ascii", b"Add-MpPreference", "添加 Defender 配置"),
            ("ascii", b"ExclusionPath", "添加扫描排除路径"),
        ),
        "desc": "先把杀毒软件关掉或加白名单，再干坏事 —— 恶意软件的固定流程。",
    },
    {
        "id": "DefEvasion.StopSecurityService",
        "name": "终止/停用安全软件服务",
        "family": "Trojan.DefenseEvasion",
        "severity": "malicious",
        "score": 55,
        "targets": ("any",),
        "condition": 2,
        "patterns": (
            ("ascii", b"netsh advfirewall set", "修改防火墙配置"),
            ("ascii", b"state off", "关闭防火墙"),
            ("ascii", b"sc stop", "停止系统服务"),
            ("ascii", b"sc delete", "删除系统服务"),
            ("ascii", b"WinDefend", "Windows Defender 服务"),
            ("ascii", b"MsMpSvc", "Microsoft 反恶意软件服务"),
            ("ascii", b"avp.exe", "卡巴斯基进程"),
            ("ascii", b"ekrn.exe", "ESET 进程"),
        ),
        "desc": "主动关闭防火墙或安全软件服务，属于高置信度的恶意行为。",
    },

    # ------------------------------------------------------------------
    # Office 宏 / 钓鱼文档
    # ------------------------------------------------------------------
    {
        "id": "Office.Macro.AutoExec",
        "name": "Office 宏自动执行入口",
        "family": "Trojan.Macro",
        "severity": "suspicious",
        "score": 35,
        "targets": ("office", "text", "binary", "script"),
        "condition": 1,
        "patterns": (
            ("ascii", b"AutoOpen", "Word 打开文档时自动执行的宏"),
            ("ascii", b"Document_Open", "文档打开事件"),
            ("ascii", b"Workbook_Open", "Excel 打开工作簿事件"),
            ("ascii", b"Auto_Open", "Excel 自动宏"),
            ("ascii", b"AutoClose", "关闭文档时自动执行"),
        ),
        "desc": "宏只要带这类入口名，打开文档就会自动跑，不需要用户点任何按钮。",
    },
    {
        "id": "Office.Macro.ShellExec",
        "name": "Office 宏拉起外部程序",
        "family": "Trojan.Macro",
        "severity": "malicious",
        "score": 55,
        "targets": ("office", "text", "binary", "script"),
        "condition": 2,
        "patterns": (
            ("ascii", b"WScript.Shell", "创建 WScript.Shell 对象"),
            ("ascii", b"Shell(", "调用 Shell 执行命令"),
            ("ascii", b"CreateObject", "创建 COM 对象"),
            ("ascii", b"powershell", "调用 PowerShell"),
            ("ascii", b"cmd.exe", "调用命令行"),
            ("ascii", b"ShellExecute", "调用 ShellExecute"),
        ),
        "desc": "宏的作用就是不声不响地拉起外部程序 —— 这是钓鱼文档的核心 payload 通道。",
    },
    {
        "id": "Office.Excel4Macro",
        "name": "Excel 4.0 宏（XLM）",
        "family": "Trojan.Macro",
        "severity": "malicious",
        "score": 50,
        "targets": ("office", "binary", "text"),
        "condition": 1,
        "patterns": (
            ("ascii", b"=EXEC(", "XLM EXEC 函数"),
            ("ascii", b"=CALL(", "XLM CALL 函数"),
            ("ascii", b"=REGISTER(", "XLM REGISTER 函数"),
            ("ascii", b"=HALT(", "XLM HALT 函数"),
        ),
        "desc": "古老的 Excel 4.0 宏可以绕过大部分现代检测，近几年被大量重新启用。",
    },
    {
        "id": "Office.DDE",
        "name": "DDE 命令执行",
        "family": "Trojan.Macro",
        "severity": "suspicious",
        "score": 40,
        "targets": ("office", "binary", "text"),
        "condition": 1,
        "patterns": (
            ("ascii", b"DDEAUTO", "DDE 自动执行字段"),
            ("ascii", b"w:fldChar", "Word 域代码"),
            ("regex", rb"(?i)DDE\s+\w+\s+\w+", "DDE 命令字段"),
        ),
        "desc": "不依赖宏就能执行命令的文档字段，常被用来钓鱼。",
    },

    # ------------------------------------------------------------------
    # WebShell / 服务器后门
    # ------------------------------------------------------------------
    {
        "id": "Webshell.PHP",
        "name": "PHP WebShell 特征",
        "family": "Backdoor.WebShell",
        "severity": "malicious",
        "score": 70,
        "targets": ("any",),
        "condition": 1,
        "patterns": (
            ("ascii", b"eval($_POST", "执行 POST 参数"),
            ("ascii", b"eval($_REQUEST", "执行 REQUEST 参数"),
            ("ascii", b"assert($_POST", "断言执行 POST 参数"),
            ("ascii", b"system($_GET", "系统命令执行"),
            ("ascii", b"passthru($_", "透传命令执行"),
            ("ascii", b"shell_exec($_", "shell 命令执行"),
            ("ascii", b"eval(gzinflate(base64_decode", "多层编码混淆的 Webshell"),
        ),
        "desc": "直接把 HTTP 请求参数当代码执行，是 WebShell 的定义性特征。",
    },
    {
        "id": "Webshell.ASP",
        "name": "ASP/ASPX WebShell 特征",
        "family": "Backdoor.WebShell",
        "severity": "malicious",
        "score": 65,
        "targets": ("any",),
        "condition": 2,
        "patterns": (
            ("ascii", b"eval request", "执行请求内容"),
            ("ascii", b"execute(request", "执行请求内容"),
            ("ascii", b"Server.CreateObject", "创建服务端对象"),
            ("ascii", b"WScript.Shell", "创建 WScript.Shell 对象"),
        ),
        "desc": "ASP 家族的 WebShell 通常以「执行请求内容」为核心。",
    },

    # ------------------------------------------------------------------
    # U 盘传播 / 网络特征
    # ------------------------------------------------------------------
    {
        "id": "Worm.USBAutorun",
        "name": "U 盘 autorun 自启动",
        "family": "Worm.USB",
        "severity": "suspicious",
        "score": 40,
        "targets": ("any",),
        "condition": 2,
        "patterns": (
            ("ascii", b"[autorun]", "autorun.inf 配置段"),
            ("ascii", b"open=", "自动打开指定程序"),
            ("ascii", b"shellexecute=", "自动执行指定程序"),
            ("ascii", b"action=", "autorun 动作定义"),
        ),
        "desc": "老式 U 盘蠕虫靠 autorun.inf 自动运行，现代 Windows 已默认禁用但仍值得标记。",
    },
    {
        "id": "C2.IPLiteralURL",
        "name": "直接使用 IP 地址的 URL",
        "family": "Trojan.Downloader",
        "severity": "suspicious",
        "score": 20,
        "targets": ("any",),
        "condition": 1,
        "patterns": (
            ("regex", rb"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "URL 中直接写 IP，没有域名"),
        ),
        "desc": "正常软件极少写死 IP 直连，这通常意味着要躲避域名封禁。",
    },
    {
        "id": "C2.TorOnion",
        "name": "暗网 .onion 地址",
        "family": "Trojan.Downloader",
        "severity": "suspicious",
        "score": 35,
        "targets": ("any",),
        "condition": 1,
        "patterns": (
            ("regex", rb"[a-z2-7]{16,56}\.onion", "Tor 隐藏服务地址"),
        ),
        "desc": "连接 Tor 隐藏服务，绝大多数情况下没有正当理由。",
    },
    {
        "id": "Exploit.EternalBlue",
        "name": "永恒之蓝漏洞利用",
        "family": "Exploit.SMB",
        "severity": "malicious",
        "score": 55,
        "targets": ("any",),
        "condition": 1,
        "patterns": (
            ("ascii", b"eternalblue", "永恒之蓝"),
            ("ascii", b"ms17-010", "MS17-010 漏洞编号"),
            ("ascii", b"doublepulsar", "DoublePulsar 后门"),
            ("ascii", b"CVE-2017-0144", "SMB 远程代码执行漏洞"),
        ),
        "desc": "针对 SMB 服务的经典远程代码执行漏洞，是勒索软件蠕虫化的关键。",
    },
]


# ============================================================================
#  文件名规则
# ============================================================================
FILENAME_RULES = [
    {
        "id": "Phish.DoubleExtension",
        "name": "双扩展名伪装",
        "family": "Phishing",
        "severity": "suspicious",
        "score": 25,
        "regex": r"\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|csv|mp[34]|avi|zip|rar|7z|htm|html)\.(?:exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|wsh|lnk|ps1|msi|hta)$",
        "desc": "文件名形如「发票.pdf.exe」，靠隐藏真实扩展名骗人双击。",
    },
    {
        "id": "Phish.RightToLeftOverride",
        "name": "文件名 RLO 字符伪装",
        "family": "Phishing",
        "severity": "malicious",
        "score": 60,
        "regex": "\u202e",
        "desc": "使用 Unicode 从右到左覆盖字符（U+202E）颠倒文件名显示顺序，例如把 exe 伪装成 txt。",
    },
    {
        "id": "PUA.Keygen",
        "name": "疑似注册机 / 破解补丁",
        "family": "Riskware.HackTool",
        "severity": "pua",
        "score": 25,
        "regex": r"(?i)(keygen|keymaker|注册机|破解|patch[_-]?crack|crack(?:ed|fix)?|序列号生成)",
        "desc": "注册机/破解补丁类文件常捆绑木马，按灰色软件（PUA）提示。",
    },
    {
        "id": "PUA.PasswordDump",
        "name": "疑似密码抓取工具",
        "family": "Riskware.HackTool",
        "severity": "pua",
        "score": 35,
        "regex": r"(?i)(mimikatz|lsass[_-]?dump|pwdump|hashdump|wce\.exe|procdump)",
        "desc": "文件名直指凭据转储工具，属于黑客工具范畴。",
    },
    {
        "id": "Susp.ScriptInTemp",
        "name": "临时目录中的脚本文件",
        "family": "Trojan.Dropper",
        "severity": "suspicious",
        "score": 20,
        "regex": r"(?i)[\\/](?:temp|tmp|appdata[\\/]local[\\/]temp)[\\/].*\.(?:ps1|vbs|js|bat|cmd|hta|scr)$",
        "desc": "脚本从临时目录运行，是「释放到 Temp 再执行」这一常见投放链的痕迹。",
    },
]


# ============================================================================
#  PE 静态分析用到的可疑导入函数表
# ============================================================================
# 格式：函数名 -> (分值, 说明)
# 分值普遍压得比较低，因为正常程序也会用；靠「多个组合 + 阈值」来判定。
SUSPICIOUS_IMPORTS = {
    # 进程注入 / 内存操作
    "VirtualAllocEx": (22, "在别的进程里申请内存"),
    "WriteProcessMemory": (25, "改写其他进程的内存"),
    "CreateRemoteThread": (28, "在远程进程里创建线程（注入）"),
    "NtCreateThreadEx": (22, "创建远程线程（未文档化 API）"),
    "QueueUserAPC": (18, "APC 注入"),
    "SetThreadContext": (18, "劫持线程上下文"),
    "VirtualProtect": (6, "修改内存页权限"),
    "VirtualAlloc": (5, "申请可执行内存"),
    "RtlMoveMemory": (4, "内存拷贝"),
    "NtUnmapViewOfSection": (25, "进程镂空（Process Hollowing）"),
    "ZwUnmapViewOfSection": (25, "进程镂空（Process Hollowing）"),
    # 反调试 / 反沙箱
    "IsDebuggerPresent": (8, "检查是否被调试"),
    "CheckRemoteDebuggerPresent": (10, "检查是否被远程调试"),
    "NtQueryInformationProcess": (8, "查询进程信息（常用于反调试）"),
    "OutputDebugStringA": (3, "调试输出（常用于反调试）"),
    "GetTickCount": (3, "常用于沙箱延时检测"),
    "QueryPerformanceCounter": (3, "常用于沙箱延时检测"),
    "Sleep": (2, "延时执行"),
    # 键盘 / 屏幕监控
    "GetAsyncKeyState": (18, "轮询键盘状态"),
    "SetWindowsHookExA": (14, "安装系统钩子"),
    "SetWindowsHookExW": (14, "安装系统钩子"),
    "GetForegroundWindow": (6, "获取前台窗口"),
    "GetWindowTextA": (6, "读取窗口标题"),
    "BitBlt": (10, "屏幕抓取"),
    # 下载 / 执行
    "URLDownloadToFileA": (22, "从网络下载文件"),
    "URLDownloadToFileW": (22, "从网络下载文件"),
    "WinExec": (12, "执行外部程序（老 API）"),
    "ShellExecuteA": (8, "执行外部程序"),
    "ShellExecuteW": (8, "执行外部程序"),
    "CreateProcessA": (5, "创建进程"),
    "CreateProcessW": (5, "创建进程"),
    # 加密（勒索软件特征）
    "CryptEncrypt": (18, "加密数据"),
    "CryptGenKey": (10, "生成加密密钥"),
    "CryptAcquireContextA": (6, "获取加密服务提供者"),
    "BCryptEncrypt": (18, "加密数据（CNG）"),
    "CryptStringToBinaryA": (10, "解码 Base64 字符串"),
    # 提权 / 凭据
    "AdjustTokenPrivileges": (12, "调整进程令牌权限"),
    "OpenProcessToken": (6, "打开进程令牌"),
    "LookupPrivilegeValueA": (8, "查询特权名称"),
    "CredEnumerateA": (15, "枚举系统保存的凭据"),
    "LsaEnumerateLogonSessions": (15, "枚举登录会话"),
    # 服务 / 注册表持久化
    "CreateServiceA": (16, "注册系统服务"),
    "CreateServiceW": (16, "注册系统服务"),
    "OpenSCManagerA": (7, "打开服务管理器"),
    "RegSetValueExA": (5, "写注册表"),
    "RegSetValueExW": (5, "写注册表"),
    "RegCreateKeyExA": (4, "创建注册表项"),
    # 破坏 / 反杀软
    "TerminateProcess": (8, "结束进程"),
    "Process32First": (6, "枚举进程（常配合杀软识别）"),
    "Process32Next": (6, "枚举进程"),
    "EnumProcesses": (6, "枚举进程"),
    "FindWindowA": (6, "查找窗口（常用于查找杀软界面）"),
    # 网络通信
    "InternetOpenA": (7, "初始化 WinINet"),
    "InternetOpenUrlA": (10, "发起 HTTP 请求"),
    "InternetReadFile": (8, "读取 HTTP 响应"),
    "HttpSendRequestA": (9, "发送 HTTP 请求"),
    "WSASocketA": (6, "创建套接字"),
    "WSAStartup": (4, "初始化 Winsock"),
    "connect": (6, "建立网络连接"),
    "send": (4, "发送网络数据"),
    "recv": (4, "接收网络数据"),
    "socket": (4, "创建套接字"),
    "bind": (3, "绑定端口（后门监听）"),
    "listen": (4, "监听端口（后门监听）"),
    "accept": (3, "接受连接"),
    "URLDownloadToCacheFileA": (15, "下载文件到缓存"),
    # 动态解析（常用来隐藏导入表）
    "LoadLibraryA": (2, "动态加载 DLL"),
    "GetProcAddress": (3, "动态解析函数地址"),
}

# 加壳器 / 保护器的节区名特征
PACKER_SECTIONS = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX", ".UPX0": "UPX", ".UPX1": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".themida": "Themida", ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".enigma1": "Enigma", ".enigma2": "Enigma",
    ".petite": "Petite", ".nsp0": "NsPack", ".nsp1": "NsPack", ".nsp2": "NsPack",
    ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    ".fsg": "FSG", ".boom": "Themida", ".pck": "Packer", ".pebundle": "PEBundle",
    ".mpqt": "MPQ", ".taz": "Packer", ".neolite": "NeoLite", ".neolit": "NeoLite",
    ".sforce": "Packer", ".pdata": "Packer", ".rmnet": "Packer",
    ".winlice": "Packer", ".y0da": "Yoda", ".cryptor": "Cryptor",
}
