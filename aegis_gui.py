# -*- coding: utf-8 -*-
"""AEGIS 神盾扫描器 · 图形界面

tkinter + ttk 实现，纯标准库，零依赖。
启动：双击 启动扫描器.bat，或 `pyw -3.13 Aegis.pyw`
"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aegis_engine as E  # noqa: E402

# ---------------------------------------------------------------------------
#  配色（GitHub Dark 风）
# ---------------------------------------------------------------------------
BG        = "#0d1117"
BG_PANEL  = "#161b22"
BG_INPUT  = "#0b0f14"
BG_HOVER  = "#21262d"
FG        = "#e6edf3"
FG_DIM    = "#8b949e"
FG_FAINT  = "#6e7681"
ACCENT    = "#2f81f7"
ACCENT_D  = "#1f6feb"
RED       = "#f85149"
RED_D     = "#8b2c28"
YELLOW    = "#d29922"
YELLOW_D  = "#7a5c14"
GREEN     = "#3fb950"
BORDER    = "#30363d"
PURPLE    = "#bc8cff"

VERDICT_COLOR = {
    E.VERDICT_MALICIOUS: RED,
    E.VERDICT_SUSPICIOUS: YELLOW,
    E.VERDICT_ERROR: PURPLE,
}
SEV_COLOR = {
    "malicious": RED,
    "suspicious": YELLOW,
    "pua": YELLOW,
    "info": FG_DIM,
}
SEV_LABEL = {
    "malicious": "恶意",
    "suspicious": "可疑",
    "pua": "灰色",
    "info": "提示",
}


def pick_font() -> str:
    """挑一个系统里有的中文字体。"""
    try:
        families = set(tkfont.families())
    except Exception:
        return "Segoe UI"
    for name in ("Microsoft YaHei UI", "Microsoft YaHei", "微软雅黑",
                 "Segoe UI", "Tahoma"):
        if name in families:
            return name
    return "Segoe UI"


def reveal_in_explorer(path: str):
    """在资源管理器里定位文件。"""
    try:
        if os.path.exists(path):
            subprocess.Popen('explorer /select,"%s"' % os.path.normpath(path))
            return
    except Exception:
        pass
    try:
        os.startfile(os.path.dirname(path))
    except Exception:
        pass


# ===========================================================================
class AegisGUI:

    def __init__(self, root: tk.Tk):
        self.root = root
        self.font_name = pick_font()
        self.queue: queue.Queue = queue.Queue()
        self.scanner: E.Scanner | None = None
        self.worker: threading.Thread | None = None
        self.results: dict[str, E.ScanResult] = {}
        self.last_stats: dict = {}
        self.targets: list[str] = []
        self._polling = False
        self._t0 = 0.0

        root.title("AEGIS 神盾扫描器  ·  v" + E.ENGINE_VERSION)
        root.geometry("1220x780")
        root.minsize(1000, 640)
        root.configure(bg=BG)

        self._init_style()
        self._build_header()
        self._build_toolbar()
        self._build_status()
        self._build_main()
        self._build_statusbar()
        self._bind_keys()

        self.log("AEGIS 神盾扫描引擎已就绪。")
        self.log(f"引擎版本 {E.ENGINE_NAME} {E.ENGINE_VERSION}　"
                 f"特征规则 {len(E.COMPILED_RULES)} 条 + 文件名规则 {len(E.R.FILENAME_RULES)} 条")
        self.log("提示：按 F5 开始扫描，Esc 停止。双击结果可在资源管理器中定位文件。")

    # ------------------------------------------------------------------
    #  样式
    # ------------------------------------------------------------------
    def _init_style(self):
        f = self.font_name
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except Exception:
            pass

        st.configure(".", background=BG, foreground=FG, font=(f, 9))

        st.configure("Treeview",
                     background=BG_PANEL, fieldbackground=BG_PANEL,
                     foreground=FG, rowheight=27, borderwidth=0,
                     font=(f, 9))
        st.configure("Treeview.Heading",
                     background=BG_HOVER, foreground=FG_DIM,
                     relief="flat", borderwidth=0, padding=(6, 6),
                     font=(f, 9, "bold"))
        st.map("Treeview.Heading", background=[("active", BORDER)])
        st.map("Treeview",
               background=[("selected", ACCENT_D)],
               foreground=[("selected", "#ffffff")])

        st.configure("Aegis.Horizontal.TProgressbar",
                     troughcolor=BG_INPUT, background=ACCENT,
                     bordercolor=BG_INPUT, lightcolor=ACCENT, darkcolor=ACCENT,
                     thickness=16, borderwidth=0)

        st.configure("Aegis.TCheckbutton",
                     background=BG_PANEL, foreground=FG,
                     focuscolor=BG_PANEL, indicatorcolor=BG_INPUT,
                     bordercolor=BORDER, font=(f, 9))
        st.map("Aegis.TCheckbutton",
               background=[("active", BG_PANEL)],
               foreground=[("disabled", FG_FAINT)],
               indicatorcolor=[("selected", ACCENT), ("!selected", BG_INPUT)])

        st.configure("Aegis.TEntry",
                     fieldbackground=BG_INPUT, background=BG_INPUT,
                     foreground=FG, insertcolor=FG,
                     bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER,
                     borderwidth=1, relief="flat", padding=6)
        st.map("Aegis.TEntry", bordercolor=[("focus", ACCENT)])

        st.configure("Aegis.TCombobox",
                     fieldbackground=BG_INPUT, background=BG_INPUT,
                     foreground=FG, arrowcolor=FG_DIM,
                     bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER,
                     borderwidth=1, padding=4)
        st.map("Aegis.TCombobox",
               fieldbackground=[("readonly", BG_INPUT)],
               foreground=[("readonly", FG)])
        try:
            self.root.option_add("*TCombobox*Listbox.background", BG_PANEL)
            self.root.option_add("*TCombobox*Listbox.foreground", FG)
            self.root.option_add("*TCombobox*Listbox.selectBackground", ACCENT_D)
        except Exception:
            pass

        st.configure("Aegis.Vertical.TScrollbar",
                     background=BG_HOVER, troughcolor=BG, bordercolor=BG,
                     arrowcolor=FG_DIM, borderwidth=0)
        st.map("Aegis.Vertical.TScrollbar", background=[("active", BORDER)])

        st.configure("Aegis.TPanedwindow", background=BORDER, sashwidth=4,
                     borderwidth=0, sashrelief="flat")

        st.configure("Aegis.TNotebook", background=BG, borderwidth=0, tabmargins=0)
        st.configure("Aegis.TNotebook.Tab",
                     background=BG_PANEL, foreground=FG_DIM,
                     padding=(16, 8), borderwidth=0, font=(f, 9))
        st.map("Aegis.TNotebook.Tab",
               background=[("selected", BG_HOVER)],
               foreground=[("selected", FG)])

    def _btn(self, parent, text, command, bg=BG_HOVER, fg=FG, width=None,
             font_size=9, bold=False, padx=14, pady=6):
        b = tk.Button(
            parent, text=text, command=command,
            bg=bg, fg=fg, activebackground=self._lighten(bg),
            activeforeground=fg, relief="flat", bd=0,
            padx=padx, pady=pady, cursor="hand2",
            font=(self.font_name, font_size, "bold" if bold else "normal"),
            highlightthickness=0,
        )
        if width:
            b.configure(width=width)
        b.bind("<Enter>", lambda e: b.configure(bg=self._lighten(bg)))
        b.bind("<Leave>", lambda e: b.configure(bg=bg))
        return b

    @staticmethod
    def _lighten(hexcolor: str) -> str:
        table = {BG_HOVER: "#2d333b", ACCENT: ACCENT_D, RED_D: "#a8332e",
                 BG_PANEL: BG_HOVER, "#3d4450": "#4a5260"}
        return table.get(hexcolor, hexcolor)

    # ------------------------------------------------------------------
    #  顶部标题
    # ------------------------------------------------------------------
    def _build_header(self):
        head = tk.Frame(self.root, bg=BG_PANEL, height=66)
        head.pack(fill="x", side="top")
        head.pack_propagate(False)
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x", side="top")

        # 手绘盾牌图标
        cv = tk.Canvas(head, width=40, height=46, bg=BG_PANEL,
                       highlightthickness=0)
        cv.pack(side="left", padx=(18, 12), pady=10)
        cv.create_polygon(20, 3, 37, 12, 37, 26, 20, 43, 3, 26, 3, 12,
                          fill=ACCENT, outline="")
        cv.create_polygon(20, 9, 31, 15, 31, 25, 20, 36, 9, 25, 9, 15,
                          fill=BG_PANEL, outline="")
        cv.create_polygon(20, 14, 26, 17, 26, 24, 20, 30, 14, 24, 14, 17,
                          fill=ACCENT, outline="")

        left = tk.Frame(head, bg=BG_PANEL)
        left.pack(side="left", pady=12)
        tk.Label(left, text="AEGIS 神盾扫描器", bg=BG_PANEL, fg=FG,
                 font=(self.font_name, 15, "bold")).pack(anchor="w")
        tk.Label(left, text="纯 Python 杀毒扫描引擎　·　只扫描，不做清除",
                 bg=BG_PANEL, fg=FG_DIM, font=(self.font_name, 9)).pack(anchor="w")

        right = tk.Frame(head, bg=BG_PANEL)
        right.pack(side="right", padx=18)
        tk.Label(right, text=f"引擎 {E.ENGINE_VERSION}", bg=BG_PANEL,
                 fg=FG_FAINT, font=(self.font_name, 9)).pack(anchor="e")
        tk.Label(right, text=f"{len(E.COMPILED_RULES)} 条内容特征 · "
                             f"{len(E.R.FILENAME_RULES)} 条文件名规则",
                 bg=BG_PANEL, fg=FG_FAINT,
                 font=(self.font_name, 8)).pack(anchor="e")

    # ------------------------------------------------------------------
    #  工具栏
    # ------------------------------------------------------------------
    def _build_toolbar(self):
        bar = tk.Frame(self.root, bg=BG_PANEL)
        bar.pack(fill="x", side="top")
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x", side="top")

        # --- 第一行：目标选择 ---
        row1 = tk.Frame(bar, bg=BG_PANEL)
        row1.pack(fill="x", padx=16, pady=(12, 6))

        tk.Label(row1, text="扫描目标", bg=BG_PANEL, fg=FG_DIM,
                 font=(self.font_name, 9)).pack(side="left", padx=(0, 8))

        self.var_target = tk.StringVar(value="")
        self.entry = ttk.Entry(row1, textvariable=self.var_target,
                               style="Aegis.TEntry", font=(self.font_name, 9))
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self._btn(row1, "选择目录", self.choose_dir).pack(side="left", padx=3)
        self._btn(row1, "选择文件", self.choose_file).pack(side="left", padx=3)

        # --- 第二行：选项 + 动作 ---
        row2 = tk.Frame(bar, bg=BG_PANEL)
        row2.pack(fill="x", padx=16, pady=(0, 12))

        self.var_heur = tk.BooleanVar(value=True)
        self.var_arch = tk.BooleanVar(value=True)
        self.var_office = tk.BooleanVar(value=True)
        self.var_pua = tk.BooleanVar(value=True)
        for text, var in (("启发式分析", self.var_heur),
                          ("扫描压缩包", self.var_arch),
                          ("Office 宏", self.var_office),
                          ("报告灰色软件", self.var_pua)):
            ttk.Checkbutton(row2, text=text, variable=var,
                            style="Aegis.TCheckbutton").pack(side="left", padx=(0, 14))

        tk.Label(row2, text="线程", bg=BG_PANEL, fg=FG_DIM,
                 font=(self.font_name, 9)).pack(side="left", padx=(6, 4))
        self.var_threads = tk.StringVar(value="8")
        ttk.Combobox(row2, textvariable=self.var_threads, width=4,
                     values=("1", "2", "4", "8", "12", "16", "24", "32"),
                     state="readonly", style="Aegis.TCombobox",
                     font=(self.font_name, 9)).pack(side="left", padx=(0, 14))

        tk.Label(row2, text="跳过大于", bg=BG_PANEL, fg=FG_DIM,
                 font=(self.font_name, 9)).pack(side="left", padx=(0, 4))
        self.var_maxsize = tk.StringVar(value="64 MB")
        ttk.Combobox(row2, textvariable=self.var_maxsize, width=8,
                     values=("8 MB", "32 MB", "64 MB", "256 MB", "1 GB"),
                     state="readonly", style="Aegis.TCombobox",
                     font=(self.font_name, 9)).pack(side="left", padx=(0, 14))

        self.btn_export = self._btn(row2, "导出报告", self.export_report)
        self.btn_export.pack(side="right", padx=3)
        self.btn_export.configure(state="disabled", fg=FG_FAINT)

        self.btn_stop = self._btn(row2, "■  停止", self.stop_scan, bg=RED_D,
                                  fg="#ffffff", bold=True)
        self.btn_stop.pack(side="right", padx=3)
        self.btn_stop.configure(state="disabled")

        self.btn_scan = self._btn(row2, "▶  开始扫描", self.start_scan,
                                  bg=ACCENT, fg="#ffffff", bold=True,
                                  font_size=10, padx=20, pady=6)
        self.btn_scan.pack(side="right", padx=(0, 8))

    # ------------------------------------------------------------------
    #  进度与统计
    # ------------------------------------------------------------------
    def _build_status(self):
        wrap = tk.Frame(self.root, bg=BG_PANEL)
        wrap.pack(fill="x", side="top")
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x", side="top")

        row = tk.Frame(wrap, bg=BG_PANEL)
        row.pack(fill="x", padx=16, pady=(10, 4))

        self.pb = ttk.Progressbar(row, style="Aegis.Horizontal.TProgressbar",
                                  orient="horizontal", mode="determinate",
                                  maximum=100, value=0)
        self.pb.pack(side="left", fill="x", expand=True)

        self.lbl_pct = tk.Label(row, text="  0.0%", bg=BG_PANEL, fg=FG,
                                width=8, anchor="w",
                                font=(self.font_name, 10, "bold"))
        self.lbl_pct.pack(side="left")

        self.lbl_count = tk.Label(row, text="恶意 0　可疑 0　已扫 0/0",
                                  bg=BG_PANEL, fg=FG_DIM, anchor="e",
                                  font=(self.font_name, 9))
        self.lbl_count.pack(side="right")

        row2 = tk.Frame(wrap, bg=BG_PANEL)
        row2.pack(fill="x", padx=16, pady=(0, 10))
        self.lbl_current = tk.Label(row2, text="等待扫描任务…", bg=BG_PANEL,
                                    fg=FG_FAINT, anchor="w",
                                    font=(self.font_name, 8))
        self.lbl_current.pack(side="left", fill="x", expand=True)
        self.lbl_speed = tk.Label(row2, text="", bg=BG_PANEL, fg=FG_FAINT,
                                  anchor="e", font=(self.font_name, 8))
        self.lbl_speed.pack(side="right")

    # ------------------------------------------------------------------
    #  主区域
    # ------------------------------------------------------------------
    def _build_main(self):
        outer = tk.Frame(self.root, bg=BG)
        outer.pack(fill="both", expand=True, padx=12, pady=(6, 6))

        paned = ttk.Panedwindow(outer, orient="horizontal",
                                style="Aegis.TPanedwindow")
        paned.pack(fill="both", expand=True)

        # ---------- 左侧：结果列表 ----------
        left = tk.Frame(paned, bg=BG_PANEL)
        paned.add(left, weight=3)

        head = tk.Frame(left, bg=BG_PANEL)
        head.pack(fill="x", padx=10, pady=(8, 4))
        tk.Label(head, text="检出结果", bg=BG_PANEL, fg=FG,
                 font=(self.font_name, 10, "bold")).pack(side="left")
        self.lbl_filter = tk.Label(head, text="", bg=BG_PANEL, fg=FG_FAINT,
                                   font=(self.font_name, 8))
        self.lbl_filter.pack(side="right")

        tree_wrap = tk.Frame(left, bg=BG_PANEL)
        tree_wrap.pack(fill="both", expand=True, padx=(10, 4), pady=(0, 10))

        cols = ("verdict", "threat", "path", "size", "score")
        self.tree = ttk.Treeview(tree_wrap, columns=cols, show="headings",
                                 selectmode="browse")
        self.tree.heading("verdict", text="级别")
        self.tree.heading("threat", text="威胁名称")
        self.tree.heading("path", text="文件路径")
        self.tree.heading("size", text="大小")
        self.tree.heading("score", text="分值")
        self.tree.column("verdict", width=62, anchor="center", stretch=False)
        self.tree.column("threat", width=250, anchor="w", stretch=False)
        self.tree.column("path", width=380, anchor="w")
        self.tree.column("size", width=80, anchor="e", stretch=False)
        self.tree.column("score", width=58, anchor="center", stretch=False)

        self.tree.tag_configure(E.VERDICT_MALICIOUS, foreground=RED)
        self.tree.tag_configure(E.VERDICT_SUSPICIOUS, foreground=YELLOW)
        self.tree.tag_configure(E.VERDICT_ERROR, foreground=PURPLE)

        sb = ttk.Scrollbar(tree_wrap, orient="vertical", command=self.tree.yview,
                           style="Aegis.Vertical.TScrollbar")
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<Double-1>", self.on_double)
        self.tree.bind("<Button-3>", self.on_right_click)

        # 右键菜单
        self.menu = tk.Menu(self.root, tearoff=0, bg=BG_PANEL, fg=FG,
                            activebackground=ACCENT_D, activeforeground="#ffffff",
                            bd=0, font=(self.font_name, 9))
        self.menu.add_command(label="在资源管理器中定位", command=self.on_double)
        self.menu.add_command(label="复制文件路径", command=lambda: self.copy_field("path"))
        self.menu.add_command(label="复制 SHA-256", command=lambda: self.copy_field("sha256"))
        self.menu.add_separator()
        self.menu.add_command(label="复制威胁名称", command=lambda: self.copy_field("threat"))

        # ---------- 右侧：详情 / 日志 ----------
        right = tk.Frame(paned, bg=BG_PANEL)
        paned.add(right, weight=2)

        vp = ttk.Panedwindow(right, orient="vertical", style="Aegis.TPanedwindow")
        vp.pack(fill="both", expand=True)

        det = tk.Frame(vp, bg=BG_PANEL)
        vp.add(det, weight=3)
        dhead = tk.Frame(det, bg=BG_PANEL)
        dhead.pack(fill="x", padx=10, pady=(8, 4))
        tk.Label(dhead, text="检出详情", bg=BG_PANEL, fg=FG,
                 font=(self.font_name, 10, "bold")).pack(side="left")
        dbody = tk.Frame(det, bg=BG_PANEL)
        dbody.pack(fill="both", expand=True, padx=(10, 10), pady=(0, 8))
        self.txt_detail = self._make_text(dbody)

        lg = tk.Frame(vp, bg=BG_PANEL)
        vp.add(lg, weight=2)
        lhead = tk.Frame(lg, bg=BG_PANEL)
        lhead.pack(fill="x", padx=10, pady=(8, 4))
        tk.Label(lhead, text="运行日志", bg=BG_PANEL, fg=FG,
                 font=(self.font_name, 10, "bold")).pack(side="left")
        self._btn(lhead, "清空", self.clear_log, padx=10, pady=2,
                  font_size=8).pack(side="right")
        lbody = tk.Frame(lg, bg=BG_PANEL)
        lbody.pack(fill="both", expand=True, padx=(10, 10), pady=(0, 10))
        self.txt_log = self._make_text(lbody, font_size=8)

        self._detail_default()

    def _make_text(self, parent, font_size=9) -> tk.Text:
        """在 parent 里放一个 Text + 滚动条，返回 Text 组件。"""
        t = tk.Text(parent, bg=BG_INPUT, fg=FG, insertbackground=FG,
                    relief="flat", bd=0, highlightthickness=1,
                    highlightbackground=BORDER, highlightcolor=BORDER,
                    font=(self.font_name, font_size), wrap="word",
                    padx=10, pady=8, spacing1=1, spacing3=2,
                    selectbackground=ACCENT_D, selectforeground="#ffffff")
        sb = ttk.Scrollbar(parent, orient="vertical", command=t.yview,
                           style="Aegis.Vertical.TScrollbar")
        t.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        t.pack(side="left", fill="both", expand=True)
        for tag, color, fnt in (
            ("h", FG, (self.font_name, font_size + 1, "bold")),
            ("red", RED, (self.font_name, font_size, "bold")),
            ("yellow", YELLOW, (self.font_name, font_size, "bold")),
            ("green", GREEN, (self.font_name, font_size, "bold")),
            ("dim", FG_DIM, (self.font_name, font_size)),
            ("faint", FG_FAINT, (self.font_name, font_size)),
            ("bold", FG, (self.font_name, font_size, "bold")),
            ("mono", "#79c0ff", ("Consolas", font_size)),
        ):
            t.tag_configure(tag, foreground=color, font=fnt)
        t.configure(state="disabled")
        return t

    def _build_statusbar(self):
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x", side="bottom")
        bar = tk.Frame(self.root, bg=BG_PANEL, height=26)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        self.lbl_status = tk.Label(bar, text="就绪", bg=BG_PANEL, fg=FG_FAINT,
                                   anchor="w", font=(self.font_name, 8))
        self.lbl_status.pack(side="left", padx=12)
        tk.Label(bar, text="仅扫描，不修改或删除任何文件", bg=BG_PANEL,
                 fg=FG_FAINT, anchor="e",
                 font=(self.font_name, 8)).pack(side="right", padx=12)

    def _bind_keys(self):
        self.root.bind("<F5>", lambda e: self.start_scan())
        self.root.bind("<Escape>", lambda e: self.stop_scan())
        self.root.bind("<Control-o>", lambda e: self.choose_dir())

    # ------------------------------------------------------------------
    #  日志 / 详情
    # ------------------------------------------------------------------
    def log(self, msg: str, tag: str = "dim"):
        t = self.txt_log
        t.configure(state="normal")
        t.insert("end", time.strftime("[%H:%M:%S] "), "faint")
        t.insert("end", msg + "\n", tag)
        t.see("end")
        t.configure(state="disabled")

    def clear_log(self):
        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.configure(state="disabled")

    def _detail_default(self):
        t = self.txt_detail
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("end", "AEGIS 神盾扫描器\n", "h")
        t.insert("end", "─" * 46 + "\n\n", "faint")
        t.insert("end", "在上方选择扫描目标，然后点「开始扫描」。\n\n", "dim")
        t.insert("end", "这里会显示每个检出文件的详细判定依据：\n", "dim")
        t.insert("end", "  · 命中了哪些特征规则、各自的权重分值\n", "dim")
        t.insert("end", "  · PE 结构分析结果（节区熵值、导入表、加壳识别）\n", "dim")
        t.insert("end", "  · 从文件里提取到的 URL / IP / 邮箱等 IOC\n", "dim")
        t.configure(state="disabled")

    def show_detail(self, res: E.ScanResult):
        t = self.txt_detail
        t.configure(state="normal")
        t.delete("1.0", "end")

        color = VERDICT_COLOR.get(res.verdict, FG)
        t.insert("end", f"{res.verdict_label}", color)
        t.insert("end", f"　{res.threat_name or '（无命中）'}\n", "h")
        t.insert("end", "─" * 46 + "\n", "faint")

        rows = [
            ("文件", res.path),
            ("大小", f"{E.format_size(res.size)}"),
            ("类型", res.kind),
            ("威胁分值", str(res.score)),
            ("耗时", f"{res.duration_ms:.1f} ms"),
            ("SHA-256", res.sha256),
            ("MD5", res.md5),
        ]
        for k, v in rows:
            t.insert("end", f"{k:<10}", "faint")
            t.insert("end", f"{v}\n", "mono" if k in ("SHA-256", "MD5") else "dim")

        if res.error:
            t.insert("end", f"\n扫描错误：{res.error}\n", "red")

        if res.findings:
            t.insert("end", f"\n检出项（{len(res.findings)}）\n", "h")
            t.insert("end", "─" * 46 + "\n", "faint")
            for f in res.findings:
                if f.severity == "info":
                    continue
                c = SEV_COLOR.get(f.severity, FG_DIM)
                t.insert("end", f"[{SEV_LABEL.get(f.severity, f.severity)} +{f.score}] ", c)
                t.insert("end", f"{f.name}\n", "bold")
                t.insert("end", f"    家族　{f.family}\n", "faint")
                if f.detail:
                    t.insert("end", f"    依据　{f.detail}\n", "dim")
                if f.desc:
                    t.insert("end", f"    说明　{f.desc}\n", "faint")
                t.insert("end", "\n")

        infos = [f for f in res.findings if f.severity == "info"]
        if infos:
            t.insert("end", "补充信息\n", "h")
            t.insert("end", "─" * 46 + "\n", "faint")
            for f in infos:
                t.insert("end", f"· {f.name}：{f.detail}\n", "faint")
            t.insert("end", "\n")

        if res.iocs:
            t.insert("end", "提取到的 IOC\n", "h")
            t.insert("end", "─" * 46 + "\n", "faint")
            for key, vals in res.iocs.items():
                t.insert("end", f"{key}（{len(vals)}）\n", "faint")
                for v in vals[:12]:
                    t.insert("end", f"    {v}\n", "mono")
            t.insert("end", "\n")

        t.configure(state="disabled")
        t.see("1.0")

    # ------------------------------------------------------------------
    #  目标选择
    # ------------------------------------------------------------------
    def choose_dir(self):
        d = filedialog.askdirectory(title="选择要扫描的目录")
        if d:
            self.var_target.set(os.path.normpath(d))

    def choose_file(self):
        f = filedialog.askopenfilename(title="选择要扫描的文件")
        if f:
            self.var_target.set(os.path.normpath(f))

    def parse_targets(self) -> list[str]:
        raw = self.var_target.get()
        parts = [p.strip().strip('"') for p in raw.replace("\n", ";").split(";")]
        return [p for p in parts if p]

    # ------------------------------------------------------------------
    #  扫描控制
    # ------------------------------------------------------------------
    def start_scan(self):
        if self.worker and self.worker.is_alive():
            return
        targets = self.parse_targets()
        if not targets:
            messagebox.showwarning("没有扫描目标", "请先选择要扫描的目录或文件。")
            return
        missing = [t for t in targets if not os.path.exists(t)]
        if missing:
            messagebox.showerror("路径不存在", "找不到以下路径：\n" + "\n".join(missing))
            return

        try:
            mb = int(self.var_maxsize.get().split()[0])
            if "GB" in self.var_maxsize.get():
                mb *= 1024
        except Exception:
            mb = 64
        try:
            threads = int(self.var_threads.get())
        except Exception:
            threads = 8

        opts = E.ScanOptions(
            heuristics=self.var_heur.get(),
            scan_archives=self.var_arch.get(),
            scan_office=self.var_office.get(),
            detect_pua=self.var_pua.get(),
            threads=threads,
            max_file_size=mb * 1024 * 1024,
        )
        self.scanner = E.Scanner(opts)
        self.targets = targets
        self.results.clear()
        self.tree.delete(*self.tree.get_children())
        self._detail_default()
        self.pb.configure(value=0)
        self.lbl_pct.configure(text="  0.0%")
        self.lbl_count.configure(text="恶意 0　可疑 0　已扫 0/0")
        self.lbl_speed.configure(text="")
        self.btn_scan.configure(state="disabled", bg="#25405f")
        self.btn_stop.configure(state="normal")
        self.btn_export.configure(state="disabled", fg=FG_FAINT)
        self.lbl_status.configure(text="扫描中…")
        self._t0 = time.time()

        self.log("─" * 40, "faint")
        self.log("开始扫描：" + "；".join(targets), "bold")
        self.log(f"启发式 {'开' if opts.heuristics else '关'}　"
                 f"压缩包 {'开' if opts.scan_archives else '关'}　"
                 f"Office {'开' if opts.scan_office else '关'}　"
                 f"线程 {opts.threads}", "faint")

        def run():
            try:
                stats = self.scanner.scan(
                    targets,
                    on_result=lambda r: self.queue.put(("result", r)),
                    on_progress=lambda s: self.queue.put(("progress", s)),
                    on_done=lambda s: self.queue.put(("done", s)),
                )
                self.queue.put(("done", stats))
            except Exception as exc:
                self.queue.put(("fatal", exc))

        self.worker = threading.Thread(target=run, daemon=True)
        self.worker.start()
        self._start_polling()

    def stop_scan(self):
        if self.scanner and self.worker and self.worker.is_alive():
            self.scanner.cancel()
            self.log("正在停止扫描…", "yellow")
            self.lbl_status.configure(text="正在停止…")

    def _start_polling(self):
        if self._polling:
            return
        self._polling = True
        self.root.after(70, self._drain)

    def _drain(self):
        handled = 0
        try:
            while handled < 120:
                kind, payload = self.queue.get_nowait()
                handled += 1
                if kind == "result":
                    self._add_result(payload)
                elif kind == "progress":
                    self._update_progress(payload)
                elif kind == "log":
                    tag = payload[2] if len(payload) > 2 else "dim"
                    self.log(payload[1], tag)
                elif kind == "done":
                    self._finish(payload)
                elif kind == "fatal":
                    self.log(f"扫描线程异常: {payload}", "red")
                    self._finish({"total": 0, "done": 0, "threats": 0,
                                  "suspicious": 0, "errors": 0, "skipped": 0,
                                  "bytes": 0, "elapsed": 0, "results": [],
                                  "error_list": [], "cancelled": True})
        except queue.Empty:
            pass

        if self.worker and self.worker.is_alive():
            self.root.after(70, self._drain)
        else:
            self._polling = False
            try:
                while True:
                    kind, payload = self.queue.get_nowait()
                    if kind == "result":
                        self._add_result(payload)
                    elif kind == "progress":
                        self._update_progress(payload)
                    elif kind == "done":
                        self._finish(payload)
                    elif kind == "log":
                        self.log(payload[1], payload[2] if len(payload) > 2 else "dim")
            except queue.Empty:
                pass

    def _add_result(self, res: E.ScanResult):
        if res.verdict not in (E.VERDICT_MALICIOUS, E.VERDICT_SUSPICIOUS):
            return
        self.results[res.path] = res
        iid = self.tree.insert("", "end", values=(
            res.verdict_label,
            res.threat_name,
            res.path,
            E.format_size(res.size),
            res.score,
        ), tags=(res.verdict,))
        if res.verdict == E.VERDICT_MALICIOUS:
            self.log(f"[恶意] {res.threat_name}　→　{res.path}", "red")
        else:
            self.log(f"[可疑] {res.threat_name}　→　{res.path}", "yellow")

    def _update_progress(self, st: dict):
        self.last_stats = st
        total = st.get("total", 0)
        done = st.get("done", 0)
        pct = (done / total * 100) if total else 0
        self.pb.configure(value=pct)
        self.lbl_pct.configure(text=f"  {pct:4.1f}%")
        self.lbl_count.configure(
            text=f"恶意 {st.get('threats', 0)}　可疑 {st.get('suspicious', 0)}　"
                 f"已扫 {done}/{total}")
        cur = st.get("current", "")
        if cur:
            if len(cur) > 70:
                cur = "…" + cur[-69:]
            self.lbl_current.configure(text=cur, fg=FG_DIM)
        el = time.time() - self._t0
        if el > 0.3 and done:
            self.lbl_speed.configure(
                text=f"{done / el:.0f} 文件/秒　已读取 {E.format_size(st.get('bytes', 0))}　"
                     f"用时 {el:.1f}s")

    def _finish(self, st: dict):
        self.last_stats = st
        self.btn_scan.configure(state="normal", bg=ACCENT)
        self.btn_stop.configure(state="disabled")
        self.btn_export.configure(state="normal", fg=FG)
        if st.get("total"):
            self.pb.configure(value=100)
            self.lbl_pct.configure(text=" 100.0%")
        self.lbl_current.configure(text="扫描结束。", fg=FG_FAINT)

        threats = st.get("threats", 0)
        susp = st.get("suspicious", 0)
        errs = st.get("errors", 0)
        if st.get("cancelled"):
            self.lbl_status.configure(text="扫描已中断")
            self.log("扫描已中断。", "yellow")
        elif threats or susp:
            self.lbl_status.configure(
                text=f"扫描完成 —— 发现 {threats} 个恶意、{susp} 个可疑文件")
        else:
            self.lbl_status.configure(text="扫描完成 —— 未发现威胁")

        self.log("─" * 40, "faint")
        self.log(f"扫描完成：文件 {st.get('total', 0)}　已扫描 {st.get('done', 0)}　"
                 f"恶意 {threats}　可疑 {susp}　错误 {errs}　"
                 f"耗时 {st.get('elapsed', 0):.2f}s",
                 "red" if threats else ("yellow" if susp else "green"))

        for e in st.get("error_list", [])[:8]:
            self.log(f"无法读取：{e['path']}　({e['error']})", "faint")
        if errs > 8:
            self.log(f"…… 另有 {errs - 8} 个文件无法读取。", "faint")

        if threats or susp:
            first = self.tree.get_children()
            if first:
                self.tree.selection_set(first[0])
                self.tree.focus(first[0])

    # ------------------------------------------------------------------
    #  交互
    # ------------------------------------------------------------------
    def _selected_result(self) -> E.ScanResult | None:
        sel = self.tree.selection()
        if not sel:
            return None
        vals = self.tree.item(sel[0], "values")
        if len(vals) < 3:
            return None
        return self.results.get(vals[2])

    def on_select(self, _event=None):
        res = self._selected_result()
        if res:
            self.show_detail(res)

    def on_double(self, _event=None):
        res = self._selected_result()
        if res:
            reveal_in_explorer(res.path)

    def on_right_click(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self.menu.tk_popup(event.x_root, event.y_root)

    def copy_field(self, field: str):
        res = self._selected_result()
        if not res:
            return
        val = {"path": res.path, "sha256": res.sha256,
               "threat": res.threat_name}.get(field, "")
        self.root.clipboard_clear()
        self.root.clipboard_append(val)
        self.lbl_status.configure(text=f"已复制到剪贴板：{val[:80]}")

    def export_report(self):
        if not self.last_stats:
            messagebox.showinfo("没有报告", "请先完成一次扫描。")
            return
        path = filedialog.asksaveasfilename(
            title="导出扫描报告",
            defaultextension=".txt",
            initialfile=f"AEGIS报告_{time.strftime('%Y%m%d_%H%M%S')}.txt",
            filetypes=[("文本报告", "*.txt"), ("JSON 报告", "*.json"), ("所有文件", "*.*")],
        )
        if not path:
            return
        try:
            if path.lower().endswith(".json"):
                E.export_json(self.last_stats, path, self.targets)
            else:
                E.export_text(self.last_stats, path, self.targets)
            self.log(f"报告已导出：{path}", "green")
            if messagebox.askyesno("导出完成", f"报告已保存到：\n{path}\n\n要打开所在文件夹吗？"):
                reveal_in_explorer(path)
        except Exception as exc:
            messagebox.showerror("导出失败", str(exc))


def main():
    root = tk.Tk()
    try:
        # 高分屏适配
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    AegisGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
