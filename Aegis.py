# -*- coding: utf-8 -*-
"""AEGIS 神盾扫描器 · 启动器

直接双击本文件，或者在命令行里执行：

    py -3.13 Aegis.py
    python Aegis.py

小技巧：双击时如果先弹出一个黑色控制台窗口，本文件会自动改用 pythonw.exe
重新拉起自己，控制台会立刻消失 —— 你不需要做任何额外操作。

如果双击 .py 被编辑器（PyCharm / VS Code）抢走了，双击同目录的 Aegis.pyw 即可。
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


# ---------------------------------------------------------------------------
#  自动摆脱控制台窗口
# ---------------------------------------------------------------------------
def _has_console() -> bool:
    """当前进程是否挂着一个控制台窗口。"""
    if os.name != "nt":
        return False
    try:
        import ctypes
        return ctypes.windll.kernel32.GetConsoleWindow() != 0
    except Exception:
        return False


def _relaunch_without_console() -> bool:
    """用同目录的 pythonw.exe 重新启动自己。成功接管则返回 True。"""
    if os.name != "nt":
        return False
    if os.environ.get("AEGIS_NO_DETACH"):
        return False          # 调试用：保持前台，方便看输出

    exe = sys.executable or ""
    if exe.lower().endswith("pythonw.exe"):
        return False          # 已经是没有控制台的解释器了
    if not _has_console():
        return False          # 本来就没有控制台（例如从 IDE 里启动）

    pythonw = os.path.join(os.path.dirname(exe), "pythonw.exe")
    if not os.path.isfile(pythonw):
        return False

    try:
        import subprocess
        DETACHED_PROCESS = 0x00000008
        CREATE_NO_WINDOW = 0x08000000
        subprocess.Popen(
            [pythonw, os.path.abspath(__file__)],
            creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW,
            close_fds=True,
        )
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
#  启动失败时把原因显示出来，而不是静默退出
# ---------------------------------------------------------------------------
def _report_failure(err_text: str):
    try:
        import tkinter as tk
        import tkinter.messagebox as mb
        r = tk.Tk()
        r.withdraw()
        mb.showerror("AEGIS 启动失败", err_text)
        r.destroy()
    except Exception:
        sys.stderr.write(err_text + "\n")
        try:
            input("\n按回车键退出…")
        except Exception:
            pass


def main() -> int:
    if _relaunch_without_console():
        return 0

    try:
        import aegis_gui
    except Exception:
        import traceback
        _report_failure(
            "无法加载图形界面模块。\n\n"
            f"Python 解释器: {sys.executable}\n"
            f"版本: {sys.version.split()[0]}\n"
            f"项目目录: {HERE}\n\n"
            + traceback.format_exc()
        )
        return 1

    try:
        aegis_gui.main()
    except Exception:
        import traceback
        _report_failure("运行时出错：\n\n" + traceback.format_exc())
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
