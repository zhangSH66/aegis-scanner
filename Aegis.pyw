# -*- coding: utf-8 -*-
"""AEGIS 神盾扫描器 · 图形界面入口（.pyw 版本，双击不弹控制台）

和 Aegis.py 是同一个程序，只是扩展名不同：
Windows 对 .pyw 的默认处理是「用 pythonw.exe 运行，不分配控制台」，
所以双击这个文件最干净。
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import Aegis  # noqa: E402

if __name__ == "__main__":
    sys.exit(Aegis.main())
