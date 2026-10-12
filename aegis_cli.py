# -*- coding: utf-8 -*-
"""AEGIS 神盾扫描器 · 命令行版本

用法：
    py -3.13 aegis_cli.py <目标路径> [更多路径...]
    py -3.13 aegis_cli.py . --json report.json
    py -3.13 aegis_cli.py . --no-heuristics --threads 16
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aegis_engine as E  # noqa: E402

C_RESET = "\033[0m"
C_DIM = "\033[90m"
C_RED = "\033[91m"
C_YEL = "\033[93m"
C_GRN = "\033[92m"
C_CYA = "\033[96m"
C_BOLD = "\033[1m"


def _enable_ansi():
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            pass


SEV_COLOR = {
    "malicious": C_RED,
    "suspicious": C_YEL,
    "pua": C_YEL,
    "info": C_DIM,
}


def main():
    ap = argparse.ArgumentParser(
        prog="aegis",
        description="AEGIS 神盾扫描器 —— 纯 Python 实现的杀毒扫描引擎（仅扫描，不做清除）",
    )
    ap.add_argument("targets", nargs="+", help="要扫描的文件或目录")
    ap.add_argument("--json", metavar="FILE", help="把完整报告导出为 JSON")
    ap.add_argument("--text", metavar="FILE", help="把完整报告导出为 TXT")
    ap.add_argument("--threads", type=int, default=8, help="扫描线程数（默认 8）")
    ap.add_argument("--max-size", type=int, default=64, help="跳过大于 N MB 的文件（默认 64）")
    ap.add_argument("--no-heuristics", action="store_true", help="只跑特征规则，跳过 PE 启发式分析")
    ap.add_argument("--no-archives", action="store_true", help="不递归扫描压缩包")
    ap.add_argument("--no-office", action="store_true", help="不分析 Office 宏")
    ap.add_argument("--no-pua", action="store_true", help="不报告灰色软件（PUA）")
    ap.add_argument("-q", "--quiet", action="store_true", help="只输出检出结果")
    args = ap.parse_args()

    _enable_ansi()

    opts = E.ScanOptions(
        heuristics=not args.no_heuristics,
        scan_archives=not args.no_archives,
        scan_office=not args.no_office,
        detect_pua=not args.no_pua,
        threads=max(1, args.threads),
        max_file_size=max(1, args.max_size) * 1024 * 1024,
    )

    print(f"{C_BOLD}{C_CYA}")
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║        AEGIS 神盾扫描器  ·  仅扫描，不做清除         ║")
    print("  ╚══════════════════════════════════════════════════════╝")
    print(C_RESET)
    print(f"  引擎版本 : {E.ENGINE_NAME} {E.ENGINE_VERSION}")
    print(f"  特征规则 : {len(E.COMPILED_RULES)} 条内容规则 + "
          f"{len(E.R.FILENAME_RULES)} 条文件名规则")
    print(f"  扫描目标 : {', '.join(args.targets)}")
    print(f"  启发式   : {'开' if opts.heuristics else '关'}"
          f"   压缩包: {'开' if opts.scan_archives else '关'}"
          f"   Office: {'开' if opts.scan_office else '关'}"
          f"   线程: {opts.threads}")
    print()

    scanner = E.Scanner(opts)
    state = {"t": time.time(), "last": 0.0}

    def on_progress(st):
        if args.quiet:
            return
        now = time.time()
        if now - state["last"] < 0.08 and st["done"] != st["total"]:
            return
        state["last"] = now
        pct = (st["done"] / st["total"] * 100) if st["total"] else 0
        bar_len = 32
        filled = int(bar_len * pct / 100)
        bar = "█" * filled + "░" * (bar_len - filled)
        cur = st.get("current", "")
        if len(cur) > 46:
            cur = "…" + cur[-45:]
        sys.stdout.write(
            f"\r  {C_GRN}{bar}{C_RESET} {pct:5.1f}%  "
            f"{st['done']}/{st['total']}  "
            f"{C_RED}恶意 {st['threats']}{C_RESET} "
            f"{C_YEL}可疑 {st['suspicious']}{C_RESET}  "
            f"{C_DIM}{cur}{C_RESET}"
        )
        sys.stdout.flush()

    def on_result(res):
        if not args.quiet:
            sys.stdout.write("\r" + " " * 160 + "\r")
        color = C_RED if res.verdict == E.VERDICT_MALICIOUS else C_YEL
        print(f"  {color}[{res.verdict_label}]{C_RESET} {C_BOLD}{res.threat_name}{C_RESET}")
        print(f"          文件   : {res.path}")
        print(f"          大小   : {E.format_size(res.size)}   类型: {res.kind}   分值: {res.score}")
        print(f"          SHA256 : {res.sha256}")
        for f in res.findings:
            if f.severity == "info":
                continue
            fc = SEV_COLOR.get(f.severity, "")
            print(f"            {fc}· {f.name}{C_RESET} {C_DIM}(+{f.score}){C_RESET}")
            if f.detail:
                print(f"              {C_DIM}{f.detail}{C_RESET}")
        print()
        if args.quiet:
            print()

    def on_done(st):
        pass

    try:
        stats = scanner.scan(args.targets, on_result=on_result,
                             on_progress=on_progress, on_done=on_done)
    except KeyboardInterrupt:
        scanner.cancel()
        print("\n\n  用户中断扫描。")
        return 130

    sys.stdout.write("\r" + " " * 160 + "\r")
    print("  " + "─" * 58)
    print(f"  {C_BOLD}扫描完成{C_RESET}")
    print(f"    文件总数 : {stats['total']}")
    print(f"    已扫描   : {stats['done']}")
    print(f"    {C_RED}恶意     : {stats['threats']}{C_RESET}")
    print(f"    {C_YEL}可疑     : {stats['suspicious']}{C_RESET}")
    print(f"    读取错误 : {stats['errors']}")
    print(f"    跳过     : {stats['skipped']}")
    print(f"    数据量   : {E.format_size(stats['bytes'])}")
    print(f"    耗时     : {stats['elapsed']:.2f} 秒"
          f"  ({stats['done'] / stats['elapsed']:.0f} 文件/秒)" if stats["elapsed"] else "")
    print("  " + "─" * 58)

    if args.json:
        E.export_json(stats, args.json, args.targets)
        print(f"  JSON 报告已导出: {args.json}")
    if args.text:
        E.export_text(stats, args.text, args.targets)
        print(f"  文本报告已导出: {args.text}")

    return 1 if (stats["threats"] or stats["suspicious"]) else 0


if __name__ == "__main__":
    sys.exit(main())
