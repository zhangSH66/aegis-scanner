/*
   AEGIS 神盾扫描器 · 示例 YARA 规则
   ---------------------------------------------------------------------------
   把 .yar / .yara 文件放进这个目录，引擎启动时会自动编译并加载。

   前置条件：需要安装 yara-python，否则本目录会被完全忽略（不影响其它功能）。
       py -3.13 -m ensurepip
       py -3.13 -m pip install yara-python

   规则里可用的 meta 字段：
       name         显示名称（默认用规则名）
       family       家族/类别
       severity     malicious / suspicious / pua / info
       score        命中后累加的威胁分值
       description  说明文字，会显示在 UI 详情面板

   注意：AEGIS 自带的规则引擎和 YARA 是两套并行的匹配层，结果会一起汇总。
*/

rule Aegis_Demo_Marker
{
    meta:
        name        = "AEGIS 示例规则（测试标记）"
        family      = "Demo"
        severity    = "suspicious"
        score       = 40
        description = "演示用规则：命中文件里的 AEGIS-YARA-DEMO-MARKER 标记。往样本文件里写入这串字符即可验证 YARA 是否生效。"

    strings:
        $marker = "AEGIS-YARA-DEMO-MARKER"

    condition:
        $marker
}
