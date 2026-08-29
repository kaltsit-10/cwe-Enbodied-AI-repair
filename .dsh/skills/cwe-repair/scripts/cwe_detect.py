#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cwe_detect.py — 检测 C/C++ 源码中的特定 CWE 模式（防御侧，检测阶段）

用途：定位疑似越界、计数/长度契约、整数溢出、除零、空指针和部分逻辑类代码点，
输出结构化发现（文件:行号:CWE:模式:证据片段），供后续 repair/verify 阶段使用。

这是"规则模板"式检测器——精确、可复现、低误报优先。
不替代 CodeQL/cppcheck；当前规则以本项目验证过的输入契约模式为主，并包含少量实验性逻辑类规则。

用法:
  python cwe_detect.py <file-or-dir> [--cwe 787,125,190,369] [--json]
输出:
  默认文本表格；--json 输出机器可读（供 DSH agent 解析）
"""
import argparse
import json
import os
import re
import sys
import hashlib

# ---- 模式库：每条 = (CWE, 名称, 正则, 说明, 置信度) ----
# 置信度: high=明确漏洞信号(外部输入/平行数组/已知模式), medium=较强信号,
#         low=泛化模式(需大量人工核验,默认关闭)
# 基于本项目已实证的漏洞模式（NCNN/AimRT/MindSpore/AGIBOT/XR）+ MNN/TNN 误报分析
PATTERNS = [
    # ===== CWE-125/787 越界：数组索引无边界校验 =====
    (125, "array_index_raw",
     r"(?P<pre>[\w>\]\)\-\>]+)\[(?P<idx>[a-zA-Z_]\w*)\]",
     "数组下标直接使用变量，未见边界校验（泛化模式，低置信）", "low"),
    (125, "index_from_attacker",
     r"(?P<arr>[\w>\]\)\-\>]+)\[(?P<idx>(?:msg|data|buf|packet|cmd|input|config)\w*)\]",
     "数组下标来自外部输入类变量（消息/数据/缓冲区），高优先", "high"),
    (125, "shape_axis_index",
     r"(?P<arr>(?:x_shape|shape|x_shp|input_shape|output_shape))\s*\[\s*(?P<idx>(?:dim_value|axis|dim)\w*)\s*\]",
     "shape 由 axis/dim 标量索引；需先验证 [-rank, rank-1] 并归一化负轴（MindSpore CumsumExt 同款）", "medium"),
    (125, "parallel_array_loop",
     r"for\s*\([^;]*;[^;]*;\s*(?:i|j|k|idx)\s*\+\+\)[\s\S]{0,200}?(?P<b>[\w>]+)\[(?:i|j|k|idx)\]",
     "平行数组模式：以数组A长度循环，直接索引数组B（A/B长度未互检）——AGIBOT JointCmdCallback 同款", "high"),
    (125, "nested_index",
     r"\]\s*\[\s*[a-zA-Z_]\w*\s*\]|\[\s*[^\]]*\[[^\]]*\]\s*\]|\[[^\]]*\.at\s*\(|\[[^\]]*->\s*\w+\s*\]",
     "二次/嵌套/派生下标（arr[x][i]、arr[map.at(k)]、arr[obj->field]）——AR-1 json[name][i] / X1-9 同款", "high"),
    (787, "index_write_raw",
     r"\[\s*(?:i|j|k|idx|n)\s*\]\s*=",
     "数组下标写入（arr[i] = v）——越界写信号（NCNN blob.consumer=i 同款）", "medium"),
    (787, "config_pointer_offset",
     r"(?P<base>\w+)\s*\+\s*[^;\n]*(?:id_|can_id|index|offset)\s*[-+]?\s*\(?\s*1\s*\)?",
     "配置/消息字段参与指针偏移，需核对索引范围与底层缓冲区容量（AGIBOT PowerFlowR 同款）", "high"),

    # ===== CWE-190 整数溢出：长度/计数相乘或增长 =====
    (787, "partial_param_id_guard",
      r"if\s*\(\s*id\s*>=\s*NCNN_MAX_PARAM_COUNT\s*\)",
      "parameter parser id has only an upper-bound check; require a non-negative lower bound on text and binary paths", "high"),
     (703, "partial_init_cleanup",
       r"\b(?:register_callback|create_backend|open_backend)\s*\([^;]*\)\s*;[\s\S]{0,260}?\breturn\s+-1\s*;",
       "initialization registers or creates a resource before a failure return without an obvious rollback/state guard", "medium"),
     (703, "parser_error_continue",
       r"if\s*\(\s*(?:pdlr|lr)\s*!=\s*0\s*\)\s*\{[\s\S]{0,360}?\bcontinue\s*;",
       "parser layer-load failure continues with a partially initialized layer instead of cleaning up and returning an error", "high"),
     (787, "unchecked_blob_index",
      r"\bd->blobs\[\s*(?:bottom_blob_index|top_blob_index)\s*\]",
      "model blob index is used before a [0, blob_count) input-range check", "high"),
     (787, "text_blob_index_access",
      r"\bd->blobs\[\s*blob_index\s*\]",
      "text parser blob_index is used before a blob_count capacity check; validate the generated index before access", "high"),
     (190, "unchecked_parser_count",
      r"(?:d->(?:layers|blobs)|layer->(?:bottoms|tops))\.resize\(\s*(?:layer_count|blob_count|bottom_count|top_count)\s*\)",
      "parser count reaches resize without a bounded input-count contract", "high"),
     (476, "array_length_contract",
      r"\bd->params\s*\[\s*id\s*\]\.v\.create\(\s*len\s*\)",
      "parameter array length reaches allocation and subsequent I/O without an input-length/allocation contract", "high"),

     (787, "text_layer_header_contract",
      r"SCAN_VALUE\(\s*\"%255s\"\s*,\s*layer_type\s*\)[\s\S]{0,240}?SCAN_VALUE\(\s*\"%d\"\s*,\s*top_count\s*\)",
      "text model layer header reads type/name/count fields across scans without an explicit same-line token contract", "high"),
     (20, "paramdict_terminal_quote_rescan",
       r'\bdr\.scan\(\s*"%255\[\^\\"\\n\]\\""\s*,\s*vstr2\s*\)',
       "ParamDict rescans after a quoted token without proving that the first scan did not already consume its closing quote", "high"),
     (190, "pointer_offset_int_multiply",
      r"(?:\.cstep\s*=\s*|(?:const\s+)?unsigned\s+char\s*\*\s*\w+\s*=\s*\([^)]*\)\s*[\w>\-]+\s*\+\s*)(?!(?:\(\s*size_t\s*\)|static_cast\s*<\s*size_t\s*>\s*\())\w+\s*\*\s*\w+",
      "pointer offset or cstep is multiplied in int domain before being widened; promote an operand to size_t before multiplication", "high"),
     (190, "unchecked_shape_product_narrow",
      r"(?:static_cast\s*<\s*(?:int|int32_t)\s*>|narrow\s*<\s*(?:int|int32_t)\s*>)\s*\([^;\n]*(?:seq_length|batch_size|shape|count|dim|stride)[^;\n]*\*[^;\n]*\)",
      "shape/count product is narrowed after an unchecked multiplication; checked arithmetic must happen before the multiply", "medium"),
     (190, "zero_extent_offset",
      r"\(\s*(?:seq_length|length|count|extent|dim)\w*\s*-\s*1\s*\)\s*\*\s*[A-Za-z_]\w*",
      "shape-derived count minus one participates in an offset without a visible zero-extent contract", "medium"),
     (190, "size_mult",
     r"(?P<expr>(?:sizeof\s*\(\s*\w+\s*\)|elem_size|size)\s*\*\s*(?:\w+|\([^)]+\)))",
     "大小乘法：len × elemsize 未检查溢出（MindSpore dims→字节数 同款）", "medium"),
    (190, "resize_from_attacker",
     r"\.(?:resize|create|assign|push_back)\(\s*(?P<v>(?:msg|data|buf|len|count|n|size)\w*)\s*\)",
     "用外部输入直接 resize/create，未校验上限（NCNN layer_count/blob_count 同款）", "high"),
    (190, "index_arith",
     r"(?P<e>(?:\w+\s*\+\s*\w+|\w+\s*\*\s*\w+|\w+\s*-\s*\w+))(?=\s*[;\])])",
     "索引/偏移算术，未检查符号与范围（泛化模式，低置信）", "low"),
    (190, "size_truncation",
     r"(?:\(int\)|\(int32_t\)|\(uint32_t\))\s*(?P<v>[a-zA-Z_]\w*)",
     "size_t/int64 → int 显式截断：大值截断后分配不足，但后续按未截断值使用 → 越界（MNN FileLoader::merge 同款）", "medium"),
    (190, "static_cast_narrow_truncation",
     r"static_cast\s*<\s*(?:int|int32_t|uint32_t)\s*>\s*\(\s*(?P<v>(?:model_data_length|data_length|buffer_length|length|size|count|dim)\w*)\s*\)",
     "size_t/int64 型长度经 static_cast 窄化为 int/int32_t，未见显式上限检查——ORT PR #28112 同款（应先检查 INT32_MAX 再 narrow）", "medium"),
    (129, "declared_length_contract",
     r"(?:observations_size|actions_size|array_size_|num_hist)\s*[^;\n]*(?:resize|segment|tail|head|CreateTensor|<<)",
     "配置声明长度参与向量/张量构造，需核对声明值、实际写入维度与模型输入 shape 一致", "medium"),
    (125, "memcpy_source_contract",
     r"\bmemcpy\s*\([^;\n]+,\s*[^;\n]*(?:qpos|qvel|qfrc_actuator|sensordata)[^;\n]*(?:size\(\)|count|num|sizeof)",
     "memcpy 长度由运行时数量决定，需核对源数组容量、偏移和目标容器长度", "medium"),
    (125, "config_index_access",
     r"(?:buttons|axis|position|velocity|effort)\s*\[\s*(?:button|axis|index|.*\.at\s*\([^)]*\))\s*\]",
     "配置索引参与消息数组访问，需校验索引范围并处理缺失配置", "high"),
    (129, "model_output_contract",
     r"(?:output_values|GetTensorMutableData|actions_|output_shapes?)\s*[^;\n]*(?:actions_size|\+\s*i|resize)",
     "模型输出长度与配置动作维度共同决定数组访问，需核对输出 shape 与 actions_size", "medium"),
    (190, "signed_unsigned_assign",
     r"(?P<v>[a-zA-Z_]\w*)\s*=\s*(?:int|int32_t|size_t)\s*\)\s*(?P<src>[a-zA-Z_]\w*)",
     "有符号/无符号强制转换赋值（截断/符号扩展风险，MNN merge 同族）", "low"),

    # ===== CWE-369 除零：除法/模的分母未校验 =====
    (369, "divide_by_input",
     r"/\s*(?P<d>[\w.]+)\s*[;)]",
     "除法分母为变量，未确认非零（NCNN shape_hints.w/top_count 同款）", "medium"),
    (369, "mod_by_input",
     r"%\s*(?P<d>[\w.]+)\s*[;)]",
     "取模分母为变量，未确认非零（AGIBOT freq:0 同款）", "medium"),

    # ===== CWE-476 空指针解引用（泛化模式，误报高 → 低置信）=====
    (476, "deref_after_alloc",
     r"(?P<fn>\w+)\s*\(\s*\)[\s\S]{0,120}?(?P<ptr>\w+)\s*->",
     "调用返回后直接解引用，未见判空（泛化模式——需确认调用可能返回 null 才有效）", "low"),

    # ===== CWE-248 未捕获异常：.at() 无 try/catch =====
    (248, "at_uncaught",
     r"(?:map|unordered_map|dict|_map_)[\w_]*\.at\s*\(",
     "容器 .at() 可能抛 out_of_range，回调无 try/catch（AGIBOT X1-8 同款）", "high"),
    (476, "iterator_end_deref",
     r"(?P<it>\b(?:iter|it|itr|entry|node)\b)\s*->\s*(?:second|first|value|key)",
     "迭代器成员在使用前未显式确认 != end()，配置条目不足时可能解引用无效迭代器", "medium"),
    (476, "loader_result_deref",
     r"(?P<loader>mj_loadXML|loadModel|LoadModel|load_model)\s*\([^;]+\)[\s\S]{0,180}?\b(?P<obj>m_|model_|model)\s*->",
     "模型加载返回值后继续解引用，需处理加载失败/空指针分支（AGIBOT SimModule 同款）", "high"),

    # ===== 逻辑类（Python/脚本）：认证/反序列化/注入 =====
    (306, "bind_all_interfaces",
     r"(?:host\s*=\s*['\"]0\.0\.0\.0['\"]|bind\s*\(\s*['\"]tcp://0\.0\.0\.0|0\.0\.0\.0\s*:\d+)",
     "服务绑定所有接口 0.0.0.0（默认网络可达，无认证则暴露——XR VUL-01/04 同款）", "high"),
    (78, "command_from_config",
     r"\bsystem\s*\([^;\n]*(?:config|cfg|service_name|interface_type|cmd|command)[^;\n]*\)",
     "命令执行参数来自配置/运行时字符串，建议白名单与参数化 API，避免 shell 字符串拼接", "high"),
    (306, "no_auth_server",
     r"(?:CERT_NONE|verify_mode\s*=\s*ssl\.CERT_NONE|Access-Control-Allow-Origin:\s*\*|allow_origin\s*=\s*['\"]\*['\"])",
     "无认证/TLS 不校验/通配 CORS（XR VUL-01/04 同款）", "high"),
    (502, "pickle_load",
     r"pickle\.load\s*\(|pickle\.loads\s*\(",
     "pickle 反序列化不可信数据 → 任意代码执行（XR VUL-02 同款）", "high"),
    (78, "shell_concat",
     r"system\s*\(\s*[^)]*\+|os\.system\s*\(\s*f?['\"][^'\"]*\{|subprocess\.[A-Za-z]+\s*\(\s*shell\s*=\s*True",
     "shell 命令拼接未净化（XR/AGIBOT X1-1 system() 同款）", "high"),
    (20, "no_input_clamp",
     r"(?:thumbstick|joystick|axis|input)\w*\s*[\*x]\s*(?:0\.3|0\.5|speed|scale)|Move\s*=\s*\w+\s*\*\s*\w+",
     "控制器输入无范围校验（clamp）——XR VUL-05 限速绕过同款", "high"),

    # ===== CWE-190/787 I/O 读取大小参数（MNN FileLoader 同款）=====
    (190, "read_size_unchecked",
     r"(?:fread|fwrite)\s*\(\s*[^,]+,\s*[^,]+,\s*(?P<sz>[a-zA-Z_]\w*)\s*,|memcpy|memmove\s*\(\s*[^,]+,\s*[^,]+,\s*(?P<sz2>[a-zA-Z_]\w*)\s*\)",
     "I/O/内存操作大小参数直接来自调用方（int64_t/攻击者可控），未见上界校验——MNN FileLoader::read 同款", "medium"),
    (787, "alloc_then_read",
     r"(?:MNNMemoryAllocAlign|malloc|new\s+\w+\[)\s*\([^)]*\)[\s\S]{0,150}?fread\s*\(\s*[^,]+,\s*[^,]+,\s*(?P<sz>[a-zA-Z_]\w*)\s*,|fread\s*\(\s*[^,]+,\s*[^,]+,\s*(?P<sz2>[a-zA-Z_]\w*)\s*,",
     "按大小分配后直接 fread 读入，大小未与分配量校验（读越界风险）", "medium"),
]

CWE_NAMES = {125: "Out-of-bounds Read", 787: "Out-of-bounds Write",
             190: "Integer Overflow", 369: "Divide By Zero", 476: "Null Deref", 703: "Improper Error Handling",
             248: "Uncaught Exception", 306: "Missing Auth", 502: "Unsafe Deserialization",
             78: "Command Injection", 20: "Improper Input Validation"}


# ---- 误报过滤规则：每项 = (模式名, 判定函数) ----
def _is_map_insert(line):
    """map/vector operator[] 赋值语义（map[key] = v 合法，非越界读）"""
    # 仅当左侧是 map/容器名 时才算 insert（arr[i]= 是越界写信号，不过滤）
    return bool(re.search(r"(?:map|unordered_map|dict|_map_|lookup)[\w_]*\s*\[\s*[^]]+\]\s*=", line)) or "insert(" in line or "emplace" in line

def _has_guard_in_context(lines, lineno):
    """当前行前后 3 行内是否有真正的边界守卫：
    - if + 比较 + 边界（< 0 / >= / > size 类）
    - throw ... exceeded/out of range（范围限制异常）
    """
    ctx = lines[max(0, lineno-4):min(len(lines), lineno+2)]
    joined = " ".join(ctx)
    if re.search(r"if\s*\([^)]*(?:< 0|>=|> [a-z_]+\.(?:size|count|len)|< [a-z_]+\.(?:size|count|len))", joined):
        return True
    # 等长检查守卫：if (A == B.size()) 或 if (A != B.size()) throw/return（AimRT WriteMember 同款）
    if re.search(r"==\s*[\w\[\].]*(?:size|count|len)\(\)|!=\s*[\w\[\].]*(?:size|count|len)\(\)", joined):
        return True
    # throw ... exceeded / out of range / too large：范围守卫异常
    if re.search(r"throw[^;]*(?:exceed|out of range|too (?:large|small)|invalid)", joined, re.I):
        return True
    return False

def _is_map_read(line):
    """map 类容器的 operator[] 读取（有插入语义，误报概率高）"""
    return bool(re.search(r"(?:map|unordered_map|dict|_map_|_index_|lookup)[\w_]*\s*\[", line))


def _is_index_from_map_at(line):
    """arr[map.at(key)] —— map.at 返回值作为数组下标（X1-9 模式，真实漏洞信号）"""
    return bool(re.search(r"\[[^\]]*\.at\s*\(", line))


def filter_false_positive(finding, lines, lineno):
    """返回 True 表示应过滤（误报）。"""
    line = lines[lineno - 1]
    pattern = finding["pattern"]
    if pattern == "array_index_raw":
        # 0) map.at() 返回值作为数组下标 → 真实漏洞信号，最高优先级保留（X1-9）
        if _is_index_from_map_at(line):
            return False
        # 1) map 赋值语义（insert）→ 过滤
        if _is_map_insert(line):
            return True
        # 2) 纯 map 读（插入语义）→ 过滤
        if _is_map_read(line):
            return True
        # 3) 同函数已有守卫 → 过滤（保守：宁可少报不误报）
        if _has_guard_in_context(lines, lineno):
            return True
        # 4) 内部成员遍历（members_/member_info/typeinfo 等）→ 非外部输入索引，过滤
        if re.search(r"(?:member_info|members_|member|typeinfo|meta)[\w_]*\s*\[", line):
            return True
        # 5) resize 后索引（动态分配）→ 安全，过滤（上下文含 resize/create）
        if re.search(r"resize|create|reserve", " ".join(lines[max(0, lineno-4):lineno+1])):
            return True
    if pattern in ("nested_index", "map_at_index"):
        # 只保留确实含有数组/容器下标的表达式；nullptr 等箭头条件不是 nested index。
        if not re.search(r"\[[^\]]+\]", line):
            return True
        # 内部索引向量模式（xxx_ids_[i]、archs_[i]、active_ids_[0]）通常不是外部输入。
        if re.search(r"\w+_ids?_\s*\[", line) or re.search(r"archs?_\s*\[|active_ids?_\s*\[|cache_\s*\[|cluster_ids?_\s*\[", line):
            return True
        return False
    if pattern in ("divide_by_input", "mod_by_input"):
        # 明确的字面量、sizeof、编译期宏和常见固定仿真常量不属于输入驱动除零。
        m = re.search(r"[%/]\s*(?P<d>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?|\d+)", line)
        if not m:
            return True
        den = m.group("d")
        if den.isdigit() or den in ("size", "count", "len", "sizeof", "mjNFRAME", "mjNLABEL", "mjNGROUP", "mjNENABLE", "mjNDISABLE"):
            return True
        # 分母是明显的固定成员/编译期配置，而非消息、配置或模型字段。
        if den.startswith(("kMax", "MAX_", "default_", "constexpr_")):
            return True
        # 已有非零保护时不再报告。
        ctx = " ".join(lines[max(0, lineno - 5):lineno + 1])
        if re.search(rf"(?:if|assert|CHECK)\s*\([^)]*\b{re.escape(den)}\b\s*(?:!=|>)\s*0", ctx):
            return True
    if pattern == "text_blob_index_access":
        # Text parsing creates blob_index sequentially; retain the candidate unless
        # the same path proves a capacity check before the access.
        ctx = " ".join(lines[max(0, lineno - 32):lineno])
        if re.search(r"\bblob_index\s*>=\s*blob_count", ctx) or re.search(r"\bblob_index\s*<\s*blob_count", ctx):
            if re.search(r"(?:return|clear|reject|invalid|error)", ctx, re.I):
                return True
    if pattern == "unchecked_blob_index":
        # 修复后的 NCNN 路径必须在同一路径紧邻访问前同时检查下限和上限。
        match = re.search(r"d->blobs\[\s*(?P<idx>bottom_blob_index|top_blob_index)\s*\]", line)
        if match:
            idx = match.group("idx")
            ctx = " ".join(lines[max(0, lineno - 24):lineno])
            if (re.search(rf"\b{re.escape(idx)}\s*<\s*0", ctx) and
                    re.search(rf"\b{re.escape(idx)}\s*>=\s*blob_count", ctx)):
                return True
    if pattern == "unchecked_parser_count":
        # 过滤 PR-6922 同款已加固 resize：负值/上限均在分配前检查。
        match = re.search(r"resize\(\s*(?P<count>layer_count|blob_count|bottom_count|top_count)\s*\)", line)
        if match:
            count = match.group("count")
            # Count guards commonly sit after decoding and before resize, with
            # layer construction code between the guard and the allocation.
            ctx = " ".join(lines[max(0, lineno - 96):lineno])
            lower = rf"\b{re.escape(count)}\s*(?:<=|<)\s*0"
            upper = rf"\b{re.escape(count)}\s*>\s*(?:MAX_[A-Z_]+|\d+)"
            if re.search(lower, ctx) and re.search(upper, ctx):
                return True
    if pattern == "array_length_contract":
        # 修复后的 ParamDict 路径拒绝非正长度并检查 Mat::create 结果。
        before = " ".join(lines[max(0, lineno - 24):lineno])
        after = " ".join(lines[lineno:min(len(lines), lineno + 8)])
        if re.search(r"\blen\s*<=\s*0", before) and re.search(r"\.v\.empty\s*\(\s*\)", after):
            return True
    if pattern == "paramdict_terminal_quote_rescan":
        # PR #6337: a short quoted token may already include its closing quote.
        # The fixed path scans again only when the terminal quote is absent.
        before = " ".join(lines[max(0, lineno - 14):lineno])
        if "vstr[0]" not in before:
            return True
        if re.search(r"\b(?:end|vstr\[[^\]]+\])\s*!=", before):
            return True
    if pattern == "parser_error_continue":
        # PR #6383: cleanup + explicit error return replaces continue.
        ctx = " ".join(lines[max(0, lineno - 1):min(len(lines), lineno + 16)])
        if re.search(r"delete\s+layer", ctx) and re.search(r"clear\s*\(\s*\)", ctx) and re.search(r"return\s+-1", ctx):
            return True
    if pattern == "partial_init_cleanup":
        ctx = " ".join(lines[max(0, lineno - 1):min(len(lines), lineno + 20)])
        if re.search(r"(?:unregister|release|destroy|cleanup|reset|initialized\s*=)", ctx, re.I):
            return True
    if pattern == "unchecked_shape_product_narrow":
        ctx = " ".join(lines[max(0, lineno - 6):min(len(lines), lineno + 4)])
        if re.search(r"SafeInt|safe[_ ]?multiply|checked|overflow|numeric_limits", ctx, re.I):
            return True
    if pattern == "zero_extent_offset":
        ctx = " ".join(lines[max(0, lineno - 20):lineno])
        if re.search(r"(?:seq_length|length|count|extent|dim)\w*\s*(?:==|<=)\s*0|zero[_ -]?fill|empty", ctx, re.I):
            return True
    if pattern == "divide_by_input":
        # 支持嵌套调用的守卫，例如 if (!shape_hints.empty() && top_count > 0)。
        m = re.search(r"[%/]\s*(?P<d>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?|\d+)", line)
        if m:
            den = m.group("d")
            ctx_lines = lines[max(0, lineno - 5):lineno]
            if any(re.search(rf"\b(?:if|assert|CHECK)\b[^;\n]*\b{re.escape(den)}\b\s*(?:!=|>)\s*0", value)
                   for value in ctx_lines):
                return True
    if pattern == "partial_param_id_guard":
        # The exact partial guard is itself the candidate; a complete guard does not match it.
        return False
    if pattern == "at_uncaught":
        # .at() 调用本身是越界信号（可能抛异常），不过滤
        # 若上下文有 try/catch 才算安全
        ctx = " ".join(lines[max(0, lineno-4):lineno+1])
        if "try" in ctx:
            return True
    if pattern == "read_size_unchecked":
        # 自洽构造参数豁免：同函数/构造函数内 new char[size] 或 reset(size) 与 memcpy 大小一致
        # （TNN RawBuffer 案例：分配与拷贝同 bytes_size，安全）
        ctx = " ".join(lines[max(0, lineno-6):lineno+1])
        m = re.search(r"(?:read_size_unchecked|memcpy|fread|fwrite)\s*\(\s*[^,]+,\s*[^,]+,\s*(?P<sz>[a-zA-Z_]\w*)", line)
        if m and m.group("sz"):
            sz = m.group("sz")
            # 同窗口内有 new char[sz] 或 reset(sz) 或 = sz 赋值 → 自洽
            if re.search(r"new\s+char\s*\[\s*" + re.escape(sz) + r"\s*\]|reset\s*\(\s*\(?\s*(?:int\s*)?\s*" + re.escape(sz) + r"\s*\)?", ctx):
                return True
            # size 来自常量（gCacheSize/sizeof）→ 安全
            if sz in ("gCacheSize", "sizeof", "size_t"):
                return True
    return False


COMPONENT_INPUT_HINTS = {
    "agibot": ("joint_state", "jointcommand", "sensor_msgs", "cmd.position", "cmd.velocity", "cmd.effort", "msg->", "joint_names"),
    "aimrt": ("json", "root", "request", "payload", "member.name_", "array_size_"),
    "ncnn": ("param", "blob", "layer_count", "top_count", "bottom_count", "shape_hints"),
    "mindspore": ("dims", "content", "checkpoint", "tensor", "buffer"),
}


def classify_evidence(finding, component=None):
    """Classify likely source of an index/size/divisor without claiming reachability."""
    text = " ".join([finding.get("evidence", ""), finding.get("context", "")]).lower()
    if component:
        for hint in COMPONENT_INPUT_HINTS.get(component.lower(), ()):
            if hint.lower() in text:
                return "external-like"
    if re.search(r"\b(msg|data|buf|packet|cmd|input|config|json|root|request|content|payload)\w*", text):
        return "external-like"
    if re.search(r"\b(freq|interval|count|size|len|dim|shape|index|id|n[a-z_]*)\b", text):
        return "runtime-state"
    if re.search(r"\b(mj[a-z_]+|constexpr|const |static const|kmax|max_)\b", text):
        return "constant-or-library"
    return "internal-state"


def confidence_for(finding):
    """Add a review priority, not a vulnerability verdict."""
    if finding.get("pattern") in ("index_from_attacker", "nested_index") and finding.get("evidence_source") == "external-like":
        return "high"
    if finding.get("pattern") in ("parallel_array_loop", "size_truncation", "alloc_then_read"):
        return "medium"
    if finding.get("pattern") in ("partial_param_id_guard", "parser_error_continue", "partial_init_cleanup", "unchecked_blob_index", "unchecked_parser_count", "array_length_contract", "paramdict_terminal_quote_rescan", "pointer_offset_int_multiply", "unchecked_shape_product_narrow", "zero_extent_offset", "text_layer_header_contract", "text_blob_index_access"):
        return "high"
    return "low"


def repair_requirements(finding):
    """Describe review obligations for a candidate; this is not an auto-fix."""
    pattern = finding.get("pattern")
    if pattern == "parallel_array_loop":
        return ["validate all parallel array lengths before the loop"]
    if pattern in ("nested_index", "index_from_attacker"):
        text = (finding.get("evidence", "") + " " + finding.get("context", "")).lower()
        requirements = ["validate derived index is non-negative and within the selected array length"]
        if ".at(" in text or "_[" in text or "map[" in text:
            requirements.insert(0, "validate key existence and reject default-inserted map indices")
        return requirements
    if pattern == "divide_by_input":
        return ["validate divisor is non-zero before division"]
    if pattern == "config_pointer_offset":
        return ["validate configured index against buffer capacity before pointer arithmetic", "validate configuration source and reject out-of-range IDs"]
    if pattern == "iterator_end_deref":
        return ["check iterator is not end() before dereference", "validate configuration contains the required number of entries"]
    if pattern == "loader_result_deref":
        return ["check model loader return value before every dependent dereference", "return or enter an explicit error state when loading fails"]
    if pattern == "declared_length_contract":
        return ["validate configured length against actual constructed/write dimension", "validate model input shape and history multiplier before tensor creation"]
    if pattern == "memcpy_source_contract":
        return ["validate source capacity and pointer offset before memcpy", "ensure copy length is no greater than both source and destination capacity"]
    if pattern == "config_index_access":
        return ["validate configured index against runtime message length", "reject missing or out-of-range configuration entries before array access"]
    if pattern == "model_output_contract":
        return ["validate model output rank and element count before indexed reads", "require configured action dimension to match output shape"]
    if pattern == "command_from_config":
        return ["replace shell-string execution with a parameterized API", "validate command and arguments against an explicit allowlist"]
    if pattern == "size_truncation":
        return ["validate source value fits destination integer range before narrowing"]
    if pattern == "partial_param_id_guard":
        return ["validate parser id is non-negative and below NCNN_MAX_PARAM_COUNT before every parameter access", "apply the same id-range contract to text and binary parser paths"]
    if pattern == "unchecked_blob_index":
        return ["validate blob index is non-negative and less than blob_count before d->blobs access", "apply equivalent guards to both bottom and top index paths"]
    if pattern == "text_blob_index_access":
        return ["validate generated text-path blob_index before every d->blobs access", "reject a layer whose declared bottom/top names would create more blobs than blob_count"]
    if pattern == "unchecked_parser_count":
        return ["validate decoded count for sign and an explicit upper bound before resize", "mirror count validation across text and binary loaders"]
    if pattern == "array_length_contract":
        return ["reject non-positive or over-limit array lengths before allocation", "check allocation result before reading or writing the allocated buffer"]
    if pattern == "paramdict_terminal_quote_rescan":
        return ["do not rescan a quoted token when its first scan already consumed the closing quote", "preserve the next key-value token after a complete quoted string"]
    if pattern == "parser_error_continue":
        return ["destroy the partially initialized layer on parser failure", "clear parser-owned state and return an explicit error instead of continuing"]
    if pattern == "partial_init_cleanup":
        return ["roll back every resource registered before the failure", "guard callbacks and later run/destructor paths with an initialization-complete state"]
    if pattern == "pointer_offset_int_multiply":
        return ["promote one pointer-offset operand to size_t before multiplication", "keep byte-offset and cstep arithmetic in size_t through the address calculation"]
    if pattern == "unchecked_shape_product_narrow":
        return ["check the product before narrowing it to int/int32_t", "return a controlled invalid-shape result when checked multiplication fails"]
    if pattern == "zero_extent_offset":
        return ["define the zero-extent behavior before subtracting one", "avoid negative offsets and preserve valid empty-input semantics"]
    if pattern == "text_layer_header_contract":
        return ["validate all required layer-header fields are consumed from the same input record", "reject truncated or extra-token layer headers before using bottom_count/top_count"]
    return ["review input validation and error-path semantics"]


def display_path(path):
    """Return a stable display path even when source is on a WSL UNC share."""
    try:
        return os.path.relpath(path)
    except ValueError:
        # Windows cannot relativize a UNC mount against the current drive.
        return os.path.normpath(path)


def _finding_key(finding):
    """Return a stable, content-based identity for a candidate location."""
    raw = "|".join([
        finding["file"], str(finding["line"]), str(finding["cwe"]),
        finding["pattern"], finding.get("evidence", "")[:120],
    ])
    return "cr-" + hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()[:12]


def merge_findings(findings, line_distance=2):
    """Merge same-location findings while preserving all detection evidence.

    This is presentation/data normalization, not a claim that merged candidates
    are one confirmed vulnerability. The original patterns and lines remain
    available for agent or human review.
    """
    merged = []
    for finding in sorted(findings, key=lambda x: (x["file"], x["line"], x["cwe"], x["pattern"])):
        target = None
        for candidate in reversed(merged):
            if candidate["file"] != finding["file"]:
                break
            if finding["line"] - candidate["last_line"] > line_distance:
                break
            if candidate["cwe"] != finding["cwe"]:
                continue
            target = candidate
            break
        if target is None:
            item = dict(finding)
            item["patterns"] = [finding["pattern"]]
            item["evidence_lines"] = [finding["line"]]
            item["evidence_items"] = [{"pattern": finding["pattern"], "line": finding["line"], "evidence": finding["evidence"]}]
            item["last_line"] = finding["line"]
            merged.append(item)
        else:
            if finding["pattern"] not in target["patterns"]:
                target["patterns"].append(finding["pattern"])
            if finding["line"] not in target["evidence_lines"]:
                target["evidence_lines"].append(finding["line"])
            target["evidence_items"].append({"pattern": finding["pattern"], "line": finding["line"], "evidence": finding["evidence"]})
            target["last_line"] = finding["line"]
            target["context"] = (target["context"] + " | " + finding["context"])[:500]
    for item in merged:
        item.pop("last_line", None)
        item["finding_key"] = _finding_key(item)
    return merged


def detect_in_file(path, cwes, no_filter=False, include_low=False, component=None):
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        return findings
    seen_window_hits = set()
    loader_lines = [i + 1 for i, value in enumerate(lines)
                    if re.search(r"\b(?:m_|model_|model)\s*=\s*(?:mj_loadXML|loadModel|LoadModel|load_model)\s*\(", value)]
    for lineno, line in enumerate(lines, 1):
        stripped_line = line.strip()
        # 全局过滤：注释/#include/纯字符串/文档行不检测（减少注释误报，ORT 扫描发现）
        if (stripped_line.startswith(("//", "/*", "*", "#", "//")) or
                "#include" in stripped_line or
                stripped_line.startswith("// The") or
                (stripped_line.startswith('"') and stripped_line.endswith('"'))):
            continue
        for cwe, name, pattern, desc, conf in PATTERNS:
            if cwes and cwe not in cwes:
                continue
            # 低置信模式默认关闭（需 --include-low）
            if conf == "low" and not include_low:
                continue
            if name == "loader_result_deref":
                # 两阶段匹配：加载赋值后 60 行内出现同一对象成员访问。
                prior_loader = any(0 < lineno - load_line <= 60 for load_line in loader_lines)
                m = re.search(r"\b(?:m_|model_|model)\s*->", line) if prior_loader else None
            elif name in ("parallel_array_loop", "alloc_then_read"):
                window = "".join(lines[max(0, lineno-6):lineno])
                m = re.search(pattern, window)
            elif name == "text_layer_header_contract":
                window = "".join(lines[max(0, lineno - 1):lineno + 8])
                m = re.search(pattern, window)
            elif name == "parser_error_continue":
                # Anchor the cross-line rule only on the error-condition line.
                if not re.search(r"if\s*\(\s*(?:pdlr|lr)\s*!=\s*0", line):
                    m = None
                else:
                    window = "".join(lines[lineno - 1:min(len(lines), lineno + 16)])
                    m = re.search(pattern, window)
            elif name == "partial_init_cleanup":
                # Review lifecycle candidates from the registration/create line.
                if not re.search(r"(?:->|\.)\s*(?:register_callback|create_backend|open_backend)\s*\(", line):
                    m = None
                else:
                    window = "".join(lines[lineno - 1:min(len(lines), lineno + 20)])
                    m = re.search(pattern, window)
            else:
                m = re.search(pattern, line)
            if m:
                # 窗口模式同一 for/body 会在多个行号重复命中，只保留首次证据点。
                if name == "loader_result_deref":
                    window_key = (os.path.abspath(path), name)
                    if window_key in seen_window_hits:
                        continue
                    seen_window_hits.add(window_key)
                elif name in ("parallel_array_loop", "alloc_then_read"):
                    window_key = (os.path.abspath(path), name, m.group(0))
                    if window_key in seen_window_hits:
                        continue
                    seen_window_hits.add(window_key)
                elif name == "text_layer_header_contract":
                    window_key = (os.path.abspath(path), name)
                    if window_key in seen_window_hits:
                        continue
                    seen_window_hits.add(window_key)
                elif name in ("parser_error_continue", "partial_init_cleanup"):
                    window_key = (os.path.abspath(path), name, lineno)
                    if window_key in seen_window_hits:
                        continue
                    seen_window_hits.add(window_key)
                # 提取上下文（前后 1 行）
                ctx = " ".join(l.strip() for l in lines[max(0, lineno-2):lineno+1])
                finding = {
                    "file": display_path(path),
                    "line": lineno,
                    "cwe": cwe,
                    "cwe_name": CWE_NAMES.get(cwe, ""),
                    "pattern": name,
                    "evidence": line.strip()[:120],
                    "context": ctx[:300],
                    "desc": desc,
                }
                finding["evidence_source"] = classify_evidence(finding, component)
                finding["confidence"] = confidence_for(finding)
                finding["repair_requirements"] = repair_requirements(finding)
                if not no_filter and filter_false_positive(finding, lines, lineno):
                    continue
                findings.append(finding)
    return findings


def main():
    ap = argparse.ArgumentParser(description="CWE 模式检测器（越界/溢出/除零）")
    ap.add_argument("target", help="文件或目录")
    ap.add_argument("--cwe", default="125,787,190,369,476,248", help="逗号分隔 CWE 列表")
    ap.add_argument("--json", action="store_true", help="JSON 输出")
    ap.add_argument("--ext", default=".cpp,.cc,.c,.h,.hpp,.cxx", help="扫描扩展名")
    ap.add_argument("--no-filter", action="store_true", help="关闭误报过滤（原始命中）")
    ap.add_argument("--include-low", action="store_true", help="包含低置信泛化模式（index_arith/array_index_raw，默认关闭以降误报）")
    ap.add_argument("--component", choices=["agibot", "aimrt", "ncnn", "mindspore", "xr"], help="组件语义提示，用于证据分层，不改变规则命中")
    args = ap.parse_args()

    cwes = {int(x) for x in args.cwe.split(",") if x.strip()}
    exts = set(args.ext.split(","))

    files = []
    if os.path.isfile(args.target):
        files = [args.target]
    else:
        for root, _, fnames in os.walk(args.target):
            # 跳过构建目录
            if any(skip in root for skip in ("build", ".git", "node_modules", "venv")):
                continue
            for fn in fnames:
                if os.path.splitext(fn)[1] in exts:
                    files.append(os.path.join(root, fn))

    all_findings = []
    for f in files:
        all_findings.extend(detect_in_file(f, cwes, no_filter=args.no_filter, include_low=args.include_low, component=args.component))

    raw_count = len(all_findings)
    all_findings = merge_findings(all_findings)

    # 按 CWE 分组统计
    stats = {}
    for fnd in all_findings:
        stats[fnd["cwe"]] = stats.get(fnd["cwe"], 0) + 1

    if args.json:
        print(json.dumps({"files_scanned": len(files), "raw_findings": raw_count,
                          "merged_findings": len(all_findings),
                          "stats": {str(k): v for k, v in sorted(stats.items())},
                          "findings": all_findings}, ensure_ascii=False, indent=1))
    else:
        print(f"扫描文件: {len(files)}  原始命中: {raw_count}  合并候选: {len(all_findings)}")
        print(f"按 CWE 分布: {', '.join(f'{CWE_NAMES.get(k,k)}={v}' for k, v in sorted(stats.items()))}")
        print("-" * 100)
        for fnd in all_findings:
            print(f"[CWE-{fnd['cwe']} {fnd['pattern']}] {fnd['file']}:{fnd['line']}")
            print(f"    {fnd['evidence']}")


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    main()
