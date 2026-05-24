#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
零成本鸿蒙代码AI查询工具 v2.0
完全重写版 - 修复所有已知缺陷

改进清单：
  [致命] 移除不存在的 arkanalyzer 依赖，改用自研纯Python ArkTS解析器
  [致命] API Key 改为环境变量读取
  [致命] AI生成的SQL增加安全校验（只允许SELECT）
  [严重] 数据库表增加主键和索引
  [严重] 使用上下文管理器确保连接关闭
  [严重] 支持增量解析（CREATE TABLE IF NOT EXISTS）
  [中等] SQLite连接设置超时
  [中等] 数据库使用绝对路径
  [中等] 健壮的SQL清理逻辑
  [中等] 完善的异常处理
  [轻微] 支持命令行参数
  [轻微] 解析进度反馈
  [轻微] requirements.txt
"""

import os
import re
import sys
import sqlite3
import argparse
import logging
import threading
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field

# ============================================================
# 日志配置
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


# ============================================================
# 数据模型
# ============================================================
@dataclass
class ArkDecorator:
    """ArkTS 装饰器"""
    name: str
    params: str = ""


@dataclass
class ArkMethod:
    """ArkTS 方法"""
    name: str
    params: str = ""
    return_type: str = ""
    decorators: List[ArkDecorator] = field(default_factory=list)
    body: str = ""
    line_start: int = 0
    line_end: int = 0


@dataclass
class ArkClass:
    """ArkTS 类/结构体"""
    name: str
    file_path: str
    kind: str = "struct"  # struct, class, interface, enum
    decorators: List[ArkDecorator] = field(default_factory=list)
    methods: List[ArkMethod] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)
    line_start: int = 0
    line_end: int = 0
    extends: str = ""
    implements: List[str] = field(default_factory=list)
    body: str = ""  # 类体原始源码（用于提取变量类型声明）

    @property
    def is_component(self) -> bool:
        return any(d.name == "Component" for d in self.decorators)

    @property
    def is_entry(self) -> bool:
        return any(d.name == "Entry" for d in self.decorators)

    @property
    def is_page(self) -> bool:
        return any(d.name == "Entry" for d in self.decorators)


@dataclass
class ArkImport:
    """ArkTS 导入语句"""
    raw: str
    module: str = ""
    components: List[str] = field(default_factory=list)
    is_from: bool = False


@dataclass
class ArkCall:
    """方法调用关系"""
    caller_method: str
    caller_class: str
    callee_method: str
    callee_class: str = ""
    line: int = 0


@dataclass
class ArkComponent:
    """组件嵌套关系"""
    parent_class: str
    child_component: str


# ============================================================
# ArkTS 解析器（纯Python实现）
# ============================================================
class ArkTSParser:
    """纯Python ArkTS代码解析器，不依赖任何外部解析库"""

    # ArkUI 内置组件列表（用于识别组件嵌套）
    BUILTIN_COMPONENTS = {
        'Column', 'Row', 'Stack', 'Flex', 'List', 'Grid', 'GridRow', 'GridItem',
        'Scroll', 'Swiper', 'Tabs', 'TabContent', 'Navigation', 'NavDestination',
        'Button', 'Text', 'Image', 'TextInput', 'TextArea', 'Search', 'Toggle',
        'Checkbox', 'Radio', 'Slider', 'Rating', 'Select', 'Picker', 'DatePicker',
        'TimePicker', 'Counter', 'Marquee', 'Progress', 'Gauge', 'QRCode',
        'Divider', 'Blank', 'Badge', 'LoadingProgress', 'If', 'ForEach', 'LazyForEach',
        'ListItem', 'ListItemGroup', 'Section', 'RichText', 'Span', 'Container',
        'Panel', 'Popup', 'Dialog', 'AlertDialog', 'ActionSheet', 'Toast',
        'Web', 'Video', 'XComponent', 'Canvas', 'Circle', 'Ellipse', 'Line',
        'Path', 'Polygon', 'Polyline', 'Rect', 'Shape', 'SymbolGlyph',
        'WaterFlow', 'FlowItem', 'Stepper', 'StepperItem', 'Menu', 'MenuItem',
        'NavigationMenuItem', 'Toolbar', 'ToolbarItem', 'SearchButton',
        'FormComponent', 'DataPanel', 'Gauge', 'LinearGradient',
        'RelativeContainer', 'MediaQuery', 'Overlay', 'Sheet', 'FullScreenModal',
        'BindSheet', 'BindMenu', 'BindContentCover', 'Gesture', 'GestureGroup',
        'ParallelGesture', 'SequentialGesture', 'TabsController', 'ListController',
        'Scroller', 'ScrollController', 'SwiperController', 'PanelController',
    }

    def __init__(self):
        self.files_parsed = 0
        self.errors: List[str] = []
        
        # 预编译正则表达式以提高性能
        self._class_pattern = re.compile(
            r'^(\s*)'
            r'((?:@\w+\s*)*)'
            r'(export\s+)?(default\s+)?(abstract\s+)?'
            r'(struct|class|interface|enum)\s+(\w+)'
            r'(\s*<[^>]*>)?'
            r'(?:\s+extends\s+(\w+))?'
            r'(?:\s+implements\s+([\w,\s]+))?',
            re.MULTILINE
        )
        
        self._method_pattern = re.compile(
            r'(?:^|\n|\}|\{|\;)'
            r'(\s*)'
            r'(?:(?:@Builder\s+)?)?'
            r'((?:(?:async|public|private|protected|static|override|readonly|abstract)\s+)*)'
            r'(\w+)'
            r'\s*'
            r'(?:<[^>]*>)?\s*'
            r'\(',
            re.MULTILINE
        )
        
        self._decorator_method_pattern = re.compile(
            r'(?:^|\n|\}|\{|\;)'
            r'(\s*)'
            r'@(\w+)\s*'
            r'(?:\([^)]*\))?\s*'
            r'(\w+)'
            r'\s*'
            r'(?:<[^>]*>)?\s*'
            r'\(',
            re.MULTILINE
        )
        
        self._call_pattern = re.compile(
            r'(?:(\w+)\s*\.\s*)?(\w+)'
            r'\s*'
            r'\(',
            re.MULTILINE
        )
        
        self._import_pattern = re.compile(
            r"""^\s*import\s+(?:"""
            r"""(?:\{([^}]+)\}\s+from\s+)"""  # import { A, B } from 'module'
            r"""|from\s+)"""                   # import from 'module'
            r"""["']([^"']+)["']"""            # 'module' 或 "module"
            r"""|(["'])([^"']+)\3"""           # import 'module' (无 from)
            r"""$""",
            re.MULTILINE | re.VERBOSE
        )

    def parse_project(self, project_path: str) -> Tuple[List[ArkClass], List[ArkCall], List[ArkComponent], List[str], List[ArkImport]]:
        """
        解析整个鸿蒙项目
        返回: (类列表, 调用关系, 组件关系, 文件列表, 导入列表)
        """
        project = Path(project_path)
        if not project.exists():
            raise FileNotFoundError(f"项目路径不存在: {project_path}")

        all_classes: List[ArkClass] = []
        all_calls: List[ArkCall] = []
        all_components: List[ArkComponent] = []
        all_files: List[str] = []
        all_imports: List[ArkImport] = []

        # 查找所有 .ets 和 .ts 文件
        ets_files = list(project.rglob("*.ets")) + list(project.rglob("*.ts"))
        # 排除 node_modules, oh_modules, .preview, build 等目录
        ets_files = [
            f for f in ets_files
            if not any(part in f.parts for part in
                      ['node_modules', 'oh_modules', '.preview', 'build',
                       '.idea', 'dist', 'test', '__tests__', 'ohosTest'])
        ]

        total = len(ets_files)
        if total == 0:
            logger.warning(f"未找到任何 .ets/.ts 文件（已排除 node_modules/oh_modules/build）")

        for i, file_path in enumerate(ets_files):
            try:
                rel_path = str(file_path.relative_to(project))
                all_files.append(rel_path)

                content = file_path.read_text(encoding='utf-8', errors='replace')
                file_imports = self._parse_imports(content)
                all_imports.extend(file_imports)

                classes = self._parse_file(content, rel_path)
                for cls in classes:
                    all_classes.append(cls)
                    # 提取组件嵌套（不依赖其他类）
                    if cls.is_component:
                        comps = self._extract_components(cls)
                        all_components.extend(comps)

                self.files_parsed += 1
                if (i + 1) % 50 == 0 or (i + 1) == total:
                    logger.info(f"解析进度: {i + 1}/{total} 文件 ({(i+1)/total*100:.0f}%)")

            except Exception as e:
                self.errors.append(f"解析 {file_path} 失败: {e}")
                logger.debug(f"解析 {file_path} 失败: {e}")

        # 第二遍：提取调用关系（此时所有类都已解析完成）
        for cls in all_classes:
            calls = self._extract_calls(cls, all_classes)
            all_calls.extend(calls)

        logger.info(f"解析完成: {self.files_parsed} 文件, {len(all_classes)} 个类, "
                    f"{len(all_calls)} 个调用关系, {len(all_components)} 个组件关系")
        if self.errors:
            logger.warning(f"解析过程中有 {len(self.errors)} 个错误")

        return all_classes, all_calls, all_components, all_files, all_imports

    def _parse_imports(self, content: str) -> List[ArkImport]:
        """解析导入语句"""
        imports = []
        seen_raw = set()
        # 使用预编译的正则表达式
        for m in self._import_pattern.finditer(content):
            # 跳过字符串内的匹配
            if self._is_in_string(content, m.start()):
                continue
            raw = m.group(0)
            if raw in seen_raw:
                continue
            seen_raw.add(raw)
            # group(1): 花括号内容, group(2): from后的模块名, group(3): 引号字符, group(4): 无from时的模块名
            if m.group(1) is not None:
                # import { A, B } from 'module'
                components_str = m.group(1)
                components = [c.strip() for c in components_str.split(',')]
                module = m.group(2)
                imports.append(ArkImport(raw=raw, module=module, components=components, is_from=True))
            elif m.group(2):
                # import from 'module'
                module = m.group(2)
                imports.append(ArkImport(raw=raw, module=module, components=[], is_from=True))
            elif m.group(4):
                # import 'module'
                module = m.group(4)
                imports.append(ArkImport(raw=raw, module=module, components=[], is_from=False))
        return imports

    def _is_in_backtick_string(self, content: str, pos: int) -> bool:
        """检查给定位置是否在反引号模板字符串内"""
        if pos < 0 or pos >= len(content):
            return False
        count = 0
        i = 0
        while i < pos and i < len(content):
            if content[i] == '\\':
                i += 2  # 跳过转义字符
                continue
            if content[i] == '`':
                count += 1
            i += 1
        return count % 2 != 0

    def _is_in_string(self, content: str, pos: int) -> bool:
        """检查给定位置是否在任何字符串内（单引号、双引号、反引号）"""
        if pos < 0 or pos >= len(content):
            return False
        
        # 使用缓存避免重复计算
        cache_key = id(content)
        if not hasattr(self, '_string_cache'):
            self._string_cache = {}
        
        if cache_key not in self._string_cache:
            # 预计算所有字符串区域
            self._string_cache[cache_key] = self._compute_string_regions(content)
        
        regions = self._string_cache[cache_key]
        for start, end in regions:
            # 引号字符本身不算在字符串内，只有引号之间的内容才算
            if start < pos < end - 1:
                return True
        return False
    
    def _compute_string_regions(self, content: str) -> List[Tuple[int, int]]:
        """预计算所有字符串区域，返回 (start, end) 列表"""
        regions = []
        i = 0
        in_single = False
        in_double = False
        in_backtick = False
        string_start = 0
        
        while i < len(content):
            ch = content[i]
            
            if ch == '\\' and (in_single or in_double or in_backtick):
                i += 2
                continue
            
            if not in_single and not in_double and not in_backtick:
                if ch == "'":
                    in_single = True
                    string_start = i
                elif ch == '"':
                    in_double = True
                    string_start = i
                elif ch == '`':
                    in_backtick = True
                    string_start = i
            elif in_single and ch == "'":
                in_single = False
                regions.append((string_start, i + 1))
            elif in_double and ch == '"':
                in_double = False
                regions.append((string_start, i + 1))
            elif in_backtick and ch == '`':
                in_backtick = False
                regions.append((string_start, i + 1))
            
            i += 1
        
        # 处理未闭合的字符串
        if in_single or in_double or in_backtick:
            regions.append((string_start, len(content)))
        
        return regions
    
    def clear_string_cache(self):
        """清除字符串缓存"""
        self._string_cache = {}

    def _parse_file(self, content: str, file_path: str) -> List[ArkClass]:
        """解析单个文件中的所有类/结构体"""
        classes = []
        lines = content.split('\n')

        # 查找所有 struct/class/interface/enum 定义
        # 支持 @decorator 前缀、export、default、abstract
        # 使用预编译的正则表达式
        for match in self._class_pattern.finditer(content):
            # 跳过字符串内的匹配（反引号模板字符串、单引号、双引号）
            if self._is_in_string(content, match.start()):
                continue

            kind = match.group(6)
            name = match.group(7)
            generic_part = (match.group(8) or "").strip()  # 泛型参数部分，如 <T> 或 <K, V>
            extends = match.group(9) or ""
            implements_str = match.group(10) or ""
            implements = [i.strip() for i in implements_str.split(',') if i.strip()]

            # 提取装饰器（从正则匹配的装饰器部分 + 向上查找）
            start_pos = match.start()
            decorators_str = match.group(2) or ""
            decorators = self._extract_decorators_from_text(decorators_str)
            # 同时向上查找（处理多行装饰器）
            decorators.extend(self._extract_decorators(content[:start_pos]))

            # 计算行号
            line_start = content[:start_pos].count('\n') + 1

            # 查找类体结束位置
            body_start = match.end()
            body_end = self._find_block_end(content, body_start)
            body = content[body_start:body_end]
            line_end = content[:body_end].count('\n') + 1

            # 解析方法
            if kind == "interface":
                methods = self._parse_interface_methods(body, name, line_start)
            else:
                methods = self._parse_methods(body, name, line_start)

            # 解析字段
            fields = self._parse_fields(body)

            cls = ArkClass(
                name=name,
                file_path=file_path,
                kind=kind,
                decorators=decorators,
                methods=methods,
                fields=fields,
                line_start=line_start,
                line_end=line_end,
                extends=extends,
                implements=implements,
                body=body
            )
            classes.append(cls)

        return classes

    def _extract_decorators(self, text_before: str) -> List[ArkDecorator]:
        """从类定义前的文本中提取装饰器"""
        decorators = []
        lines = text_before.rstrip().split('\n')

        for line in reversed(lines):
            stripped = line.strip()
            if not stripped:
                continue
            # 匹配 @DecoratorName 或 @DecoratorName(params)
            m = re.match(r'^@(\w+)(?:\((.+)\))?$', stripped)
            if m:
                decorators.insert(0, ArkDecorator(
                    name=m.group(1),
                    params=m.group(2) or ""
                ))
            else:
                # 遇到非空非装饰器行
                # 如果是字段定义行（包含 : 和可能的 =），继续向上查找
                # 因为装饰器可能出现在字段定义之前
                if ':' in stripped and ('=' in stripped or stripped.endswith(';')):
                    continue
                # 如果是普通代码行，停止
                break

        return decorators

    def _extract_decorators_from_text(self, text: str) -> List[ArkDecorator]:
        """从文本中提取装饰器（如 @Component @Entry）"""
        decorators = []
        # 匹配 @DecoratorName 或 @DecoratorName(params)
        pattern = re.compile(r'@(\w+)(?:\(([^)]*)\))?')
        for m in pattern.finditer(text):
            decorators.append(ArkDecorator(
                name=m.group(1),
                params=m.group(2) or ""
            ))
        return decorators

    def _find_block_end(self, content: str, start: int) -> int:
        """找到花括号块的结束位置"""
        depth = 0
        i = start
        in_string = False
        string_char = ''
        in_line_comment = False
        in_block_comment = False

        while i < len(content):
            char = content[i]

            # 处理注释
            if not in_string:
                if content[i:i+2] == '//' and not in_block_comment:
                    in_line_comment = True
                    i += 2
                    continue
                if content[i:i+2] == '/*' and not in_line_comment:
                    in_block_comment = True
                    i += 2
                    continue
                if content[i:i+2] == '*/' and in_block_comment:
                    in_block_comment = False
                    i += 2
                    continue

            if in_line_comment:
                if char == '\n':
                    in_line_comment = False
                i += 1
                continue

            if in_block_comment:
                i += 1
                continue

            # 处理字符串
            if in_string:
                if char == '\\':
                    i += 2  # 跳过转义字符
                    continue
                if char == string_char:
                    in_string = False
                i += 1
                continue

            if char in ('"', "'", '`'):
                in_string = True
                string_char = char
                i += 1
                continue

            # 计算花括号深度
            if char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    return i + 1

            i += 1

        return len(content)

    def _parse_methods(self, body: str, class_name: str, class_line_start: int) -> List[ArkMethod]:
        """解析类体中的方法"""
        methods = []

        # 使用预编译的正则表达式匹配方法定义
        for match in self._method_pattern.finditer(body):
            # 跳过字符串内的匹配（反引号模板字符串等）
            if self._is_in_string(body, match.start()):
                continue

            modifiers = match.group(2).strip()
            method_name = match.group(3)

            # 跳过构造函数、if/for/while 等关键字
            if method_name in ('if', 'for', 'while', 'switch', 'catch', 'constructor', 'function',
                                'class', 'struct', 'interface', 'enum', 'type', 'import', 'export'):
                continue

            # 跳过 ArkUI 内置组件名（它们在 build() 中以 ComponentName() 形式出现，
            # 但不是方法定义）
            if method_name in self.BUILTIN_COMPONENTS:
                continue

            # 手动查找匹配的参数列表右括号（支持嵌套括号）
            paren_start = match.end() - 1  # '(' 的位置
            paren_end = self._find_matching_paren(body, paren_start)
            if paren_end is None:
                continue
            params = body[paren_start + 1:paren_end].strip()

            # 从右括号之后找到方法体 '{' 的位置
            # 跳过可选的返回类型 ": ReturnType"
            after_paren = body[paren_end + 1:]
            body_start_offset = self._find_method_body_start(after_paren)
            if body_start_offset is None:
                continue  # 没有方法体，不是方法定义

            # 提取返回类型
            return_type = ""
            between = after_paren[:body_start_offset].strip()
            if between.startswith(':'):
                return_type = between[1:].strip()

            # 提取方法体
            body_start = paren_end + 1 + body_start_offset
            body_end = self._find_block_end(body, body_start)
            method_body = body[body_start:body_end]

            # 计算行号
            line_start = body[:match.start()].count('\n') + 1 + class_line_start
            line_end = body[:body_end].count('\n') + 1 + class_line_start

            # 提取方法装饰器
            method_decorators = self._extract_decorators(body[:match.start()])
            
            # 检查方法定义行中是否有 @Builder 装饰器
            # （如 @Builder MyHeader() { ... }，@Builder 和方法名在同一行）
            # match 的完整文本中可能包含 @Builder
            full_match_text = body[match.start():match.end()]
            if '@Builder' in full_match_text:
                method_decorators.append(ArkDecorator(name="Builder", params=""))

            methods.append(ArkMethod(
                name=method_name,
                params=params,
                return_type=return_type,
                decorators=method_decorators,
                body=method_body,
                line_start=line_start,
                line_end=line_end
            ))

        # 使用第二个正则匹配带装饰器的方法（如 @Watch('onChange') onChange() { ... }）
        # 这些方法可能被第一个正则漏掉，因为装饰器参数中的括号干扰了匹配
        existing_names = {m.name for m in methods}
        for match in self._decorator_method_pattern.finditer(body):
            # 跳过字符串内的匹配
            if self._is_in_string(body, match.start()):
                continue

            deco_name = match.group(2)
            method_name = match.group(3)

            # 跳过已匹配的方法和关键字
            if method_name in existing_names:
                continue
            if method_name in ('if', 'for', 'while', 'switch', 'catch', 'constructor', 'function',
                                'class', 'struct', 'interface', 'enum', 'type', 'import', 'export'):
                continue
            if method_name in self.BUILTIN_COMPONENTS:
                continue

            # 手动查找匹配的参数列表右括号
            paren_start = match.end() - 1
            paren_end = self._find_matching_paren(body, paren_start)
            if paren_end is None:
                continue
            params = body[paren_start + 1:paren_end].strip()

            # 找方法体
            after_paren = body[paren_end + 1:]
            body_start_offset = self._find_method_body_start(after_paren)
            if body_start_offset is None:
                continue

            return_type = ""
            between = after_paren[:body_start_offset].strip()
            if between.startswith(':'):
                return_type = between[1:].strip()

            body_start = paren_end + 1 + body_start_offset
            body_end = self._find_block_end(body, body_start)
            method_body = body[body_start:body_end]

            line_start = body[:match.start()].count('\n') + 1 + class_line_start
            line_end = body[:body_end].count('\n') + 1 + class_line_start

            method_decorators = self._extract_decorators(body[:match.start()])
            method_decorators.append(ArkDecorator(name=deco_name, params=""))

            methods.append(ArkMethod(
                name=method_name,
                params=params,
                return_type=return_type,
                decorators=method_decorators,
                body=method_body,
                line_start=line_start,
                line_end=line_end
            ))

        return methods

    def _parse_interface_methods(self, body: str, class_name: str, class_line_start: int) -> List[ArkMethod]:
        """解析 interface 中的方法签名（没有方法体，以分号结尾）"""
        methods = []

        pattern = re.compile(
            r'(?:^|\n|\}|\{|\;)'  # 添加 \{ 以匹配花括号后的方法
            r'\s*'
            r'((?:(?:async|public|private|protected|static|override|readonly|abstract)\s+)*)'
            r'(\w+)'
            r'\s*'
            r'(?:<[^>]*>)?\s*'
            r'\(',
            re.MULTILINE
        )

        for match in pattern.finditer(body):
            # 跳过字符串内的匹配
            if self._is_in_string(body, match.start()):
                continue

            modifiers = match.group(1).strip()
            method_name = match.group(2)

            # 跳过关键字
            if method_name in ('if', 'for', 'while', 'switch', 'catch', 'constructor', 'function',
                                'class', 'struct', 'interface', 'enum', 'type', 'import', 'export'):
                continue

            # 查找匹配的参数列表右括号
            paren_start = match.end() - 1
            paren_end = self._find_matching_paren(body, paren_start)
            if paren_end is None:
                continue
            params = body[paren_start + 1:paren_end].strip()

            # 在 interface 中，方法签名以分号结尾，可能有返回类型
            after_paren = body[paren_end + 1:]
            # 找到分号或行尾
            semi_pos = after_paren.find(';')
            if semi_pos >= 0:
                between = after_paren[:semi_pos].strip()
            else:
                # 可能在行尾
                newline_pos = after_paren.find('\n')
                between = after_paren[:newline_pos].strip() if newline_pos >= 0 else after_paren.strip()

            return_type = ""
            if between.startswith(':'):
                return_type = between[1:].strip()

            line_start = body[:match.start()].count('\n') + 1 + class_line_start

            methods.append(ArkMethod(
                name=method_name,
                params=params,
                return_type=return_type,
                decorators=[],
                body="",
                line_start=line_start,
                line_end=line_start
            ))

        return methods

    def _find_matching_paren(self, text: str, start: int) -> Optional[int]:
        """找到匹配的右括号位置，支持嵌套"""
        depth = 0
        i = start
        in_string = False
        string_char = ''
        while i < len(text):
            char = text[i]
            if in_string:
                if char == '\\':
                    i += 2
                    continue
                if char == string_char:
                    in_string = False
                i += 1
                continue
            if char in ('"', "'", '`'):
                in_string = True
                string_char = char
                i += 1
                continue
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth == 0:
                    return i
            i += 1
        return None

    def _find_brace_after_type(self, type_str: str) -> Optional[int]:
        """在类型字符串中找到方法体 '{' 的位置，跳过泛型尖括号"""
        depth_angle = 0
        i = 0
        in_string = False
        string_char = ''
        while i < len(type_str):
            char = type_str[i]
            if in_string:
                if char == '\\':
                    i += 2
                    continue
                if char == string_char:
                    in_string = False
                i += 1
                continue
            if char in ('"', "'", '`'):
                in_string = True
                string_char = char
                i += 1
                continue
            if char == '<':
                depth_angle += 1
            elif char == '>':
                depth_angle -= 1
            elif char == '{' and depth_angle == 0:
                return i
            i += 1
        return None

    def _find_method_body_start(self, text: str) -> Optional[int]:
        """在返回类型之后找到方法体 '{' 的位置"""
        return self._find_brace_after_type(text)

    def _parse_fields(self, body: str) -> List[str]:
        """解析类体中的字段"""
        fields = []
        # 匹配 @State, @Prop, @Provide, @Link, @Consume, @StorageLink, @StorageProp, @BuilderParam 等装饰的字段
        # 注意：@Link 和 @Consume 字段可能没有默认值（没有 = 号）
        # 注意：@BuilderParam 字段类型可能是函数类型 () => void
        pattern = re.compile(
            r'@(?:State|Prop|Provide|Link|Consume|StorageLink|StorageProp|Watch|Builder|BuilderParam|Extend|Styles|ObjectLink|V2)\s*'
            r'(?:\([^)]*\))?\s*'
            r'(\w+)\s*(?::\s*[\w\[\]|<>=>()\s]+)?\s*(?:[=;\n}])'
        )
        for m in pattern.finditer(body):
            # 跳过字符串内的匹配
            if self._is_in_string(body, m.start()):
                continue
            # 跳过注释内的匹配
            if self._is_in_comment(body, m.start()):
                continue
            fields.append(m.group(1))

        # 匹配普通字段: fieldName: Type = value 或 fieldName: Type
        # 支持联合类型: fieldName: Type | null, fieldName: string | number
        pattern2 = re.compile(
            r'(?:private|public|protected|readonly|static)?\s*'
            r'(\w+)\s*:\s*(?:[\w\[\]|<>]+(?:\s*\|\s*[\w\[\]|<>]+)*)\s*(?:[=;\n])'
        )
        for m in pattern2.finditer(body):
            # 跳过字符串内的匹配
            if self._is_in_string(body, m.start()):
                continue
            # 跳过注释内的匹配
            if self._is_in_comment(body, m.start()):
                continue
            name = m.group(1)
            if name not in fields and name not in ('if', 'for', 'while', 'return', 'const', 'let', 'var',
                                                    'build', 'aboutToAppear', 'aboutToDisappear',
                                                    'onPageShow', 'onPageHide', 'onBackPress'):
                fields.append(name)

        return fields

    def _extract_calls(self, cls: ArkClass, all_classes: List[ArkClass]) -> List[ArkCall]:
        """从类的方法体中提取方法调用关系"""
        calls = []
        # 构建类名到类的映射
        class_map = {c.name: c for c in all_classes}

        # 构建变量名到类名的映射（从类体源码中提取类型声明）
        var_to_class: Dict[str, str] = {}
        if cls.body:
            # 匹配字段声明: (private|public|protected)?\s*varName: ClassName
            # 支持泛型: varName: ClassName<Type>
            var_decl_pattern = re.compile(
                r'(?:private|public|protected|readonly|static)?\s*'
                r'(\w+)\s*:\s*([A-Z]\w*)'  # 变量名: 大写开头的类型名
            )
            for m in var_decl_pattern.finditer(cls.body):
                var_name = m.group(1)
                type_name = m.group(2)
                # 跳过 ArkTS 内置类型
                if type_name in ('string', 'number', 'boolean', 'void', 'undefined',
                                 'Object', 'Array', 'Map', 'Set', 'Promise', 'Record',
                                 'List', 'Resource', 'ResourceColor', 'ResourceStr',
                                 'Length', 'EdgeInsets', 'Size', 'Color', 'Font',
                                 'ErrorHandler',
                                 'ScrollController', 'TabsController', 'SwiperController',
                                 'ListController', 'PanelController', 'NavPathStack'):
                    continue
                # 不再要求 type_name 必须在 class_map 中
                # 这样即使类定义在其他文件中，也能记录跨文件调用关系
                if type_name not in var_to_class:  # 避免覆盖
                    var_to_class[var_name] = type_name
            # camelCase -> PascalCase 推断作为补充
            for field_name in cls.fields:
                if field_name not in var_to_class:
                    pascal_name = field_name[0].upper() + field_name[1:] if field_name else ""
                    if pascal_name in class_map:
                        var_to_class[field_name] = pascal_name

        for method in cls.methods:
            # 在方法体中查找函数调用
            # 使用两遍扫描：
            # 第一遍：匹配 identifier.identifier( （不含泛型参数）
            # 第二遍：匹配 identifier< 后跟 ( 的模式（含泛型参数，包括嵌套）
            # 第二遍使用手动字符扫描来正确处理嵌套尖括号

            # 第一遍：不含泛型参数的调用（使用预编译正则）
            call_pattern = self._call_pattern

            seen = set()

            def process_match(obj, callee, name_end, paren_pos):
                """处理一个调用匹配"""
                # 检查方法名和 '(' 之间是否有未闭合的 '<'（嵌套泛型参数）
                between = method.body[name_end:paren_pos]
                angle_depth = between.count('<') - between.count('>')
                if angle_depth != 0:
                    # 有未闭合的泛型参数，尝试找到真正的 '('
                    depth = 0
                    i = name_end
                    while i < len(method.body):
                        ch = method.body[i]
                        if ch == '<': depth += 1
                        elif ch == '>': depth -= 1
                        elif ch == '(' and depth == 0: break
                        i += 1
                    if depth != 0 or i >= len(method.body):
                        return  # 无法找到正确的括号

                # 跳过关键字和内置函数
                skip_callees = ('if', 'for', 'while', 'switch', 'catch', 'typeof',
                              'instanceof', 'new', 'return', 'function',
                              'class', 'import', 'export', 'from', 'const', 'let',
                              'var', 'true', 'false', 'null', 'undefined', 'this',
                              'super', 'console', 'Math', 'JSON', 'parseInt',
                              'parseFloat', 'String', 'Number', 'Boolean', 'Array',
                              'Object', 'Promise', 'setTimeout', 'setInterval',
                              'clearTimeout', 'clearInterval', 'require',
                              'Logger', 'hilog',
                              'forEach', 'map', 'filter', 'reduce', 'find',
                              'indexOf', 'includes', 'push', 'pop', 'shift',
                              'slice', 'splice', 'join', 'split', 'replace',
                              'trim', 'startsWith', 'endsWith', 'toLowerCase',
                              'toUpperCase', 'substring', 'charAt', 'toString',
                              'valueOf', 'hasOwnProperty', 'keys', 'values',
                              'entries', 'assign', 'freeze', 'length', 'size',
                              'width', 'height', 'fontSize', 'fontColor', 'fontWeight',
                              'backgroundColor', 'objectFit', 'padding', 'margin',
                              'borderRadius', 'opacity', 'visibility', 'enabled',
                              'textAlign', 'maxLines', 'textOverflow', 'decoration',
                              'layoutWeight', 'constraintSize', 'alignItems',
                              'justifyContent', 'offset', 'position', 'markAnchor',
                              'bindMenu', 'bindSheet', 'onClick', 'onChange',
                              'onAppear', 'onDisappear', 'onGesture', 'animation',
                              'transition', 'id', 'tag', 'key')
                skip_objs = ('console', 'Math', 'JSON', 'Promise', 'setTimeout',
                            'setInterval', 'clearTimeout', 'clearInterval',
                            'Logger', 'hilog', 'parseInt', 'parseFloat',
                            'String', 'Number', 'Boolean', 'Array', 'Object')
                if callee in skip_callees or (obj and obj in skip_objs):
                    return

                # 跳过 ArkUI 组件名
                if callee in self.BUILTIN_COMPONENTS:
                    return

                # 跳过字符串中的内容（使用精确的位置检查）
                if self._is_in_string(method.body, paren_pos):
                    return

                # 跳过注释中的内容
                if self._is_in_comment(method.body, paren_pos):
                    return

                # 跳过链式调用中的UI属性
                ui_properties = {
                    'width', 'height', 'fontSize', 'fontColor', 'fontWeight',
                    'backgroundColor', 'objectFit', 'padding', 'margin',
                    'borderRadius', 'borderWidth', 'borderColor', 'opacity',
                    'visibility', 'enabled', 'textAlign', 'maxLines',
                    'textOverflow', 'decoration', 'layoutWeight', 'flexGrow',
                    'flexShrink', 'alignItems', 'justifyContent', 'offset',
                    'position', 'markAnchor', 'size', 'constraintSize',
                    'bindMenu', 'bindSheet', 'bindContentCover', 'id', 'tag',
                    'onClick', 'onChange', 'onAppear', 'onDisappear', 'onGesture',
                    'animation', 'transition', 'gesture', 'priorityGesture',
                    'parallelGesture', 'hitTestBehavior', 'responseRegion',
                    'clip', 'blur', 'shadow', 'overlay', 'linearGradient',
                    'brightness', 'contrast', 'saturate', 'grayscale',
                    'colorBlend', 'renderFit', 'foregroundEffect',
                    'backgroundEffect', 'backgroundBlurStyle',
                    'geometryTransition', 'expandSafeArea', 'mode', 'index',
                    'vertical', 'scrollable', 'barState', 'cachedCount',
                    'divider', 'lanes', 'alignListItem', 'sticky',
                    'nestedScroll', 'edgeEffect', 'enableScrollInteraction',
                    'friction', 'spring', 'nestedScrollForward',
                    'scrollBar', 'scrollBarColor', 'scrollBarWidth',
                    'fadeColor', 'indicator', 'displayMode', 'selectedMode',
                    'space', 'direction', 'wrap', 'alignContent',
                    'align', 'flexDirection', 'flexWrap', 'alignItems',
                    'justifyContent', 'type', 'value', 'selected',
                    'style', 'shape', 'icon', 'labelStyle', 'fontStyle',
                    'fontFamily', 'textCase', 'copyOption', 'baselineOffset',
                    'letterSpacing', 'lineHeight', 'textIndent', 'wordSpacing',
                    'fillColor', 'strokeColor', 'strokeWidth', 'font',
                    'textAlign', 'textDecoration', 'baseline', 'dominantBaseline',
                    'textBaseline', 'clip', 'textShadow', 'pixelRound',
                    'color', 'number', 'calendar', 'lunar', 'timeZoneOffset',
                    'hour24', 'followSystem', 'useMilitaryTime',
                    'vibrate', 'locale', 'scaleCount', 'scaleSize',
                    'target', 'threshold', 'direction', 'autoCancel',
                    'gestureMask', 'deviceOrientation', 'useShadow',
                    'showEffect', 'offset', 'lightUp', 'closeOnOverlayClick',
                    'showInSubWindow', 'autoCancel', 'modalMode',
                    'shouldDismiss', 'showInSubWindow', 'backgroundColor',
                    'backgroundBlurStyle', 'onWillDismiss', 'onDidAppear',
                    'onDidDisappear', 'onWillShow', 'onWillHide',
                    'title', 'subtitle', 'menus', 'titleMode', 'navDestination',
                    'hideToolBar', 'hideTitleBar', 'hideBackButton',
                    'mode', 'icon', 'text', 'action', 'message', 'duration',
                    'showMode', 'alignment', 'offset', 'targetArea',
                    'enableArrow', 'placement', 'onAppear', 'onDisappear',
                    'state', 'checked', 'select', 'content', 'selected',
                    'name', 'src', 'alt', 'objectFit', 'renderMode',
                    'syncLoad', 'colorFilter', 'autoResize', 'fillColor',
                    'draggable', 'interpolation', 'sourceSize',
                    'placeholder', 'forceResize', 'placeholderColor',
                    'autoPreview', 'renderMode', 'isPreview', 'isShow',
                    'controller', 'url', 'controller', 'domStorageAccess',
                    'fileAccess', 'imageAccess', 'mixedMode', 'onlineImageAccess',
                    'blockNetwork', 'horizontalScrollBarAccess',
                    'verticalScrollBarAccess', 'cacheMode', 'darkMode',
                    'textZoomAtio', 'initialScale', 'blockNetwork',
                    'overviewModeEnabled', 'textZoomAtio', 'javaScriptAccess',
                    'allowWindowOpen', 'mediaPlayGestureAccess',
                    'fileAccess', 'geolocationAccess', 'databaseAccess',
                    'mediaAutoPlay', 'textZoomAtio', 'layoutMode',
                    'minFontSize', 'maxFontSize', 'fontSize',
                    'fontWeight', 'fontColor', 'fontStyle', 'fontFamily',
                    'textAlign', 'overflow', 'maxLines', 'textOverflow',
                    'decoration', 'baselineOffset', 'textCase', 'copyOption',
                    'placeholderColor', 'placeholderFont', 'caretStyle',
                    'maxLength', 'inputFilter', 'enterKeyType', 'copyOption',
                    'showPasswordIcon', 'style', 'showCounter', 'enableKeyboardOnFocus',
                    'selectionMenuHidden', 'type', 'placeholder', 'icon',
                    'value', 'onChange', 'onSubmit', 'onEditChange', 'onCopy',
                    'onCut', 'onPaste', 'textStyle', 'placeholderStyle',
                    'caretStyle', 'keyboardType', 'enterKeyType',
                    'selectedBackgroundColor', 'selectedFontColor',
                    'selectedBackgroundColor', 'menuOption', 'responseRegion',
                    'controller', 'total', 'status', 'color', 'style',
                    'enableScan', 'autoScan', 'repeat', 'multiCamera',
                    'scanTypes', 'cameraId', 'flashMode', 'torch',
                }
                if callee in ui_properties:
                    return

                callee_class = ""
                if obj:
                    if obj in class_map:
                        callee_class = obj
                    elif obj == 'this':
                        callee_class = cls.name
                    elif obj in var_to_class:
                        callee_class = var_to_class[obj]

                key = (method.name, cls.name, callee, callee_class)
                if key not in seen:
                    seen.add(key)
                    calls.append(ArkCall(
                        caller_method=method.name,
                        caller_class=cls.name,
                        callee_method=callee,
                        callee_class=callee_class,
                        line=method.line_start
                    ))

            # 第一遍：不含泛型参数的调用
            for m in call_pattern.finditer(method.body):
                obj = m.group(1)
                callee = m.group(2)
                name_end = m.end(2)
                paren_pos = m.end() - 1
                process_match(obj, callee, name_end, paren_pos)

            # 第二遍：含泛型参数的调用（正则无法处理嵌套，使用手动扫描）
            # 扫描所有 word< 模式，然后手动找到匹配的 > 和 (
            generic_pattern = re.compile(r'(?:(\w+)\s*\.\s*)?(\w+)\s*<')
            for m in generic_pattern.finditer(method.body):
                obj = m.group(1)
                callee = m.group(2)
                name_end = m.end(2)

                # 跳过已经被第一遍匹配的（不含泛型的调用）
                # 检查 name_end 后面是否直接是 (
                j = name_end
                while j < len(method.body) and method.body[j] in ' \t\n\r':
                    j += 1
                if j < len(method.body) and method.body[j] == '(':
                    continue  # 已被第一遍处理

                # 手动跳过泛型参数，找到 (
                depth = 0
                i = name_end
                while i < len(method.body):
                    ch = method.body[i]
                    if ch == '<': depth += 1
                    elif ch == '>': depth -= 1
                    elif ch == '(' and depth == 0: break
                    i += 1

                if depth == 0 and i < len(method.body):
                    process_match(obj, callee, name_end, i)

        return calls

    def _is_in_comment(self, content: str, pos: int) -> bool:
        """检查给定位置是否在注释中（单行注释 // 或多行注释 /* */）"""
        if pos < 0 or pos >= len(content):
            return False
        i = 0
        in_block_comment = False
        while i < pos:
            if in_block_comment:
                if content[i:i+2] == '*/':
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue
            if content[i:i+2] == '/*':
                in_block_comment = True
                i += 2
                continue
            if content[i:i+2] == '//':
                # 单行注释，检查pos是否在同一行
                line_end = content.find('\n', i)
                if line_end == -1:
                    line_end = len(content)
                if pos < line_end:
                    return True
                i = line_end + 1
                continue
            # 跳过字符串（字符串中的 // 或 /* 不是注释）
            if content[i] in ('"', "'", '`'):
                quote_char = content[i]
                i += 1
                while i < len(content):
                    if content[i] == '\\':
                        i += 2
                        continue
                    if content[i] == quote_char:
                        i += 1
                        break
                    i += 1
                continue
            i += 1
        return in_block_comment

    def _extract_components(self, cls: ArkClass) -> List[ArkComponent]:
        """从 @Component 类的 build() 和 @Builder 方法中提取组件嵌套关系"""
        components = []

        # 收集需要扫描的方法：build() 和所有 @Builder 方法
        target_methods = []
        build_method = next((m for m in cls.methods if m.name == "build"), None)
        if build_method:
            target_methods.append(build_method)
        for m in cls.methods:
            if any(d.name == "Builder" for d in m.decorators):
                if m not in target_methods:
                    target_methods.append(m)

        if not target_methods:
            return components

        # 在方法体中查找组件使用
        # 匹配: ComponentName({ 或 ComponentName() 或 ComponentName(
        component_pattern = re.compile(r'(\w+)\s*\(')

        seen = set()
        for method in target_methods:
            for m in component_pattern.finditer(method.body):
                # 跳过注释中的匹配
                if self._is_in_comment(method.body, m.start()):
                    continue
                # 跳过字符串中的匹配
                if self._is_in_string(method.body, m.start()):
                    continue
                comp_name = m.group(1)
                # 检查是否是已知组件（内置或自定义）
                if comp_name in self.BUILTIN_COMPONENTS or comp_name[0].isupper():
                    if comp_name not in seen and comp_name != cls.name:
                        seen.add(comp_name)
                        components.append(ArkComponent(
                            parent_class=cls.name,
                            child_component=comp_name
                        ))

        return components


# ============================================================
# 数据库管理器
# ============================================================
class CodeDatabase:
    """代码数据库管理器"""

    # 类级别的锁，用于序列化所有数据库操作
    _lock = threading.Lock()

    def __init__(self, db_path: str = "code.db"):
        self.db_path = os.path.abspath(db_path)
        self.conn: Optional[sqlite3.Connection] = None

    def __enter__(self):
        # 获取锁确保线程安全
        self._lock.acquire()
        try:
            self.conn = sqlite3.connect(self.db_path, timeout=60)
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.execute("PRAGMA foreign_keys=ON")
            self._create_tables()
            return self
        except:
            self._lock.release()
            raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if self.conn:
                self.conn.close()
                self.conn = None
        finally:
            self._lock.release()

    def _create_tables(self):
        """创建表（如果不存在）"""
        # 注意：SQLite外键必须引用主键或UNIQUE列
        # classes的UNIQUE(name, file)是复合唯一约束，不能被单列外键引用
        # 因此关闭外键约束，改用应用层保证一致性
        self.conn.execute("PRAGMA foreign_keys=OFF")
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS files(
            path TEXT PRIMARY KEY
        );

        CREATE TABLE IF NOT EXISTS classes(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            file TEXT NOT NULL,
            kind TEXT DEFAULT 'struct',
            is_comp INTEGER DEFAULT 0,
            is_entry INTEGER DEFAULT 0,
            extends TEXT DEFAULT '',
            line_start INTEGER DEFAULT 0,
            line_end INTEGER DEFAULT 0,
            UNIQUE(name, file)
        );

        CREATE TABLE IF NOT EXISTS methods(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            class_name TEXT NOT NULL,
            params TEXT DEFAULT '',
            return_type TEXT DEFAULT '',
            line_start INTEGER DEFAULT 0,
            line_end INTEGER DEFAULT 0,
            UNIQUE(name, class_name)
        );

        CREATE TABLE IF NOT EXISTS calls(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            caller TEXT NOT NULL,
            caller_class TEXT NOT NULL,
            callee TEXT NOT NULL,
            callee_class TEXT DEFAULT '',
            line INTEGER DEFAULT 0,
            UNIQUE(caller, caller_class, callee, callee_class)
        );

        CREATE TABLE IF NOT EXISTS components(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent TEXT NOT NULL,
            child TEXT NOT NULL,
            UNIQUE(parent, child)
        );

        CREATE TABLE IF NOT EXISTS fields(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            class_name TEXT NOT NULL,
            UNIQUE(name, class_name)
        );

        CREATE TABLE IF NOT EXISTS imports(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            raw TEXT NOT NULL,
            module TEXT DEFAULT '',
            components TEXT DEFAULT '',
            file_path TEXT DEFAULT '',
            UNIQUE(raw, file_path)
        );

        -- 索引
        CREATE INDEX IF NOT EXISTS idx_classes_name ON classes(name);
        CREATE INDEX IF NOT EXISTS idx_classes_file ON classes(file);
        CREATE INDEX IF NOT EXISTS idx_classes_comp ON classes(is_comp);
        CREATE INDEX IF NOT EXISTS idx_classes_entry ON classes(is_entry);
        CREATE INDEX IF NOT EXISTS idx_methods_class ON methods(class_name);
        CREATE INDEX IF NOT EXISTS idx_methods_name ON methods(name);
        CREATE INDEX IF NOT EXISTS idx_calls_caller ON calls(caller_class);
        CREATE INDEX IF NOT EXISTS idx_calls_callee ON calls(callee);
        CREATE INDEX IF NOT EXISTS idx_components_parent ON components(parent);
        CREATE INDEX IF NOT EXISTS idx_fields_class ON fields(class_name);
        CREATE INDEX IF NOT EXISTS idx_imports_module ON imports(module);
        CREATE INDEX IF NOT EXISTS idx_imports_file ON imports(file_path);
        """)
        self.conn.commit()

    def clear_project_data(self):
        """清除项目数据（保留表结构）"""
        # 锁已在 __enter__ 中获取
        self.conn.executescript("""
        DELETE FROM files;
        DELETE FROM classes;
        DELETE FROM methods;
        DELETE FROM calls;
        DELETE FROM components;
        DELETE FROM fields;
        DELETE FROM imports;
        """)
        self.conn.commit()

    def insert_data(self, classes: List[ArkClass], calls: List[ArkCall],
                    components: List[ArkComponent], files: List[str],
                    imports: List[ArkImport]):
        """批量插入解析数据（线程安全，锁已在__enter__中获取）"""
        # 插入文件
        self.conn.executemany(
            "INSERT OR IGNORE INTO files(path) VALUES (?)",
            [(f,) for f in files]
        )

        # 插入类
        for cls in classes:
            self.conn.execute(
                "INSERT OR REPLACE INTO classes(name, file, kind, is_comp, is_entry, extends, line_start, line_end) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (cls.name, cls.file_path, cls.kind,
                 int(cls.is_component), int(cls.is_entry),
                 cls.extends, cls.line_start, cls.line_end)
            )

            # 插入方法（使用 INSERT OR IGNORE 避免重复）
            for m in cls.methods:
                self.conn.execute(
                    "INSERT OR IGNORE INTO methods(name, class_name, params, return_type, line_start, line_end) "
                    "VALUES (?,?,?,?,?,?)",
                    (m.name, cls.name, m.params, m.return_type, m.line_start, m.line_end)
                )

            # 插入字段（使用 INSERT OR IGNORE 避免重复）
            for f in cls.fields:
                self.conn.execute(
                    "INSERT OR IGNORE INTO fields(name, class_name) VALUES (?,?)",
                    (f, cls.name)
                )

        # 插入调用关系（使用 INSERT OR IGNORE 避免重复）
        for call in calls:
            self.conn.execute(
                "INSERT OR IGNORE INTO calls(caller, caller_class, callee, callee_class, line) "
                "VALUES (?,?,?,?,?)",
                (call.caller_method, call.caller_class,
                 call.callee_method, call.callee_class, call.line)
            )

        # 插入组件关系
        for comp in components:
            self.conn.execute(
                "INSERT OR IGNORE INTO components(parent, child) VALUES (?,?)",
                (comp.parent_class, comp.child_component)
            )

        # 插入导入（使用 INSERT OR IGNORE 避免重复）
        for imp in imports:
            self.conn.execute(
                "INSERT OR IGNORE INTO imports(raw, module, components, file_path) VALUES (?,?,?,?)",
                (imp.raw, imp.module, ','.join(imp.components), "")
            )

        self.conn.commit()

    def query(self, sql: str) -> List[Dict]:
        """执行查询并返回字典列表"""
        try:
            cursor = self.conn.execute(sql)
            if cursor.description:
                columns = [d[0] for d in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
            return []
        except Exception as e:
            # 查询失败返回空列表（如表不存在）
            return []

    def get_stats(self) -> Dict:
        """获取数据库统计信息"""
        stats = {}
        for table in ['files', 'classes', 'methods', 'calls', 'components', 'fields', 'imports']:
            count = self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            stats[table] = count
        return stats


# ============================================================
# SQL 安全校验器
# ============================================================
class SQLValidator:
    """SQL安全校验器 - 防止注入和破坏性操作"""

    # 允许的SQL前缀（只读操作）
    ALLOWED_PREFIXES = ('SELECT', 'WITH', 'EXPLAIN')

    # 禁止的关键字（注意：ATTACH/DETACH 移除，因为它们可能作为表名/列名出现，
    # 且作为SQL命令时已被前缀检查拦截）
    FORBIDDEN_KEYWORDS = (
        'DROP', 'DELETE', 'INSERT', 'UPDATE', 'ALTER', 'CREATE',
        'TRUNCATE', 'EXEC', 'EXECUTE', 'GRANT', 'REVOKE',
        'REINDEX', 'REPLACE', 'VACUUM', 'PRAGMA'
    )

    @classmethod
    def validate(cls, sql: str) -> Tuple[bool, str]:
        """
        校验SQL是否安全
        返回: (是否安全, 错误信息)
        """
        if not sql or not sql.strip():
            return False, "SQL为空"

        cleaned = sql.strip()

        # 先移除注释，再检查前缀
        # 移除单行注释 --
        no_comment = re.sub(r'--[^\n]*', '', cleaned)
        # 移除多行注释 /* */
        no_comment = re.sub(r'/\*.*?\*/', '', no_comment, flags=re.DOTALL)
        no_comment = no_comment.strip()

        # 检查前缀（移除注释后，转大写比较）
        first_word = no_comment.split()[0].upper() if no_comment.split() else ""
        if first_word not in cls.ALLOWED_PREFIXES:
            return False, f"只允许只读查询(SELECT/WITH/EXPLAIN)，检测到: {first_word}"

        # 检查多语句（分号分隔）
        # 移除字符串后检查是否还有分号
        no_strings = re.sub(r"'(?:[^'\\]|\\.)*'", "''", no_comment)
        no_strings = re.sub(r'"(?:[^"\\]|\\.)*"', '""', no_strings)
        semicolon_count = no_strings.count(';')
        if semicolon_count > 0:
            # 任何分号都视为多语句风险（注释注入场景）
            return False, "SQL中包含分号，可能存在多语句注入"

        # 检查禁止关键字（不区分大小写）
        upper_sql = no_strings.upper()
        for keyword in cls.FORBIDDEN_KEYWORDS:
            # 使用单词边界匹配，避免误判
            pattern = r'\b' + keyword + r'\b'
            if re.search(pattern, upper_sql):
                return False, f"SQL中包含禁止的关键字: {keyword}"

        return True, ""

    @classmethod
    def clean_ai_response(cls, raw: str) -> str:
        """清理AI返回的SQL"""
        if not raw:
            return ""

        # 去除markdown代码块
        raw = re.sub(r'```(?:sql|sqlite|SQL)?\s*', '', raw)
        raw = re.sub(r'```', '', raw)
        raw = raw.strip()

        # 尝试提取SQL语句（以SELECT/WITH/EXPLAIN开头）
        match = re.search(
            r'((?:SELECT|WITH|EXPLAIN)\s+.*?)(?:;|\s*$)',
            raw, re.DOTALL | re.IGNORECASE
        )
        if match:
            return match.group(1).strip()

        return raw.strip()


# ============================================================
# AI 查询引擎
# ============================================================
class AIQueryEngine:
    """AI自然语言转SQL查询引擎"""

    SCHEMA_DESC = """
数据库表结构：
1. files(path) - 文件路径，主键
2. classes(id, name, file, kind, is_comp, is_entry, extends, line_start, line_end) - 类/结构体
   - kind: struct/class/interface/enum
   - is_comp: 是否为@Component装饰的组件(1=是,0=否)
   - is_entry: 是否为@Entry装饰的入口(1=是,0=否)
3. methods(id, name, class_name, params, return_type, line_start, line_end) - 方法
4. calls(id, caller, caller_class, callee, callee_class, line) - 方法调用关系
5. components(id, parent, child) - 组件嵌套关系
6. fields(id, name, class_name) - 类字段/状态变量
7. imports(id, raw, module, components, file_path) - 导入语句

注意事项：
- is_comp 和 is_entry 是整数(0或1)，不是布尔值
- SQLite不支持布尔类型，用0和1代替
- 使用 LIKE 进行模糊匹配
- 表名和字段名区分大小写
"""

    def __init__(self, api_key: str, base_url: str = "https://api.siliconflow.cn/v1",
                 model: str = "Qwen/Qwen2.5-7B-Instruct"):
        try:
            from openai import OpenAI
            self.client = OpenAI(api_key=api_key, base_url=base_url)
            self.model = model
            self.available = True
        except ImportError:
            logger.error("未安装 openai 库，请执行: pip install openai")
            self.available = False
        except Exception as e:
            logger.error(f"AI客户端初始化失败: {e}")
            self.available = False

    def text_to_sql(self, question: str) -> Tuple[str, str]:
        """
        将自然语言问题转换为SQL
        返回: (sql, error_message)
        """
        if not self.available:
            return "", "AI服务不可用，请检查 openai 库是否已安装"

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{
                    "role": "system",
                    "content": f"你是一个SQLite SQL专家。{self.SCHEMA_DESC}规则：只返回一条SQL语句，不要任何解释，不要用markdown代码块包裹。"
                }, {
                    "role": "user",
                    "content": question
                }],
                temperature=0.1,
                max_tokens=512
            )

            if not response.choices:
                return "", "AI未返回有效结果"

            content = response.choices[0].message.content
            if not content:
                return "", "AI返回了空内容"

            sql = SQLValidator.clean_ai_response(content)

            # 安全校验
            is_safe, error = SQLValidator.validate(sql)
            if not is_safe:
                return "", f"安全校验失败: {error}"

            return sql, ""

        except Exception as e:
            return "", f"AI请求失败: {e}"


# ============================================================
# 主程序
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="零成本鸿蒙代码AI查询工具 v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python harmony_code_ai.py /path/to/project
  python harmony_code_ai.py /path/to/project --rebuild
  python harmony_code_ai.py /path/to/project --query "列出所有入口页面"
  python harmony_code_ai.py /path/to/project --stats
        """
    )
    parser.add_argument("project", help="鸿蒙项目路径")
    parser.add_argument("--rebuild", action="store_true", help="强制重新解析（清除旧数据）")
    parser.add_argument("--query", "-q", help="直接执行查询（非交互模式）")
    parser.add_argument("--stats", action="store_true", help="显示数据库统计信息")
    parser.add_argument("--db", default="code.db", help="数据库文件路径（默认: code.db）")
    parser.add_argument("--api-key", default="", help="硅基流动API Key（也可通过 SILICONFLOW_API_KEY 环境变量设置）")
    parser.add_argument("--model", default="Qwen/Qwen2.5-7B-Instruct", help="AI模型名称")

    args = parser.parse_args()

    # 验证项目路径
    project_path = os.path.abspath(args.project)
    if not os.path.exists(project_path):
        print(f"❌ 项目路径不存在: {project_path}")
        sys.exit(1)

    # 获取API Key
    api_key = args.api_key or os.environ.get("SILICONFLOW_API_KEY", "")
    if not api_key:
        print("⚠️  未设置API Key，AI查询功能将不可用")
        print("   设置方式: --api-key YOUR_KEY 或 export SILICONFLOW_API_KEY=YOUR_KEY")

    # 数据库路径（放在项目目录下）
    db_path = os.path.join(project_path, ".code_insight", "code.db")

    print(f"📂 项目路径: {project_path}")
    print(f"💾 数据库路径: {db_path}")

    # 确保数据库目录存在
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    # 解析项目
    with CodeDatabase(db_path) as db:
        if args.rebuild:
            print("🔄 强制重新解析...")
            db.clear_project_data()

        # 检查是否需要解析
        stats = db.get_stats()
        if stats['files'] == 0 or args.rebuild:
            print("\n🔍 正在解析鸿蒙项目...")
            parser_engine = ArkTSParser()
            classes, calls, components, files, imports = parser_engine.parse_project(project_path)
            db.insert_data(classes, calls, components, files, imports)
            stats = db.get_stats()
            print(f"✅ 解析完成！")
        else:
            print(f"✅ 使用已有数据库（{stats['files']} 个文件）")

        # 显示统计信息
        if args.stats:
            print(f"\n📊 数据库统计:")
            print(f"   文件: {stats['files']}")
            print(f"   类/结构体: {stats['classes']}")
            print(f"   方法: {stats['methods']}")
            print(f"   调用关系: {stats['calls']}")
            print(f"   组件关系: {stats['components']}")
            print(f"   字段: {stats['fields']}")
            print(f"   导入: {stats['imports']}")
            return

        # AI查询引擎
        ai_engine = AIQueryEngine(api_key=api_key, model=args.model) if api_key else None

        # 直接查询模式
        if args.query:
            if not ai_engine:
                print("❌ 需要API Key才能使用AI查询功能")
                sys.exit(1)
            result, error = ai_engine.text_to_sql(args.query)
            if error:
                print(f"❌ {error}")
                sys.exit(1)
            print(f"📝 SQL: {result}")
            rows = db.query(result)
            if rows:
                for row in rows:
                    print(f"   {row}")
            else:
                print("   (无结果)")
            return

        # 交互式查询模式
        print(f"\n{'='*60}")
        print("🤖 鸿蒙代码AI查询工具 v2.0")
        print(f"{'='*60}")
        print(f"📊 已索引: {stats['files']} 文件, {stats['classes']} 类, "
              f"{stats['methods']} 方法, {stats['calls']} 调用关系")
        print(f"\n💡 输入中文问题查询，输入 'stats' 查看统计，输入 'quit' 退出")

        while True:
            try:
                user_input = input("\n❓ ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n👋 再见！")
                break

            if not user_input:
                continue
            if user_input.lower() in ('quit', 'exit', 'q', '退出'):
                print("👋 再见！")
                break

            # 内置命令
            if user_input.lower() == 'stats':
                stats = db.get_stats()
                print(f"\n📊 文件:{stats['files']} 类:{stats['classes']} "
                      f"方法:{stats['methods']} 调用:{stats['calls']} "
                      f"组件:{stats['components']} 字段:{stats['fields']}")
                continue

            if user_input.lower() == 'help':
                print("""
📌 使用说明:
  - 直接输入中文问题，AI会自动转换为SQL查询
  - 示例: "列出所有入口页面"
  - 示例: "UserService在哪个文件"
  - 示例: "哪些方法调用了getUserInfo"
  - 示例: "HomePage包含哪些子组件"
  - 输入 'stats' 查看统计
  - 输入 'quit' 退出
                """)
                continue

            # 直接SQL模式（以 SELECT/WITH/EXPLAIN 开头）
            if user_input.upper().startswith(('SELECT', 'WITH', 'EXPLAIN')):
                try:
                    is_safe, error = SQLValidator.validate(user_input)
                    if not is_safe:
                        print(f"❌ {error}")
                        continue
                    rows = db.query(user_input)
                    if rows:
                        for row in rows:
                            print(f"   {row}")
                    else:
                        print("   (无结果)")
                except Exception as e:
                    print(f"❌ 查询出错: {e}")
                continue

            # 检测用户输入是否为SQL语句（即使不以 SELECT 开头）
            # 如果包含常见SQL关键字且不以中文/自然语言开头，尝试校验
            sql_keywords = ('DROP', 'DELETE', 'INSERT', 'UPDATE', 'ALTER', 'CREATE',
                           'TRUNCATE', 'REPLACE', 'PRAGMA', 'ATTACH')
            upper_input = user_input.upper().split()[0] if user_input.split() else ""
            if upper_input in sql_keywords:
                is_safe, error = SQLValidator.validate(user_input)
                print(f"❌ {error}")
                continue

            # AI查询模式
            if not ai_engine:
                print("⚠️  AI查询不可用（未设置API Key），但你可以直接输入SQL语句")
                print("   设置方式: export SILICONFLOW_API_KEY=your_key")
                continue

            sql, error = ai_engine.text_to_sql(user_input)
            if error:
                print(f"❌ {error}")
                continue

            print(f"📝 SQL: {sql}")
            try:
                rows = db.query(sql)
                if rows:
                    for row in rows:
                        print(f"   {row}")
                else:
                    print("   (无结果)")
            except Exception as e:
                print(f"❌ 查询出错: {e}")


if __name__ == "__main__":
    main()
