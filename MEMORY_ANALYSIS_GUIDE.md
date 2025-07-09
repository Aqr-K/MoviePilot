# 内存分析工具使用指南

## 概述

这个增强版的内存分析工具专门用于诊断Python应用程序的内存问题，特别是解决"总内存比各对象占比内存大很多"的问题。

## 主要功能

### 1. 系统级内存分析
- 进程内存使用详情（RSS、VMS、共享内存等）
- 系统内存状态
- 内存映射分析

### 2. Python对象深度分析
- 对象类型统计（按内存大小排序）
- Python对象总内存计算
- 未统计内存识别

### 3. 内存映射详细分析
- 按权限分类的内存映射
- 按文件分类的内存映射
- 识别C扩展和系统库占用的内存

### 4. 大对象分析
- 识别大于1MB的对象
- 对象详细信息（类型、大小、内容预览）

### 5. 内存泄漏检测
- tracemalloc内存分配统计
- 内存分配最多的位置
- 垃圾回收统计
- 不可达对象检测

## 使用方法

### 基本使用

```python
from app.helper.memory import MemoryHelper

# 创建内存分析器实例
memory_helper = MemoryHelper()

# 获取内存摘要
summary = memory_helper.get_memory_summary()
print(f"总内存: {summary['total_memory_mb']:.2f} MB")
print(f"Python对象: {summary['python_objects_mb']:.2f} MB")
print(f"未统计内存: {summary['unaccounted_mb']:.2f} MB")

# 强制垃圾回收
collected = memory_helper.force_garbage_collection()
print(f"清理了 {collected} 个对象")

# 创建详细分析报告
analysis_file = memory_helper.create_detailed_memory_analysis()
print(f"详细报告已保存到: {analysis_file}")
```

### 内存增长分析

```python
# 分析内存增长趋势（5分钟间隔）
growth_info = memory_helper.analyze_memory_growth(300)
print(f"内存增长率: {growth_info['growth_rate_mb_per_hour']:.2f} MB/小时")
```

### 启动自动监控

```python
# 启动内存监控（需要配置MEMORY_ANALYSIS=True）
memory_helper.start_monitoring()

# 停止监控
memory_helper.stop_monitoring()
```

## 配置选项

在配置文件中设置以下选项：

```python
# 启用内存分析
MEMORY_ANALYSIS = True

# 内存快照间隔（分钟）
MEMORY_SNAPSHOT_INTERVAL = 5

# 保留的快照文件数量
MEMORY_SNAPSHOT_KEEP_COUNT = 30
```

## 输出文件

### 1. 内存快照文件
- 位置: `logs/memory_snapshots/memory_snapshot_YYYYMMDD_HHMMSS.txt`
- 内容: 基本的内存使用统计

### 2. 详细分析报告
- 位置: `logs/memory_snapshots/detailed_memory_analysis_YYYYMMDD_HHMMSS.txt`
- 内容: 完整的内存分析报告

## 解决内存问题的步骤

### 1. 识别未统计内存
```python
summary = memory_helper.get_memory_summary()
if summary['unaccounted_percent'] > 50:
    print("警告: 超过50%的内存未被Python对象统计")
    print("可能的原因: C扩展、系统缓存、内存碎片")
```

### 2. 分析内存映射
详细分析报告中的"内存映射详细分析"部分会显示：
- 哪些文件占用了大量内存
- 内存权限分布
- 识别C扩展库

### 3. 检测内存泄漏
```python
# 定期检查内存增长
growth_info = memory_helper.analyze_memory_growth(300)
if growth_info['growth_rate_mb_per_hour'] > 100:
    print("警告: 内存增长过快，可能存在内存泄漏")
```

### 4. 分析大对象
详细分析报告会列出所有大于1MB的对象，帮助识别：
- 意外的内存占用
- 缓存未清理
- 数据结构过大

## 常见问题解决

### 问题1: 总内存比Python对象内存大很多

**原因**: 
- C扩展库占用内存
- 系统缓存
- 内存碎片
- 共享库

**解决方法**:
1. 查看内存映射分析
2. 检查是否有大量C扩展
3. 分析系统级内存使用

### 问题2: 内存持续增长

**原因**:
- 内存泄漏
- 缓存未清理
- 循环引用

**解决方法**:
1. 使用tracemalloc分析内存分配
2. 检查垃圾回收统计
3. 分析大对象列表

### 问题3: 特定对象类型占用过多内存

**解决方法**:
1. 查看对象类型统计
2. 分析大对象详情
3. 检查对象引用关系

## 性能注意事项

1. **详细分析耗时**: `create_detailed_memory_analysis()` 可能需要几秒到几分钟
2. **内存开销**: 分析过程本身会消耗一些内存
3. **建议频率**: 不要过于频繁地运行详细分析，建议间隔5分钟以上

## 调试技巧

### 1. 在关键点添加内存检查
```python
def critical_function():
    memory_helper = MemoryHelper()
    before = memory_helper.get_memory_summary()
    
    # 执行关键操作
    do_something()
    
    after = memory_helper.get_memory_summary()
    growth = after['total_memory_mb'] - before['total_memory_mb']
    if growth > 10:
        print(f"警告: 函数执行后内存增长 {growth:.2f} MB")
```

### 2. 监控特定操作
```python
def monitor_operation(operation_name):
    memory_helper = MemoryHelper()
    before = memory_helper.get_memory_summary()
    
    # 执行操作
    result = perform_operation()
    
    after = memory_helper.get_memory_summary()
    growth = after['total_memory_mb'] - before['total_memory_mb']
    
    logger.info(f"{operation_name}: 内存增长 {growth:.2f} MB")
    return result
```

## 示例输出

### 内存摘要示例
```
total_memory_mb: 708.20
python_objects_mb: 130.45
unaccounted_mb: 577.75
unaccounted_percent: 81.6
```

### 详细分析报告结构
```
详细内存分析报告 - 2025-07-09 14:26:00
====================================================================================================

1. 系统级内存分析
--------------------------------------------------
进程ID: 12345
进程名称: python
内存使用详情:
  RSS (物理内存): 708.20 MB
  VMS (虚拟内存): 1024.50 MB
  共享内存: 45.30 MB
  ...

2. Python对象深度分析
--------------------------------------------------
总对象数: 1,234,567
对象类型统计 (按内存大小排序):
类型                 数量        总大小(MB)    平均大小(B)
str                  318,537     34.56         113.5
dict                 101,049     32.23         319.2
...

3. 内存映射详细分析
--------------------------------------------------
按权限分类的内存映射:
权限        数量      大小(MB)
r-xp        45        156.78
rw-p        23        89.45
...

4. 大对象详细分析
--------------------------------------------------
大对象 (>1MB) 数量: 15

 1. dict - 45.67 MB
    字典项数: 125000
    示例键: ['user_data', 'cache', 'config']

 2. list - 23.45 MB
    元素数量: 500000

5. 内存泄漏检测
--------------------------------------------------
tracemalloc当前内存: 125.67 MB
tracemalloc峰值内存: 145.23 MB

内存分配最多的位置 (前15个):
 1.     1250 个对象,    45.67 MB
    File "/app/core/cache.py", line 123
    cache_data = load_large_dataset()
```

这个工具将帮助你全面了解应用程序的内存使用情况，特别是找出那些"消失"的内存去向。