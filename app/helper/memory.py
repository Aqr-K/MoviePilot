import gc
import sys
import threading
import time
import os
import tracemalloc
from datetime import datetime
from typing import Optional, Dict, List, Tuple

import psutil
from pympler import muppy, summary, asizeof

from app.core.config import settings
from app.core.event import eventmanager, Event
from app.log import logger
from app.schemas import ConfigChangeEventData
from app.schemas.types import EventType
from app.utils.singleton import Singleton


class MemoryHelper(metaclass=Singleton):
    """
    内存管理工具类，用于监控和优化内存使用
    """

    def __init__(self):
        # 检查间隔(秒) - 从配置获取，默认5分钟
        self._check_interval = settings.MEMORY_SNAPSHOT_INTERVAL * 60
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        # 内存快照保存目录
        self._memory_snapshot_dir = settings.LOG_PATH / "memory_snapshots"
        # 保留的快照文件数量
        self._keep_count = settings.MEMORY_SNAPSHOT_KEEP_COUNT
        
        # 启用tracemalloc以获得更详细的内存信息
        if not tracemalloc.is_tracing():
            tracemalloc.start(25)  # 保留25个帧

    @eventmanager.register(EventType.ConfigChanged)
    def handle_config_changed(self, event: Event):
        """
        处理配置变更事件，更新内存监控设置
        :param event: 事件对象
        """
        if not event:
            return
        event_data: ConfigChangeEventData = event.event_data
        if event_data.key not in ['MEMORY_ANALYSIS', 'MEMORY_SNAPSHOT_INTERVAL', 'MEMORY_SNAPSHOT_KEEP_COUNT']:
            return

        # 更新配置
        if event_data.key == 'MEMORY_SNAPSHOT_INTERVAL':
            self._check_interval = settings.MEMORY_SNAPSHOT_INTERVAL * 60
        elif event_data.key == 'MEMORY_SNAPSHOT_KEEP_COUNT':
            self._keep_count = settings.MEMORY_SNAPSHOT_KEEP_COUNT
        self.stop_monitoring()
        self.start_monitoring()

    def start_monitoring(self):
        """
        开始内存监控
        """
        if not settings.MEMORY_ANALYSIS:
            return
        if self._monitoring:
            return

        # 创建内存快照目录
        self._memory_snapshot_dir.mkdir(parents=True, exist_ok=True)

        # 初始化内存分析器
        self._monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        logger.info("内存监控已启动")

    def stop_monitoring(self):
        """
        停止内存监控
        """
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
            logger.info("内存监控已停止")

    def _monitor_loop(self):
        """
        内存监控循环
        """
        logger.info("内存监控循环开始")
        while self._monitoring:
            try:
                # 生成内存快照
                self._create_memory_snapshot()
                time.sleep(self._check_interval)
            except Exception as e:
                logger.error(f"内存监控出错: {e}")
                # 出错后等待1分钟再继续
                time.sleep(60)
        logger.info("内存监控循环结束")

    def _create_memory_snapshot(self):
        """
        创建内存快照并保存到文件
        """
        try:
            # 获取当前时间戳
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            snapshot_file = self._memory_snapshot_dir / f"memory_snapshot_{timestamp}.txt"

            # 获取系统内存使用情况
            memory_usage = psutil.Process().memory_info().rss

            logger.info(f"开始创建内存快照: {snapshot_file}")

            # 第一步：写入基本信息和系统内存统计
            self._write_system_memory_info(snapshot_file, memory_usage)

            # 第二步：写入Python对象类型统计
            self._write_python_objects_info(snapshot_file)

            # 第三步：分析并写入类实例内存使用情况
            self._append_class_analysis(snapshot_file)

            # 第四步：分析并写入大内存变量详情
            self._append_variable_analysis(snapshot_file)

            # 第五步：分析内存泄漏和增长趋势
            self._append_memory_leak_analysis(snapshot_file)

            logger.info(f"内存快照已保存: {snapshot_file}, 当前内存使用: {memory_usage / 1024 / 1024:.2f} MB")

            # 清理过期的快照文件（保留最近30个）
            self._cleanup_old_snapshots()

        except Exception as e:
            logger.error(f"创建内存快照失败: {e}")

    def _write_system_memory_info(self, snapshot_file, memory_usage):
        """
        写入系统内存信息
        """
        process = psutil.Process()
        memory_info = process.memory_info()
        memory_percent = process.memory_percent()
        
        # 获取系统总内存信息
        system_memory = psutil.virtual_memory()
        
        # 获取内存映射信息
        memory_maps = process.memory_maps()
        
        with open(snapshot_file, 'w', encoding='utf-8') as f:
            f.write(f"内存快照时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n")
            f.write("系统内存使用情况:\n")
            f.write("-" * 80 + "\n")
            f.write(f"当前进程内存使用: {memory_usage / 1024 / 1024:.2f} MB\n")
            f.write(f"进程内存使用率: {memory_percent:.2f}%\n")
            f.write(f"系统总内存: {system_memory.total / 1024 / 1024 / 1024:.2f} GB\n")
            f.write(f"系统可用内存: {system_memory.available / 1024 / 1024 / 1024:.2f} GB\n")
            f.write(f"系统内存使用率: {system_memory.percent:.2f}%\n")
            f.write(f"进程RSS内存: {memory_info.rss / 1024 / 1024:.2f} MB\n")
            f.write(f"进程VMS内存: {memory_info.vms / 1024 / 1024:.2f} MB\n")
            f.write(f"进程共享内存: {memory_info.shared / 1024 / 1024:.2f} MB\n")
            f.write(f"进程文本段: {memory_info.text / 1024 / 1024:.2f} MB\n")
            f.write(f"进程数据段: {memory_info.data / 1024 / 1024:.2f} MB\n")
            
            # 分析内存映射
            f.write("\n内存映射分析:\n")
            f.write("-" * 80 + "\n")
            memory_regions = self._analyze_memory_maps(memory_maps)
            for region_type, size_mb in memory_regions.items():
                f.write(f"{region_type}: {size_mb:.2f} MB\n")
            
            f.flush()

    def _analyze_memory_maps(self, memory_maps) -> Dict[str, float]:
        """
        分析内存映射，按类型分类统计
        """
        regions = {}
        for mmap in memory_maps:
            size_mb = mmap.size / 1024 / 1024
            perms = mmap.perms
            
            if 'r' in perms and 'w' in perms:
                region_type = "读写内存"
            elif 'r' in perms and 'x' in perms:
                region_type = "代码段"
            elif 'r' in perms:
                region_type = "只读内存"
            else:
                region_type = "其他内存"
            
            if region_type in regions:
                regions[region_type] += size_mb
            else:
                regions[region_type] = size_mb
        
        return regions

    def _write_python_objects_info(self, snapshot_file):
        """
        写入Python对象类型统计信息
        """
        # 获取当前tracemalloc统计
        current, peak = tracemalloc.get_traced_memory()
        
        # 获取所有对象
        all_objects = muppy.get_objects()
        sum1 = summary.summarize(all_objects)
        
        # 计算Python对象总内存
        python_total_mb = 0
        for line in summary.format_(sum1):
            if '|' in line and line.strip() and not line.startswith('=') and not line.startswith('-'):
                parts = line.split('|')
                if len(parts) >= 3:
                    try:
                        size_str = parts[2].strip()
                        if 'MB' in size_str:
                            size_mb = float(size_str.replace('MB', '').strip())
                            python_total_mb += size_mb
                    except:
                        pass

        with open(snapshot_file, 'a', encoding='utf-8') as f:
            f.write("\n" + "=" * 80 + "\n")
            f.write("Python内存使用情况:\n")
            f.write("-" * 80 + "\n")
            f.write(f"tracemalloc当前内存: {current / 1024 / 1024:.2f} MB\n")
            f.write(f"tracemalloc峰值内存: {peak / 1024 / 1024:.2f} MB\n")
            f.write(f"Python对象总内存: {python_total_mb:.2f} MB\n")
            f.write(f"未统计内存(可能为C扩展): {self._get_unaccounted_memory():.2f} MB\n")
            
            f.write("\n对象类型统计:\n")
            f.write("-" * 80 + "\n")
            # 写入对象统计信息
            for line in summary.format_(sum1):
                f.write(line + "\n")
            
            f.flush()

    def _get_unaccounted_memory(self) -> float:
        """
        计算未统计的内存（可能是C扩展、系统缓存等）
        """
        try:
            # 获取进程总内存
            process = psutil.Process()
            total_memory = process.memory_info().rss / 1024 / 1024  # MB
            
            # 获取Python对象总内存
            all_objects = muppy.get_objects()
            sum1 = summary.summarize(all_objects)
            
            python_total_mb = 0
            for line in summary.format_(sum1):
                if '|' in line and line.strip() and not line.startswith('=') and not line.startswith('-'):
                    parts = line.split('|')
                    if len(parts) >= 3:
                        try:
                            size_str = parts[2].strip()
                            if 'MB' in size_str:
                                size_mb = float(size_str.replace('MB', '').strip())
                                python_total_mb += size_mb
                        except:
                            pass
            
            return max(0, total_memory - python_total_mb)
        except:
            return 0.0

    def _append_memory_leak_analysis(self, snapshot_file):
        """
        分析内存泄漏和增长趋势
        """
        with open(snapshot_file, 'a', encoding='utf-8') as f:
            f.write("\n" + "=" * 80 + "\n")
            f.write("内存泄漏分析:\n")
            f.write("-" * 80 + "\n")
            
            # 获取tracemalloc统计
            current, peak = tracemalloc.get_traced_memory()
            f.write(f"当前tracemalloc内存: {current / 1024 / 1024:.2f} MB\n")
            f.write(f"tracemalloc峰值内存: {peak / 1024 / 1024:.2f} MB\n")
            
            # 获取内存分配统计
            try:
                stats = tracemalloc.get_traced_memory()
                f.write(f"内存分配统计: {stats}\n")
                
                # 获取前10个内存分配最多的位置
                snapshot = tracemalloc.take_snapshot()
                top_stats = snapshot.statistics('lineno')
                
                f.write("\n内存分配最多的位置 (前10个):\n")
                f.write("-" * 80 + "\n")
                for i, stat in enumerate(top_stats[:10], 1):
                    f.write(f"{i:2d}. {stat.count:>8} 个对象, {stat.size / 1024 / 1024:>8.2f} MB\n")
                    f.write(f"    {stat.traceback.format()}\n")
                    
            except Exception as e:
                f.write(f"获取内存分配统计失败: {e}\n")
            
            # 垃圾回收统计
            f.write("\n垃圾回收统计:\n")
            f.write("-" * 80 + "\n")
            for i in range(3):
                count = gc.get_count()[i]
                f.write(f"GC代 {i}: {count} 次\n")
            
            # 获取不可达对象数量
            unreachable = len(gc.garbage)
            f.write(f"不可达对象数量: {unreachable}\n")
            
            f.flush()
        
        logger.debug("内存泄漏分析已完成并写入")

    def create_detailed_memory_analysis(self):
        """
        创建详细的内存分析报告，专门用于诊断内存问题
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            analysis_file = self._memory_snapshot_dir / f"detailed_memory_analysis_{timestamp}.txt"
            
            logger.info(f"开始创建详细内存分析: {analysis_file}")
            
            with open(analysis_file, 'w', encoding='utf-8') as f:
                f.write(f"详细内存分析报告 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 100 + "\n\n")
                
                # 1. 系统级内存分析
                self._write_detailed_system_analysis(f)
                
                # 2. Python对象深度分析
                self._write_detailed_python_analysis(f)
                
                # 3. 内存映射详细分析
                self._write_detailed_memory_maps(f)
                
                # 4. 大对象分析
                self._write_detailed_large_objects(f)
                
                # 5. 内存泄漏检测
                self._write_memory_leak_detection(f)
                
            logger.info(f"详细内存分析已保存: {analysis_file}")
            return analysis_file
            
        except Exception as e:
            logger.error(f"创建详细内存分析失败: {e}")
            return None

    def _write_detailed_system_analysis(self, f):
        """
        写入详细的系统内存分析
        """
        f.write("1. 系统级内存分析\n")
        f.write("-" * 50 + "\n")
        
        process = psutil.Process()
        memory_info = process.memory_info()
        
        f.write(f"进程ID: {process.pid}\n")
        f.write(f"进程名称: {process.name()}\n")
        f.write(f"进程命令行: {' '.join(process.cmdline())}\n\n")
        
        f.write("内存使用详情:\n")
        f.write(f"  RSS (物理内存): {memory_info.rss / 1024 / 1024:.2f} MB\n")
        f.write(f"  VMS (虚拟内存): {memory_info.vms / 1024 / 1024:.2f} MB\n")
        f.write(f"  共享内存: {memory_info.shared / 1024 / 1024:.2f} MB\n")
        f.write(f"  文本段: {memory_info.text / 1024 / 1024:.2f} MB\n")
        f.write(f"  数据段: {memory_info.data / 1024 / 1024:.2f} MB\n")
        f.write(f"  库内存: {memory_info.lib / 1024 / 1024:.2f} MB\n")
        f.write(f"  脏页: {memory_info.dirty / 1024 / 1024:.2f} MB\n")
        
        # 系统内存信息
        system_memory = psutil.virtual_memory()
        f.write(f"\n系统内存:\n")
        f.write(f"  总内存: {system_memory.total / 1024 / 1024 / 1024:.2f} GB\n")
        f.write(f"  可用内存: {system_memory.available / 1024 / 1024 / 1024:.2f} GB\n")
        f.write(f"  使用率: {system_memory.percent:.2f}%\n")
        f.write(f"  缓存: {system_memory.cached / 1024 / 1024 / 1024:.2f} GB\n")
        f.write(f"  缓冲区: {system_memory.buffers / 1024 / 1024 / 1024:.2f} GB\n")
        
        f.write("\n" + "=" * 100 + "\n\n")

    def _write_detailed_python_analysis(self, f):
        """
        写入详细的Python对象分析
        """
        f.write("2. Python对象深度分析\n")
        f.write("-" * 50 + "\n")
        
        # 强制垃圾回收
        collected = gc.collect()
        f.write(f"垃圾回收清理对象数: {collected}\n\n")
        
        # 获取所有对象
        all_objects = muppy.get_objects()
        f.write(f"总对象数: {len(all_objects):,}\n")
        
        # 按类型统计
        type_stats = {}
        for obj in all_objects:
            obj_type = type(obj).__name__
            if obj_type not in type_stats:
                type_stats[obj_type] = {'count': 0, 'size': 0}
            type_stats[obj_type]['count'] += 1
            type_stats[obj_type]['size'] += sys.getsizeof(obj)
        
        # 按大小排序
        sorted_types = sorted(type_stats.items(), key=lambda x: x[1]['size'], reverse=True)
        
        f.write("对象类型统计 (按内存大小排序):\n")
        f.write(f"{'类型':<20} {'数量':<10} {'总大小(MB)':<12} {'平均大小(B)':<12}\n")
        f.write("-" * 60 + "\n")
        
        total_python_memory = 0
        for obj_type, stats in sorted_types[:20]:  # 只显示前20个
            size_mb = stats['size'] / 1024 / 1024
            avg_size = stats['size'] / stats['count'] if stats['count'] > 0 else 0
            total_python_memory += size_mb
            f.write(f"{obj_type:<20} {stats['count']:<10,} {size_mb:<12.2f} {avg_size:<12.1f}\n")
        
        f.write(f"\nPython对象总内存: {total_python_memory:.2f} MB\n")
        
        # 计算未统计内存
        process = psutil.Process()
        total_memory = process.memory_info().rss / 1024 / 1024
        unaccounted = total_memory - total_python_memory
        f.write(f"未统计内存: {unaccounted:.2f} MB ({unaccounted/total_memory*100:.1f}%)\n")
        
        f.write("\n" + "=" * 100 + "\n\n")

    def _write_detailed_memory_maps(self, f):
        """
        写入详细的内存映射分析
        """
        f.write("3. 内存映射详细分析\n")
        f.write("-" * 50 + "\n")
        
        process = psutil.Process()
        memory_maps = process.memory_maps()
        
        # 按权限分类
        perm_stats = {}
        file_stats = {}
        
        for mmap in memory_maps:
            size_mb = mmap.size / 1024 / 1024
            perms = mmap.perms
            
            # 按权限统计
            if perms not in perm_stats:
                perm_stats[perms] = {'count': 0, 'size': 0}
            perm_stats[perms]['count'] += 1
            perm_stats[perms]['size'] += size_mb
            
            # 按文件统计
            if mmap.path:
                if mmap.path not in file_stats:
                    file_stats[mmap.path] = {'count': 0, 'size': 0}
                file_stats[mmap.path]['count'] += 1
                file_stats[mmap.path]['size'] += size_mb
        
        f.write("按权限分类的内存映射:\n")
        f.write(f"{'权限':<10} {'数量':<8} {'大小(MB)':<12}\n")
        f.write("-" * 35 + "\n")
        for perms, stats in sorted(perm_stats.items(), key=lambda x: x[1]['size'], reverse=True):
            f.write(f"{perms:<10} {stats['count']:<8} {stats['size']:<12.2f}\n")
        
        f.write(f"\n按文件分类的内存映射 (前10个):\n")
        f.write(f"{'文件路径':<50} {'大小(MB)':<12}\n")
        f.write("-" * 70 + "\n")
        for path, stats in sorted(file_stats.items(), key=lambda x: x[1]['size'], reverse=True)[:10]:
            if len(path) > 47:
                path = path[:44] + "..."
            f.write(f"{path:<50} {stats['size']:<12.2f}\n")
        
        f.write("\n" + "=" * 100 + "\n\n")

    def _write_detailed_large_objects(self, f):
        """
        写入大对象详细分析
        """
        f.write("4. 大对象详细分析\n")
        f.write("-" * 50 + "\n")
        
        all_objects = muppy.get_objects()
        large_objects = []
        
        for obj in all_objects:
            try:
                size = asizeof.asizeof(obj)
                if size > 1024 * 1024:  # 大于1MB的对象
                    large_objects.append((obj, size))
            except:
                continue
        
        # 按大小排序
        large_objects.sort(key=lambda x: x[1], reverse=True)
        
        f.write(f"大对象 (>1MB) 数量: {len(large_objects)}\n\n")
        
        for i, (obj, size) in enumerate(large_objects[:20], 1):  # 只显示前20个
            size_mb = size / 1024 / 1024
            obj_type = type(obj).__name__
            
            f.write(f"{i:2d}. {obj_type} - {size_mb:.2f} MB\n")
            
            # 尝试获取更多信息
            try:
                if isinstance(obj, dict):
                    f.write(f"    字典项数: {len(obj)}\n")
                    if obj:
                        sample_keys = list(obj.keys())[:3]
                        f.write(f"    示例键: {sample_keys}\n")
                elif isinstance(obj, (list, tuple)):
                    f.write(f"    元素数量: {len(obj)}\n")
                elif isinstance(obj, str):
                    f.write(f"    字符串长度: {len(obj)}\n")
                    if len(obj) > 100:
                        f.write(f"    内容预览: {obj[:100]}...\n")
                    else:
                        f.write(f"    内容: {obj}\n")
                elif hasattr(obj, '__dict__'):
                    f.write(f"    属性数量: {len(obj.__dict__)}\n")
                    if hasattr(obj, '__class__'):
                        f.write(f"    类名: {obj.__class__.__name__}\n")
            except:
                pass
            
            f.write("\n")
        
        f.write("=" * 100 + "\n\n")

    def _write_memory_leak_detection(self, f):
        """
        写入内存泄漏检测
        """
        f.write("5. 内存泄漏检测\n")
        f.write("-" * 50 + "\n")
        
        # tracemalloc分析
        current, peak = tracemalloc.get_traced_memory()
        f.write(f"tracemalloc当前内存: {current / 1024 / 1024:.2f} MB\n")
        f.write(f"tracemalloc峰值内存: {peak / 1024 / 1024:.2f} MB\n")
        
        try:
            snapshot = tracemalloc.take_snapshot()
            top_stats = snapshot.statistics('lineno')
            
            f.write(f"\n内存分配最多的位置 (前15个):\n")
            f.write("-" * 50 + "\n")
            for i, stat in enumerate(top_stats[:15], 1):
                f.write(f"{i:2d}. {stat.count:>8} 个对象, {stat.size / 1024 / 1024:>8.2f} MB\n")
                for line in stat.traceback.format():
                    f.write(f"    {line}\n")
                f.write("\n")
        except Exception as e:
            f.write(f"获取tracemalloc统计失败: {e}\n")
        
        # 垃圾回收分析
        f.write("垃圾回收分析:\n")
        f.write("-" * 50 + "\n")
        gc_counts = gc.get_count()
        f.write(f"GC计数: {gc_counts}\n")
        
        # 检查不可达对象
        unreachable = len(gc.garbage)
        f.write(f"不可达对象数量: {unreachable}\n")
        if unreachable > 0:
            f.write("不可达对象详情:\n")
            for i, obj in enumerate(gc.garbage[:5], 1):  # 只显示前5个
                f.write(f"  {i}. {type(obj).__name__} - {id(obj)}\n")
        
        f.write("\n" + "=" * 100 + "\n\n")

    def _append_class_analysis(self, snapshot_file):
        """
        分析并追加类实例内存使用情况
        """
        with open(snapshot_file, 'a', encoding='utf-8') as f:
            f.write("\n" + "=" * 80 + "\n")
            f.write("类实例内存使用情况 (按内存大小排序):\n")
            f.write("-" * 80 + "\n")
            f.write("正在分析中...\n")
            # 立即刷新，让用户知道这部分开始了
            f.flush()

        try:
            logger.debug("开始分析类实例内存使用情况")
            class_objects = self._get_class_memory_usage()

            # 重新打开文件，移除"正在分析中..."并写入实际结果
            with open(snapshot_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # 替换"正在分析中..."
            content = content.replace("正在分析中...\n", "")

            with open(snapshot_file, 'w', encoding='utf-8') as f:
                f.write(content)

                if class_objects:
                    # 只显示前100个类
                    for i, class_info in enumerate(class_objects[:100], 1):
                        f.write(f"{i:3d}. {class_info['name']:<50} "
                                f"{class_info['size_mb']:>8.2f} MB ({class_info['count']} 个实例)\n")
                else:
                    f.write("未找到有效的类实例信息\n")

                f.flush()

        except Exception as e:
            logger.error(f"获取类实例信息失败: {e}")

            # 即使出错也要更新文件
            with open(snapshot_file, 'r', encoding='utf-8') as f:
                content = f.read()

            content = content.replace("正在分析中...\n", f"获取类实例信息失败: {e}\n")

            with open(snapshot_file, 'w', encoding='utf-8') as f:
                f.write(content)
                f.flush()

        logger.debug("类实例分析已完成并写入")

    def _append_variable_analysis(self, snapshot_file):
        """
        分析并追加大内存变量详情
        """
        with open(snapshot_file, 'a', encoding='utf-8') as f:
            f.write("\n" + "=" * 80 + "\n")
            f.write("大内存变量详情 (前100个):\n")
            f.write("-" * 80 + "\n")
            f.write("正在分析中...\n")
            # 立即刷新，让用户知道这部分开始了
            f.flush()

        try:
            logger.debug("开始分析大内存变量")
            large_variables = self._get_large_variables(100)

            # 重新打开文件，移除"正在分析中..."并写入实际结果
            with open(snapshot_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # 替换最后的"正在分析中..."
            content = content.replace("正在分析中...\n", "")

            with open(snapshot_file, 'w', encoding='utf-8') as f:
                f.write(content)

                if large_variables:
                    for i, var_info in enumerate(large_variables, 1):
                        f.write(
                            f"{i:3d}. {var_info['name']:<30} {var_info['type']:<15} {var_info['size_mb']:>8.2f} MB\n")
                else:
                    f.write("未找到大内存变量\n")

                f.flush()

        except Exception as e:
            logger.error(f"获取大内存变量信息失败: {e}")

            # 即使出错也要更新文件
            with open(snapshot_file, 'r', encoding='utf-8') as f:
                content = f.read()

            content = content.replace("正在分析中...\n", f"获取变量信息失败: {e}\n")

            with open(snapshot_file, 'w', encoding='utf-8') as f:
                f.write(content)
                f.flush()

        logger.debug("大内存变量分析已完成并写入")

    def _cleanup_old_snapshots(self):
        """
        清理过期的内存快照文件，只保留最近的指定数量文件
        """
        try:
            snapshot_files = list(self._memory_snapshot_dir.glob("memory_snapshot_*.txt"))
            if len(snapshot_files) > self._keep_count:
                # 按修改时间排序，删除最旧的文件
                snapshot_files.sort(key=lambda x: x.stat().st_mtime)
                for old_file in snapshot_files[:-self._keep_count]:
                    old_file.unlink()
                    logger.debug(f"已删除过期内存快照: {old_file}")
        except Exception as e:
            logger.error(f"清理过期快照失败: {e}")

    @staticmethod
    def _get_class_memory_usage():
        """
        获取所有类实例的内存使用情况，按内存大小排序
        """
        class_info = {}
        processed_count = 0
        error_count = 0

        # 获取所有对象
        all_objects = muppy.get_objects()
        logger.debug(f"开始分析 {len(all_objects)} 个对象的类实例内存使用情况")

        for obj in all_objects:
            try:
                # 跳过类对象本身，统计类的实例
                if isinstance(obj, type):
                    continue

                # 获取对象的类名 - 这里可能会出错
                obj_class = type(obj)

                # 安全地获取类名
                try:
                    if hasattr(obj_class, '__module__') and hasattr(obj_class, '__name__'):
                        class_name = f"{obj_class.__module__}.{obj_class.__name__}"
                    else:
                        class_name = str(obj_class)
                except Exception as e:
                    # 如果获取类名失败，使用简单的类型描述
                    class_name = f"<unknown_class_{id(obj_class)}>"
                    logger.debug(f"获取类名失败: {e}")

                # 计算对象本身的内存使用（不包括引用对象，避免重复计算）
                size_bytes = sys.getsizeof(obj)
                if size_bytes < 100:  # 跳过太小的对象
                    continue

                size_mb = size_bytes / 1024 / 1024
                processed_count += 1

                if class_name in class_info:
                    class_info[class_name]['size_mb'] += size_mb
                    class_info[class_name]['count'] += 1
                else:
                    class_info[class_name] = {
                        'name': class_name,
                        'size_mb': size_mb,
                        'count': 1
                    }

            except Exception as e:
                # 捕获所有可能的异常，包括SQLAlchemy、ORM等框架的异常
                error_count += 1
                if error_count <= 5:  # 只记录前5个错误，避免日志过多
                    logger.debug(f"分析对象时出错: {e}")
                continue

        logger.debug(f"类实例分析完成: 处理了 {processed_count} 个对象, 遇到 {error_count} 个错误")

        # 按内存大小排序
        sorted_classes = sorted(class_info.values(), key=lambda x: x['size_mb'], reverse=True)
        return sorted_classes

    def _get_large_variables(self, limit=100):
        """
        获取大内存变量信息，按内存大小排序
        使用已计算对象集合避免重复计算
        """
        large_vars = []
        processed_count = 0
        calculated_objects = set()  # 避免重复计算

        # 获取所有对象
        all_objects = muppy.get_objects()
        logger.debug(f"开始分析 {len(all_objects)} 个对象的内存使用情况")

        for obj in all_objects:
            # 跳过类对象
            if isinstance(obj, type):
                continue

            # 跳过已经计算过的对象
            obj_id = id(obj)
            if obj_id in calculated_objects:
                continue

            try:
                # 首先使用 sys.getsizeof 快速筛选
                shallow_size = sys.getsizeof(obj)
                if shallow_size < 1024:  # 只处理大于1KB的对象
                    continue

                # 对于较大的对象，使用 asizeof 进行深度计算
                size_bytes = asizeof.asizeof(obj)

                # 只处理大于10KB的对象，提高分析效率
                if size_bytes < 10240:
                    continue

                size_mb = size_bytes / 1024 / 1024
                processed_count += 1
                calculated_objects.add(obj_id)

                # 获取对象信息
                var_info = self._get_variable_info(obj, size_mb)
                if var_info:
                    large_vars.append(var_info)

                # 如果已经找到足够多的大对象，可以提前结束
                if len(large_vars) >= limit * 2:  # 多收集一些，后面排序筛选
                    break

            except Exception as e:
                # 更广泛的异常捕获
                logger.debug(f"分析对象失败: {e}")
                continue

        logger.debug(f"处理了 {processed_count} 个大对象，找到 {len(large_vars)} 个有效变量")

        # 按内存大小排序并返回前N个
        large_vars.sort(key=lambda x: x['size_mb'], reverse=True)
        return large_vars[:limit]

    def _get_variable_info(self, obj, size_mb):
        """
        获取变量的描述信息
        """
        try:
            obj_type = type(obj).__name__

            # 尝试获取变量名
            var_name = self._get_variable_name(obj)

            # 生成描述性信息
            if isinstance(obj, dict):
                key_count = len(obj)
                if key_count > 0:
                    sample_keys = list(obj.keys())[:3]
                    var_name += f" ({key_count}项, 键: {sample_keys})"
            elif isinstance(obj, (list, tuple, set)):
                var_name += f" ({len(obj)}个元素)"
            elif isinstance(obj, str):
                if len(obj) > 50:
                    var_name += f" (长度: {len(obj)}, 内容: '{obj[:50]}...')"
                else:
                    var_name += f" ('{obj}')"
            elif hasattr(obj, '__class__') and hasattr(obj.__class__, '__name__'):
                if hasattr(obj, '__dict__'):
                    attr_count = len(obj.__dict__)
                    var_name += f" ({attr_count}个属性)"

            return {
                'name': var_name,
                'type': obj_type,
                'size_mb': size_mb
            }

        except Exception as e:
            logger.debug(f"获取变量信息失败: {e}")
            return None

    @staticmethod
    def _get_variable_name(obj):
        """
        尝试获取变量名
        """
        try:
            # 尝试通过gc获取引用该对象的变量名
            referrers = gc.get_referrers(obj)

            for referrer in referrers:
                if isinstance(referrer, dict):
                    # 检查是否在某个模块的全局变量中
                    for name, value in referrer.items():
                        if value is obj and isinstance(name, str):
                            return name
                elif hasattr(referrer, '__dict__'):
                    # 检查是否在某个实例的属性中
                    for name, value in referrer.__dict__.items():
                        if value is obj and isinstance(name, str):
                            return f"{type(referrer).__name__}.{name}"

            # 如果找不到变量名，返回对象类型和id
            return f"{type(obj).__name__}_{id(obj)}"

        except Exception as e:
            logger.debug(f"获取变量名失败: {e}")
            return f"{type(obj).__name__}_{id(obj)}"

    def get_memory_summary(self) -> Dict[str, float]:
        """
        获取内存使用摘要
        """
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            
            # 获取Python对象总内存
            all_objects = muppy.get_objects()
            sum1 = summary.summarize(all_objects)
            
            python_total_mb = 0
            for line in summary.format_(sum1):
                if '|' in line and line.strip() and not line.startswith('=') and not line.startswith('-'):
                    parts = line.split('|')
                    if len(parts) >= 3:
                        try:
                            size_str = parts[2].strip()
                            if 'MB' in size_str:
                                size_mb = float(size_str.replace('MB', '').strip())
                                python_total_mb += size_mb
                        except:
                            pass
            
            total_memory = memory_info.rss / 1024 / 1024
            unaccounted = total_memory - python_total_mb
            
            return {
                'total_memory_mb': total_memory,
                'python_objects_mb': python_total_mb,
                'unaccounted_mb': unaccounted,
                'unaccounted_percent': (unaccounted / total_memory * 100) if total_memory > 0 else 0
            }
        except Exception as e:
            logger.error(f"获取内存摘要失败: {e}")
            return {}

    def force_garbage_collection(self):
        """
        强制垃圾回收并返回清理的对象数量
        """
        try:
            collected = gc.collect()
            logger.info(f"强制垃圾回收完成，清理了 {collected} 个对象")
            return collected
        except Exception as e:
            logger.error(f"强制垃圾回收失败: {e}")
            return 0

    def analyze_memory_growth(self, interval_seconds: int = 300) -> Dict[str, float]:
        """
        分析内存增长趋势
        :param interval_seconds: 分析间隔（秒）
        :return: 内存增长信息
        """
        try:
            # 获取当前内存使用
            current_summary = self.get_memory_summary()
            
            # 等待指定时间
            time.sleep(interval_seconds)
            
            # 获取新的内存使用
            new_summary = self.get_memory_summary()
            
            if current_summary and new_summary:
                growth_info = {
                    'total_growth_mb': new_summary['total_memory_mb'] - current_summary['total_memory_mb'],
                    'python_growth_mb': new_summary['python_objects_mb'] - current_summary['python_objects_mb'],
                    'unaccounted_growth_mb': new_summary['unaccounted_mb'] - current_summary['unaccounted_mb'],
                    'growth_rate_mb_per_hour': (new_summary['total_memory_mb'] - current_summary['total_memory_mb']) * 3600 / interval_seconds
                }
                
                logger.info(f"内存增长分析: 总增长 {growth_info['total_growth_mb']:.2f} MB, "
                           f"Python对象增长 {growth_info['python_growth_mb']:.2f} MB, "
                           f"未统计增长 {growth_info['unaccounted_growth_mb']:.2f} MB")
                
                return growth_info
            
            return {}
            
        except Exception as e:
            logger.error(f"分析内存增长失败: {e}")
            return {}


# 使用示例
if __name__ == "__main__":
    # 创建内存分析器实例
    memory_helper = MemoryHelper()
    
    # 获取内存摘要
    summary = memory_helper.get_memory_summary()
    print("内存使用摘要:")
    for key, value in summary.items():
        print(f"  {key}: {value:.2f}")
    
    # 创建详细分析报告
    analysis_file = memory_helper.create_detailed_memory_analysis()
    if analysis_file:
        print(f"详细分析报告已保存到: {analysis_file}")
    
    # 强制垃圾回收
    collected = memory_helper.force_garbage_collection()
    print(f"垃圾回收清理了 {collected} 个对象")
