#!/usr/bin/env python3
"""
测试修复后的超时机制
验证ThreadPoolExecutor超时机制在守护线程中的工作情况
"""

import time
import threading
import psutil
from app.helper.memory import MemoryHelper


def test_timeout_in_daemon_thread():
    """测试在守护线程中的超时机制"""
    print("=== 测试守护线程中的超时机制 ===")
    
    def long_running_task():
        """模拟长时间运行的任务"""
        print("开始长时间运行的任务...")
        time.sleep(60)  # 模拟60秒的长时间任务
        return "任务完成"
    
    def worker():
        """守护线程工作函数"""
        print(f"守护线程 {threading.current_thread().name} 开始工作")
        
        memory_helper = MemoryHelper()
        
        # 测试超时机制
        print("测试超时机制...")
        start_time = time.time()
        result = memory_helper._run_with_timeout(long_running_task)
        end_time = time.time()
        
        print(f"任务执行时间: {end_time - start_time:.2f}秒")
        print(f"任务结果: {result}")
        
        # 测试内存分析功能
        print("测试内存分析功能...")
        summary = memory_helper.get_memory_summary()
        print(f"内存摘要: {summary}")
    
    # 创建守护线程
    daemon_thread = threading.Thread(target=worker, daemon=True, name="TestDaemonThread")
    daemon_thread.start()
    
    # 等待线程完成或超时
    daemon_thread.join(timeout=40)  # 给40秒时间
    
    if daemon_thread.is_alive():
        print("守护线程仍在运行，但主线程继续执行")
    else:
        print("守护线程已完成")


def test_memory_analysis_performance():
    """测试内存分析性能"""
    print("\n=== 测试内存分析性能 ===")
    
    memory_helper = MemoryHelper()
    
    # 监控CPU使用率
    def monitor_cpu():
        cpu_samples = []
        for i in range(10):
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_samples.append(cpu_percent)
            print(f"CPU使用率: {cpu_percent:.1f}%")
        return sum(cpu_samples) / len(cpu_samples)
    
    print("测试前CPU使用率:")
    avg_cpu_before = monitor_cpu()
    
    # 执行内存分析
    print("\n执行内存分析...")
    start_time = time.time()
    
    # 测试详细内存分析（应该会超时）
    analysis_file = memory_helper.create_detailed_memory_analysis()
    
    end_time = time.time()
    print(f"内存分析耗时: {end_time - start_time:.2f}秒")
    
    if analysis_file:
        print(f"分析报告已保存: {analysis_file}")
    else:
        print("内存分析超时或失败")
    
    print("\n测试后CPU使用率:")
    avg_cpu_after = monitor_cpu()
    
    print(f"\n性能对比:")
    print(f"测试前平均CPU: {avg_cpu_before:.1f}%")
    print(f"测试后平均CPU: {avg_cpu_after:.1f}%")


def test_concurrent_analysis():
    """测试并发内存分析"""
    print("\n=== 测试并发内存分析 ===")
    
    def analysis_worker(worker_id):
        """分析工作线程"""
        print(f"工作线程 {worker_id} 开始")
        memory_helper = MemoryHelper()
        
        # 执行内存摘要
        summary = memory_helper.get_memory_summary()
        print(f"工作线程 {worker_id} 内存摘要: {summary}")
        
        # 执行垃圾回收
        collected = memory_helper.force_garbage_collection()
        print(f"工作线程 {worker_id} 垃圾回收: {collected} 个对象")
        
        print(f"工作线程 {worker_id} 完成")
    
    # 创建多个工作线程
    threads = []
    for i in range(3):
        thread = threading.Thread(target=analysis_worker, args=(i,), daemon=True)
        threads.append(thread)
        thread.start()
    
    # 等待所有线程完成
    for thread in threads:
        thread.join(timeout=30)
    
    print("所有工作线程已完成")


def main():
    """主测试函数"""
    print("超时机制修复测试")
    print("=" * 50)
    
    # 测试1: 守护线程中的超时机制
    test_timeout_in_daemon_thread()
    
    # 测试2: 内存分析性能
    test_memory_analysis_performance()
    
    # 测试3: 并发分析
    test_concurrent_analysis()
    
    print("\n测试完成！")


if __name__ == "__main__":
    main()