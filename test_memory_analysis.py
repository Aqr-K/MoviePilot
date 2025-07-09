#!/usr/bin/env python3
"""
内存分析工具测试脚本
用于验证内存分析工具的功能和修复后的效果
"""

import sys
import os
import time
import gc

# 添加项目路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app.helper.memory import MemoryHelper
from app.log import logger

def test_memory_analysis():
    """测试内存分析功能"""
    print("开始测试内存分析工具...")
    
    # 创建内存分析器实例
    memory_helper = MemoryHelper()
    
    # 1. 测试内存摘要
    print("\n1. 测试内存摘要:")
    summary = memory_helper.get_memory_summary()
    for key, value in summary.items():
        print(f"  {key}: {value:.2f}")
    
    # 2. 测试强制垃圾回收
    print("\n2. 测试强制垃圾回收:")
    collected = memory_helper.force_garbage_collection()
    print(f"  清理了 {collected} 个对象")
    
    # 3. 创建一些测试数据来模拟内存使用
    print("\n3. 创建测试数据:")
    test_data = {
        'large_list': [i for i in range(100000)],  # 约2.4MB
        'large_dict': {f'key_{i}': f'value_{i}' for i in range(50000)},  # 约3MB
        'large_string': 'x' * 1000000,  # 约1MB
    }
    print(f"  创建了测试数据，包含 {len(test_data)} 个大对象")
    
    # 4. 再次获取内存摘要
    print("\n4. 创建测试数据后的内存摘要:")
    summary_after = memory_helper.get_memory_summary()
    for key, value in summary_after.items():
        print(f"  {key}: {value:.2f}")
    
    # 5. 计算内存增长
    print("\n5. 内存增长分析:")
    if summary and summary_after:
        total_growth = summary_after['total_memory_mb'] - summary['total_memory_mb']
        python_growth = summary_after['python_objects_mb'] - summary['python_objects_mb']
        unaccounted_growth = summary_after['unaccounted_mb'] - summary['unaccounted_mb']
        
        print(f"  总内存增长: {total_growth:.2f} MB")
        print(f"  Python对象增长: {python_growth:.2f} MB")
        print(f"  未统计内存增长: {unaccounted_growth:.2f} MB")
    
    # 6. 创建详细分析报告
    print("\n6. 创建详细分析报告:")
    analysis_file = memory_helper.create_detailed_memory_analysis()
    if analysis_file:
        print(f"  详细分析报告已保存到: {analysis_file}")
        
        # 显示报告的前几行
        print("\n  报告预览:")
        try:
            with open(analysis_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()[:20]
                for line in lines:
                    print(f"    {line.rstrip()}")
            print("    ...")
        except Exception as e:
            print(f"    读取报告失败: {e}")
    
    # 7. 清理测试数据
    print("\n7. 清理测试数据:")
    del test_data
    collected = memory_helper.force_garbage_collection()
    print(f"  清理了 {collected} 个对象")
    
    # 8. 最终内存摘要
    print("\n8. 清理后的内存摘要:")
    final_summary = memory_helper.get_memory_summary()
    for key, value in final_summary.items():
        print(f"  {key}: {value:.2f}")
    
    print("\n内存分析工具测试完成!")

def test_memory_growth_detection():
    """测试内存增长检测功能"""
    print("\n开始测试内存增长检测...")
    
    memory_helper = MemoryHelper()
    
    # 获取初始内存
    initial_summary = memory_helper.get_memory_summary()
    print(f"初始内存: {initial_summary.get('total_memory_mb', 0):.2f} MB")
    
    # 创建一些数据
    data_list = []
    for i in range(10):
        data_list.append([j for j in range(10000)])  # 每次约240KB
        time.sleep(0.1)  # 短暂延迟
    
    # 获取最终内存
    final_summary = memory_helper.get_memory_summary()
    print(f"最终内存: {final_summary.get('total_memory_mb', 0):.2f} MB")
    
    # 计算增长
    if initial_summary and final_summary:
        growth = final_summary['total_memory_mb'] - initial_summary['total_memory_mb']
        print(f"内存增长: {growth:.2f} MB")
    
    # 清理
    del data_list
    memory_helper.force_garbage_collection()
    
    print("内存增长检测测试完成!")

if __name__ == "__main__":
    try:
        test_memory_analysis()
        test_memory_growth_detection()
    except Exception as e:
        print(f"测试过程中出现错误: {e}")
        import traceback
        traceback.print_exc()