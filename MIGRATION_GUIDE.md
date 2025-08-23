# CacheBackend Dict操作特性迁移指南

## 概述

现在CacheBackend已经支持dict相关的操作特性，可以直接使用dict-like的接口操作缓存，无需TTLCache包装器。

## 新增的Dict操作特性

### 同步操作
- `__getitem__`: `cache[key]` - 获取缓存项
- `__setitem__`: `cache[key] = value` - 设置缓存项
- `__delitem__`: `del cache[key]` - 删除缓存项
- `__contains__`: `key in cache` - 检查键是否存在
- `__iter__`: `for key in cache` - 迭代缓存键
- `__len__`: `len(cache)` - 获取缓存项数量
- `keys()`: 获取所有缓存键
- `values()`: 获取所有缓存值
- `items()`: 获取所有键值对
- `update()`: 批量更新缓存
- `pop()`: 弹出缓存项
- `popitem()`: 弹出最后一个缓存项
- `setdefault()`: 设置默认值

### 异步操作
- `__getitem__`: `await cache[key]` - 获取缓存项
- `__setitem__`: `await cache[key] = value` - 设置缓存项
- `__delitem__`: `await del cache[key]` - 删除缓存项
- `__contains__`: `await key in cache` - 检查键是否存在
- `__aiter__`: `async for key in cache` - 异步迭代缓存键
- `__len__`: `await len(cache)` - 获取缓存项数量
- `keys()`: 异步获取所有缓存键
- `values()`: 异步获取所有缓存值
- `items()`: 异步获取所有键值对
- `update()`: 异步批量更新缓存
- `pop()`: 异步弹出缓存项
- `popitem()`: 异步弹出最后一个缓存项
- `setdefault()`: 异步设置默认值

## 迁移示例

### 从TTLCache迁移

#### 旧代码（使用TTLCache）
```python
from app.core.cache import TTLCache

# 创建TTLCache实例
cache = TTLCache(region="my_region", maxsize=1024, ttl=600)

# 设置缓存
cache.set("key1", "value1")
cache.set("key2", "value2")

# 获取缓存
value1 = cache.get("key1")
value2 = cache.get("key2", "default")

# 删除缓存
cache.delete("key1")

# 清空缓存
cache.clear()
```

#### 新代码（直接使用CacheBackend）
```python
from app.core.cache import Cache

# 创建Cache实例（等同于TTLCache）
cache = Cache(maxsize=1024, ttl=600)

# 设置缓存（支持region参数）
cache["key1"] = "value1"  # 使用默认region
cache.set("key2", "value2", region="my_region")  # 指定region

# 获取缓存
value1 = cache["key1"]
value2 = cache.get("key2", "default", region="my_region")

# 检查键是否存在
if "key1" in cache:
    print("key1 exists")

# 删除缓存
del cache["key1"]
cache.delete("key2", region="my_region")

# 迭代缓存
for key in cache:
    print(key)

# 获取所有键值对
for key, value in cache.items():
    print(f"{key}: {value}")

# 新增的dict操作
# 批量更新
cache.update({"batch1": "value1", "batch2": "value2"})

# 弹出值
value = cache.pop("batch1")

# 设置默认值
value = cache.setdefault("new_key", "default_value")

# 弹出最后一个项
key, value = cache.popitem()

# 获取所有键和值
keys = list(cache.keys())
values = list(cache.values())

# 获取缓存项数量
count = len(cache)

# 清空缓存
cache.clear()  # 清空默认region
cache.clear(region="my_region")  # 清空指定region
```

### 异步操作示例

#### 旧代码（使用AsyncTTLCache）
```python
from app.core.cache import AsyncTTLCache

# 创建异步TTLCache实例
cache = AsyncTTLCache(region="my_region", maxsize=1024, ttl=600)

# 异步设置缓存
await cache["key1"] = "value1"
await cache.set("key2", "value2")

# 异步获取缓存
value1 = await cache["key1"]
value2 = await cache.get("key2", "default")

# 异步检查键是否存在
if await "key1" in cache:
    print("key1 exists")

# 异步删除缓存
await del cache["key1"]
await cache.delete("key2")

# 异步迭代缓存
async for key in cache:
    print(key)

# 异步获取所有键值对
async for key, value in cache.items():
    print(f"{key}: {value}")

# 异步清空缓存
await cache.clear()
```

#### 新代码（直接使用AsyncCacheBackend）
```python
from app.core.cache import AsyncCache

# 创建异步Cache实例
cache = AsyncCache(maxsize=1024, ttl=600)

# 异步设置缓存
await cache["key1"] = "value1"
await cache.set("key2", "value2", region="my_region")

# 异步获取缓存
value1 = await cache["key1"]
value2 = await cache.get("key2", "default", region="my_region")

# 异步检查键是否存在
if await "key1" in cache:
    print("key1 exists")

# 异步删除缓存
await del cache["key1"]
await cache.delete("key2", region="my_region")

# 异步迭代缓存
async for key in cache:
    print(key)

# 异步获取所有键值对
async for key, value in cache.items():
    print(f"{key}: {value}")

# 新增的异步dict操作
# 异步批量更新
await cache.update({"batch1": "value1", "batch2": "value2"})

# 异步弹出值
value = await cache.pop("batch1")

# 异步设置默认值
value = await cache.setdefault("new_key", "default_value")

# 异步弹出最后一个项
key, value = await cache.popitem()

# 异步获取所有键和值
keys = []
async for key in cache.keys():
    keys.append(key)

values = []
async for value in cache.values():
    values.append(value)

# 异步获取缓存项数量
count = await len(cache)

# 异步清空缓存
await cache.clear()
await cache.clear(region="my_region")
```

## 主要优势

1. **统一接口**: 所有缓存后端都支持相同的dict操作接口
2. **减少包装器**: 无需TTLCache包装器，直接使用CacheBackend
3. **更好的性能**: 减少了一层包装，性能更好
4. **更灵活**: 支持region参数，可以更好地组织缓存
5. **向后兼容**: 原有的set/get/delete等方法仍然可用

## 注意事项

1. **Region参数**: dict-like操作默认使用DEFAULT_CACHE_REGION，如需指定region请使用set/get/delete等方法
2. **错误处理**: 访问不存在的键会抛出KeyError，使用get()方法可以避免
3. **异步操作**: 异步版本的所有操作都需要使用await关键字
4. **性能考虑**: 某些操作（如len()、items()）可能需要遍历整个缓存，在大缓存中可能较慢

## 迁移步骤

1. 将 `TTLCache` 替换为 `Cache`
2. 将 `AsyncTTLCache` 替换为 `AsyncCache`
3. 更新导入语句
4. 根据需要调整region参数的使用
5. 测试所有缓存操作是否正常工作

## 测试

运行测试文件验证dict操作特性：
```bash
python test_cache_dict_operations.py
```