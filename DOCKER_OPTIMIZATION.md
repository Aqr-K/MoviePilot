# Docker 构建和启动逻辑优化

## 优化概述

本次优化主要解决了以下问题：

1. **统一使用虚拟pip环境**：避免pip包在多个地方存在
2. **优化依赖管理**：使用pip-tools进行依赖锁定
3. **减少重复安装**：在构建时安装依赖，运行时只更新变化的部分
4. **提升构建速度**：优化.dockerignore文件
5. **简化部署**：提供docker-compose配置

## 主要改进

### 1. 虚拟环境管理

- **虚拟环境路径**：`/opt/venv`
- **环境变量**：`VENV_PATH=/opt/venv`
- **PATH设置**：自动将虚拟环境bin目录添加到PATH

### 2. 依赖管理优化

#### 构建阶段
```dockerfile
# 创建虚拟环境
RUN python3 -m venv ${VENV_PATH} \
    && ${VENV_PATH}/bin/pip install --upgrade pip \
    && ${VENV_PATH}/bin/pip install Cython pip-tools

# 安装依赖到虚拟环境
RUN ${VENV_PATH}/bin/pip-compile requirements.in \
    && ${VENV_PATH}/bin/pip install -r requirements.txt
```

#### 运行时更新
- 只在依赖文件发生变化时才重新安装
- 自动备份和恢复机制
- 使用虚拟环境中的pip进行安装

### 3. 文件结构优化

#### .dockerignore 优化
排除不必要的文件，减少构建上下文大小：
- 开发文件（.pyc, __pycache__, .pytest_cache等）
- 文档文件
- IDE配置文件
- 临时文件
- 测试文件

#### requirements.txt 优化
- 使用具体版本号锁定依赖
- 包含平台特定依赖
- 自动生成注释说明

### 4. 启动脚本优化

#### entrypoint.sh 改进
- 设置虚拟环境PATH
- 使用虚拟环境中的Python启动应用
- 正确设置虚拟环境权限

#### update.sh 改进
- 使用虚拟环境中的pip
- 智能依赖更新：只在变化时更新
- 备份和恢复机制

## 使用方法

### 1. 简单部署（推荐）

使用SQLite数据库，适合个人使用：

```bash
# 创建配置目录
mkdir -p config

# 启动服务
docker-compose -f docker-compose.simple.yml up -d
```

### 2. 完整部署

使用PostgreSQL和Redis，适合生产环境：

```bash
# 创建配置目录
mkdir -p config

# 启动所有服务
docker-compose up -d
```

### 3. 自定义配置

创建 `config/app.env` 文件：

```env
# 代理设置
PIP_PROXY='https://pypi.tuna.tsinghua.edu.cn/simple'
GITHUB_PROXY='https://ghproxy.com/'

# 数据库设置
DB_TYPE='postgresql'
DB_POSTGRESQL_HOST='postgres'
DB_POSTGRESQL_DATABASE='moviepilot'
DB_POSTGRESQL_USERNAME='moviepilot'
DB_POSTGRESQL_PASSWORD='moviepilot'

# SSL设置
ENABLE_SSL='true'
SSL_DOMAIN='your.domain.com'
```

## 环境变量说明

### 基础配置
- `PUID`: 用户ID（默认：1000）
- `PGID`: 组ID（默认：1000）
- `UMASK`: 文件权限掩码（默认：022）
- `CONFIG_DIR`: 配置目录（默认：/config）

### 代理设置
- `PIP_PROXY`: pip代理地址
- `GITHUB_PROXY`: GitHub代理地址
- `PROXY_HOST`: 全局代理地址
- `GITHUB_TOKEN`: GitHub访问令牌

### 数据库设置
- `DB_TYPE`: 数据库类型（sqlite/postgresql）
- `DB_POSTGRESQL_HOST`: PostgreSQL主机
- `DB_POSTGRESQL_PORT`: PostgreSQL端口
- `DB_POSTGRESQL_DATABASE`: 数据库名
- `DB_POSTGRESQL_USERNAME`: 用户名
- `DB_POSTGRESQL_PASSWORD`: 密码

### SSL设置
- `ENABLE_SSL`: 是否启用SSL
- `SSL_DOMAIN`: SSL域名

### 更新设置
- `MOVIEPILOT_AUTO_UPDATE`: 自动更新模式（false/release/dev）

## 性能优化

### 构建优化
1. **多阶段构建**：减少最终镜像大小
2. **依赖缓存**：利用Docker层缓存
3. **最小化上下文**：优化.dockerignore

### 运行时优化
1. **虚拟环境**：隔离依赖，避免冲突
2. **智能更新**：只在必要时更新依赖
3. **健康检查**：确保服务正常运行

## 故障排除

### 常见问题

1. **权限问题**
   ```bash
   # 修改目录权限
   sudo chown -R 1000:1000 config/
   ```

2. **依赖安装失败**
   ```bash
   # 检查网络连接
   docker exec moviepilot curl -I https://pypi.org
   
   # 查看日志
   docker logs moviepilot
   ```

3. **虚拟环境问题**
   ```bash
   # 进入容器检查虚拟环境
   docker exec -it moviepilot bash
   ls -la /opt/venv/bin/
   ```

### 日志查看

```bash
# 查看应用日志
docker logs moviepilot

# 实时查看日志
docker logs -f moviepilot

# 查看特定时间段的日志
docker logs --since="2024-01-01T00:00:00" moviepilot
```

## 更新和维护

### 更新依赖
```bash
# 重新构建镜像
docker-compose build --no-cache

# 重启服务
docker-compose up -d
```

### 备份配置
```bash
# 备份配置目录
tar -czf moviepilot_config_backup.tar.gz config/
```

### 清理资源
```bash
# 清理未使用的镜像
docker image prune -f

# 清理未使用的卷
docker volume prune -f

# 清理未使用的网络
docker network prune -f
```