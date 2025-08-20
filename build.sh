#!/bin/bash

# MoviePilot Docker 构建脚本
# 使用方法: ./build.sh [选项]

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 默认值
IMAGE_NAME="moviepilot"
TAG="latest"
DOCKERFILE="docker/Dockerfile"
BUILD_CONTEXT="."
NO_CACHE=false
PUSH=false
PLATFORM=""

# 帮助信息
show_help() {
    echo "MoviePilot Docker 构建脚本"
    echo ""
    echo "使用方法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -n, --name NAME     镜像名称 (默认: moviepilot)"
    echo "  -t, --tag TAG       镜像标签 (默认: latest)"
    echo "  -f, --file FILE     Dockerfile路径 (默认: docker/Dockerfile)"
    echo "  -c, --context DIR   构建上下文目录 (默认: .)"
    echo "  --no-cache          不使用缓存构建"
    echo "  --push              构建后推送到镜像仓库"
    echo "  --platform PLATFORM 指定目标平台 (例如: linux/amd64,linux/arm64)"
    echo "  -h, --help          显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0                                    # 使用默认设置构建"
    echo "  $0 -n myapp -t v1.0                  # 指定镜像名称和标签"
    echo "  $0 --no-cache --platform linux/amd64 # 不使用缓存，指定平台"
    echo "  $0 --push                            # 构建并推送镜像"
}

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--name)
            IMAGE_NAME="$2"
            shift 2
            ;;
        -t|--tag)
            TAG="$2"
            shift 2
            ;;
        -f|--file)
            DOCKERFILE="$2"
            shift 2
            ;;
        -c|--context)
            BUILD_CONTEXT="$2"
            shift 2
            ;;
        --no-cache)
            NO_CACHE=true
            shift
            ;;
        --push)
            PUSH=true
            shift
            ;;
        --platform)
            PLATFORM="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}错误: 未知选项 $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# 检查Docker是否安装
if ! command -v docker &> /dev/null; then
    echo -e "${RED}错误: Docker 未安装${NC}"
    exit 1
fi

# 检查Dockerfile是否存在
if [[ ! -f "$DOCKERFILE" ]]; then
    echo -e "${RED}错误: Dockerfile 不存在: $DOCKERFILE${NC}"
    exit 1
fi

# 检查构建上下文是否存在
if [[ ! -d "$BUILD_CONTEXT" ]]; then
    echo -e "${RED}错误: 构建上下文目录不存在: $BUILD_CONTEXT${NC}"
    exit 1
fi

# 构建命令
BUILD_CMD="docker build"

# 添加平台参数
if [[ -n "$PLATFORM" ]]; then
    BUILD_CMD="$BUILD_CMD --platform $PLATFORM"
fi

# 添加缓存参数
if [[ "$NO_CACHE" == true ]]; then
    BUILD_CMD="$BUILD_CMD --no-cache"
fi

# 添加文件参数
BUILD_CMD="$BUILD_CMD -f $DOCKERFILE"

# 添加标签参数
BUILD_CMD="$BUILD_CMD -t $IMAGE_NAME:$TAG"

# 添加构建上下文
BUILD_CMD="$BUILD_CMD $BUILD_CONTEXT"

# 显示构建信息
echo -e "${GREEN}开始构建 MoviePilot Docker 镜像${NC}"
echo "镜像名称: $IMAGE_NAME:$TAG"
echo "Dockerfile: $DOCKERFILE"
echo "构建上下文: $BUILD_CONTEXT"
if [[ -n "$PLATFORM" ]]; then
    echo "目标平台: $PLATFORM"
fi
if [[ "$NO_CACHE" == true ]]; then
    echo "缓存: 禁用"
else
    echo "缓存: 启用"
fi
echo ""

# 执行构建
echo -e "${YELLOW}执行构建命令: $BUILD_CMD${NC}"
echo ""

if eval $BUILD_CMD; then
    echo -e "${GREEN}构建成功!${NC}"
    
    # 显示镜像信息
    echo ""
    echo -e "${GREEN}镜像信息:${NC}"
    docker images "$IMAGE_NAME:$TAG"
    
    # 如果指定了推送，则推送镜像
    if [[ "$PUSH" == true ]]; then
        echo ""
        echo -e "${YELLOW}推送镜像到仓库...${NC}"
        if docker push "$IMAGE_NAME:$TAG"; then
            echo -e "${GREEN}推送成功!${NC}"
        else
            echo -e "${RED}推送失败!${NC}"
            exit 1
        fi
    fi
    
    echo ""
    echo -e "${GREEN}构建完成!${NC}"
    echo "运行命令: docker run -d -p 3000:3000 -v ./config:/config $IMAGE_NAME:$TAG"
    
else
    echo -e "${RED}构建失败!${NC}"
    exit 1
fi