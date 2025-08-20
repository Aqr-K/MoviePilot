FROM python:3.12.8-slim-bookworm
ENV LANG="C.UTF-8" \
    TZ="Asia/Shanghai" \
    HOME="/moviepilot" \
    CONFIG_DIR="/config" \
    TERM="xterm" \
    DISPLAY=:987 \
    PUID=0 \
    PGID=0 \
    UMASK=000 \
    VENV_PATH="/opt/venv"
WORKDIR "/app"

# 安装系统依赖
RUN apt-get update -y \
    && apt-get upgrade -y \
    && apt-get -y install \
        musl-dev \
        nginx \
        gettext-base \
        locales \
        procps \
        gosu \
        bash \
        wget \
        curl \
        busybox \
        dumb-init \
        jq \
        fuse3 \
        rsync \
        ffmpeg \
        nano \
        build-essential \
    && dpkg-reconfigure --frontend noninteractive tzdata \
    && \
    if [ "$(uname -m)" = "x86_64" ]; \
        then ln -s /usr/lib/x86_64-linux-musl/libc.so /lib/libc.musl-x86_64.so.1; \
    elif [ "$(uname -m)" = "aarch64" ]; \
        then ln -s /usr/lib/aarch64-linux-musl/libc.so /lib/libc.musl-aarch64.so.1; \
    fi \
    && curl https://rclone.org/install.sh | bash \
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf \
        /tmp/* \
        /moviepilot/.cache \
        /var/lib/apt/lists/* \
        /var/tmp/*

# 创建虚拟环境
RUN python3 -m venv ${VENV_PATH} \
    && ${VENV_PATH}/bin/pip install --upgrade pip \
    && ${VENV_PATH}/bin/pip install Cython pip-tools

# 复制依赖文件并安装到虚拟环境
COPY ../requirements.in requirements.in
RUN ${VENV_PATH}/bin/pip-compile requirements.in \
    && ${VENV_PATH}/bin/pip install -r requirements.txt \
    && ${VENV_PATH}/bin/playwright install-deps chromium \
    && apt-get remove -y build-essential \
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf \
        /tmp/* \
        /moviepilot/.cache \
        /var/lib/apt/lists/* \
        /var/tmp/*

# 复制应用代码
COPY .. .

# 配置nginx和其他文件
RUN cp -f /app/docker/nginx.common.conf /etc/nginx/common.conf \
    && cp -f /app/docker/nginx.template.conf /etc/nginx/nginx.template.conf \
    && cp -f /app/docker/update.sh /usr/local/bin/mp_update.sh \
    && cp -f /app/docker/entrypoint.sh /entrypoint.sh \
    && cp -f /app/docker/docker_http_proxy.conf /etc/nginx/docker_http_proxy.conf \
    && chmod +x /entrypoint.sh /usr/local/bin/mp_update.sh \
    && mkdir -p ${HOME} \
    && groupadd -r moviepilot -g 918 \
    && useradd -r moviepilot -g moviepilot -d ${HOME} -s /bin/bash -u 918 \
    && python_ver=$(python3 -V | awk '{print $2}') \
    && echo "/app/" > ${VENV_PATH}/lib/python${python_ver%.*}/site-packages/app.pth \
    && echo 'fs.inotify.max_user_watches=5242880' >> /etc/sysctl.conf \
    && echo 'fs.inotify.max_user_instances=5242880' >> /etc/sysctl.conf \
    && locale-gen zh_CN.UTF-8 \
    && FRONTEND_VERSION=$(sed -n "s/^FRONTEND_VERSION\s*=\s*'\([^']*\)'/\1/p" /app/version.py) \
    && curl -sL "https://github.com/jxxghp/MoviePilot-Frontend/releases/download/${FRONTEND_VERSION}/dist.zip" | busybox unzip -d / - \
    && mv /dist /public \
    && curl -sL "https://github.com/jxxghp/MoviePilot-Plugins/archive/refs/heads/main.zip" | busybox unzip -d /tmp - \
    && mv -f /tmp/MoviePilot-Plugins-main/plugins.v2/* /app/app/plugins/ \
    && cat /tmp/MoviePilot-Plugins-main/package.json | jq -r 'to_entries[] | select(.value.v2 == true) | .key' | awk '{print tolower($0)}' | \
        while read -r i; do if [ ! -d "/app/app/plugins/$i" ]; then mv "/tmp/MoviePilot-Plugins-main/plugins/$i" "/app/app/plugins/"; else echo "跳过 $i"; fi; done \
    && curl -sL "https://github.com/jxxghp/MoviePilot-Resources/archive/refs/heads/main.zip" | busybox unzip -d /tmp - \
    && mv -f /tmp/MoviePilot-Resources-main/resources.v2/* /app/app/helper/ \
    && rm -rf /tmp/*

EXPOSE 3000
VOLUME [ "${CONFIG_DIR}" ]
ENTRYPOINT [ "/entrypoint.sh" ]
