# 使用 Python 官方镜像作为基础镜像
FROM python:3.9

# 设置工作目录
WORKDIR /app

# 复制项目文件到容器中
COPY . /app

# 创建目录
RUN mkdir -p /home/admin /home/ctfer /home/j0k3r /upload \
    && chmod +x flag.sh && chmod +x start.sh \
    && mv start.sh /usr/local/bin/start.sh \
    && rm -f app/dockerfile

# 安装项目依赖
RUN pip install -r requirements.txt

# 设置 Flask 应用的环境变量
ENV FLASK_APP app.py
ENV FLASK_RUN_HOST 0.0.0.0
ENV FLASK_RUN_PORT 5000

# 执行 flag.sh 脚本，然后启动 Flask 应用
CMD ["/bin/sh", "-c", "/bin/bash /usr/local/bin/start.sh"]
