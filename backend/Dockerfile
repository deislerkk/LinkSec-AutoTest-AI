FROM kalilinux/kali-rolling

# 安装 Python 及 Kali 工具链（nuclei 使用 Kali 官方源，无需外部下载）
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    nmap masscan nikto hydra enum4linux whatweb gobuster \
    smbclient curl dnsutils net-tools nuclei \
    && nuclei -update-templates 2>/dev/null || true \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --break-system-packages --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# 需要 root 权限以使用 nmap SYN 扫描（--cap-add NET_RAW 的替代方案）
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", \
     "--timeout", "600", "app:app"]
