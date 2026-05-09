FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends nginx \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir Flask==3.0.3 gunicorn==22.0.0
WORKDIR /app
COPY app.py .
COPY nginx.conf /etc/nginx/nginx.conf
COPY start.sh /start.sh
RUN chmod +x /start.sh
EXPOSE 80
CMD ["/start.sh"]
