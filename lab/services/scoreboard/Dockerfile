FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir Flask==3.0.3
COPY app.py .
COPY templates ./templates
EXPOSE 8090
CMD ["python", "app.py"]
