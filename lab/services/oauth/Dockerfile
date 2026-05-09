FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir Flask==3.0.3 PyJWT==2.8.0
COPY app.py .
EXPOSE 8081
CMD ["python", "app.py"]
