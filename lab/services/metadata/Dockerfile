FROM python:3.11-alpine
WORKDIR /app
RUN pip install --no-cache-dir Flask==3.0.3
COPY app.py .
EXPOSE 80
CMD ["python", "app.py"]
