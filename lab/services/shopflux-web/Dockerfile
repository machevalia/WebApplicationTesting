FROM python:3.11-slim

# imagemagick + ghostscript intentionally installed to enable image-tragick
# style upload chains; xmlsec1 for the XXE chain; wkhtmltopdf for the PDF
# rendering command-injection via the admin diagnostics page.
RUN apt-get update && apt-get install -y --no-install-recommends \
        imagemagick ghostscript curl wkhtmltopdf libxml2-dev libxslt-dev \
        build-essential && \
    rm -rf /var/lib/apt/lists/*

# Loosen the ImageMagick policy so the tragick-style PoCs work in the lab.
RUN sed -i 's/rights="none"/rights="read|write"/g' /etc/ImageMagick-6/policy.xml || true

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

EXPOSE 5000
CMD ["python", "app.py"]
