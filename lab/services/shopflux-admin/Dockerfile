FROM php:8.1-apache
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*
RUN sed -i 's/Listen 80/Listen 9000/' /etc/apache2/ports.conf \
    && sed -i 's|<VirtualHost \*:80>|<VirtualHost *:9000>|' /etc/apache2/sites-available/000-default.conf
COPY public/ /var/www/html/
EXPOSE 9000
