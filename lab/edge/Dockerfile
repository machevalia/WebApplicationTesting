FROM nginx:1.25-alpine
RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/shopflux.conf
COPY robots.txt /usr/share/nginx/html/robots.txt
COPY .git-leak/ /usr/share/nginx/html/.git/
EXPOSE 80
