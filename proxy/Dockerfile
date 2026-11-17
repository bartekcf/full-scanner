FROM nginx@sha256:901e593c95dc85f5a729f5765516321366ef4ac401821431d408897e95287d0a

COPY proxy/start-nginx.sh /usr/local/sbin/start-nginx
COPY proxy/bootstrap.conf /etc/nginx/bootstrap.conf
COPY proxy/api.conf /etc/nginx/api.conf
RUN rm -f /etc/nginx/conf.d/default.conf \
    && chmod 0555 /usr/local/sbin/start-nginx

ENTRYPOINT ["/usr/local/sbin/start-nginx"]
