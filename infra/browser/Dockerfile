FROM cloakhq/cloakbrowser:latest
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends x11vnc novnc websockify \
    && rm -rf /var/lib/apt/lists/*
COPY start-browser.sh /usr/local/bin/start-browser
RUN chmod +x /usr/local/bin/start-browser
EXPOSE 9222 5900 7900
CMD ["/usr/local/bin/start-browser"]
