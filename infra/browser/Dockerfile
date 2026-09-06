FROM cloakhq/cloakbrowser:latest
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends x11vnc novnc websockify xclip x11-utils \
    && rm -rf /var/lib/apt/lists/*
COPY start-browser.sh /usr/local/bin/start-browser
COPY browser-healthcheck.sh /usr/local/bin/browser-healthcheck
COPY clipboard_server.py /usr/local/bin/clipboard-server
RUN chmod +x /usr/local/bin/start-browser /usr/local/bin/browser-healthcheck /usr/local/bin/clipboard-server
EXPOSE 9222 5900 7900 8765
CMD ["/usr/local/bin/start-browser"]
