FROM cloakhq/cloakbrowser:latest
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends x11vnc novnc websockify xclip \
    && rm -rf /var/lib/apt/lists/*
COPY start-browser.sh /usr/local/bin/start-browser
COPY clipboard_server.py /usr/local/bin/clipboard-server
RUN chmod +x /usr/local/bin/start-browser /usr/local/bin/clipboard-server
EXPOSE 9222 5900 7900 8765
CMD ["/usr/local/bin/start-browser"]
