from flask import Flask
import threading
import time
import webview

from logic import (
    packets, http_events, dns_queries, dns_errors,
    arp_alerts, stats, current_bpf, sniffer,
    start_sniffer, arp_cache, start_time, set_start_time
)
from routes import routes, init_route_vars

app = Flask(__name__)


init_route_vars(
    packets, http_events, dns_queries, dns_errors,
    arp_alerts, stats, current_bpf, sniffer,
    start_sniffer, arp_cache
)
app.register_blueprint(routes)

if __name__ == '__main__':
    threading.Thread(
        target=app.run,
        kwargs={'host': '127.0.0.1', 'port': 5000, 'debug': False},
        daemon=True
    ).start()
    time.sleep(1)
    set_start_time()
    start_sniffer()
    webview.create_window(
        'Network Security Analyzer',
        'http://127.0.0.1:5000',
        width=1000, height=700
    )
    webview.start()
