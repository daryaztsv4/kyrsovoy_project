from flask import Blueprint, render_template, jsonify, request
import time

routes = Blueprint('routes', __name__)


packets = []
http_events = []
dns_queries = []
dns_errors = []
arp_alerts = []
stats = {}
current_bpf = ''
sniffer = None
start_sniffer = None
arp_cache = {}


def init_route_vars(p, h, dq, de, a, s, cbpf, snif, starter, ac):
    global packets, http_events, dns_queries, dns_errors, arp_alerts, stats
    global current_bpf, sniffer, start_sniffer, arp_cache
    packets = p
    http_events = h
    dns_queries = dq
    dns_errors = de
    arp_alerts = a
    stats = s
    current_bpf = cbpf
    sniffer = snif
    start_sniffer = starter
    arp_cache = ac

@routes.route('/')
def index():
    return render_template('index.html', filter=current_bpf)

@routes.route('/data')
def data():
    return jsonify(packets)

@routes.route('/http')
def http_data():
    return jsonify(http_events)

@routes.route('/dashboard')
def dashboard():
    br = {}
    for p in packets:
        sec = int(float(p['time']))
        br[sec] = br.get(sec, 0) + p['len']
    times = sorted(br)
    vals = [br[t] for t in times]
    vol = {}
    for p in packets:
        vol[p['src']] = vol.get(p['src'], 0) + p['len']
    top = sorted(vol.items(), key=lambda x: x[1], reverse=True)[:5]
    ips, ipv = zip(*top) if top else ([], [])
    pr = {}
    for p in packets:
        pr[p['proto']] = pr.get(p['proto'], 0) + 1
    protos, pv = zip(*pr.items()) if pr else ([], [])
    return jsonify({
        'bitrate': {'times': times, 'values': vals},
        'top_ips': {'labels': list(ips), 'values': list(ipv)},
        'protos': {'labels': list(protos), 'values': list(pv)}
    })

@routes.route('/dns')
def dns_stats():
    cnt_q = {}
    for d in dns_queries:
        cnt_q[d] = cnt_q.get(d, 0) + 1
    cnt_e = {}
    for d in dns_errors:
        cnt_e[d] = cnt_e.get(d, 0) + 1
    top = sorted(cnt_q.items(), key=lambda x: x[1], reverse=True)[:10]
    result = []
    for domain, req in top:
        result.append({
            'domain': domain,
            'requests': req,
            'errors': cnt_e.get(domain, 0)
        })
    return jsonify(result)

@routes.route('/stats')
def get_stats():
    return jsonify(stats)

@routes.route('/arp_alerts')
def get_arp_alerts():
    return jsonify(arp_alerts)

@routes.route('/set', methods=['POST'])
def set_filter():
    global current_bpf, sniffer
    current_bpf = request.get_json().get('bpf', '').strip()
    if sniffer:
        sniffer.stop()
    packets.clear()
    http_events.clear()
    dns_queries.clear()
    dns_errors.clear()
    arp_cache.clear()
    arp_alerts.clear()
    stats['incoming'] = stats['outgoing'] = stats['alert'] = 0
    start_sniffer()
    return ('', 204)