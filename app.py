import os
import json
import uuid
import random
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'sentinel.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# =========================================================================
# ADAPTIS Data Model (Unidirectional Flow & Threat Record - PS 26145)
# =========================================================================

class ADAPTISAlert(db.Model):
    __tablename__ = 'adaptis_alerts'
    
    id = db.Column(db.String(36), primary_key=True)
    timestamp = db.Column(db.String(50), nullable=False)
    flow_id = db.Column(db.String(50), nullable=False)
    threat_class = db.Column(db.String(50), nullable=False) # ddos, c2_beaconing, dga_dns_tunnel, encrypted_malware, recon_scan, exfiltration
    source_ip = db.Column(db.String(50), nullable=False)
    dest_ip_or_domain = db.Column(db.String(255), nullable=False)
    confidence = db.Column(db.Float, nullable=False) # 0 to 100
    severity = db.Column(db.String(20), nullable=False) # low, medium, high, critical
    evidence = db.Column(db.Text, nullable=False) # JSON array string of tags
    evidence_detail = db.Column(db.Text, nullable=False) # JSON object of raw features & lab tags
    observability_note = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(30), default="new") # new, reviewing, confirmed, false_positive
    generator_source = db.Column(db.String(50), default="iperf3") # hping3, dnscat2, iodine, DGArchive, C2-emulator, Slowloris, Ostinato

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "flow_id": self.flow_id,
            "threat_class": self.threat_class,
            "source_ip": self.source_ip,
            "dest_ip_or_domain": self.dest_ip_or_domain,
            "confidence": round(self.confidence, 1),
            "severity": self.severity,
            "evidence": json.loads(self.evidence) if self.evidence else [],
            "evidence_detail": json.loads(self.evidence_detail) if self.evidence_detail else {},
            "observability_note": self.observability_note,
            "status": self.status,
            "generator_source": self.generator_source
        }

# =========================================================================
# Realistic Mock Seed Generator (~200 alerts across 6 threat classes)
# =========================================================================

def _seed_adaptis_data():
    with app.app_context():
        db.create_all()
        if ADAPTISAlert.query.first():
            return # Data already seeded
        
        print("[ADAPTIS] Seeding ~200 mock alerts across 6 flow/metadata threat classes...")
        
        now = datetime.utcnow()
        alerts = []
        
        internal_subnets = ["10.0.4.15", "10.0.4.22", "10.0.12.88", "10.0.15.101", "10.0.18.4", "192.168.10.45", "192.168.10.89", "172.16.5.12"]
        external_targets = ["185.220.101.5", "194.26.29.112", "45.154.255.7", "91.240.118.17", "103.253.41.9", "185.193.127.44"]
        dga_domains = [
            "vzx79a01mnklq.biz", "k92xya-tunnel.dnscat2.net", "x99182371a.iodine.org", "qww194-c2.ru",
            "d182jklmnp.info", "b772189ac.cc", "z0192847a.cn", "m819231920.net"
        ]
        
        ja3_hashes = ["e7d705a3286e19ea42f587b344ee6865", "6734f37d97d0b724adc260798bfb74b2", "ada18902cfa12093847a001923847012"]
        ja4_fps = ["t13d151600_8da5c3a3c20d_0c00", "t12d140800_7bb1a2b3c4d5_0b00", "q13d111200_9aa8b7c6d5e4_0a00"]

        def rand_ts(hours_back=6):
            mins = random.randint(0, hours_back * 60)
            dt = now - timedelta(minutes=mins)
            return dt.isoformat() + "Z"

        # 1. Recon Scan (hping3)
        for i in range(62):
            src = random.choice(external_targets)
            dst = random.choice(internal_subnets)
            fanout = random.randint(120, 1800)
            ts = rand_ts()
            alerts.append(ADAPTISAlert(
                id=str(uuid.uuid4()),
                timestamp=ts,
                flow_id=f"FL-RECON-{random.randint(1000, 9999)}",
                threat_class="recon_scan",
                source_ip=src,
                dest_ip_or_domain=f"{dst} (Ports: 1-{fanout})",
                confidence=random.uniform(88.0, 99.5),
                severity=random.choice(["medium", "high"]),
                evidence=json.dumps([f"fan-out={fanout} ports", "SYN-stealth-pattern", "zero-data-payload", "hping3-signature"]),
                evidence_detail=json.dumps({
                    "flow_stats": {"packets_out": fanout, "packets_in": 12, "bytes_out": fanout * 44, "bytes_in": 720, "duration_ms": 1420},
                    "lab_tool": "hping3 (TCP Port Sweep)",
                    "fan_out_ports_count": fanout,
                    "target_subnets_probed": 4,
                    "tcp_flags": "SYN (0x02)"
                }),
                observability_note="Diode captured unidirectional SYN probe sequence. Return RST/ACK responses unobserved due to diode isolation.",
                status=random.choice(["new", "new", "reviewing", "confirmed"]),
                generator_source="hping3"
            ))

        # 2. Volumetric / Protocol DDoS (hping3 / Slowloris / UDP Amp)
        for i in range(54):
            src = random.choice(external_targets)
            dst = random.choice(internal_subnets)
            sub_type = random.choice(["SYN Flood", "UDP Amplification", "Slowloris Connection Exhaustion"])
            tool = "Slowloris" if "Slowloris" in sub_type else "hping3"
            pps = random.randint(45000, 250000)
            ts = rand_ts()
            alerts.append(ADAPTISAlert(
                id=str(uuid.uuid4()),
                timestamp=ts,
                flow_id=f"FL-DDOS-{random.randint(1000, 9999)}",
                threat_class="ddos",
                source_ip=src,
                dest_ip_or_domain=dst,
                confidence=random.uniform(92.0, 99.9),
                severity=random.choice(["high", "critical"]),
                evidence=json.dumps([f"pps={pps:,}", sub_type.lower().replace(" ", "-"), "spoofed-source-ratio=0.84", f"{tool.lower()}-flood"]),
                evidence_detail=json.dumps({
                    "flow_stats": {"packets_out": pps * 10, "packets_in": 0, "bytes_out": pps * 512, "bytes_in": 0, "duration_ms": 30000},
                    "lab_tool": f"{tool} ({sub_type})",
                    "packets_per_sec": pps,
                    "throughput_mbps": round(pps * 512 * 8 / 1e6, 2),
                    "spoofed_ip_entropy": 4.92
                }),
                observability_note="Diode monitored passive ingress flow burst. Reverse ACK/ICMP unreachable drops not visible on diode egress.",
                status=random.choice(["new", "new", "reviewing", "confirmed"]),
                generator_source=tool.lower()
            ))

        # 3. DGA / DNS Tunnelling (dnscat2 / iodine / DGArchive)
        for i in range(36):
            src = random.choice(internal_subnets)
            domain = random.choice(dga_domains)
            entropy = round(random.uniform(4.3, 5.8), 2)
            tool = "dnscat2" if "dnscat2" in domain else ("iodine" if "iodine" in domain else "DGArchive")
            ts = rand_ts()
            alerts.append(ADAPTISAlert(
                id=str(uuid.uuid4()),
                timestamp=ts,
                flow_id=f"FL-DNS-{random.randint(1000, 9999)}",
                threat_class="dga_dns_tunnel",
                source_ip=src,
                dest_ip_or_domain=domain,
                confidence=random.uniform(85.0, 98.0),
                severity=random.choice(["medium", "high", "critical"]),
                evidence=json.dumps([f"entropy={entropy}", "n-gram-score=0.91", "txt-record-exfil", f"{tool.lower()}-pattern"]),
                evidence_detail=json.dumps({
                    "dns_query": domain,
                    "shannon_entropy": entropy,
                    "ngram_anomaly_score": 0.91,
                    "query_type": "TXT",
                    "lab_tool": f"{tool} (DNS Exfil/DGA)",
                    "encoded_payload_bytes": random.randint(1400, 18400)
                }),
                observability_note="Entropy and n-gram anomaly detected on passive DNS stream. Upstream recursive resolver response absent.",
                status=random.choice(["new", "reviewing", "confirmed"]),
                generator_source=tool.lower()
            ))

        # 4. Encrypted Session Malware (TLS / QUIC JA3 / JA4 Metadata)
        for i in range(26):
            src = random.choice(internal_subnets)
            dst = random.choice(external_targets)
            ja3 = random.choice(ja3_hashes)
            ja4 = random.choice(ja4_fps)
            ts = rand_ts()
            alerts.append(ADAPTISAlert(
                id=str(uuid.uuid4()),
                timestamp=ts,
                flow_id=f"FL-TLS-{random.randint(1000, 9999)}",
                threat_class="encrypted_malware",
                source_ip=src,
                dest_ip_or_domain=f"{dst} (SNI: c2-node.malware-net.org)",
                confidence=random.uniform(82.0, 97.5),
                severity=random.choice(["high", "critical"]),
                evidence=json.dumps([f"JA3={ja3[:8]}...", f"JA4={ja4}", "packet-size-timing-anomaly", "no-payload-decryption"]),
                evidence_detail=json.dumps({
                    "tls_metadata": {
                        "ja3_fingerprint": ja3,
                        "ja4_fingerprint": ja4,
                        "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                        "sni": "c2-node.malware-net.org",
                        "tls_version": "TLS 1.3"
                    },
                    "packet_timing_sequence": [44, 182, 1420, 180, 1420],
                    "lab_tool": "Ostinato + C2 Malware Fingerprint DB",
                    "decryption_attempted": False
                }),
                observability_note="Detection performed strictly on TLS 1.3 ClientHello metadata and packet length/IAT distribution. Zero payload decryption.",
                status=random.choice(["new", "reviewing", "confirmed"]),
                generator_source="ostinato"
            ))

        # 5. Botnet C2 Beaconing (Sandboxed C2 Emulator)
        for i in range(14):
            src = random.choice(internal_subnets)
            dst = random.choice(external_targets)
            interval = round(random.uniform(59.5, 60.5), 2)
            jitter = round(random.uniform(0.1, 0.4), 2)
            ts = rand_ts()
            alerts.append(ADAPTISAlert(
                id=str(uuid.uuid4()),
                timestamp=ts,
                flow_id=f"FL-C2-{random.randint(1000, 9999)}",
                threat_class="c2_beaconing",
                source_ip=src,
                dest_ip_or_domain=dst,
                confidence=random.uniform(91.0, 99.2),
                severity="critical",
                evidence=json.dumps([f"beacon-interval={interval}s±{jitter}s", "low-jitter=0.03", "dest-cardinality=2", "sandboxed-c2-emulator"]),
                evidence_detail=json.dumps({
                    "beacon_period_seconds": interval,
                    "jitter_standard_deviation": jitter,
                    "total_connections_observed": random.randint(48, 120),
                    "unique_destinations": 2,
                    "lab_tool": "Sandboxed C2 Emulator (Cobalt/Empire Profile)"
                }),
                observability_note="Strict 60s periodic cadence observed over 4 hours across diode stream. Telemetry confirms low-variance C2 heartbeats.",
                status=random.choice(["new", "reviewing", "confirmed"]),
                generator_source="c2-emulator"
            ))

        # 6. Data Exfiltration (Asymmetric Byte Ratio)
        for i in range(10):
            src = random.choice(internal_subnets)
            dst = random.choice(external_targets)
            out_bytes = random.randint(450, 1200) * 1024 * 1024 # 450MB - 1.2GB
            in_bytes = random.randint(12, 45) * 1024 # 12KB - 45KB
            ratio = round(out_bytes / max(in_bytes, 1), 1)
            ts = rand_ts()
            alerts.append(ADAPTISAlert(
                id=str(uuid.uuid4()),
                timestamp=ts,
                flow_id=f"FL-EXFIL-{random.randint(1000, 9999)}",
                threat_class="exfiltration",
                source_ip=src,
                dest_ip_or_domain=dst,
                confidence=random.uniform(89.0, 98.8),
                severity="critical",
                evidence=json.dumps([f"asymmetric-ratio={ratio}:1", f"outbound={round(out_bytes/1e6, 1)}MB", "sustained-burst", "iperf3-exfil-test"]),
                evidence_detail=json.dumps({
                    "bytes_outbound": out_bytes,
                    "bytes_inbound": in_bytes,
                    "asymmetric_ratio": ratio,
                    "flow_duration_seconds": random.randint(120, 600),
                    "lab_tool": "iperf3 (Sustained Outbound Exfil Load)"
                }),
                observability_note="Asymmetric outbound burst detected via diode flow metrics. Destination server TCP window ACKs not captured on diode.",
                status=random.choice(["new", "reviewing", "confirmed"]),
                generator_source="iperf3"
            ))

        db.session.add_all(alerts)
        db.session.commit()
        print(f"[ADAPTIS] Successfully seeded {len(alerts)} mock alerts into database!")

# =========================================================================
# View Routes
# =========================================================================

@app.route('/')
@app.route('/overview')
def overview():
    return render_template('overview.html')

@app.route('/alerts')
def alert_log():
    return render_template('alerts.html')

@app.route('/graph')
def entity_graph():
    return render_template('graph.html')

@app.route('/pipeline')
def pipeline_status():
    return render_template('pipeline.html')

# =========================================================================
# JSON REST APIs
# =========================================================================

@app.route('/api/stats')
def api_stats():
    alerts = ADAPTISAlert.query.all()
    total_alerts = len(alerts)
    high_critical_count = sum(1 for a in alerts if a.severity in ['high', 'critical'])
    
    class_counts = {}
    for a in alerts:
        class_counts[a.threat_class] = class_counts.get(a.threat_class, 0) + 1
        
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in alerts:
        sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1

    gen_counts = {}
    for a in alerts:
        gen_counts[a.generator_source] = gen_counts.get(a.generator_source, 0) + 1

    return jsonify({
        "status": "online",
        "diode_mode": "unidirectional_passive",
        "throughput": {
            "current_flows_per_sec": 485240,
            "target_flows_per_sec": 500000,
            "current_mbps": 9840.5,
            "target_gbps": 10.0,
            "total_flows_ingested": 184920412,
            "packet_drop_rate": 0.0000
        },
        "total_alerts": total_alerts,
        "high_critical_count": high_critical_count,
        "threat_class_counts": class_counts,
        "severity_counts": sev_counts,
        "generator_counts": gen_counts
    })

@app.route('/api/alerts')
def api_alerts():
    threat_class = request.args.get('threat_class')
    severity = request.args.get('severity')
    status = request.args.get('status')
    search = request.args.get('search')
    
    query = ADAPTISAlert.query
    if threat_class:
        query = query.filter_by(threat_class=threat_class)
    if severity:
        query = query.filter_by(severity=severity)
    if status:
        query = query.filter_by(status=status)
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (ADAPTISAlert.flow_id.like(search_term)) |
            (ADAPTISAlert.source_ip.like(search_term)) |
            (ADAPTISAlert.dest_ip_or_domain.like(search_term))
        )
        
    alerts = query.order_by(ADAPTISAlert.timestamp.desc()).all()
    return jsonify([a.to_dict() for a in alerts])

@app.route('/api/alerts/<alert_id>')
def api_alert_detail(alert_id):
    alert = ADAPTISAlert.query.get_or_404(alert_id)
    return jsonify(alert.to_dict())

@app.route('/api/alerts/<alert_id>/status', methods=['PATCH'])
def api_update_status(alert_id):
    alert = ADAPTISAlert.query.get_or_404(alert_id)
    data = request.get_json() or {}
    new_status = data.get('status')
    if new_status in ['new', 'reviewing', 'confirmed', 'false_positive']:
        alert.status = new_status
        db.session.commit()
        return jsonify({"success": True, "alert": alert.to_dict()})
    return jsonify({"error": "Invalid status"}), 400

@app.route('/api/graph')
def api_graph():
    alerts = ADAPTISAlert.query.limit(50).all()
    
    nodes = {}
    edges = []
    
    def add_node(node_id, label, node_type, severity="low"):
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "label": label, "type": node_type, "severity": severity, "threat_count": 0}
        nodes[node_id]["threat_count"] += 1
        if severity in ["critical", "high"]:
            nodes[node_id]["severity"] = severity

    for a in alerts:
        src_id = f"ip:{a.source_ip}"
        dst_raw = a.dest_ip_or_domain.split()[0]
        dst_id = f"target:{dst_raw}"
        
        add_node(src_id, a.source_ip, "ip", a.severity)
        add_node(dst_id, dst_raw, "host_or_domain", a.severity)
        
        edges.append({
            "source": src_id,
            "target": dst_id,
            "threat_class": a.threat_class,
            "severity": a.severity,
            "flow_id": a.flow_id,
            "confidence": a.confidence
        })

    return jsonify({
        "nodes": list(nodes.values()),
        "links": edges
    })

@app.route('/api/pipeline')
def api_pipeline():
    return jsonify({
        "stages": [
            {"id": "ingest", "name": "Diode Ingest", "count": 485240, "latency_ms": 0.05, "status": "active"},
            {"id": "normalize", "name": "Normalize & Decap", "count": 485210, "latency_ms": 0.12, "status": "active"},
            {"id": "trust", "name": "Validate Trust", "count": 485190, "latency_ms": 0.08, "status": "active"},
            {"id": "features", "name": "Extract Flow/TLS Features", "count": 485150, "latency_ms": 0.28, "status": "active"},
            {"id": "detectors", "name": "Run AI Detectors", "count": 485120, "latency_ms": 0.42, "status": "active"},
            {"id": "fuse", "name": "Correlate & Fuse", "count": 485100, "latency_ms": 0.15, "status": "active"},
            {"id": "calibrate", "name": "Calibrate Confidence", "count": 485090, "latency_ms": 0.06, "status": "active"},
            {"id": "alert", "name": "Alert Dispatch", "count": 203, "latency_ms": 0.04, "status": "active"}
        ],
        "bounded_latency": {
            "total_mean_ms": 1.20,
            "max_sla_ms": 5.0,
            "dropped_packets": 0
        }
    })

# Initialize DB on import
_seed_adaptis_data()

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000, allow_unsafe_werkzeug=True)
