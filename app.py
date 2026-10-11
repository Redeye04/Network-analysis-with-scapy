from pathlib import Path
from flask import Flask, jsonify, render_template, request
from scapy.all import rdpcap, IP, TCP, UDP, ARP
from collections import Counter
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = Path(app.root_path) / 'uploads'
app.config['CURRENT_PCAP'] = Path(app.root_path) / 'network_analysis.pcapng'

PCAP_MAGICS = {
    bytes.fromhex('a1b2c3d4'), bytes.fromhex('d4c3b2a1'),
    bytes.fromhex('a1b23c4d'), bytes.fromhex('4d3cb2a1'),
    bytes.fromhex('0a0d0d0a'),
}

# Route to serve the web interface
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/upload', methods=['POST'])
def upload_pcap():
    upload = request.files.get('file')
    if upload is None or not upload.filename:
        return jsonify({'error': 'Please choose a pcap or pcapng file.'}), 400

    name = secure_filename(upload.filename)
    if not name or Path(name).suffix.lower() not in {'.pcap', '.pcapng', '.cap'}:
        return jsonify({'error': 'Only .pcap, .pcapng, and .cap files are supported.'}), 400
    if upload.stream.read(4) not in PCAP_MAGICS:
        return jsonify({'error': 'That file does not look like a packet capture.'}), 400
    upload.stream.seek(0)

    folder = Path(app.config['UPLOAD_FOLDER'])
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / name
    counter = 1
    while target.exists():
        target = folder / f'{Path(name).stem}-{counter}{Path(name).suffix.lower()}'
        counter += 1
    upload.save(target)
    try:
        rdpcap(str(target))
    except Exception:
        target.unlink(missing_ok=True)
        return jsonify({'error': 'The uploaded capture could not be read.'}), 422

    app.config['CURRENT_PCAP'] = target
    return jsonify({'file': target.name}), 201

# API Route to process PCAP and return data
@app.route('/api/network-data')
def get_network_data():
    try:
        packets = rdpcap(str(app.config['CURRENT_PCAP']))
    except FileNotFoundError:
        return jsonify({"error": "PCAP file not found"}), 404

    protocols = {"TCP": 0, "UDP": 0, "ARP": 0, "Other": 0}
    device_comms = Counter()

    for pkt in packets:
        # Tally Protocols
        if pkt.haslayer(TCP): protocols["TCP"] += 1
        elif pkt.haslayer(UDP): protocols["UDP"] += 1
        elif pkt.haslayer(ARP): protocols["ARP"] += 1
        else: protocols["Other"] += 1

        # Track Device Communications (Source IP -> Destination IP)
        if pkt.haslayer(IP):
            comm_pair = f"{pkt[IP].src} -> {pkt[IP].dst}"
            device_comms[comm_pair] += 1

    # Get the top 10 most active communication paths
    top_comms = dict(device_comms.most_common(10))

    return jsonify({
        "protocols": protocols,
        "communications": top_comms
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)