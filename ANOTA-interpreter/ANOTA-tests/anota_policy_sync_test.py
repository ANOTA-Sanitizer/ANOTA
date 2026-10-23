"""Check handle removal/rollback and URL/kernel policy separation over the wire."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading

CLIENT = r'''
import contextlib, io
from anota_url import check
url_rule = ANOTA_SYSCALL.NETWORK.BLOCK(HOST='blocked.example')
read_rule = ANOTA_SYSCALL.READ.BLOCK(PATH='/tmp/private')
ANOTA_SYSCALL_SIGNAL_START()                    # 0
other = ANOTA_SYSCALL.READ.BLOCK(PATH='/tmp/private')  # 1
log = io.StringIO()
with contextlib.redirect_stderr(log): check('https', 'blocked.example')
assert 'HOST blocked.example' in log.getvalue()  # URL hooks stay active in eBPF mode.
url_rule.clear()                               # 2
try:
    other.clear()                             # 3: rejected; local policy must roll back
except RuntimeError:
    pass
else:
    raise AssertionError('rejected removal did not raise')
assert other.active
ANOTA_SYSCALL.WRITE.BLOCK(PATH='/tmp/public')   # 4: snapshot still has both READ rules
other.clear()                                 # 5
read_rule.clear()                             # 6
watch = ANOTA_WATCH.BLOCK([], 'W')
secret = 'request-local-secret'
taint = ANOTA_TAINT(secret)
CLEAR()                                       # 7: reset all families
assert not watch.active and not taint.active
assert not ANOTA_TAINT.IS_TAINTED(secret)
ANOTA_SYSCALL_SIGNAL_STOP()                    # 8
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--python', type=Path, default=Path(__file__).resolve().parents[1] / 'python')
    args = parser.parse_args()
    requests, errors = [], []
    with tempfile.TemporaryDirectory(prefix='anota-handle-sync-') as tmp:
        path = str(Path(tmp) / 'monitor.sock')
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(path); listener.listen(); listener.settimeout(15)
            def serve():
                try:
                    for index in range(9):
                        with listener.accept()[0] as stream:
                            stream.settimeout(5)
                            requests.append(json.loads(stream.makefile('rb').readline()))
                            stream.sendall(b'ERR rejected removal\n' if index == 3 else b'OK\n')
                except Exception as exc:
                    errors.append(repr(exc))
            worker = threading.Thread(target=serve, daemon=True); worker.start()
            result = subprocess.run([str(args.python), '-c', CLIENT],
                                    env=dict(os.environ, ANOTA_SYSCALL_BACKEND='local', ANOTA_SYSCALL_SOCKET=path),
                                    capture_output=True, text=True, timeout=20)
            assert result.returncode == 0, result.stderr
            worker.join(timeout=16)
        assert not errors, errors
        assert len(requests) == 9, requests
        assert all('NETWORK' not in r['operations'] for r in requests)
        assert len(requests[0]['operations']['READ'][1]) == 1
        assert len(requests[1]['operations']['READ'][1]) == 2
        assert len(requests[3]['operations']['READ'][1]) == 1
        assert len(requests[4]['operations']['READ'][1]) == 2
        assert len(requests[5]['operations']['READ'][1]) == 1
        assert 'READ' not in requests[6]['operations']
        assert requests[7]['operations'] == {}
        assert requests[8]['action'] == 'stop'
    print('ANOTA handle synchronization: PASS')


if __name__ == '__main__':
    main()
