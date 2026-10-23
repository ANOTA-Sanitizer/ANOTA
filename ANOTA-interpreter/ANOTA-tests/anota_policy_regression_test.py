"""Isolated regression checks for taint, builtin WATCH, lifecycle, and URL rules.

Run with system Python and --python /path/to/the/ANOTA/interpreter.
Each case gets its own process; false-negative probes must raise a policy
violation, and positive controls must still complete normally.
"""
import argparse
import os
from pathlib import Path
import subprocess
import textwrap

ROOT = Path(__file__).resolve().parents[1]
PREAMBLE = '''
def blocked(call):
    try:
        call()
    except RuntimeError as exc:
        assert 'ANOTA_' in str(exc), str(exc)
    else:
        raise AssertionError('policy was bypassed')
'''
CASES = {
    'taint_formatting_and_join': '''
        s = 'regression-private-format'
        ANOTA_TAINT(s, Sink=[print])
        blocked(lambda: print(f'prefix={s}'))
        blocked(lambda: print(f'{s!r:>40}'))
        blocked(lambda: print('{}:{}'.format(s, 'clean')))
        blocked(lambda: print('prefix'.join([s, 'suffix'])))
        blocked(lambda: print(''.join(v for v in [s, 'suffix'])))
        print('public')
    ''',
    'taint_nested_and_cyclic_containers': '''
        s = 'regression-private-cycle'
        ANOTA_TAINT(s, Sink=[print])
        values = [s]; values.append(values)
        blocked(lambda: print(values))
        blocked(lambda: print({'public': ({s},)}))
        blocked(lambda: print({s: 'public'}))
        clean = []; clean.append(clean)
        print(clean)
        values.pop(0)
        assert not ANOTA_TAINT.IS_TAINTED(values)
    ''',
    'taint_return_preserves_existing_source': '''
        s = 'regression-private-global'
        def get_secret(): return s
        ANOTA_TAINT(s, Sink=[print])
        out = get_secret()
        blocked(lambda: print(out))
        blocked(lambda: print(s))
    ''',
    'taint_source_specific_sanitizers': '''
        a = 'regression-source-a'; b = 'regression-source-b'
        ANOTA_TAINT(a, sanitization=[hash], Sink=[print])
        ANOTA_TAINT(b, Sink=[print])
        print(hash(a))
        mixed = a + b
        blocked(lambda: print(hash(mixed)))
        blocked(lambda: print(a))
        blocked(lambda: print(b))
        ANOTA_TAINT.CLEAR(b)
        print(hash(mixed))
    ''',
    'taint_default_and_explicit_sinks': '''
        import io
        secret = 'regression-default-output'
        handle = ANOTA_TAINT(secret)
        blocked(lambda: print(secret))
        blocked(lambda: io.StringIO().write(secret))
        blocked(lambda: io.StringIO().writelines([secret]))
        CLEAR(handle)
        print(secret)
        ANOTA_TAINT(secret, Sink=[])
        print(secret)
    ''',
    'taint_reset_does_not_revive_old_labels': '''
        s = 'regression-private-reset'
        h = ANOTA_TAINT(s)
        derived = s + '-derived'
        ANOTA_TAINT.CLEAR_ALL()
        assert not h.active
        assert not ANOTA_TAINT.IS_TAINTED(derived)
        print(derived)
        fresh = 'new-private-source'
        ANOTA_TAINT(fresh)
        print(derived)
        blocked(lambda: print(fresh))
        CLEAR()
        print(fresh)
    ''',
    'taint_control_names_cannot_disable_checks': '''
        class ANOTA_FAKE:
            def __call__(self): return 'private-factory-output'
        factory = ANOTA_FAKE()
        ANOTA_TAINT(factory, Sink=[print])
        blocked(lambda: print(factory()))
    ''',
    'taint_independent_handles': '''
        s = 'regression-two-handles'
        a = ANOTA_TAINT(s, Sink=[print])
        b = ANOTA_TAINT(s, Sink=[print])
        derived = s.upper()
        CLEAR(a); CLEAR(a)
        assert not a.active and b.active
        blocked(lambda: print(derived))
        b.clear()
        print(derived)
    ''',
    'taint_invalid_registration_is_atomic': '''
        s = 'regression-invalid-registration'
        try: ANOTA_TAINT(s, Sink=[print, 123])
        except TypeError: pass
        else: raise AssertionError('invalid sink accepted')
        assert not ANOTA_TAINT.IS_TAINTED(s)
        print(s)
    ''',
    'watch_builtin_list_mutations': '''
        x = [3, 1, 2]
        h = ANOTA_WATCH.BLOCK(x, 'W')
        for action in [lambda: x.append(4), lambda: list.append(x, 4),
                       lambda: x.extend([4]), lambda: x.insert(0, 4),
                       lambda: x.pop(), lambda: x.remove(1),
                       lambda: x.clear(), lambda: x.reverse(), lambda: x.sort(),
                       lambda: list.__init__(x, [4])]:
            blocked(action)
        h.clear()
        assert x == [3, 1, 2]
        x.append(4)
        assert x[-1] == 4
    ''',
    'watch_dictionary_members': '''
        d = {'secret': 'private', 'public': 'ok'}
        h = ANOTA_WATCH.BLOCK(d, 'R', key='secret')
        blocked(lambda: d.get('secret'))
        blocked(lambda: dict.get(d, 'secret'))
        blocked(lambda: d.setdefault('secret', 'new'))
        blocked(lambda: list(d.values()))
        blocked(lambda: d.copy())
        assert d.get('public') == 'ok'
        assert d.get('absent', 'fallback') == 'fallback'
        h.clear()
        assert d.get('secret') == 'private'
    ''',
    'watch_attribute_builtins': '''
        class Box: pass
        obj = Box(); obj.secret = 'private'; obj.public = 'ok'
        h = ANOTA_WATCH.BLOCK(obj, 'R', key='secret')
        blocked(lambda: getattr(obj, 'secret'))
        blocked(lambda: getattr(obj, 'secret', 'fallback'))
        blocked(lambda: hasattr(obj, 'secret'))
        blocked(lambda: object.__getattribute__(obj, 'secret'))
        assert getattr(obj, 'public') == 'ok'
        h.clear()
        assert getattr(obj, 'secret') == 'private'
        h = ANOTA_WATCH.BLOCK(obj, 'W', key='secret')
        blocked(lambda: setattr(obj, 'secret', 'changed'))
        blocked(lambda: delattr(obj, 'secret'))
        h.clear()
        assert obj.secret == 'private'
    ''',
    'watch_independent_handles_and_context': '''
        x = []
        a = ANOTA_WATCH.BLOCK(x, 'W'); b = ANOTA_WATCH.BLOCK(x, 'W')
        a.clear(); a.clear()
        blocked(lambda: x.append(1))
        b.clear(); x.append(1)
        with ANOTA_WATCH.BLOCK(x, 'W') as h:
            blocked(lambda: x.append(2))
        assert not h.active
        x.append(2)
        read = ANOTA_WATCH.BLOCK(x, 'R')
        # The handle allows clearing without evaluating the blocked object.
        read.clear()
        assert x == [1, 2]
    ''',
    'watch_clear_invalidates_old_handles': '''
        x = []
        old = ANOTA_WATCH.BLOCK(x, 'W')
        ANOTA_WATCH.CLEAR(x)
        new = ANOTA_WATCH.BLOCK(x, 'W')
        old.clear()
        assert not old.active and new.active
        blocked(lambda: x.append(1))
        CLEAR()
        assert not new.active
        x.append(1)
    ''',
    'syscall_handles_remove_only_their_own_rules': '''
        import contextlib, io
        stream = io.StringIO()
        a = ANOTA_SYSCALL.READ.BLOCK(PATH='/dev/null')
        b = ANOTA_SYSCALL.READ.BLOCK(PATH='/dev/null')
        with contextlib.redirect_stderr(stream):
            a.clear()
            with open('/dev/null'): pass
        assert 'violation:' in stream.getvalue()
        stream = io.StringIO()
        with contextlib.redirect_stderr(stream):
            b.clear()
            with open('/dev/null'): pass
        assert 'violation:' not in stream.getvalue()
        old = ANOTA_SYSCALL.BLOCK('open')
        ANOTA_SYSCALL.CLEAR()
        new = ANOTA_SYSCALL.BLOCK('open')
        old.clear()
        assert not old.active and new.active
        CLEAR()
        assert not new.active
    ''',
    'url_scheme_and_host_rules': '''
        import contextlib, io, urllib.request
        from anota_url import check
        log = io.StringIO()
        a = ANOTA_SYSCALL.NETWORK.BLOCK(SCHEME=['file', 'data'])
        b = ANOTA_SYSCALL.NETWORK.BLOCK(HOST=['*.example.com', 'BÜCHER.example.'])
        with contextlib.redirect_stderr(log):
            # Reporting is deliberately nonfatal; the data is still returned.
            assert urllib.request.urlopen('data:text/plain,hello').read() == b'hello'
            check('HTTPS', 'private.example.com')
            check('https', 'xn--bcher-kva.example')
        text = log.getvalue()
        assert 'SCHEME data' in text and 'HOST private.example.com' in text
        assert 'HOST xn--bcher-kva.example' in text
        a.clear(); b.clear()
        log = io.StringIO()
        with contextlib.redirect_stderr(log):
            urllib.request.urlopen('data:text/plain,hello').close()
            check('https', 'private.example.com')
        assert 'violation:' not in log.getvalue()
    ''',
    'url_allow_kinds_and_block_precedence': '''
        import contextlib, io
        from anota_url import check
        ANOTA_SYSCALL.NETWORK.ALLOW(SCHEME='https')
        ANOTA_SYSCALL.NETWORK.ALLOW(HOST='*.example.com')
        deny = ANOTA_SYSCALL.NETWORK.BLOCK(HOST='secret.example.com')
        log = io.StringIO()
        with contextlib.redirect_stderr(log): check('https', 'public.example.com')
        assert not log.getvalue()
        with contextlib.redirect_stderr(log):
            check('http', 'public.example.com')
            check('https', 'secret.example.com')
        assert 'SCHEME http' in log.getvalue() and 'HOST secret.example.com' in log.getvalue()
        ANOTA_SYSCALL.NETWORK.CLEAR()
        assert not deny.active
    ''',
    'url_redirect_and_file_dispatch': '''
        import contextlib, io, tempfile, threading, urllib.request
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from pathlib import Path
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/redirect':
                    self.send_response(302)
                    self.send_header('Location', f'http://127.0.0.1:{self.server.server_port}/final')
                    self.end_headers()
                else:
                    self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
            def log_message(self, *args): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        log = io.StringIO()
        try:
            ANOTA_SYSCALL.NETWORK.BLOCK(HOST='127.0.0.1')
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with contextlib.redirect_stderr(log):
                response = opener.open(f'http://localhost:{server.server_port}/redirect')
                assert response.read() == b'ok'; response.close()
            assert 'HOST 127.0.0.1' in log.getvalue()
            assert 'HOST localhost' not in log.getvalue()
            ANOTA_SYSCALL.NETWORK.BLOCK(SCHEME='file')
            with tempfile.NamedTemporaryFile() as f:
                f.write(b'file contents'); f.flush()
                with contextlib.redirect_stderr(log):
                    response = opener.open('  ' + Path(f.name).as_uri())
                    assert response.read() == b'file contents'; response.close()
            assert 'SCHEME file' in log.getvalue()
        finally:
            server.shutdown(); worker.join(); server.server_close()
    ''',
    'url_http_client_effective_target': '''
        import contextlib, http.client, io
        ANOTA_SYSCALL.NETWORK.BLOCK(HOST=['target.example.com', 'tunnel.example.com'])
        log = io.StringIO()
        # putrequest constructs buffered requests without contacting a server.
        with contextlib.redirect_stderr(log):
            http.client.HTTPConnection('target.example.com').putrequest('GET', '/')
            http.client.HTTPConnection('proxy.example.com').putrequest('GET', 'http://target.example.com/path')
            c = http.client.HTTPSConnection('proxy.example.com')
            c.set_tunnel('tunnel.example.com'); c.putrequest('GET', '/')
        assert log.getvalue().count('HOST target.example.com') == 2
        assert 'HOST tunnel.example.com' in log.getvalue()
    ''',
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--python', type=Path, default=ROOT / 'python')
    parser.add_argument('--case', action='append')
    args = parser.parse_args()
    failed = []
    for name, code in CASES.items():
        if args.case and name not in args.case:
            continue
        result = subprocess.run(
            [str(args.python), '-c', PREAMBLE + textwrap.dedent(code)],
            capture_output=True, text=True, timeout=30,
            env=dict(os.environ, ANOTA_SYSCALL_BACKEND='local'))
        print(('PASS' if result.returncode == 0 else 'FAIL'), name)
        if result.returncode:
            failed.append(name)
            print(result.stderr[-4000:])
    if failed:
        raise SystemExit(f'{len(failed)} regression case(s) failed')


if __name__ == '__main__':
    main()
