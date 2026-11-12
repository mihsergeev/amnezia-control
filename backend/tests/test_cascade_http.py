import asyncio
from contextlib import asynccontextmanager
import json
import os
import subprocess
import tempfile
import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import event

from app import cascade_http, config
from app.models import Cascade, Server


@pytest.fixture(autouse=True)
def isolate_diagnostics(monkeypatch):
    monkeypatch.setattr(cascade_http, "_active", set())
    monkeypatch.setattr(cascade_http, "_recent", {})


@pytest.fixture
async def inventory(client, auth_headers):
    async with client.session_factory() as session:
        session.add_all([Server(id=1, name="Entry", host="192.0.2.1", ssh_user="fixture"),
                         Server(id=2, name="Exit", host="192.0.2.2", ssh_user="fixture")])
        session.add(Cascade(id=1, entry_server_id=1, exit_server_id=2, transport="vless", status="ready", params="{}"))
        await session.commit()
    return auth_headers


async def test_site_diagnostics_auth_limits_and_no_ssh_for_bad_request(client, monkeypatch):
    def forbidden(*a, **k):
        pytest.fail("Unexpected diagnostic SSH")
    monkeypatch.setattr(cascade_http.asyncssh, "connect", forbidden)
    for path in ("/api/servers/1/site-check", "/api/cascades/1/routes/http-check"):
        assert (await client.post(path, json={"via": "entry", "destinations": ["example.com"]})).status_code == 401


async def test_schema_limits_do_not_start_diagnostics(client, inventory, monkeypatch):
    async def forbidden(*a, **k):
        pytest.fail("Invalid request started diagnostics")
    monkeypatch.setattr(cascade_http, "run_check", forbidden)
    for body in ({"destinations": ["example.com"] * 101}, {"destinations": ["x" * 1025]},
                 {"destinations": [123]}, {"destinations": ["example.com"], "scheme": "file"}):
        assert (await client.post("/api/servers/1/site-check", json=body, headers=inventory)).status_code == 422


async def test_cascade_and_standalone_sources_readonly(client, inventory, monkeypatch):
    calls = []
    async def check(server, body, management, settings, **kwargs):
        calls.append((server.id, body.scheme, management))
        return [cascade_http.SiteResult(destination="example.com", status="response", http_status=403, scheme=body.scheme)]
    monkeypatch.setattr(cascade_http, "run_check", check)
    async with client.session_factory() as session:
        engine = session.bind.sync_engine
    def no_writes(_conn, _cursor, statement, *_):
        assert statement.lstrip().upper().startswith(("SELECT", "PRAGMA")), statement
    event.listen(engine, "before_cursor_execute", no_writes)
    try:
        a = await client.post("/api/cascades/1/routes/http-check", headers=inventory, json={"via": "exit", "destinations": ["example.com"]})
        b = await client.post("/api/servers/1/site-check", headers=inventory, json={"destinations": ["example.com"], "scheme": "http"})
    finally:
        event.remove(engine, "before_cursor_execute", no_writes)
    assert a.status_code == b.status_code == 200
    assert a.json()["source"] == {"server_id": 2, "via": "exit"}
    assert b.json()["source"] == {"server_id": 1, "via": None}
    assert a.json()["draft_applied"] is False and a.json()["results"][0]["http_status"] == 403
    assert [(x[0], x[1]) for x in calls] == [(2, "https"), (1, "http")]
    assert {"192.0.2.1", "192.0.2.2"}.issubset(calls[0][2])


@pytest.mark.parametrize("changed", ["server", "cascade", "deleted"])
async def test_diagnostic_identity_race_is_discarded(client, inventory, monkeypatch, changed):
    async def check(*args, **kwargs):
        async with client.session_factory() as session:
            obj = await session.get(Server if changed == "server" else Cascade, 1)
            if changed == "server":obj.host = "192.0.2.9"
            elif changed == "cascade":obj.params = '{"changed":true}'
            else:await session.delete(obj)
            await session.commit()
        return []
    monkeypatch.setattr(cascade_http, "run_check", check)
    response = await client.post("/api/cascades/1/routes/http-check", headers=inventory, json={"via": "entry", "destinations": []})
    assert response.status_code == 409


async def test_concurrent_batches_and_cooldown_have_no_queue():
    server = SimpleNamespace(host="192.0.2.1", ssh_port=22)
    async with cascade_http.bounded_node(server):
        with pytest.raises(HTTPException) as failure:
            async with cascade_http.bounded_node(server):pytest.fail("Concurrent check admitted")
        assert failure.value.status_code == 429
    with pytest.raises(HTTPException):
        async with cascade_http.bounded_node(server):pytest.fail("Cooldown bypassed")
    assert not cascade_http._active


async def test_invalid_and_cidr_skip_ssh_and_duplicates_probe_once(tmp_path, monkeypatch):
    key = tmp_path / "ssh/id_ed25519";key.parent.mkdir();key.write_text("fixture")
    calls = []
    class Connection:
        async def run(self, command, **kwargs):
            data = json.loads(kwargs["input"]);calls.append(data)
            assert "example.com" not in command and "sudo" not in command
            targets = data.get("targets") or [{"destination": d, "scheme": data["scheme"]} for d in data["destinations"]]
            return SimpleNamespace(exit_status=0, stdout=json.dumps({"results": {(t["scheme"]+"://"+t["destination"] if "targets" in data else t["destination"]): {"status": "response", "http_status": 200, "scheme": t["scheme"]} for t in targets}}))
        def close(self):pass
    async def connect(*a, **kw):
        assert kw["known_hosts"] and kw["connect_timeout"] == 2
        return Connection()
    monkeypatch.setattr(cascade_http.asyncssh, "connect", connect)
    monkeypatch.setattr(cascade_http.sshops, "_host_known", lambda *a: True)
    server = SimpleNamespace(host="192.0.2.1", ssh_port=22, ssh_user="fixture")
    settings = SimpleNamespace(data_dir=str(tmp_path))
    body = cascade_http.SiteCheck(destinations=["*.example.com", "198.51.100.0/24"])
    assert [r.status for r in await cascade_http.run_check(server, body, [], settings)] == ["invalid", "not_applicable"]
    assert not calls
    body = cascade_http.SiteCheck(destinations=["Example.com.", "example.com"])
    result = await cascade_http.run_check(server, body, [], settings)
    assert calls[0]["targets"] == [{"destination": "example.com", "scheme": "https"}] and result[0] == result[1]
    cascade_http._recent.clear()
    body = cascade_http.SiteCheck(destinations=["API.IPIFY.ORG."])
    assert (await cascade_http.run_check(server, body, [], settings))[0].http_status == 200
    assert calls[-1]["targets"] == [{"destination": "api.ipify.org", "scheme": "https"}]
    before = len(calls)
    body = cascade_http.CascadeSiteCheck(destinations=["api.ipify.org"], via="entry")
    assert (await cascade_http.run_check(server, body, [], settings))[0].reason == "reserved_destination"
    assert len(calls) == before
    cascade_http._recent.clear()
    body = cascade_http.SiteCheck(destinations=["HTTP://Example.com/", "example.com", "https://example.com/", "https://faß.example", "https://fass.example", "https://example.com/a?secret-value"], scheme="http")
    result = await cascade_http.run_check(server, body, [], settings)
    assert len(calls) == before+1 and len(calls[-1]["targets"]) == 3
    assert result[0] == result[1] and result[3] == result[4]
    assert result[0].scheme == "http" and result[2].scheme == "https"
    assert result[5].status == "invalid" and result[5].destination is None and result[5].scheme is None
    assert "secret-value" not in json.dumps(calls[-1])
    cascade_http._recent.clear()
    result = await cascade_http.run_check(server, cascade_http.CascadeSiteCheck(destinations=["example.com", "https://example.com"], scheme="http", via="entry"), [], settings)
    assert calls[-1]["destinations"] == ["example.com"] and calls[-1]["scheme"] == "http" and "targets" not in calls[-1]
    assert result[0].scheme == "http" and result[1].status == "invalid"


@pytest.mark.parametrize("raw", ["https://example.com/path", "https://example.com?secret", "https://example.com?", "https://example.com#", "https://user:secret@example.com", "https://example.com:443", "http://example.com:80/", "//example.com", "ftp://example.com", "https:// example.com", "https://exam\nple.com", "https://example.com\\@other.example", "example.com//", "example.com/path", "198.51.100.1//", "httpſ://example.com"])
def test_standalone_origin_rejects_entire_unsafe_input(raw):
    result = cascade_http.normalize_targets(cascade_http.SiteCheck(destinations=[raw]))[0]
    assert result.status == "invalid" and result.reason == "invalid_destination"
    assert result.destination is None and result.scheme is None


def test_standalone_origin_normalization_default_legacy_and_route_idna():
    body = cascade_http.SiteCheck(destinations=["Example.com.", "http://EXAMPLE.com./", "HTTPS://faß.example/", "https://API.IPIFY.ORG/", "198.51.100.0/24", "example.com/", "198.51.100.1/"])
    results = cascade_http.normalize_targets(body)
    assert [(r.destination,r.scheme) for r in results[:4]] == [("example.com","https"),("example.com","http"),("fass.example","https"),("api.ipify.org","https")]
    assert results[4].status == "not_applicable"
    assert [(r.destination,r.scheme) for r in results[5:]] == [("example.com","https"),("198.51.100.1","https")]


async def test_mixed_api_rejects_unicode_scheme_per_row_without_unsafe_ssh(client, inventory, tmp_path, monkeypatch):
    key=tmp_path/'id_ed25519';key.write_text('fixture');calls=[]
    class Connection:
        async def run(self,command,**kwargs):
            payload=json.loads(kwargs['input']);calls.append(payload)
            assert payload['targets']==[{'destination':'example.com','scheme':'https'}]
            return SimpleNamespace(exit_status=0,stdout=json.dumps({'results':{'https://example.com':{'status':'response','http_status':200,'scheme':'https'}}}))
        def close(self):pass
    async def connect(*a,**kw):return Connection()
    monkeypatch.setattr(cascade_http,'key_paths',lambda data:(key,key.with_suffix('.pub')))
    monkeypatch.setattr(cascade_http.sshops,'_host_known',lambda *a:True)
    monkeypatch.setattr(cascade_http.asyncssh,'connect',connect)
    response=await client.post('/api/servers/1/site-check',headers=inventory,json={'destinations':['https://example.com','httpſ://example.com']})
    assert response.status_code==200 and len(calls)==1
    results=response.json()['results']
    assert results[0]['http_status']==200 and results[1]['status']=='invalid' and results[1]['destination'] is None and results[1]['scheme'] is None


@pytest.mark.parametrize("failure,expected", [("python", "python_missing"), ("malformed", "worker_failed"), ("timeout", "batch_deadline"), ("ssh", "node_unreachable")])
async def test_worker_transport_failures_are_honest_and_generic(tmp_path, monkeypatch, failure, expected):
    key = tmp_path / "ssh/id_ed25519";key.parent.mkdir();key.write_text("fixture")
    closed = []
    class Connection:
        async def run(self, command, **kwargs):
            assert "install" not in command and "sudo" not in command
            if failure == "timeout":raise TimeoutError("private transport detail")
            if failure == "ssh":raise cascade_http.asyncssh.ConnectionLost("private transport detail")
            return SimpleNamespace(exit_status=0, stdout='{"unavailable":"python_missing"}' if failure == "python" else '{"results":{"example.com":{"status":"error","reason":"private detail"}}}')
        def close(self):closed.append(True)
    async def connect(*a, **kw):return Connection()
    monkeypatch.setattr(cascade_http.asyncssh, "connect", connect)
    monkeypatch.setattr(cascade_http.sshops, "_host_known", lambda *a: True)
    result = await cascade_http.run_check(SimpleNamespace(host="192.0.2.1", ssh_port=22, ssh_user="fixture"), cascade_http.SiteCheck(destinations=["example.com"]), [], SimpleNamespace(data_dir=str(tmp_path)))
    assert result[0].reason == expected and "private" not in result[0].model_dump_json()
    assert closed and not cascade_http._active


FAKE_NETWORK = r'''
import socket,ssl,http.client,time,os
socket.if_nameindex=lambda:[]
def dns(host,*a,**k):
 if host.startswith('slow'):time.sleep(30)
 if host.startswith('unknown'):raise socket.gaierror('unavailable split DNS')
 addresses={'private.example':['127.0.0.1'],'mixed.example':['8.8.8.8','169.254.169.254'],
 'nat64.example':['64:ff9b::a9fe:a9fe'],'mapped.example':['::ffff:169.254.169.254'],
 'six.example':['2002:a9fe:a9fe::'],'teredo.example':['2001:0:1:1:1:1:1:1'],
 'management.example':['9.9.9.9']}.get(host,['8.8.8.8'])
 return [(socket.AF_INET6 if ':' in ip else socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,0)) for ip in addresses]
socket.getaddrinfo=dns
class Sock:
 def __init__(self,*a):self.stopped=False
 def settimeout(self,value):assert 0<value<=3
 def connect(self,target):
  assert target[0]=='8.8.8.8' and target[1] in (80,443);self.port=target[1];self.tls=False
 def shutdown(self,*a):self.stopped=True
 def close(self):pass
socket.socket=Sock
class TLS:
 def wrap_socket(self,sock,server_hostname):
  assert sock.port==443;sock.tls=True
  if server_hostname=='tls.example':raise ssl.SSLError('private exception details')
  assert server_hostname.endswith('.example');return sock
ssl.create_default_context=lambda:TLS()
class Response:
 def __init__(self,status):self.status=status
 def read(self,*a):raise AssertionError('Response body must never be read')
class HTTP:
 def __init__(self,host,port):self.host=host;self.port=port
 def request(self,method,path,headers):
  assert method=='GET' and path=='/' and headers['Host']==self.host
  assert self.sock.port==self.port and self.sock.tls==(self.port==443)
 def getresponse(self):
  if self.host=='headers.example':
   while not self.sock.stopped:time.sleep(.005)
   raise OSError('interrupted slow headers')
  return Response(999 if self.host=='badstatus.example' else 403 if self.host=='forbidden.example' or self.host=='scheme.example' and self.port==80 else 302 if self.host=='redirect.example' else 200)
 def close(self):self.sock.close()
http.client.HTTPConnection=HTTP
os.environ['HTTPS_PROXY']='http://127.0.0.1:1'
'''


def worker(hosts, scheme="https", management=None, resolution=None):
    code = FAKE_NETWORK + "\n" + cascade_http.WORKER
    cfg = {"management": management or []}
    cfg.update(targets=hosts) if hosts and isinstance(hosts[0],dict) else cfg.update(destinations=hosts,scheme=scheme)
    if resolution is not None:cfg["resolve_management"] = resolution
    # A file avoids WSL's inherited stdin/argument handling on Windows. The
    # measured deadline starts inside Linux, excluding distribution startup.
    source = "import io,json,sys,time\nstart=time.monotonic()\nsys.stdin=io.StringIO(" + repr(json.dumps(cfg)) + ")\n" + code
    source = source.replace("print(json.dumps({'results':results}),flush=True)", "print(json.dumps({'results':results,'elapsed':time.monotonic()-start}),flush=True)")
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as handle:
        handle.write(source.encode());path = handle.name
    try:
        argument = path if os.name != "nt" else "/mnt/" + path[0].lower() + path[2:].replace("\\", "/")
        command = ["python3", argument] if os.name != "nt" else ["wsl", "--cd", "/", "--exec", "python3", argument]
        p = subprocess.run(command, capture_output=True, timeout=35)
    finally:
        os.unlink(path)
    assert p.returncode == 0, p.stderr.decode(errors="replace")
    data = json.loads(p.stdout)
    return data["results"], data["elapsed"]


def test_worker_http_response_tls_error_redirect_no_body_and_proxy():
    results, _ = worker(["ok.example", "forbidden.example", "redirect.example", "tls.example", "badstatus.example"])
    assert [results[h].get("http_status") for h in ("ok.example", "forbidden.example", "redirect.example")] == [200, 403, 302]
    assert results["tls.example"]["reason"] == "tls_error" and results["tls.example"]["scheme"] == "https"
    assert results["badstatus.example"]["reason"] == "http_error"
    assert "private exception details" not in json.dumps(results)
    assert all(k in results["ok.example"]["timings_ms"] for k in ("dns", "tcp", "tls", "total"))


def test_worker_mixed_schemes_share_one_batch_and_keep_independent_sockets():
    results, elapsed = worker([{"destination": "scheme.example", "scheme": "http"}, {"destination": "scheme.example", "scheme": "https"}, {"destination": "tls.example", "scheme": "https"}, {"destination": "tls.example", "scheme": "http"}, {"destination": "private.example", "scheme": "http"}, {"destination": "headers.example", "scheme": "http"}, {"destination": "headers.example", "scheme": "https"}])
    assert elapsed < 5
    assert results["http://scheme.example"]["http_status"] == 403 and results["https://scheme.example"]["http_status"] == 200
    assert results["https://tls.example"]["reason"] == "tls_error" and results["http://tls.example"]["http_status"] == 200
    assert results["http://private.example"]["status"] == "blocked"
    assert results["http://headers.example"]["reason"] == results["https://headers.example"]["reason"] == "target_timeout"


def test_worker_ssrf_all_answers_transition_and_management_blocked():
    hosts = ["private.example", "mixed.example", "nat64.example", "mapped.example", "six.example", "teredo.example", "management.example"]
    results, _ = worker(hosts, management=["9.9.9.9"])
    assert all(r["status"] == "blocked" for r in results.values())
    assert results["management.example"]["reason"] == "management_address"


def test_split_dns_and_unknown_vpn_endpoint_do_not_disable_public_checks():
    server = SimpleNamespace(host="unknown-node.example", client_endpoint="unknown-client.example", egress_ip="9.9.9.9")
    settings = SimpleNamespace(panel_ip="203.0.113.1", panel_url="https://unknown-panel.example")
    names = cascade_http.management_hosts([server], settings)
    resolution = cascade_http.management_resolution(server, [server], settings)
    assert "unknown-client.example" in names and "unknown-client.example" not in resolution
    results, _ = worker(["ok.example", "unknown-panel.example", "management.example"], management=names, resolution=resolution)
    assert results["ok.example"]["http_status"] == 200
    assert results["unknown-panel.example"]["reason"] == results["management.example"]["reason"] == "management_address"


@pytest.mark.parametrize("host", ["slow.example", "headers.example"])
def test_worker_per_target_wall_clock_limits_dns_and_drip_headers(host):
    results, elapsed = worker([host])
    assert results[host]["status"] == "timeout" and results[host]["reason"] == "target_timeout"
    assert 2.8 < elapsed < 7


def test_worker_overall_deadline_does_not_wait_dns_threads_and_marks_queue_honestly():
    results, elapsed = worker([f"slow{i}.example" for i in range(100)])
    assert elapsed < 12
    assert sum(r["status"] == "not_checked" for r in results.values()) >= 76
    assert any(r["status"] == "timeout" for r in results.values())
