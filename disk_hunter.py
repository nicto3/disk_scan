#!/usr/bin/env python3
"""
DiskHunter — находит самые тяжёлые файлы и папки, даёт выделить и удалить.
Запуск:  python disk_hunter.py     (Python 3.8+, больше ничего ставить не нужно)
Необязательно:  pip install send2trash   — тогда файлы можно удалять в корзину.
"""
import os, json, time, string, shutil, secrets, threading, webbrowser
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

try:
    from send2trash import send2trash
except Exception:
    send2trash = None

TOKEN = secrets.token_urlsafe(16)
MIN_COLLECT = 1024 * 1024  # собираем файлы от 1 МБ
S = dict(running=False, stop=False, scanned=0, cur="", files=[], folders=[], total=0, root="")
PROT = ["c:/windows", "c:/program files", "c:/program files (x86)", "/usr", "/bin", "/sbin",
        "/etc", "/system", "/boot", "/lib", "/var/lib", "/library/system"]
if os.environ.get("SystemRoot"):
    PROT.append(os.environ["SystemRoot"].lower().replace("\\", "/"))


def protected(p):
    q = os.path.abspath(p).lower().replace("\\", "/")
    return any(q == x or q.startswith(x + "/") for x in PROT)


def roots():
    if os.name == "nt":
        cands = [c + ":\\" for c in string.ascii_uppercase]
    else:
        cands = ["/"] + [os.path.join(b, x) for b in ("/Volumes", "/media", "/mnt")
                         if os.path.isdir(b) for x in sorted(os.listdir(b))]
    out = []
    for p in cands:
        if os.path.exists(p):
            try:
                u = shutil.disk_usage(p)
                out.append(dict(path=p, total=u.total, used=u.used))
            except Exception:
                out.append(dict(path=p, total=0, used=0))
    return out


def scan(root):
    files, folders, n, total = [], {}, 0, 0
    stack = [(root, None)]
    while stack and not S["stop"]:
        d, top = stack.pop()
        S["cur"] = d
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append((e.path, top or e.name))
                        elif e.is_file(follow_symlinks=False):
                            st = e.stat(follow_symlinks=False)
                            n += 1
                            total += st.st_size
                            S["scanned"] = n
                            k = top or "(файлы в корне)"
                            folders[k] = folders.get(k, 0) + st.st_size
                            if st.st_size >= MIN_COLLECT:
                                files.append((e.path, st.st_size, int(st.st_mtime)))
                    except OSError:
                        pass
        except OSError:
            pass
    files.sort(key=lambda f: -f[1])
    S["files"] = files[:20000]
    S["folders"] = sorted(folders.items(), key=lambda x: -x[1])[:12]
    S["total"] = total
    S["running"] = False


def delete(paths, to_trash):
    allowed = {f[0] for f in S["files"]}
    ok, fail = [], []
    for p in paths:
        if p not in allowed or protected(p):
            fail.append([p, "защищённый или не из результатов скана"])
            continue
        try:
            if to_trash and send2trash:
                send2trash(p)
            else:
                os.remove(p)
            ok.append(p)
        except Exception as ex:
            fail.append([p, str(ex)])
    gone = set(ok)
    S["files"] = [f for f in S["files"] if f[0] not in gone]
    return ok, fail


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)

    def _local(self):
        return self.headers.get("Host", "").split(":")[0] in ("127.0.0.1", "localhost")

    def do_GET(self):
        if not self._local() or self.path.split("?")[0] != "/":
            return self._send(404, {})
        self._send(200, PAGE.replace("__TOKEN__", TOKEN).encode(), "text/html")

    def do_POST(self):
        if not self._local() or self.headers.get("X-Token") != TOKEN:
            return self._send(403, {"error": "forbidden"})
        try:
            n = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._send(400, {"error": "bad request"})
        name = self.path.rsplit("/", 1)[-1]
        if name == "roots":
            return self._send(200, dict(roots=roots(), home=os.path.expanduser("~"), trash=bool(send2trash)))
        if name == "scan":
            p = req.get("path", "")
            if S["running"]:
                return self._send(200, {"error": "Сканирование уже идёт"})
            if not os.path.isdir(p):
                return self._send(200, {"error": "Такой папки нет — проверьте путь"})
            S.update(running=True, stop=False, scanned=0, cur=p, files=[], folders=[], total=0, root=p)
            threading.Thread(target=scan, args=(p,), daemon=True).start()
            return self._send(200, {"ok": True})
        if name == "status":
            return self._send(200, dict(running=S["running"], scanned=S["scanned"], cur=S["cur"]))
        if name == "stop":
            S["stop"] = True
            return self._send(200, {"ok": True})
        if name == "results":
            return self._send(200, dict(files=S["files"][:5000], folders=S["folders"],
                                        total=S["total"], scanned=S["scanned"], root=S["root"]))
        if name == "delete":
            ok, fail = delete(req.get("paths", []), bool(req.get("trash")))
            return self._send(200, dict(ok=ok, fail=fail))
        self._send(404, {})


PAGE = r"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DiskHunter</title>
<style>
:root{--bg:#274f35;--p:#193a29;--p2:#20452f;--ln:#365f43;--g:#f7f4e9;--g2:#8bb895;--tx:#f6f2e7;--mu:#b0c0b2;--rd:#fa442d;--orange:#f57b00;--cream:#20432f;--shadow:0 12px 32px #10291f55}
*{box-sizing:border-box}
body{margin:0;color:var(--tx);font:14px/1.5 "Segoe UI",system-ui,sans-serif;padding-bottom:110px;background:var(--bg);min-height:100vh}
.wrap{position:relative;max-width:1120px;margin:0 auto;padding:28px 24px}
.hero{display:grid;grid-template-columns:180px minmax(0,1fr) 180px;align-items:center;min-height:154px;margin:0 auto 24px;padding:0 8px}.brand-logo{display:block;width:170px;height:150px;object-fit:contain;justify-self:start}.hero-title{text-align:center;grid-column:2}.hero-spacer{grid-column:3}h1{margin:0;color:#fff;font:800 36px/1.08 "Segoe UI",system-ui,sans-serif;letter-spacing:-1px}.sub{color:#d1dfd2;margin:9px 0 0;font-size:14px}.hero .sub{max-width:560px;margin:9px auto 0}.hero-title h1 span{color:var(--orange)}
.panel{background:var(--p);border:1px solid var(--ln);border-radius:18px;padding:20px;margin-bottom:16px;box-shadow:var(--shadow)}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
input[type=text],input[type=number],select{background:#112e20;border:1px solid var(--ln);color:var(--tx);border-radius:11px;padding:11px 13px;font:inherit;outline:none;transition:border-color .15s,box-shadow .15s}input::placeholder{color:#8fa493}
input:focus,select:focus,button:focus-visible{border-color:var(--orange);box-shadow:0 0 0 3px #f57b0030}
#path{flex:1;min-width:240px}
.btn{background:var(--orange);color:#172d20;border:0;border-radius:11px;padding:11px 18px;font:700 14px inherit;font-family:inherit;cursor:pointer;transition:transform .12s,box-shadow .12s,background .12s;box-shadow:0 4px 14px #f57b0036}.btn:hover{background:#ff921c;box-shadow:0 7px 20px #f57b0045;transform:translateY(-1px)}
.btn.ghost{background:#244a34;color:#f2f4e9;border:1px solid #52785a;box-shadow:none}.btn.ghost:hover{background:#2d5940;border-color:#8bb895}.btn.red{background:var(--rd);color:#fff;box-shadow:0 4px 14px #fa442d35}.btn.red:hover{background:#ff5a43}.btn:disabled{opacity:.42;pointer-events:none;box-shadow:none}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}.chip{background:#1b3e2b;border:1px solid #365f43;border-radius:12px;padding:9px 12px;cursor:pointer;min-width:110px;color:var(--tx);font:inherit;text-align:left;transition:border-color .15s,transform .15s}.chip:hover,.chip.on{border-color:var(--orange);transform:translateY(-1px)}.chip small{display:block;color:var(--mu);font-size:11px}.chip s{display:block;height:4px;border-radius:2px;background:#34533d;margin-top:6px;overflow:hidden;text-decoration:none}.chip s b{display:block;height:100%;background:var(--orange)}
.prog{margin-top:16px}.prog .bar{height:7px;border-radius:8px;background:linear-gradient(90deg,var(--orange),#ffbd43,var(--g2));background-size:180% 100%;animation:mv 1.2s linear infinite}@keyframes mv{to{background-position:180% 0}}@media(prefers-reduced-motion:reduce){.prog .bar{animation:none}}.prog span{display:block;color:var(--mu);font-size:12px;margin-top:7px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:16px}.stat{background:var(--p);border:1px solid var(--ln);border-radius:18px;padding:17px 20px;box-shadow:var(--shadow)}.stat b{display:block;font:700 28px/1.2 "Segoe UI",system-ui,sans-serif;color:#ff9a32;letter-spacing:-.7px}.stat span{color:var(--mu);font-size:12px}
h3{margin:0 0 14px;font-weight:750;font-size:16px;color:#f6f2e7;letter-spacing:-.2px}
.fl{display:grid;grid-template-columns:minmax(120px,220px) 1fr 90px;gap:12px;align-items:center;margin:9px 0;font-size:13px}.fl div:nth-child(2){height:9px;border-radius:8px;background:#102c1e;overflow:hidden}.fl i{display:block;height:100%;border-radius:8px;background:linear-gradient(90deg,var(--orange),#ffbd43);box-shadow:none}.fl em{font-style:normal;text-align:right;color:var(--mu);font-variant-numeric:tabular-nums}.fl div:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.filters{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:13px}.filters label{color:var(--mu)}
.tw{max-height:560px;overflow:auto;border:1px solid var(--ln);border-radius:12px;background:#163624}table{width:100%;border-collapse:collapse}th{position:sticky;top:0;background:#244a34;text-align:left;padding:11px 12px;font-weight:700;color:#f5f0e3;cursor:pointer;user-select:none;z-index:1}td{padding:9px 12px;border-top:1px solid #2b5038;vertical-align:middle}tr.r{cursor:pointer}tr.r:hover td{background:#20452f}tr.on td{background:#31573a}td.sz{width:210px;font-variant-numeric:tabular-nums;white-space:nowrap;background:linear-gradient(90deg,#f57b0033 var(--w),transparent var(--w))}td.n{max-width:0;width:100%}td.n b{display:block;font-weight:650;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}td.n small{display:block;color:var(--mu);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:rtl;text-align:left}td.d{color:var(--mu);white-space:nowrap}input[type=checkbox]{accent-color:var(--orange);width:16px;height:16px}
.empty{padding:36px;text-align:center;color:var(--mu)}
.dock{position:fixed;left:0;right:0;bottom:0;z-index:5;background:#153322ee;backdrop-filter:blur(12px);border-top:1px solid #45694b;box-shadow:0 -8px 28px #10291f55}.dock .in{max-width:1120px;margin:0 auto;padding:14px 24px;display:flex;gap:16px;align-items:center;flex-wrap:wrap}.dock .info{flex:1;min-width:200px}.dock .info b{color:#ff9a32;font-size:18px}.dock label{color:var(--mu)}
.modal{position:fixed;inset:0;background:#07150dcc;backdrop-filter:blur(3px);display:none;place-items:center;z-index:9;padding:16px}.modal.on{display:grid}.box{background:#1c3e2b;border:1px solid #557750;border-radius:20px;padding:24px;max-width:440px;width:100%;box-shadow:0 24px 80px #07150d80}.box h3{font-size:20px;margin-bottom:8px}.box p{color:var(--mu);margin:0 0 18px}.box p b{color:var(--tx)}
.toast{position:fixed;top:16px;right:16px;background:#204d36;color:#fff;border:1px solid #83a985;border-radius:12px;padding:12px 16px;z-index:10;max-width:360px;display:none;box-shadow:0 10px 28px #10291f66}
@media(max-width:700px){.wrap{padding:22px 14px}.hero{grid-template-columns:1fr;justify-items:center;gap:6px;margin-bottom:20px;padding:0}.brand-logo{grid-column:1;grid-row:1;justify-self:center;width:120px;height:110px}.hero-title{grid-column:1;grid-row:2}.hero-spacer{display:none}h1{font-size:30px}.stats{grid-template-columns:1fr}.stat{padding:14px 16px}.dock .in{padding:12px 14px;gap:12px}td.d,th.d{display:none}td.sz{width:120px}.fl{grid-template-columns:100px 1fr 70px}.panel{padding:16px;border-radius:15px}}
</style></head><body><div class="wrap">
<header class="hero"><img class="brand-logo" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAUAAAAEsCAYAAACypmqLAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAC3DSURBVHhe7Z1f6HbZVd8HhHqlF5VAI6aZjM1EJqONGTWKKRSLjcnMO0NSK8GEBEVJ0MAQFb2StCm02ItCvRARKWjBKwVzIYigUCgiBfXCi14oCv4BC6VgFW+8eOTzjN9kz373Ps85z3P22n/WOvDh/b2/3/mzzzp7f8/ae629zzPPv/YtlyAIAo88k/8iCILACyGAQRC4JQQwCAK3hAAGQeCWEMAgCNwSAhgEgVtCACfkudfed3nbq++7vOu1b34G+Pntr77vqf2C+5GN+RcbP/vat4SNFyQEcDJoiK98z4uXn/6+t11+49NfdeUXfuCrL//2e77+qX2D+0DovuPfvOfyHz/57OXXPv2Przb+wqfecvnER1+4imG+fzAv8TAnQR4JjfD3PvMVl//3I192+esffebKX/3oM9ffIYLskx8b7Af7IX6//cNfefk/n33DvgIb/9D3vitsvBAhgBOA+H3bR77x6pH8yev/6Cp4CGAKDZRGi4eYHx/cBrvh3X3uE89d/uj1L7/aM7exXjQ8C55Jfo5gPkIABwdvgwZHFwyPpCR+qQh+9mPPhwgehC4vNv7Z7/+aXTZmv7DxGoQADgzix3gfnt1WoxRpVzgG7Pch8eMFIxvmds1tjBfOUER0hecnBHBQ6GIhZAhaqTtWgwb633/gq2Owfgd4cRrvuyV8uY0JjnzDh1+KrvDkRCMZkDTYcUT81DjxUCIgso2CHUR4j4ifoKscAZH5CQEcDIlfLdixB0SThh3jVGWU5nLPC0ZouCG8wLkJARwIjfk90jBFeChlECt5fo/aGBEkahwvmnkJARwEhIpu69HxqBqcg0YeKRtfQgEPxu/OsjEpMxF0mpcQwAFAoOhK4fmd0TAFXiApG+EFvgE2VrT3LPAiOWd4gXMSAjgAzz156Rq5fbRLlqOACF0+7x4KAvX5T77jKRudAS+a8ALnJASwMzRMZnjQiPKGdQaIqve0GDxgEsQfCSxtoaATHmZ+7WBs3DaKEaBhfuyjL1zHkfJGdSaeE3c1vICNW4if4AWGyHq08cyEAHZC83vPiPjeQom73rxAiR9jdBY2jnnC8+GqQYwE434EKPKG1Ao8FLxAT4P13CtpKnjAuT1awTJl4QXOQwhgB5Ts3LpblqLVYrwERLhH5VRa2ThNiwkvcA5CADtAtwwxat0ty6GBsniqh64w3p9F1zdHww3RFZ6D5RvCaOD9MUMjbzgWyEPBM1rZC1RSuWXXN8Vz0Gk2QgAN0TSss2Z73IMSd1dtnGngo6eNYy72HIQAGoLoMEieNxhrFBBZ0QvExgQ+WuVVHiEWpx2fEEAjWk13uweuj4e04jgVgtPTwxZKi4kZImMTAmiEUjJ6N0yBh8QMlJW6wggNieX5vfaEoFN4geMSAmiAvL8ekd8aCoistJ4duZU9Ir81sHEsTjs2IYAGaC7qCONSKQjFKh4K3t+jC8m2IAIiYxMCaIA8k5EaJqSJu7OPU40SYCoRaTHjEgLYGM1IsJz1cQQFRGZOjk6HGEa1cSRHj8m0lX4WvvLJt149k9G6vylaPn/WbpqmFo5u45gnPB4hgI1BVO798pgVjFORsoEXOKOHQrlZWGKU4EcJBUS8zMWehRDAhqj7O9rAfA3SYmbzAjW7ZoT8yltQPu+L045GPIiGKPdv5K6ZUOLubB5KGv3N72k0FHQiVzG6wmMQAtgQ3vQjRn9rzDhPmJcM3d+ZbMyQSHiBYxAPoRFa8XnUyGSJGcep9JIZefwvhx4BXuCM462rEQLYCASE/LpR019qyAucwUPB+5tl/C8lXZw2RLAvw1fyWdHsj5kapsBD4ROSowdE9JKZ0caUmVk4+T0FtoQANkL5fzN1zQSNEw9l9HnCesnMamN6BzMNN6xICGAjEECy/2f0ToByj54WM/NLBrAxww0j23h1QgAbQeOcbWwqRR7KyMvnY+PZAiApCjrFajH9CAFsBG/1GXLTtqCBkrjLYg75/Y2AFj+dVQABG5MWM/pww6qEADZAk/NnSIDeQh7KqCuZjLwAwhEUdMKjze8xaEsIYAM0BW52AQR5KKOlxSjPcuZhBqHhhvAC7RmqUq+C0jPyij4zTOkbabB+9GXGjkI3noDOaC+a1QljN4DuYq9v/7ZAaTEjrWc320ITt+Ae4iNK9oQANmA1AQQ8FObcjjIWuJoAgmbhjORpr04IYANWFEAFRPACR/BQVhTA0YNOKxIC2IAVBRDwUJi+NcI41YoCCBpuiICIDd0r8oqsKoDyUJh+1rubtqoAgr7ZnN9zcD4hgA1YVQBhlLSYlQVQAZGYJ9yerpV4VVZMg0mhK4yH0nOciu7hSmkwOdiYWTiRHN2WEMAGrJQIXUIeSs+0mJUSoWtQf0YJOq1KCGADVpkKd4veiburTIWrwX3hBUZApB3dKu/q0D2cfTGELWicdD8Z6+zVFdYnR2deDOEWvERHm4WzEiGAjWDsZtXxKcG9seZhr3Gq2ZfD2kOkxbQlBLARsy+IuhfEp5cXOPuCqHsZIei0KiGAjaBxMnXMQ+OkG9ojIDLzkvhH0HBDpMWcTwhgI9Q4V/cAQYm71uNUSjfyYGPucZRZOCsRxmwEjZM5nSsHQkSaFmPpoeizmKuPtYJszPeEoyt8HiGAjVCe2sppGim95glzPcZaV+8GA/VIy+fndgjuw7SyeoNvaZDH5UEAga6wdUCEaxEI8WJjIC3G0sYrEwLYELpoVNa8Aq8KIoTgW3qB2Jix1tWTzkWkxZyLWUX1yMoT9msocdfKQ0EEGAf0MtQg8HqtbLwyIYCNoRvsqXHKQ7H0ArmWh5QjgY0J/PRIPVoNs0rqFY1R5ZV4ZWiglom7irh76QaDPlEQAZHHCAFsjLrBHlI1hDwUqw/8aPEJT5429Ag6rUYIoAF00Ziz6qlx6gM/Vo2T6+ARebKx0mIshxtWIwxngGaFeOqiAfdL19TCC9SsEE+eNnCvn//kO8xeNKsRAmiAh8U7S2hVYysPheusvjxWjoJO1C/rqYgrYFIxgy/lBHpqnGCZFsOLBo8zL4MHCLSRcZDbJNgmBNAIDdR78wK5V33gxyJlgxeNt2CIgk7xPeHjhAAa4jElRhCgsGicXAOP08MiFCkKOvVanHZWQgANYaAeT8ijF4ggkQ5kERDB0/YWdQeGG1gtxsLTXoUQQGM0d9Vb4+R+rQIiHhOjARuzMk7ME95P88oYPA0i6GG5/BwECfG36Ap7WZG7RI/FaWclBLADXvMCtXy+xTgVHpDXvECGWMIL3EcIYCeooJ7WChTc7+sff6eJh8I1PAadNE/YwtOenRDATnicIwzyUCwG67VUFl6nNxsTdGIc1OJFMzMhgB3R/FWP41Tct0XjxMZ4nB5tbBV0mpkwTke8rmLCvTL+abVaDGOOHr1Ay6DTrIQAdkZT5DwGRKxWi+EadAe9DTdgY16uFp72rIQADoASd71107SenYUXSFeQr9Z5EkARq8XUCQEcAConQQFvjZP7JR/SYml3zcLx5gUq6GQ1C2c2QgAHgXEqr9O3rD7wg41JEvZmYyAgYmHj2QgBHASlxXidJ4x31tpDiaCTTdBpJkIAB4IGioeSV+DVYeyT8TmLGSLeviMsFHSKgMibCQEciNRD8RQQkRdotXy+vtHiycYQaTFPEwI4GJon7K1xIoKIkkXiroYbvHmB2FjL57cOOs1C88oWHEfftvA0TiWspm/xovE4Fxusgk4zEAI4IAgA+XHeUjaUuGuxfL7noJPlN5tHJwRwUBgL9DpPGA/Fwgv0+qEqRBDv18LGoxMCOCieP6JEQMTKQ0EEvA03KC2GXob3rnAI4MBQOT0m7nK/lqvFeEyLwcbMwrGw8ciEAA4MXiARO4+Ju5ZeoNJiPNkYEH2WCms93joyIYCDo4CIVw/FYml3RNbz8vme5wmHAE6A17QYRJ8ghcU4lZbP92Zj8Lx8fgjgBFA58VC8BkQsEnc9DzfwovHqBYYAToI8lLwCrw4pKlafeUQAWDvP23ADNvaaFhMCOAnyUDx6gUrcbe0FgoYbPOUGytNmrNmbCIYATgSVEw8lr8AewEN57slLT9nkbLR8fn791UEEiYRbDDeMRAjgRHhfzw5hshis50WDGOTlWB3LxWlHIQRwMpS4S5clr8Aro5QNy7QYj8MNVovTjkII4IQwTkWX0NM4FSgtxmKcymtaDPfryQsMAZwQPCAaqMfEXauVTGRjj14gNrZanLY3IYCTwvLxHtNiaKAk7losn48XhMfpSQCFl48ohQBOCm9nxmq8eSjA/TIW2LorrKCTx1k4DK9YLU7bkxDAiaFy4qF4Tdy1Coh4XJxWQSeLxWl7EgI4MWlajLeACNFKq3nCBJ08L05rYeNehABOjmaIIAiePBTECA/FInGX85OE7c3GlkGnXoQALgANlO/qemqcwP0yM8YqIBJBp6ftMjshgAuAAHr+wI/FSibYmPEwbwER7hXP18LGPQgBXAQ8FLwhb+NUNFACIlbfE/a6OC3CbzHcYE3zShPYoICIx3EqPN+PGc0TZizQ21xssFyc1pIQwIVQ4q5XD8UiLQYb0x30mBbDPa/mBYYALgYiQJfQU+MUVh4K+ZcEBvLrr47l4rRWhAAuhgbrPXooStxtPViv1COvQaeV0mJCABdEHoq3gAhdfzwUKy/Q4zebweqbzRaEAC6I5gl79AK1nl3rcap0Fo5HGxMNt3jRtCYEcFHkoeQVeHXSecK5Tc4GAUAIPEbeEf4VAiIhgIuisUBv84TloVgun88H3D3ZGBhuYGXy2bvCIYALo5QNbx4KYoTwW6TFMNyAJ+RxuMFqFk5LQgAXh8RduoR5BV4dJe5azGH1PE+Y+7awcStcCCBu+r209iBaow/8ePRQrFaL8bo4rbxAi9SjViwngFR23siAgDFH9P2vftPlyavvvXz0yTdePvPKey4//so3XH7yla+//NQrL74Jfsff4SNP3ns9hmM5R3rO1g3qbCgzqQueGqfAQ+H+c5ucDdfwGHSiTlkFnVqwhADKW+NnBOsHn7znKmi/+PILl9/60POX//3Br738+Xe94/J/v+vZK3/7gbdvov045nc/+M8uX/jQ113PhXAijBpbSq87Mp7TYvDKLBJ3lRzNlDxvARHGmAmItLZxC6YVQIkPYoTHhkAhdAjY333g7ZfLB/7pm+B391A6D+L4Pz74/OXnX37h6lXiIY4uhpon7O17wogRomQxTuV1nrAWp7UIOp3NVAKIwKgbSvf0p19+99VDQ5AeFbqj6Fp4iYghIoz3mZYxL39PUg/FU+MUeIEWaTH6ZnN+/dVBBK2CTmcyhQDKu/rOV1/6oujh6VmLXg2VAyGmy52K4UhCiACwbJS3tBju1Wo9O7qBXhennfEjSkMLoASEMT3G4ejiSnByERoJhJCy0kXGUx1JCCkHy+d7G6fSPGGL58CLhmt5tDHBNovFac9iyIJKMNTN7dHFfRSVFSEkuiyPML9Xa+ShePQCrdJiNE/Y21ig0mKsZuGcwXACiEggFggf42sziV4JlZ9uO0I4gjfI9b2uZ2eVFpMGnTyJIDZmaqCFjc9gGAGUMJBqomju7OKXgydLV753tzidJ+ypccpDsUqL8bo4reYJz+AFDiGAGIp0EgIIs3V1j8K9Ie6MD/bsFisgklfe1UGM8FAsUja851/OEBDpKoDygghyKMDhBUQQb5DIdq/UAWzvbbUYsFzPjmt4DTrxlUILGz9CNwHUWB8JzApy5CKxOtwz45x0+4mcWb8tqZwMWHv0UBB+C5sr6OTRxjN8RKmLACJ+TCkjgTgXBW8of5AXQY9xQUQADyWvwKuDR2bloSAABF+8fa1Pi9OOnBZjXjAqHOJHVDQXA+/0GBf0vlqMxUomCjp5myeMjS0Xp70HUwHkTcB43wrpLa3gxaAocW6/VjAG6XUlky986i0mttZwgzcvEBtbfbP5HswEkArAFLEQv22wDSKIJ2j11lTKhteAiNWqxggtguvJ04aR02JMBFCR3hVz+1ogEcQTtKo0XEcf+Mkr8MpotRiLcSrvww0jBkSaP3SJX3h+x0EESZOxEkG8QDwUb16gpYeC0HpdnNZqLvYRmgqgur3k+IX4HQebESm3CowoZcPjOJXVZx49J0dbzcI5QjMBpMHivYTn9zgkTFvkrAEBEY+Ju0CqioUXyDXwhjy+aJiFY2HjvTQRQMSP7pSmtuUNOjgOS/xbeYHeP/DT+kWjoJPHxWkRfaZgjiKCzQQQryVvxMH9EECyEkEqJ2NieeVdHcTIKnFXaTFeg04Www17OP1B00CZ2qVvcwTnoGlzVjmC8lC8dYXxUKwSd/XNZo82ZqkwCxvf4lQBVMTX69ze1mBThhVoOLntzyZNi/HUTUOMCIhYvGQ8zxMeJS3mNAHUuAZRyxC/duBZa2HV/BmcDV1Bj2kxgPhb2JhrEHTyJICgxWl7e4GnCSAPkoaZN9jgXHi5kFbE+omtGygeitePKOEF4p219lAUdPI2C0dBJ+pXz7SYUwSQhkiuWqS82KCZIq0FEHhDs2qKJwEE7hfPzMrGjDt6tDE9jJ7zhE8RQB4gK5nkDTVoByLIeGvrBqqVTDymxeD5Mk5l4aHwHL15gWAZdCrxsABScKK+BD7yRhq0I100ofXbU2kxHlM2rFeL8RoQsbBxiYcFkJkDNMTo+tpjFRBJE3e9eShaPr+1jUGL03oSQOB+SYuxsHHOQwJIgRmMj5y/PsgLtBhDwUNhwNpj42T6lkXKRjoX25Od5QVaLUuW8pAA8saK6W59kRdoMYbCNegS5hV4dRAkUjYsPl6FU+FxcVogKdzaC7xbACkoS9sT+c0bZWALz8CicWo9O48BEcbmLDxtzo+36fGbzbxorL3AhwSQyG94f2Ng6QUyXuNtJRPGPq3SYrjG6x9/p8ugE+PMFjYWdwkgbym6v7HO3zhoyaz8WZ2NAiIevUDu2Spx1+vitIi+1eK0cFeDoXB4HBH8GAe6wQxJWLw9lRaTV97VQQQRJYsXjWaI5GVYHWxM999iWTK460HSyCL1ZTysusGAh0J01JMXCErctWicPEsCA95sDFbzhA8LYAQ/xoSXEd1gi2AI4KGQH+ctcVerxVgFRDwHnSxm4dwlgCzMGd3f8WA2jsVbU1AXeFN7G6fSenYWww0IAMMN3oJOiCAfj2pt48MCeF0iKVZ7HhK8QKtxQFBAxONqMZarGtPmvM0TVtCJscCWXuAhAaRhMfc0xv/GhGdCapKVAAIep8fEXctPaXINhhu8eYHQeizwsABqxee88QX9QQD1GU0LzwS0Woy3xF3LhRJAaTGebCwvsGXU/dCJlf4S3t+4EJyyWCYrhWt5HKfSzAULW9MN9LpaDPfdysaHBJAI4y/G7I+hsfx6XArX8+ihWAzUCxwQb4vTanYIHnBujzM4LIAx/jc+1uOAQOP05qFwn5ZJu0qO9pQWo5QY0oFaBEMOC2Dk/40PK/Tkz84CpcXklXhlaKCWn3j0OBe75QeUdgsgbzgG1yMAMjZaI7DlwHENBUQ8eSgKhrRonCWUesQsHC9pMUo+b1Gnd5+Qtzsf5Y4E6LFBAFmkgpeVdTcYuKancSpFKluNUZVQQCQvy6pgY3JNWww17BZA3nBEF0MAx4dhCl5WPQRQHoqntBi6o1arxAieLV5gXpaVaZF3eUgA47u/c8AwhcV3g2tQVzx9RIkuGsngZzfOLbwtTqv1GM+28WEBjAjw+OCl462fXVmOwLVZycTDOJXGAVuMUW2Bjb3MwkkXocjt8Ai7H9g1wvfyu0MAJ2AEAfT0gR+lw5zdOG/BcAPzkT2kHikd5uxxwN0CyNstlsCfA54R32ruKYDA9T2kxaS5amc2zj1ouMFDWgz3yJzoM8daQwAXZBQBVOKuh4CI5eIIKWlajAcb0+U/c2w7BHBBRhFA8DROZR0IEVozcPWgEwJ/9qczQwAXhGf0mVf6jgGm4KEwn3PlgAiN03JecA7PmuuvbGPuDU/3zLHW3QIYQZB5GCEIkqKUjZUXTuW+ekSChYYbVrfx2XOvdz+sSIOZh9EEEHiBkseVV+pVoHGe7Z0cZfXhBmxM3uOZH08/LIB5YwvGo3cidAl5gaumbPRKhUlZfXFaRdvPnHVzSABjKtwc9JwKt4VWi1lxnEreidV3Qmpg45XTYujiMw/aXABjMYQ56L0Ywi0o04peIPdD4+wtgMCydSuvFkMu4FnDO7sFMJbDmoOey2HtQeNUq3koIwkgNsZLWjEggqifmW95qJHEgqhzwGdL82c3EoyTkc+1UuMcSQDhuScvXdNi8nLOTncBjCXxx6fHkvhHQCCI5K3koQwngP9g49VWi+kugPFRpLFhjJZo/cgCCNSllVaLGU0AQcMNKwkg99JlDBAiF3B8enwW8x6UuLtKQGSUKHCK5glTrlVeNN2iwKBUmAiEjAkvJusPoz8CgRrSYlYIiCCAvfMAS9BmV0mLkZfdJQ8QFAmOccAx4ZkwXfGs7kFrqE94TEwhm91DoXG2/H7tI/CiYRbOCjbuNhNEYEyijHnjC/qDAI42Be4WdNXp0szuodA4e84F3mKVxWnlZXeZCyyosIwDRkL0eDA0MZP4Cco8e0CExtlzNZhbEHSaPS2G+nG2l32XAH7kyXsjH3Aw8P7wzKno+TMbHTwUxnVmD4j0Wg9wDwo6zZwWQ7m7rQeYQgFiHHAslP4yagO8hcap8ko/C71WhD4C7Xb2WTgEzboLIA+ZFYejGzwOzP/FMz+zclgys4dCeXt9E+QISouZdZ6wvglyZh2/SwAVDabRhRc4Br/1oeeHHIA/Ai/WGdNiRswBrIGNZ5wnrBQYgjln2vjuBnOtrLFC9BDgieORn/lm7MU1y+BTb5mqceJNjRoBLkE9mW0utiLAeLBDCCBGZNHNCIb0h2ewgvgBL1a6OTN5gQjg2WNTLZkx6ISNzw6AwN0CCMoJDC+wL6N8Ae4sqOSzJUfTrZzpGWi4YRYbI9Sf+8Rzp9v4IQGkMHiBEQzpg9b+O7tb0JuZPqKkAMgM438pCojM4gXSIzhzBoh4SACBvDPmn4YXaM8sK7/cA/c0Q1qMknPP9kwsoMyf/+Q7hv+esMb/WoyxPnxCjBgLJNijhQ+oFDN5HntRWszoH/hBABGRGQUQ8AJHDzppjLWFjR8WQOBtzTqBeSMN2oEA8vHzFb0/oZSNUcep0vy/s7tmVqTzhPP7GwU81DPXAEw5TQDJCyQaGV1hGxj7m3Ha21G4R7qYI3oolKlFZNIabDyqF6jub6sx1lMEEKgEP/XKi0811OBceMHwohntu7+tUFrMqAGRM9em64WCTiMGRPD+if7mZT6L0wRQUaUIiLRlpaTnvYz4ESUaZquB+R6MuDgtz5sZNi2zHE59eGlydIjg+WBTprx5Ej/QONVoXmCLvLReaHHakYYbKAdLeLUc6jlVAIE3SXw35HywJ5H22RY8PQtEf5TEXXkmLfLSeqLhhhEEkDLo+x8t6/vpAgjXLPOX3x0J0ich8fPW9U3REMsIHgrdxJlTX7bgnkYYblCAqbWNmwigosJ018ITfBxeJASYvIqf4P5f//g7uybuyvsjR3El709wT3hdPQMi8v4s0ouaCCBQWZ+8+sbK0SGCj8F861UTno8iL7BXV5jrsqjoyi+j3kEnrktajoWNmwkgcAOMWbFuYN6og9so6IE3bVEZZqBn4i4NU9+kWPllxL3h4fbwtK3HV5sKIEgEwxM8DsnO3/nqSyF+GT0Sd9UtazUjYTSwMeOc1i8armfpYTcXQJAIMpYVInib1PPz0NiOIg/Fcp5wq/XoRsY66KTcyuee2HnYJgII3BAD+eEJboNtwvO7Dbax8lDk/bWajjUq2NhqcVpszHVap73kmAkgcGMKjOQNP3gj2stMmhjz2weegkVABPEb/YtvraAeWgREEL9WK75sYSqAgEGZLRIfVHoz2IIVdUL89qPE3bwxnQ2zEc78GPdMaJ5wSy9QUd8eHra5AAINHE8wvi38hvDh+ZHqgl1C/I7R8jOPGpPq0TBHgntv5QVyTnIOe+VVdhFA4O1NbtvPv/zCdZaDRyHknvGENcPDcyO7l1aJu2nDtO6WjQZ1k5cAL4MzXzSycc/IejcBBDV4Fvb0GBwh0jvzx8xHgRcpqRNnCaAaJuN+PbySEWkxT1hTCnu++LsKoMC4jH3RDfSQKoPHy1xphK/Xm28lNE/4jLQYRSN7eiWjQn09My2mR9AjZwgBBIzLm5xUmRUDJLofvD4tZd/zzbcaNCS8wEcG6yV+IzTMEcEmeMWP2FgwpjjC9M5hBBAwBsKAN4iHhKe0wooy3IPG+njo0eU9H3mB93ooHEO6C2v8rbLIaQuu3wJ/cBaOouq9xQ+GfNAIBFNxSAZWkCQXldGRx4fwsT4iFSe8irbcm7KRil88o200F/veoBOfOqVtjyB+MKQACnWL6TKSI6do8cjdY5WNoA7deYIcPOxRHvjqHB2nUreX7nN4fvvAxgwTHLEx/+L5jZZSNMUD562cdo3JH5RXOIIYKpcP0dMYnzy+6O7ags3xAllR5FYDVbQ3Ah7HQMD2Lp8vG2sB2ZHED6YQQKGoqbxCuscSQ0vPUNcCiR7enr7UNuKD9gTPAI8ub4wp5LPRgPmqW4jfcbAxAZGtJbOUSM4LZlRHYCoBTMGg8gpZaUaeIYKkwMkZopiKHedFbLkGKTsSPQU2Rn3I3kjTYvLEXXV5NfUqxO9+qPeai516gvqZvzFeOLIzMK0ACoyrriYPBEHEO0QQESkWFyAQgXApqrwHCR3H4uFJ8BBbrsG1o4s7LjwXvDtEEMETdI3pjiGQkeT8GAqIIHR4grIxXV7GCHnBjN4+phfAHHligoqOYDH3GG8NASMqW4NUFfYheEEUmmNTDw9GfqMFX0JjVXTBiPDSZWNq2+iNciYQQdoYLxvZmDHYWdrJcgJYQvmFgNe2hxC7NVAPQcTzbANCKBvP5Fm7EMAgCIISIYBBELglBDAIAreEAAZB4JYQwCAI3BICGASBW0IAgyBwSwhgEARuCQEMgsAtIYBBELglBDAIAreEAAZB4JYQwCAI3BICGASBW0IAgyBwSwhgEARuCQEMgsAtIYBBELglBDAIAreEAAZB4JYQwCAI3BICGASBW0IAgyBwSwhgEARuCQEMgsAtIYBBELglBPBOnnvy0hfh/+967ZuHtGVezmBM4jn14VCj5eG87UP//DC1h5rvt7XvvdffOt9WOUrH6vf8/OJ3f/ubUNnyY0St7Pl+jx6DEOs4/n+0nCOS3/+e8pdsd+sYgQ3zY++B69VejOlzyJ8Rf9c58uNK58jJ99u7f/572LJZ7Xy3jtu6HuT7taT4cGr86x/88OXT//6zh/jwj3zi8tL3fsdTN8bv8n21f6nScDx/y/eHH/4PP3Yl/z1Q5trD4Pe1csC/+L6Xr/vAP/nAi9fr/+f/9l8vv/qbv3b5X3/wu5c//NM/vsLPv/Trv3L53M/8p+K9Qq3sqvA5XJPrl+6La+T76xiuzT3Xysnvtso5GtgntwH/17PJ9wd+X6qrPIN83xzVvfzYe+B6lD+vz9gd+3Mf1Jv8Gf3P3/+dy8/98i9cj6fele6zdo+AbY7uTznz3+se8nPpfByX7w/c11a70/H5cWLruLN5SmhqYCAeyl/9zf8/DA/2J/7Lv7s+TM7FDWLYP/vLv3hqXxpobgCJH+fJ9wcqDOS/199qjYXyIBT5McC1VAGprLr3WxvHUQGe/Yf71P1S0UvXqFUU7hmb5ccA5cqPYX+eEfbDrrc2rs29731b94By/atPf+Sp+wdsUxJw1RWEJD8G29ReOCk871LdPArXS+se/wL1Q3V5a+Pv1BtswH2lQkq9LLVHyo1t8mdaq+van3KWbEb7wR7p+fiZ39XanNpOXgbBvSB0+XE6ttYmWnBYAB/Z9GBUSbnhfMsFkJ95OBi7tMnYtfOxqaGn96OHyPGljYr3zL989ouN6chGOTheXU7gvvKNyld72FRYPLXSllcufr6nnGw809oLojeUicZf2rCNXqgpvHhqdqAO3RJA1YtaXTqypS9fuLcNUUcRjLQOc+/UsXyj3KWXgwQz37Q/di61BWyZCqDuo3RtNp2v9GxSG5fag7ZSe22FqQCmXlVNsHIBfOb9b60ai+NVMaC2H0KTdyUkMKUy8DseurzOezcqiSpPqWxnCCD3TSN7pJyUTWOHeTl6clQA5eXUNmsBlAco7/yR9pOL4NkCSD0s1aFcADlvzcaci+eS2zS37612lV+zJaYCyMY59gigbr52zfxBq7HU3v6cJ91X3Zx847w84Nob8ciWlrGFAOqeHy0nG+XLy9CbIwKIjTVkUNusBVAeIOctidXRTQ4E99pDADlnzWlgo93kL6UczlEqR77tOdcZPCyANGKMklMyJhsNTV3LkiElgLcqdMlAOqa0Uc70DVrbj0pLN6p0r+nG+bhHKJUxfRtyP2cLoO6j1AjSjXJslTPdSg2nJ3sFkP32eMF7BZB90sCEKL0w2VIbp1CH1JPYsn16fO0a2tQ+rAWQ89WcBja1m1Jdzm1buk6+cb6tc53FwwLIzejGBcZioLf00PcIIA9ra3yOfUrGvmVgKgxl2/KaFMCoPWjKjB0oP41OkbXU8+TcVCqV6ZYA5pUVbgmgvOhb5aRsaTlL5dAmgcjt2os9AqhnXhKDfNsjgAKb5WC/kr0VKMj353c1odJGveG8PB+O4Znyci9dh43nyj60odJ5WwggNoNa3WGfdFimBmVivz2b7jO/j7M5RQApJAbmX/1capzclDy3LQHcepvz0CUqeRmBcyvClG/8TqkHpY2KzJhjbYyDMqnycZ+p4PM7GqXEOfVObwmgKlgKx2wJINerlTNtJLVyljaOywfbc3SuM8nTRNJr3RJA9qs9z3w7IoB5GdV48zqt82LX/BjY8po0HCQh13X4P22gNpxzdSLe/9bifbcQwK2hJXl++fVKsB/75xtlKLVX7nPPeR+hWPFK1ASQh1vK0yrdqIypylS6aR5Czdh7Bkf52623Vem6avxbx/L3VNhyOLYUTOD/pXNyTX5fo2YHiVvpnGzpeGeO7FN6PmyloQUdR6Pk3GdDfSmVl2tuCSA2qPU0StsRAcyhLFsCWLIZ91R7GfNssWdeV/JjSxvHchy2K216hqkQ3xLAmtPB/dbqCn/b66Vt2YJyleq6HISajc7gYQFkk4Kn5Bu/U0XfEsDadpaxa5saBwYvPQzOxRssv9YeagJ473YVwPe/tVhh5aVu2Ym/1Qaz8SpKjVkC0GLDNrVr1gSQRrs1TFLaeghgzUunLWw1bP7G8aVnJGGoPUNsQv3HPtwv/8KWx1jzAGubjqOcNQ8+v5/a9bFrzU61F/JZ3Cy42BLAPZvcWT3YIwLIfkcMwQNh35pR840KJe+OcpUqAqK49/o5rQSw1hip7HkZUvSCqB1fuk89sxbbPQLIs63ZlIZWeobWAsgxtTbDfW0JIHDOkvclZ6BWHjbaDHWW4/kXe5Ta270CqBflrXuQHTh/qax6JrVxecpeGu8/CzMBZONmuVEJTemB1DaO3eoy5LAfZS4ZNd9oTKkwl46ZTQC37LQlgDUxGk0AKXup/qhrWfLiewhg7SW8RwCx+ZYAbg1l7N3uFUD1NG7dg+6jZAeurbFc9qnpy97r3MPDAshNaNxO8P9SRWFTZTkqgGy1ilYDo/Jwt65DWSUYquSlisA57n0TtRLAUjn3DBXUKiTbLF3g0qZ753mOIIBbdlb3MT8mvV6tC8xzR7C4Zm2ccO92rwCysf8tp4S/YfPS81DPi2cMlKO0UT9uvdTv5WEBlIDkUFlqbydutiaAGKo0VqCNCrXVuFMwGGWplYMtPZ/2r4kVD6jm9qe/y8tXE0DuH5tShhKlY9iuArgjCFIrZ61Csm0NNVDZ8zKeQS3yfFQAORfnGcUDlKddq+cKCObHcS3OxzhhaeNY7oP9gOddusae7ZYA8rut8+vlVaprt2zAhj1TShvH1urIo5wigHoQKVsPkIpaE0AZtCaCHKOKnpexBPvVzqXuUi5etTcR106Tm/Uvx1CZKTvnzF12fi6JFQ+c63O/OVvpKpyffWp/l41UtvTeaoPhbHu8x7ycZ1C7HuXfK4Dck0R/FAEEeg0lYWHjuFQElUEA1MHStdhoh+n1JDLUMY7h+dfIt1sCiB25B+pT6Xg2yrPloZXq/tFNz3dPwOUIu0+2JYB5hQa6aKX92TDIlgByo1vjGxwnEcjLmaJKW3qwbKVuiESjVDY2fq/yc33KyXnSa1AJlaahCl2qBOxXC/Nz7prA6dq1Bsmmciq4o3LWbMrG/vIs8vL0YK8Api+y0QSQ39faARv1hueMgGiCAM9hq/7lL1igziJU2ItnzrNO4ZjSi2+PAFI2zl+7D86Ri7LKVLPZ0Y1zbInsvTwsgBQs79LA1kPkgW8JoERoS7z4fakipNSEh40HWzuWB8k93Npqb1Vt6ZuxVI5HBFDeTumZ5NutcrLx91o+Xi/2CGDutY4mgDpuj/33PCd5Qvl10uvx9xzEtVRX9gog54WtF2hef26J/9GN9rB17/fwsADes1EhapVCAsg1JYK1LX075eXVsaVrUIl5WFuV9tbY4Z5NlYuynC2AqpBnlJPtyLCCFXsEMJ0RomNGEkAdu9WF3LuVhmz2UhOjvQLIOdSmSvuxpS8j1c2SvfgdZalRaitsen733H8NcwFUF7cmTqkApvl8pX3Z2D93jfmZ8pYaAVt6jRpqfLVz7NlaeoA6Rg3+ERHEqzi7Yp2BnkFtK3XZZY/Sc+spgFy3lri8Z9vT49niUQFM61sthYqN/SnnVv3dqm9bz4+ycu3ScfdiKoBUWCo0xtkjgALB3Lp23hD4t9aF5Zq16FsO+8jDKpW1tukNx31SFmglgGk5S9fY2rgnyimb5WXoDWWqCSDPpOQNbTWgXgIo9DIvnaO28Yy4l711tsYtAeT8ewRQ5+KYWptQeUvPgO1WRFd2Km1q6/kx93JYALnpo2BYjk0HqlWZ8n1LAsj/UyHK4TzqaqoB1PZVntveaJKujRiVKki+cV0esI7Vv1w3Lwvnqwkg98I9seXH5QKYlpOKU6t46UY5FQTKzzUKlIuGlN+/bFBqRFvP/wwB5Jnl56XO7hFAnYf6seelSr3meZaE/ihpTypFbUcvjfzvlDMXQH6+pQfYpGQrfpeXLUe2LunDo55wzi4REBgCQx1FBkwLjQHz/bRvfl1QA8/3T9H5a+eGexoA55WXhfGpSFQMHgaVhoettyj7lxpmrez5fim1+6iJt8rJcZRT4ymUUeWk7JRz7woePdF95vcPtxpAvj/U6tZeas8jF4hbYHfujWOpN+kzol7x3BBJzquXen6Oe6jVQbWJ/PdbNpMI5vvf4oit8mPFPW24RrEhbSEhOwLHlRptvl+6f4l8v5w9++bnPALHUyF5mxJVS1F3Nz8mPbZEvl9Ovv/eY+4t52ikuXFHbVAi3+8I95alBsfyPPLnxP/PFL6UvOzpNfLf538vke+7h/wcNfLjjh6/h6dEKQiCwAshgEEQuCUEMAgCt4QABkHglhDAIAjcEgIYBIFbQgCDIHBLCGAQBG4JAQyCwC0hgEEQuCUEMAgCt/w9wmIN7jvyvP4AAAAASUVORK5CYII=" alt="Логотип Вкусно — и точка"><div class="hero-title"><h1>Disk<span>Hunter</span></h1><p class="sub">Найдите, что занимает место на диске. Лишнее — в корзину, и точка.</p></div><span class="hero-spacer" aria-hidden="true"></span></header>

<div class="panel">
  <div class="row"><input type="text" id="path" placeholder="Папка или диск, например C:\ или /home/user" spellcheck="false">
  <button class="btn" id="go">Сканировать</button></div>
  <div class="chips" id="drives"></div>
  <div class="prog" id="prog" hidden><div class="bar"></div><span id="cur"></span></div>
</div>

<div class="stats">
  <div class="stat"><b id="s1">—</b><span>файлов просмотрено</span></div>
  <div class="stat"><b id="s2">—</b><span>объём просмотренного</span></div>
  <div class="stat"><b id="s3">0 Б</b><span>выделено к удалению</span></div>
</div>

<div class="panel"><h3>Самые тяжёлые папки</h3><div id="folders"><div class="empty">Запустите сканирование — здесь появится рейтинг папок</div></div></div>

<div class="panel"><h3>Тяжёлые файлы</h3>
  <div class="filters">
    <label>Размер от</label><input type="number" id="minv" value="100" min="0" style="width:90px">
    <select id="unit"><option value="1048576" selected>МБ</option><option value="1073741824">ГБ</option></select>
    <input type="text" id="q" placeholder="Поиск по имени или пути" style="flex:1;min-width:160px">
    <button class="btn ghost" id="all">Выбрать все в списке</button>
    <button class="btn ghost" id="none">Снять выбор</button>
  </div>
  <div class="tw"><table><thead><tr><th style="width:36px"></th><th data-k="0">Файл</th><th data-k="1">Размер</th><th data-k="2" class="d">Изменён</th></tr></thead>
  <tbody id="tb"></tbody></table><div class="empty" id="emp">Пока пусто</div></div>
  <div class="sub" id="more" style="margin:10px 0 0"></div>
</div></div>

<div class="dock"><div class="in">
  <div class="info"><b id="dc">0 файлов</b> <span id="ds" style="color:var(--mu)"></span></div>
  <label><input type="checkbox" id="trash"> <span id="tl">Удалять в корзину</span></label>
  <button class="btn red" id="del" disabled>Удалить выбранное</button>
</div></div>

<div class="modal" id="md"><div class="box"><h3>Удалить выбранное?</h3><p id="mt"></p>
  <div class="row" style="justify-content:flex-end"><button class="btn ghost" id="no">Отмена</button><button class="btn red" id="yes">Удалить</button></div></div></div>
<div class="toast" id="ts"></div>

<script>
const T="__TOKEN__",$=s=>document.querySelector(s);
const api=(n,d={})=>fetch("/api/"+n,{method:"POST",headers:{"X-Token":T,"Content-Type":"application/json"},body:JSON.stringify(d)}).then(r=>r.json());
const fmt=b=>{const u=["Б","КБ","МБ","ГБ","ТБ"];let i=0;while(b>=1024&&i<4){b/=1024;i++}return (i>1?b.toFixed(2):Math.round(b))+" "+u[i]};
const esc=s=>s.replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
let files=[],view=[],sel=new Set(),sortK=1,sortD=-1,running=false,hasTrash=false,poll;

function toast(m){const t=$("#ts");t.textContent=m;t.style.display="block";clearTimeout(t._h);t._h=setTimeout(()=>t.style.display="none",4500)}

api("roots").then(r=>{
  hasTrash=r.trash;$("#trash").checked=hasTrash;$("#trash").disabled=!hasTrash;
  if(!hasTrash)$("#tl").textContent="Корзина недоступна (pip install send2trash) — удаление будет безвозвратным";
  $("#path").value=r.home;
  const box=$("#drives");
  const mk=(p,name,sub,pct)=>{const b=document.createElement("button");b.className="chip";
    b.innerHTML=`<b>${esc(name)}</b><small>${esc(sub)}</small><s><b style="width:${pct}%"></b></s>`;
    b.onclick=()=>{$("#path").value=p;[...box.children].forEach(c=>c.classList.remove("on"));b.classList.add("on")};box.append(b)};
  mk(r.home,"Домашняя папка",r.home,0);
  r.roots.forEach(d=>mk(d.path,d.path,d.total?fmt(d.used)+" из "+fmt(d.total):"диск",d.total?Math.round(d.used/d.total*100):0));
});

$("#go").onclick=async()=>{
  if(running){await api("stop");return}
  const r=await api("scan",{path:$("#path").value.trim()});
  if(r.error){toast(r.error);return}
  running=true;sel.clear();files=[];render();
  $("#go").textContent="Остановить";$("#prog").hidden=false;
  poll=setInterval(async()=>{
    const s=await api("status");$("#s1").textContent=s.scanned.toLocaleString("ru-RU");$("#cur").textContent=s.cur;
    if(!s.running){clearInterval(poll);running=false;$("#go").textContent="Сканировать";$("#prog").hidden=true;load()}
  },400);
};

async function load(){
  const r=await api("results");files=r.files;
  $("#s1").textContent=r.scanned.toLocaleString("ru-RU");$("#s2").textContent=fmt(r.total);
  const mx=r.folders.length?r.folders[0][1]:1;
  $("#folders").innerHTML=r.folders.length?r.folders.map(([n,s])=>`<div class="fl"><div title="${esc(n)}">${esc(n)}</div><div><i style="width:${Math.max(1,s/mx*100)}%"></i></div><em>${fmt(s)}</em></div>`).join(""):'<div class="empty">Ничего не найдено</div>';
  render();
  toast("Готово: найдено "+files.length+" файлов от 1 МБ");
}

function render(){
  const min=(+$("#minv").value||0)*(+$("#unit").value),q=$("#q").value.toLowerCase();
  view=files.filter(f=>f[1]>=min&&f[0].toLowerCase().includes(q));
  view.sort((a,b)=>sortK==0?a[0].localeCompare(b[0])*sortD*-1:(a[sortK]-b[sortK])*sortD*-1);
  const mx=Math.max(1,...view.slice(0,1000).map(f=>f[1]));
  $("#tb").innerHTML=view.slice(0,1000).map((f,i)=>{
    const p=f[0],k=Math.max(p.lastIndexOf("\\"),p.lastIndexOf("/"));
    return `<tr class="r${sel.has(p)?" on":""}" data-i="${i}"><td><input type="checkbox" ${sel.has(p)?"checked":""}></td>
    <td class="n"><b>${esc(p.slice(k+1))}</b><small title="${esc(p)}">&lrm;${esc(p.slice(0,k))}</small></td>
    <td class="sz" style="--w:${f[1]/mx*100}%">${fmt(f[1])}</td><td class="d">${new Date(f[2]*1000).toLocaleDateString("ru-RU")}</td></tr>`}).join("");
  $("#emp").style.display=view.length?"none":"block";
  $("#emp").textContent=files.length?"Под этот фильтр ничего не подошло":"Пока пусто — запустите сканирование";
  $("#more").textContent=view.length>1000?`Показаны 1000 самых больших из ${view.length}. Поднимите порог размера, чтобы сузить список.`:"";
  upd();
}

function upd(){
  const m=new Map(files.map(f=>[f[0],f[1]]));let s=0;sel.forEach(p=>s+=m.get(p)||0);
  $("#s3").textContent=fmt(s);$("#dc").textContent=sel.size+" файл(ов)";$("#ds").textContent=sel.size?"· "+fmt(s)+" освободится":"· ничего не выбрано";
  $("#del").disabled=!sel.size;
}

$("#tb").onclick=e=>{
  const tr=e.target.closest("tr");if(!tr)return;const p=view[+tr.dataset.i][0];
  sel.has(p)?sel.delete(p):sel.add(p);
  tr.classList.toggle("on",sel.has(p));tr.querySelector("input").checked=sel.has(p);upd();
};
document.querySelectorAll("th[data-k]").forEach(th=>th.onclick=()=>{const k=+th.dataset.k;sortD=sortK==k?-sortD:-1;sortK=k;render()});
["#minv","#unit","#q"].forEach(s=>$(s).oninput=render);
$("#all").onclick=()=>{view.forEach(f=>sel.add(f[0]));render()};
$("#none").onclick=()=>{sel.clear();render()};

$("#del").onclick=()=>{
  const t=$("#trash").checked&&hasTrash;
  $("#mt").innerHTML=`Выбрано файлов: <b>${sel.size}</b>, на <b>${$("#s3").textContent}</b>. `+(t?"Они переедут в корзину.":"Они будут удалены <b>безвозвратно</b>.");
  $("#md").classList.add("on");
};
$("#no").onclick=()=>$("#md").classList.remove("on");
$("#yes").onclick=async()=>{
  $("#md").classList.remove("on");
  const r=await api("delete",{paths:[...sel],trash:$("#trash").checked&&hasTrash});
  const gone=new Set(r.ok);files=files.filter(f=>!gone.has(f[0]));r.ok.forEach(p=>sel.delete(p));
  render();toast(`Удалено: ${r.ok.length}`+(r.fail.length?`, не удалось: ${r.fail.length} (${r.fail[0][1]})`:""));
};
render();
</script></body></html>
"""


def main():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    url = "http://127.0.0.1:%d/" % srv.server_address[1]
    print("DiskHunter запущен:", url, "\nЧтобы выйти — Ctrl+C")
    threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
