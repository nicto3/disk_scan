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
:root{--bg:#f5f1e8;--p:#fffdf8;--p2:#fff;--ln:#e8dfd0;--g:#174b38;--g2:#287b58;--tx:#20342c;--mu:#78847a;--rd:#d94035;--orange:#f27a24;--cream:#fff8e8;--shadow:0 10px 30px #4733180b}
*{box-sizing:border-box}
body{margin:0;color:var(--tx);font:14px/1.5 "Segoe UI",system-ui,sans-serif;padding-bottom:110px;background:radial-gradient(700px 360px at 88% -12%,#f6d9b844 0,transparent 70%),var(--bg);min-height:100vh}
.wrap{position:relative;max-width:1120px;margin:0 auto;padding:34px 24px}
.hero{margin:0 0 24px}.brandline{display:flex;align-items:center;gap:10px}.brandmark{display:grid;place-items:center;width:38px;height:38px;border-radius:50%;background:var(--g);color:#fff;font-size:21px;font-weight:800;box-shadow:inset 0 0 0 3px #fff3}.brandname{font-size:17px;font-weight:800;letter-spacing:-.3px;color:var(--g)}.brandname i{font-style:normal;color:var(--orange)}.tag{margin-left:4px;border-radius:999px;background:#f8e5d3;color:#914514;padding:5px 10px;font-size:11px;font-weight:700;letter-spacing:.02em}
.sub{color:var(--mu);margin:8px 0 0;font-size:14px}
.panel{background:var(--p);border:1px solid var(--ln);border-radius:18px;padding:20px;margin-bottom:16px;box-shadow:var(--shadow)}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
input[type=text],input[type=number],select{background:#fff;border:1px solid var(--ln);color:var(--tx);border-radius:11px;padding:11px 13px;font:inherit;outline:none;transition:border-color .15s,box-shadow .15s}
input:focus,select:focus,button:focus-visible{border-color:var(--orange);box-shadow:0 0 0 3px #f27a2420}
#path{flex:1;min-width:240px}
.btn{background:var(--orange);color:#fff;border:0;border-radius:11px;padding:11px 18px;font:700 14px inherit;font-family:inherit;cursor:pointer;transition:transform .12s,box-shadow .12s,background .12s;box-shadow:0 4px 12px #f27a2433}
.btn:hover{background:#df6818;box-shadow:0 7px 18px #f27a2444;transform:translateY(-1px)}
.btn.ghost{background:#fff;color:var(--g);border:1px solid #cfded2;box-shadow:none}.btn.ghost:hover{background:#f1f7f1;border-color:var(--g2)}
.btn.red{background:var(--rd);color:#fff;box-shadow:0 4px 12px #d940352c}.btn.red:hover{background:#bf302a}.btn:disabled{opacity:.42;pointer-events:none;box-shadow:none}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}
.chip{background:var(--cream);border:1px solid #efe3ce;border-radius:12px;padding:9px 12px;cursor:pointer;min-width:110px;color:var(--tx);font:inherit;text-align:left;transition:border-color .15s,transform .15s}.chip:hover,.chip.on{border-color:var(--orange);transform:translateY(-1px)}
.chip small{display:block;color:var(--mu);font-size:11px}.chip s{display:block;height:4px;border-radius:2px;background:#eadfce;margin-top:6px;overflow:hidden;text-decoration:none}.chip s b{display:block;height:100%;background:var(--orange)}
.prog{margin-top:16px}.prog .bar{height:7px;border-radius:8px;background:linear-gradient(90deg,var(--orange),#f5b23b,var(--g2));background-size:180% 100%;animation:mv 1.2s linear infinite}@keyframes mv{to{background-position:180% 0}}@media(prefers-reduced-motion:reduce){.prog .bar{animation:none}}
.prog span{display:block;color:var(--mu);font-size:12px;margin-top:7px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:16px}.stat{background:var(--p);border:1px solid var(--ln);border-radius:18px;padding:17px 20px;box-shadow:var(--shadow)}.stat b{display:block;font:700 28px/1.2 "Segoe UI",system-ui,sans-serif;color:var(--g);letter-spacing:-.7px}.stat span{color:var(--mu);font-size:12px}
h3{margin:0 0 14px;font-weight:750;font-size:16px;color:var(--g);letter-spacing:-.2px}
.fl{display:grid;grid-template-columns:minmax(120px,220px) 1fr 90px;gap:12px;align-items:center;margin:9px 0;font-size:13px}.fl div:nth-child(2){height:9px;border-radius:8px;background:#f0eadf;overflow:hidden}.fl i{display:block;height:100%;border-radius:8px;background:linear-gradient(90deg,var(--orange),#f4b149);box-shadow:none}.fl em{font-style:normal;text-align:right;color:var(--mu);font-variant-numeric:tabular-nums}.fl div:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.filters{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:13px}.filters label{color:var(--mu)}
.tw{max-height:560px;overflow:auto;border:1px solid var(--ln);border-radius:12px;background:#fff}
table{width:100%;border-collapse:collapse}th{position:sticky;top:0;background:#f7f2e8;text-align:left;padding:11px 12px;font-weight:700;color:var(--g);cursor:pointer;user-select:none;z-index:1}td{padding:9px 12px;border-top:1px solid #f0eadf;vertical-align:middle}tr.r{cursor:pointer}tr.r:hover td{background:#fff9ef}tr.on td{background:#fff0dc}td.sz{width:210px;font-variant-numeric:tabular-nums;white-space:nowrap;background:linear-gradient(90deg,#f5b24733 var(--w),transparent var(--w))}td.n{max-width:0;width:100%}td.n b{display:block;font-weight:650;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}td.n small{display:block;color:var(--mu);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:rtl;text-align:left}td.d{color:var(--mu);white-space:nowrap}input[type=checkbox]{accent-color:var(--g2);width:16px;height:16px}
.empty{padding:36px;text-align:center;color:var(--mu)}
.dock{position:fixed;left:0;right:0;bottom:0;z-index:5;background:#fffdf8ed;backdrop-filter:blur(12px);border-top:1px solid var(--ln);box-shadow:0 -8px 28px #47331810}.dock .in{max-width:1120px;margin:0 auto;padding:14px 24px;display:flex;gap:16px;align-items:center;flex-wrap:wrap}.dock .info{flex:1;min-width:200px}.dock .info b{color:var(--g);font-size:18px}.dock label{color:var(--mu)}
.modal{position:fixed;inset:0;background:#1b2a22a8;backdrop-filter:blur(3px);display:none;place-items:center;z-index:9;padding:16px}.modal.on{display:grid}.box{background:var(--p);border:1px solid var(--ln);border-radius:20px;padding:24px;max-width:440px;width:100%;box-shadow:0 24px 80px #16261c30}.box h3{font-size:20px;margin-bottom:8px}.box p{color:var(--mu);margin:0 0 18px}.box p b{color:var(--tx)}
.toast{position:fixed;top:16px;right:16px;background:var(--g);color:#fff;border:1px solid #ffffff33;border-radius:12px;padding:12px 16px;z-index:10;max-width:360px;display:none;box-shadow:0 10px 28px #174b3833}
@media(max-width:700px){.wrap{padding:24px 14px}.tag{display:none}.stats{grid-template-columns:1fr}.stat{padding:14px 16px}.dock .in{padding:12px 14px;gap:12px}td.d,th.d{display:none}td.sz{width:120px}.fl{grid-template-columns:100px 1fr 70px}.panel{padding:16px;border-radius:15px}}
</style></head><body><div class="wrap">
<header class="hero"><div class="brandline"><span class="brandmark">•</span><span class="brandname">Disk<i>Hunter</i></span><span class="tag">и точка</span></div><p class="sub">Найдите, что занимает место на диске. Лишнее — в корзину, и точка.</p></header>

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
