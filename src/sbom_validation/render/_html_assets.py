"""Inline CSS and JavaScript for the standalone HTML report."""

CSS = """
:root{color-scheme:light dark;--bg:#fff;--fg:#1b1f24;--muted:#57606a;--line:#d0d7de;
--head:#f6f8fa;--failed:#b42318;--ok:#1a7f37;--warn:#9a6700;--na:#57606a}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9da7b3;
--line:#30363d;--head:#161b22;--failed:#ff7b72;--ok:#56d364;--warn:#e3b341;--na:#9da7b3}}
body{margin:0;padding:16px;background:var(--bg);color:var(--fg);
font:16px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1200px;margin:0 auto}
h1{font-size:1.4rem;margin:0 0 .5rem}
dl.meta{display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem;margin:.5rem 0}
dl.meta dt{color:var(--muted)}dl.meta dd{margin:0;overflow-wrap:anywhere}
.counts{display:flex;flex-wrap:wrap;gap:.5rem;margin:.75rem 0;padding:0;list-style:none}
.counts li{border:1px solid var(--line);border-radius:6px;padding:.3rem .7rem}
.note{border-left:4px solid var(--warn);padding:.3rem .8rem;margin:.75rem 0}
.controls{display:flex;flex-wrap:wrap;gap:.75rem;align-items:center;margin:.75rem 0}
.controls label{display:flex;gap:.4rem;align-items:center}
input,select,button{font:inherit;color:inherit;background:var(--bg);
border:1px solid var(--line);border-radius:4px;padding:.25rem .5rem}
.tablewrap{overflow-x:auto}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid var(--line);padding:.35rem .6rem;text-align:left;vertical-align:top}
th{background:var(--head)}
th button{border:0;background:none;font-weight:600;padding:0;cursor:pointer}
th[aria-sort=ascending] button::after{content:" \\25B2"}
th[aria-sort=descending] button::after{content:" \\25BC"}
td.status{font-weight:600;white-space:nowrap}
tr[data-status=failed] td.status{color:var(--failed)}
tr[data-status=passed] td.status{color:var(--ok)}
tr[data-status=not_verifiable] td.status{color:var(--warn)}
tr[data-status=not_evaluated] td.status{color:var(--na)}
details ul{margin:.3rem 0;padding-left:1.2rem}
code,pre{font-family:ui-monospace,Consolas,monospace}
pre{white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid var(--line);padding:.6rem}
[hidden]{display:none!important}
@media (max-width:600px){body{padding:8px}dl.meta{grid-template-columns:1fr}}
"""

JS = """
(function(){
var tbody=document.querySelector("tbody");
if(!tbody){return;}
var rows=Array.prototype.slice.call(tbody.rows);
var heads=document.querySelectorAll("th[aria-sort]");
var select=document.getElementById("status-filter");
var search=document.getElementById("search");
function key(row,i){
  var c=row.cells[i];
  return c.getAttribute("data-rank")||c.textContent.trim().toLowerCase();
}
function sortBy(i,dir){
  var rank=rows.length>0&&rows[0].cells[i].hasAttribute("data-rank");
  rows.sort(function(a,b){
    var x=key(a,i),y=key(b,i),r;
    if(rank){r=Number(x)-Number(y);}else{r=x<y?-1:(x>y?1:0);}
    return dir==="ascending"?r:-r;
  });
  rows.forEach(function(r){tbody.appendChild(r);});
}
Array.prototype.forEach.call(heads,function(th,i){
  var b=th.querySelector("button");
  if(!b){return;}
  b.addEventListener("click",function(){
    var dir=th.getAttribute("aria-sort")==="ascending"?"descending":"ascending";
    Array.prototype.forEach.call(heads,function(h){h.setAttribute("aria-sort","none");});
    th.setAttribute("aria-sort",dir);
    sortBy(i,dir);
  });
});
function apply(){
  var s=select.value,q=search.value.trim().toLowerCase();
  rows.forEach(function(r){
    var ok=(s==="all"||r.getAttribute("data-status")===s)&&
      (q===""||r.textContent.toLowerCase().indexOf(q)!==-1);
    r.hidden=!ok;
  });
}
select.addEventListener("change",apply);
search.addEventListener("input",apply);
})();
"""
