// AI Security Hot — admin console
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;')
  .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
const fmt = s => (s||'').toString().slice(0,10);

const TOKEN = localStorage.getItem('admin_token');
if (!TOKEN) { location.href = '/login.html'; }

const api = async (path, opts = {}) => {
  const headers = {'Authorization': 'Bearer ' + TOKEN, ...(opts.headers||{})};
  if (opts.body && typeof opts.body !== 'string') { headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(opts.body); }
  const r = await fetch(path, {...opts, headers});
  if (r.status === 401) { localStorage.removeItem('admin_token'); location.href = '/login.html'; }
  if (!r.ok) { const t = await r.text(); throw new Error(r.status + ': ' + t.slice(0,200)); }
  return r.status === 204 ? null : r.json();
};

const PANELS = {
  overview: {title:'总览', render: renderOverview},
  today: {title:'今日爬取', render: renderToday},
  documents: {title:'文档管理', render: renderDocuments},
  events: {title:'事件管理', render: renderEvents},
  taxonomy: {title:'标签管理', render: renderTaxonomy},
  ops: {title:'一键运维', render: renderOps},
};

let currentPanel = 'overview';

async function switchPanel(name) {
  currentPanel = name;
  document.querySelectorAll('.admin-side a[data-panel]').forEach(a => a.classList.toggle('active', a.dataset.panel === name));
  $('panelTitle').textContent = PANELS[name].title;
  await PANELS[name].render();
}

// nav
document.querySelectorAll('.admin-side a[data-panel]').forEach(a => a.onclick = e => { e.preventDefault(); switchPanel(a.dataset.panel); });
$('logoutBtn').onclick = e => { e.preventDefault(); localStorage.removeItem('admin_token'); location.href = '/login.html'; };

// ---------- Overview ----------
async function renderOverview() {
  try {
    const [stats, selfcheck, overview] = await Promise.all([
      api('/stats'), api('/ops/self-check'), api('/api/overview'),
    ]);
    const s = stats;
    $('panel').innerHTML = `
      <div class="kpi-grid">
        <div class="kpi"><div class="n">${fmt(s.documents||0)}</div><div class="l">总文档</div></div>
        <div class="kpi"><div class="n">${fmt(s.events||0)}</div><div class="l">总事件</div></div>
        <div class="kpi"><div class="n">${fmt(s.raw_items_by_stage?.done||0)}</div><div class="l">已采集</div></div>
        <div class="kpi"><div class="n">${fmt((s.endpoints_by_status||{}).active||0)}</div><div class="l">活跃信源</div></div>
        <div class="kpi"><div class="n">${overview.hotspots.length}</div><div class="l">今日热点</div></div>
        <div class="kpi"><div class="n">${(overview.modules||[]).reduce((a,m)=>a+m.items.length,0)}</div><div class="l">今日新增</div></div>
      </div>
      <div style="background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px">
        <h3 style="margin-bottom:10px">系统健康</h3>
        <table class="admin-table">
          <tr><th>检查项</th><th>状态</th></tr>
          <tr><td>stale 信源</td><td>${selfcheck.stale?.length||0}</td></tr>
          <tr><td>degraded 信源</td><td>${selfcheck.degraded?.length||0}</td></tr>
          <tr><td>circuit_open 信源</td><td>${selfcheck.circuit_open?.length||0}</td></tr>
          <tr><td>dedupe 积压</td><td>${selfcheck.event_pipeline?.dedupe_due||0}</td></tr>
          <tr><td>cluster 积压</td><td>${selfcheck.event_pipeline?.cluster_due||0}</td></tr>
        </table>
      </div>
      <div class="ops-result" style="margin-top:14px">${esc(JSON.stringify({documents:s.documents, events:s.events, endpoints:s.endpoints_by_status}, null, 2))}</div>
    `;
  } catch(e) { $('panel').innerHTML = `<div style="color:var(--c1)">加载失败：${esc(e.message)}</div>`; }
}

// ---------- Today ----------
async function renderToday() {
  try {
    const o = await api('/api/overview');
    const html = (o.modules||[]).map(m => `
      <div class="module-section">
        <div class="module-title"><span class="bar"></span>${esc(m.label)}<span class="count">${m.items.length} 条</span></div>
        <table class="admin-table"><tr><th>时间</th><th>标题</th><th>来源</th><th>标签</th></tr>
        ${m.items.map(d => `<tr>
          <td>${esc((d.fetched||'').slice(11,16))}</td>
          <td class="title-cell" title="${esc(d.title)}"><a href="${esc(d.url)}" target="_blank">${esc(d.title)}</a></td>
          <td>${esc(d.source_name||d.source)}</td>
          <td>${(d.tech||[]).map(t=>`<span class="tag-chip">${esc(t)}</span>`).join('')}</td>
        </tr>`).join('')}
        </table>
      </div>`).join('');
    $('panel').innerHTML = html || '<div style="color:var(--dim)">今日暂无数据</div>';
  } catch(e) { $('panel').innerHTML = `<div style="color:var(--c1)">${esc(e.message)}</div>`; }
}

// ---------- Documents ----------
let docPage = 0, docQuery = '';
async function renderDocuments() {
  $('panel').innerHTML = `
    <div class="admin-filters">
      <input id="docSearch" placeholder="搜索标题/来源..." style="width:240px">
      <select id="docSource"><option value="">全部来源</option></select>
      <select id="docStatus"><option value="">全部状态</option>
        <option value="active">active</option><option value="retired">retired</option>
        <option value="superseded">superseded</option><option value="withdrawn">withdrawn</option></select>
      <button class="btn primary" id="docSearchBtn">搜索</button>
      <span class="pagination"><button class="btn" id="docPrev">←</button><span id="docPageInfo"></span><button class="btn" id="docNext">→</button></span>
    </div>
    <table class="admin-table" id="docTable"><tr><th>ID</th><th>标题</th><th>来源</th><th>标签</th><th>状态</th><th>操作</th></tr></table>`;

  // fill source options from /sources
  const srcs = await api('/sources');
  $('docSource').innerHTML = '<option value="">全部来源</option>' + srcs.map(s => `<option value="${esc(s.id)}">${esc(s.id)}</option>`).join('');
  $('docSearchBtn').onclick = () => { docQuery = $('docSearch').value.trim(); docPage = 0; loadDocs(); };
  $('docPrev').onclick = () => { if (docPage>0){docPage--;loadDocs();} };
  $('docNext').onclick = () => { docPage++; loadDocs(); };
  $('docSource').onchange = $('docStatus').onchange = () => { docPage=0; loadDocs(); };
  loadDocs();
}

async function loadDocs() {
  const source = $('docSource').value;
  const status = $('docStatus').value;
  const params = new URLSearchParams({limit:'50', offset:String(docPage*50)});
  if (source) params.set('source_id', source);
  if (status) params.set('record_status', status);
  if (docQuery) params.set('q', docQuery);
  const list = await api('/documents?' + params);
  $('docPageInfo').textContent = `第 ${docPage+1} 页`;
  const docs = Array.isArray(list) ? list : (list.items||[]);
  $('docTable').innerHTML = '<tr><th>ID</th><th>标题</th><th>来源</th><th>标签</th><th>状态</th><th>操作</th></tr>' +
    docs.map(d => `<tr>
      <td>${d.id}</td>
      <td class="title-cell" title="${esc(d.title)}"><a href="${esc(d.url||'#')}" target="_blank">${esc(d.title)}</a></td>
      <td>${esc(d.source_id||d.source||'')}</td>
      <td>${(d.tech_directions||[]).map(t=>`<span class="tag-chip">${esc(t)}</span>`).join('')}</td>
      <td>${esc(d.record_status||'')}</td>
      <td>
        <button class="btn" onclick="editDoc(${d.id})">改标签</button>
        <button class="btn" onclick="requeueDoc(${d.id})">重聚类</button>
        <button class="btn danger" onclick="softDelDoc(${d.id})">软删</button>
        <button class="btn danger" onclick="hardDelDoc(${d.id})">删除</button>
      </td>
    </tr>`).join('') || '<tr><td colspan="6" style="text-align:center;color:var(--dim)">无文档</td></tr>';
}

async function editDoc(id) {
  const doc = (await api(`/documents/${id}`));
  $('modalOverlay').style.display = 'flex';
  $('modalBox').innerHTML = `
    <span class="close" onclick="closeModal()">✕</span>
    <h3>编辑标签 · #${id}</h3>
    <p style="font-size:12px;color:var(--mut);margin-bottom:8px">${esc(doc.title)}</p>
    <label style="font-size:12px">tech_directions（逗号分隔）</label>
    <input id="mdTech" value="${esc((doc.tech_directions||[]).join(','))}">
    <label style="font-size:12px">company_models（逗号分隔）</label>
    <input id="mdCompany" value="${esc((doc.company_models||[]).join(','))}">
    <label style="font-size:12px">event_type</label>
    <input id="mdEtype" value="${esc(doc.classified_event_type||'')}">
    <button class="btn primary" onclick="saveDocTags(${id})">保存</button>`;
}
async function saveDocTags(id) {
  const body = {
    tech_directions: $('mdTech').value.split(',').map(s=>s.trim()).filter(Boolean),
    company_models: $('mdCompany').value.split(',').map(s=>s.trim()).filter(Boolean),
    classified_event_type: $('mdEtype').value.trim() || null,
  };
  try { await api(`/ops/documents/${id}`, {method:'PATCH', body}); closeModal(); loadDocs(); }
  catch(e){ alert(e.message); }
}
async function requeueDoc(id) {
  if (!confirm(`重新聚类文档 #${id}？`)) return;
  try { await api(`/ops/documents/${id}/requeue`, {method:'POST'}); alert('已入队'); }
  catch(e){ alert(e.message); }
}
async function softDelDoc(id) {
  if (!confirm(`软删除文档 #${id}？`)) return;
  try { await api(`/ops/documents/${id}/status`, {method:'PATCH', body:{kind:'source', status:'retired', reason:'admin_soft_delete'}}); loadDocs(); }
  catch(e){ alert(e.message); }
}
async function hardDelDoc(id) {
  if (!confirm(`⚠️ 物理删除文档 #${id}？不可恢复！`)) return;
  try { await api(`/ops/documents/${id}`, {method:'DELETE'}); loadDocs(); }
  catch(e){ alert(e.message); }
}

// ---------- Events ----------
async function renderEvents() {
  $('panel').innerHTML = `
    <table class="admin-table" id="evTable"><tr><th>ID</th><th>标题</th><th>Topic</th><th>Score</th><th>状态</th><th>操作</th></tr></table>`;
  const list = await api('/events?limit=100');
  const evs = Array.isArray(list) ? list : (list.items||[]);
  $('evTable').innerHTML = '<tr><th>ID</th><th>标题</th><th>Topic</th><th>Score</th><th>状态</th><th>操作</th></tr>' +
    evs.map(e => `<tr>
      <td>${e.id}</td>
      <td class="title-cell" title="${esc(e.title)}">${esc(e.title)}</td>
      <td>${esc(e.topic||'')}</td>
      <td>${e.score??''}</td>
      <td>${esc(e.status||'')}</td>
      <td>
        <button class="btn" onclick="viewEvent(${e.id})">查看</button>
        <button class="btn" onclick="softDelEvent(${e.id})">软删</button>
        <button class="btn danger" onclick="hardDelEvent(${e.id})">删除</button>
      </td>
    </tr>`).join('');
}
async function viewEvent(id) {
  const e = await api(`/events/${id}`);
  $('modalOverlay').style.display = 'flex';
  $('modalBox').innerHTML = `<span class="close" onclick="closeModal()">✕</span>
    <h3>${esc(e.title)}</h3>
    <p style="font-size:12px;color:var(--mut)">topic=${esc(e.topic||'-')} · category=${esc(e.category||'-')} · score=${e.score}</p>
    <p style="margin:10px 0">${esc((e.summary||'').slice(0,300))}</p>
    ${(e.evidence||[]).map(d=>`<div style="font-size:12px;color:var(--mut);padding:2px 0">· ${esc(d.url||'')} <span style="color:var(--acc)">${esc(d.relation_reason||'')}</span></div>`).join('')}`;
}
async function softDelEvent(id) {
  if (!confirm(`软删除事件 #${id}？`)) return;
  try { await api(`/ops/events/${id}/status`, {method:'PATCH', body:{status:'superseded'}}); renderEvents(); }
  catch(e){ alert(e.message); }
}
async function hardDelEvent(id) {
  if (!confirm(`⚠️ 物理删除事件 #${id}？不可恢复！`)) return;
  try { await api(`/ops/events/${id}`, {method:'DELETE'}); renderEvents(); }
  catch(e){ alert(e.message); }
}

// ---------- Taxonomy ----------
async function renderTaxonomy() {
  const tax = await api('/ops/taxonomy');
  $('panel').innerHTML = `
    <div class="kpi-grid">
      <div class="kpi"><div class="n">${Object.keys(tax.tech_directions||{}).length}</div><div class="l">技术方向</div></div>
      <div class="kpi"><div class="n">${Object.keys(tax.company_models||{}).length}</div><div class="l">公司/模型</div></div>
    </div>
    <div class="admin-filters">
      <select id="txBucket"><option value="tech_directions">tech_directions</option><option value="company_models">company_models</option></select>
      <input id="txTag" placeholder="标签名，如 agent">
      <input id="txKeyword" placeholder="新增关键词，如 tool calling">
      <button class="btn primary" onclick="addTaxTag()">添加关键词</button>
    </div>
    <div id="taxList"></div>`;
  renderTaxList();
}
function renderTaxList() {
  api('/ops/taxonomy').then(tax => {
    const bucket = $('txBucket').value;
    const data = bucket === 'tech_directions' ? tax.tech_directions : tax.company_models;
    $('taxList').innerHTML = Object.entries(data||{}).map(([tag, kws]) => `
      <div style="background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 16px;margin-bottom:8px">
        <b style="font-size:13px">${esc(tag)}</b>
        <div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:4px">
          ${(kws||[]).map(k=>`<span class="tag-chip x" onclick="delTaxTag('${bucket}','${esc(tag)}','${esc(k)}')">${esc(k)} ✕</span>`).join('')}
        </div>
      </div>`).join('') || '<div style="color:var(--dim)">无标签</div>';
  });
}
$('txBucket') && ($('txBucket').onchange = renderTaxList);
async function addTaxTag() {
  const bucket = $('txBucket').value, tag = $('txTag').value.trim(), kw = $('txKeyword').value.trim();
  if (!tag || !kw) { alert('标签名和关键词必填'); return; }
  try { await api('/ops/taxonomy/tags', {method:'POST', body:{bucket, tag, keyword: kw}}); $('txKeyword').value=''; renderTaxList(); }
  catch(e){ alert(e.message); }
}
async function delTaxTag(bucket, tag, kw) {
  try { await api('/ops/taxonomy/tags', {method:'DELETE', body:{bucket, tag, keyword: kw}}); renderTaxList(); }
  catch(e){ alert(e.message); }
}

// ---------- Ops ----------
async function renderOps() {
  $('panel').innerHTML = `
    <div style="background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin-bottom:16px">
      <h3 style="margin-bottom:12px">流水线运维</h3>
      <button class="ops-btn" onclick="runOps('classify')">一键分类</button>
      <button class="ops-btn" onclick="runOps('cluster')">一键聚类+去重</button>
    </div>
    <div class="ops-result" id="opsResult">点击按钮执行流水线操作</div>`;
}
async function runOps(kind) {
  $('opsResult').textContent = '执行中...';
  try {
    const r = await api('/ops/' + kind, {method:'POST'});
    $('opsResult').textContent = JSON.stringify(r, null, 2);
  } catch(e) { $('opsResult').textContent = '错误：' + e.message; }
}

function closeModal() { $('modalOverlay').style.display = 'none'; }
$('modalOverlay').onclick = e => { if (e.target === $('modalOverlay')) closeModal(); };

switchPanel('overview');
