// AI Security Hot — public frontend
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;')
  .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');

const TECH_LABELS = {
  llm:'大模型', ai_for_security:'AI 用于安全', security_for_ai:'AI 自身安全',
  agent:'智能体', system_security:'系统安全',
};

let DATA = null;
let activeFilter = 'all'; // module id or 'all'

async function load() {
  try {
    const r = await fetch('/api/overview');
    if (!r.ok) throw new Error('HTTP ' + r.status);
    DATA = await r.json();
    render();
  } catch (e) {
    $('hotList').innerHTML = `<div style="color:var(--c1);padding:24px">加载失败：${esc(e.message)}</div>`;
  }
}

function render() {
  $('dateLabel').textContent = ` · ${DATA.date.replace('2026-','')} ${DATA.weekday}`;
  $('hotCount').textContent = `${DATA.hotspots.length} 条`;
  renderHot();
  renderTabs();
  renderModules();
  $('footer').textContent = `${DATA.generated_at.replace('T',' ').slice(0,16)} UTC · AI Security Hot`;
}

function renderHot() {
  $('hotList').innerHTML = (DATA.hotspots || []).map((e, i) => {
    const sc = e.score ?? 0;
    const cls = sc >= 70 ? 's70' : '';
    const rank = `r${Math.min(i+1,3)}`;
    const src = (e.source_count||0) >= 2
      ? `<span class="src-badge multi">${e.source_count} 源印证</span>`
      : `<span class="src-badge">${e.source_count||1} 源</span>`;
    return `<div class="hot-item">
      <div class="hot-rank ${rank}">${String(i+1).padStart(2,'0')}</div>
      <div class="hot-body">
        <div class="hot-title-text">${esc(e.title)}</div>
        ${e.summary ? `<div class="hot-summary">${esc(e.summary)}</div>` : ''}
        <div class="hot-meta">
          <span class="hot-score ${cls}">${sc} 热度</span>
          ${src}
          ${e.topic ? `<span class="topic-tag">${esc(TECH_LABELS[e.topic]||e.topic)}</span>` : ''}
        </div>
      </div>
    </div>`;
  }).join('') || '<div style="color:var(--dim);padding:24px">今日暂无热点</div>';
}

function renderTabs() {
  const tabs = [{id:'all',label:'全部'}, ...(DATA.modules||[]).map(m => ({id:m.id, label:m.label}))];
  $('catTabs').innerHTML = tabs.map(t =>
    `<div class="cat-tab${t.id===activeFilter?' active':''}" data-filter="${t.id}">${esc(t.label)}</div>`
  ).join('');
  $('catTabs').querySelectorAll('.cat-tab').forEach(el => {
    el.onclick = () => {
      activeFilter = el.dataset.filter;
      document.querySelectorAll('.cat-tab').forEach(x => x.classList.toggle('active', x === el));
      document.querySelectorAll('.nav a').forEach(a => a.classList.toggle('active', a.dataset.filter === activeFilter));
      renderModules();
    };
  });
}

function techTags(arr) {
  return (arr || []).filter(x => x !== 'cve').map(x =>
    `<span class="tag ${x}">${esc(TECH_LABELS[x]||x)}</span>`).join('');
}
function multiSources(url) {
  const srcs = (DATA.url_sources||{})[url] || [];
  if (srcs.length <= 1) return '';
  const names = srcs.map(s => esc(DATA.labels.source[s]||s)).join('、');
  return `<div class="tl-multi">另有 ${srcs.length-1} 家信源报道：${names}</div>`;
}
function moduleItem(d) {
  return `<div class="tl-item">
    <div class="tl-time">${esc((d.fetched||'').substring(11,16))}</div>
    <div class="tl-body">
      <div class="tl-meta">
        <span class="tl-source">${esc(d.source_name || DATA.labels.source[d.source] || d.source)}</span>
      </div>
      <div class="tl-title"><a href="${esc(d.url)}" target="_blank" rel="noopener">${esc(d.title)}</a></div>
      ${d.summary ? `<div class="tl-summary">${esc(d.summary)}</div>` : ''}
      ${multiSources(d.url)}
      ${d.tech && d.tech.length ? `<div class="tl-tags">${techTags(d.tech)}</div>` : ''}
    </div>
  </div>`;
}

function renderModules() {
  const mods = (DATA.modules || []).filter(m => activeFilter === 'all' || m.id === activeFilter);
  $('modules').innerHTML = mods.map(m => `
    <div class="module-section" data-module="${esc(m.id)}">
      <div class="module-title"><span class="bar"></span>${esc(m.label)}
        <span class="count">${m.items.length} 条</span><span class="chevron">▼</span></div>
      <div class="module-scroll">${m.items.map(moduleItem).join('') || '<div style="color:var(--dim);padding:16px">暂无内容</div>'}</div>
    </div>`).join('') || '<div style="color:var(--dim);padding:24px">暂无内容</div>';

  // collapse toggle
  document.querySelectorAll('.module-section .module-title').forEach(t => {
    t.onclick = () => t.parentElement.classList.toggle('collapsed');
  });
}

// nav links (mobile)
document.querySelectorAll('.nav a').forEach(a => {
  a.onclick = () => {
    activeFilter = a.dataset.filter;
    document.querySelectorAll('.nav a').forEach(x => x.classList.toggle('active', x === a));
    renderTabs();
    renderModules();
  };
});

load();
