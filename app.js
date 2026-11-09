/* ============================================================
   防火墙复习要塞 · 应用逻辑
   三模式：背诵 / 做题 / 知识库；双题库：提纲 / 实验
   ============================================================ */
'use strict';

/* ---------- 常量 ---------- */
const TYPES = ['choice', 'fill', 'term', 'judge', 'short', 'comp'];
const TYPE_META = {
  choice: { name: '选择', full: '单项选择题', color: '#16293f' },
  fill:   { name: '填空', full: '填空题', color: '#b45309' },
  term:   { name: '名词', full: '名词解释', color: '#0f766e' },
  judge:  { name: '判断', full: '判别是非题', color: '#9a3412' },
  short:  { name: '简答', full: '简答题', color: '#86198f' },
  comp:   { name: '综合', full: '综合问答题', color: '#4338ca' },
};
const BANK_NAME = { outline: '提纲', experiment: '实验' };
const CHAPTER_ORDER = {
  outline: ['第一章 防火墙概述', '第二章 防火墙体系结构', '第三章 软件防火墙', '第四章 硬件防火墙', '第五章 防火墙配置', '第六章 VPN原理与技术'],
  experiment: ['实验一', '实验二', '实验三', '实验四', '实验五'],
};
const LS_MASTERY = 'fw_mastery_v1';
const LS_HISTORY = 'fw_quiz_history_v1';
const LS_AUTH = 'fw_auth_v1';
const VAULT_URL = 'data/vault.enc';
const DOCS_URL = 'data/docs.enc';
const KDF_ITER = 250000;
const VAULT_MARKER = 'FW-VAULT-V2';
const DOCS_MARKER = 'FW-DOCS-V1';
const MAMMOTH_URL = 'js/vendor/mammoth.browser.min.js';

/* ---------- 状态 ---------- */
const state = {
  mode: 'recite',
  data: null,
  recite: { bank: 'all', types: { choice: true, fill: true, term: true, judge: true, short: true, comp: true }, chapter: 'all', mastery: 'all', search: '', hide: false, limit: 40 },
  quizSetup: { bank: 'all', types: { choice: true, fill: true, term: true, judge: true, short: true, comp: true }, chapter: 'all', count: 20, shuffle: true },
  quiz: null,
  kb: { bank: 'outline', search: '', view: 'kb' },
  docs: { loaded: false, loading: false, site: [], mine: [], urls: {} },
  images: {},
  password: null,
};

/* ---------- 小工具 ---------- */
const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function norm(s) {
  return String(s == null ? '' : s).toLowerCase()
    .replace(/[\s\u3000]/g, '')
    .replace(/[，。、；;：:，,\.!！?？（）()《》<>\[\]【】{}"'"“”‘’·\-—_~～*＃#+]/g, '');
}
function store(key, val) {
  try { localStorage.setItem(key, JSON.stringify(val)); } catch (e) { /* 忽略 */ }
}
function load(key, fallback) {
  try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; } catch (e) { return fallback; }
}
let mastery = load(LS_MASTERY, {});

function banksOf(bank) { return bank === 'all' ? ['outline', 'experiment'] : [bank]; }
function bankLabel(bank) { return bank === 'all' ? '双库' : BANK_NAME[bank]; }

/* ---------- 数据加载（AES-256-CBC 加密库） ---------- */
async function decryptEnc(url, marker, password) {
  const res = await fetch(url, { cache: 'no-cache' });
  if (!res.ok) throw new Error('vault-missing');
  const buf = new Uint8Array(await res.arrayBuffer());
  /* openssl enc 格式："Salted__" + 8字节盐 + 密文 */
  if (buf.length < 33 || String.fromCharCode.apply(null, buf.slice(0, 8)) !== 'Salted__') throw new Error('vault-format');
  const salt = buf.slice(8, 16);
  const ct = buf.slice(16);
  /* PBKDF2-HMAC-SHA256 派生 48 字节：前32字节 = AES-256 密钥，后16字节 = CBC IV */
  const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: KDF_ITER }, baseKey, 384);
  const key = await crypto.subtle.importKey('raw', bits.slice(0, 32), { name: 'AES-CBC' }, false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: bits.slice(32, 48) }, key, ct);
  const obj = JSON.parse(new TextDecoder().decode(pt));
  if (!obj || obj.marker !== marker) throw new Error('bad-password');
  return obj;
}
function fetchVault(password) {
  return decryptEnc(VAULT_URL, VAULT_MARKER, password);
}
function fetchDocsVault(password) {
  return decryptEnc(DOCS_URL, DOCS_MARKER, password);
}
function distributeVault(vault) {
  const files = vault.files || {};
  ['outline', 'experiment'].forEach(bank => {
    TYPES.forEach(t => {
      const raw = files[bank + '-' + t];
      const qs = ((raw && raw.questions) || []).map(q => Object.assign({}, q, { bank, type: t, uid: bank + '-' + (q.id || Math.random().toString(36).slice(2)) }));
      state.data[bank][t] = qs;
    });
    state.data[bank].kb = files[bank + '-kb'] || { sections: [] };
  });
  /* 知识库图片 → data URI */
  state.images = {};
  const imgs = vault.images || {};
  Object.keys(imgs).forEach(k => {
    state.images[k] = 'data:' + imgs[k].mime + ';base64,' + imgs[k].b64;
  });
}

/* ---------- 题目池 ---------- */
function poolFor(bank, types, chapter) {
  let qs = [];
  banksOf(bank).forEach(b => {
    TYPES.forEach(t => { if (types[t]) qs = qs.concat(state.data[b][t]); });
  });
  if (chapter && chapter !== 'all') qs = qs.filter(q => q.chapter === chapter);
  return qs;
}
function chaptersOf(bank) {
  const set = new Set();
  banksOf(bank).forEach(b => TYPES.forEach(t => state.data[b][t].forEach(q => set.add(q.chapter))));
  const order = banksOf(bank).flatMap(b => CHAPTER_ORDER[b] || []);
  const known = order.filter(c => set.has(c));
  set.forEach(c => { if (!known.includes(c)) known.push(c); });
  return known;
}
function refAnswerText(q) {
  if (q.type === 'choice') {
    const letter = 'ABCDEFGH'[q.answer] || '?';
    return letter + '．' + (q.options ? q.options[q.answer] : '');
  }
  if (q.type === 'fill') {
    const arr = q.answers || [];
    if (arr.length > 1) return arr.map((b, i) => '［' + (i + 1) + '］' + (b[0] || '')).join('　');
    return arr.length && arr[0].length ? arr[0][0] : '';
  }
  if (q.type === 'judge') {
    return q.answer ? '√ 正确' : '× 错误';
  }
  return q.answer || '';
}
function questionDisplayText(q) {
  return q.type === 'term' ? '请解释术语：「' + q.question + '」' : q.question;
}

/* ---------- 判分 ---------- */
function gradeFill(q, values) {
  const blanks = q.answers || [];
  const perBlank = blanks.map((variants, i) => {
    const v = norm(values[i]);
    if (!v) return false;
    const vs = (variants || []).map(norm).filter(Boolean);
    return vs.some(ans => v === ans || v.includes(ans));
  });
  return { ok: blanks.length > 0 && perBlank.every(Boolean), perBlank };
}
function gradeKeywords(q, text) {
  const a = norm(text);
  const matched = [], missed = [];
  (q.keywords || []).forEach(k => { (a.includes(norm(k)) ? matched : missed).push(k); });
  const total = (q.keywords || []).length;
  const ratio = total ? matched.length / total : (a ? 1 : 0);
  return { matched, missed, ratio, empty: !a };
}

/* ============================================================
   模式切换
   ============================================================ */
function setMode(mode) {
  state.mode = mode;
  ['recite', 'quiz', 'kb'].forEach(m => {
    $('#view-' + m).hidden = m !== mode;
  });
  $$('#modeTabs .mode-tab').forEach(b => b.classList.toggle('is-active', b.dataset.mode === mode));
  $$('#bottomNav .bn-item').forEach(b => b.classList.toggle('is-active', b.dataset.mode === mode));
  if (mode === 'recite') renderRecite();
  if (mode === 'quiz') renderQuiz();
  if (mode === 'kb') renderKB();
  window.scrollTo({ top: 0 });
}

/* ============================================================
   背诵模式
   ============================================================ */
function recitePool() {
  let qs = poolFor(state.recite.bank, state.recite.types, state.recite.chapter);
  const m = state.recite.mastery;
  if (m === 'none') qs = qs.filter(q => !mastery[q.uid]);
  else if (m === 'review') qs = qs.filter(q => mastery[q.uid] === 'review');
  else if (m === 'known') qs = qs.filter(q => mastery[q.uid] === 'known');
  const s = state.recite.search.trim().toLowerCase();
  if (s) {
    qs = qs.filter(q => {
      const hay = (q.question + ' ' + refAnswerText(q) + ' ' + (q.explanation || '') + ' ' + (q.options || []).join(' ')).toLowerCase();
      return hay.includes(s);
    });
  }
  return qs;
}
function blankify(text) {
  return escapeHtml(text).replace(/_{4,}/g, '<span class="blank">＿＿＿＿</span>');
}
function reciteCardHTML(q, i) {
  const tm = TYPE_META[q.type];
  const mast = mastery[q.uid];
  const answerHTML =
    q.type === 'fill' ? escapeHtml(refAnswerText(q)) :
    q.type === 'choice' ? escapeHtml(refAnswerText(q)) :
    q.type === 'judge' ? (q.answer ? '√ 正确' : '× 错误') :
    escapeHtml(q.answer || '');
  return (
    '<article class="qa-card" style="--tc:' + tm.color + ';--i:' + Math.min(i, 14) + '" data-uid="' + q.uid + '">' +
      '<div class="qa-tags">' +
        '<span class="tag t-type">' + tm.full + '</span>' +
        '<span class="tag t-chap">' + escapeHtml(q.chapter || '') + '</span>' +
        '<span class="tag t-bank">' + BANK_NAME[q.bank] + '</span>' +
        (mast === 'known' ? '<span class="tag t-mast m-known">✓ 已掌握</span>' : '') +
        (mast === 'review' ? '<span class="tag t-mast m-review">↻ 需复习</span>' : '') +
      '</div>' +
      '<div class="qa-q"><span class="qmark">' + (q.type === 'term' ? '术语' : 'Q') + '</span>' + blankify(questionDisplayText(q)) + '</div>' +
      '<div class="qa-a' + (state.recite.hide ? ' is-hidden' : '') + '">' +
        '<span class="amark">A · 参考答案</span>' +
        '<div class="a-body">' + answerHTML + '</div>' +
      '</div>' +
      (q.explanation ? '<div class="qa-exp"><b>析</b> ' + escapeHtml(q.explanation) + '</div>' : '') +
      '<div class="qa-actions">' +
        '<button class="mini-btn m-know' + (mast === 'known' ? ' is-know' : '') + '" data-act="know" type="button">✓ 已掌握</button>' +
        '<button class="mini-btn m-rev' + (mast === 'review' ? ' is-rev' : '') + '" data-act="rev" type="button">↻ 需复习</button>' +
      '</div>' +
    '</article>'
  );
}
function renderRecite() {
  const qs = recitePool();
  const list = $('#reciteList');
  const shown = qs.slice(0, state.recite.limit);
  list.innerHTML = shown.map((q, i) => reciteCardHTML(q, i)).join('') ||
    '<div class="kb-empty">没有符合条件的题目，试试调整筛选～</div>';
  const known = qs.filter(q => mastery[q.uid] === 'known').length;
  $('#reciteCount').innerHTML = '共 <b>' + qs.length + '</b> 题' + (known ? ' · 已掌握 <b>' + known + '</b>' : '');
  $('#reciteMore').hidden = qs.length <= state.recite.limit;

  /* 卡片交互 */
  $$('.qa-card', list).forEach(card => {
    const uid = card.dataset.uid;
    const q = findQ(uid);
    const ansBox = $('.qa-a', card);
    if (ansBox && state.recite.hide) {
      ansBox.addEventListener('click', () => ansBox.classList.remove('is-hidden'));
    }
    $$('.mini-btn', card).forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const act = btn.dataset.act;
        const cur = mastery[uid];
        if (act === 'know') mastery[uid] = cur === 'known' ? undefined : 'known';
        if (act === 'rev') mastery[uid] = cur === 'review' ? undefined : 'review';
        if (!mastery[uid]) delete mastery[uid];
        store(LS_MASTERY, mastery);
        renderRecite();
      });
    });
  });
}
function findQ(uid) {
  for (const b of ['outline', 'experiment']) {
    for (const t of TYPES) {
      const hit = state.data[b][t].find(q => q.uid === uid);
      if (hit) return hit;
    }
  }
  return null;
}
function buildChapterSelect(sel, bank, current) {
  const chapters = chaptersOf(bank);
  sel.innerHTML = '<option value="all">全部章节</option>' +
    chapters.map(c => '<option value="' + escapeHtml(c) + '">' + escapeHtml(c) + '</option>').join('');
  sel.value = chapters.includes(current) || current === 'all' ? current : 'all';
}

/* ============================================================
   做题模式
   ============================================================ */
function renderQuiz() {
  if (!state.quiz) renderQuizSetup();
  else if (state.quiz.done) renderQuizSummary();
  else renderQuizQuestion();
}

/* ----- 设置页 ----- */
function renderQuizSetup() {
  const s = state.quizSetup;
  const stage = $('#quizStage');
  const avail = poolFor(s.bank, s.types, s.chapter).length;
  const history = load(LS_HISTORY, []);
  stage.innerHTML =
    '<div class="quiz-setup">' +
      '<div class="setup-title">做题模式 · 自测演练</div>' +
      '<div class="setup-sub">做完一题点击「下一题」，系统自动判分；名词解释、简答与综合问答按关键词命中判定，可自行改判。</div>' +
      '<div class="setup-block">' +
        '<div class="setup-label">题库范围</div>' +
        '<div class="segmented" id="qBank">' +
          ['outline', 'experiment', 'all'].map(b =>
            '<button type="button" data-bank="' + b + '"' + (s.bank === b ? ' class="is-active"' : '') + '>' +
            (b === 'all' ? '双库混做' : BANK_NAME[b]) + '</button>').join('') +
        '</div>' +
      '</div>' +
      '<div class="setup-block">' +
        '<div class="setup-label">题型（可多选）</div>' +
        '<div class="chip-group" id="qTypes">' +
          TYPES.map(t => '<button type="button" class="chip' + (s.types[t] ? ' is-on' : '') + '" data-type="' + t + '">' + TYPE_META[t].full + '</button>').join('') +
        '</div>' +
      '</div>' +
      '<div class="setup-block">' +
        '<div class="setup-label">章节范围</div>' +
        '<div class="select-wrap" style="max-width:340px"><select id="qChapter"></select></div>' +
      '</div>' +
      '<div class="setup-block">' +
        '<div class="setup-label">题量与顺序</div>' +
        '<div class="row">' +
          '<div class="select-wrap"><select id="qCount">' +
            [10, 20, 30, 50, 0].map(n =>
              '<option value="' + n + '"' + (s.count === n ? ' selected' : '') + '>' + (n === 0 ? '全部题目' : n + ' 题') + '</option>').join('') +
          '</select></div>' +
          '<div class="segmented" id="qOrder">' +
            '<button type="button" data-shuffle="1"' + (s.shuffle ? ' class="is-active"' : '') + '>随机顺序</button>' +
            '<button type="button" data-shuffle="0"' + (!s.shuffle ? ' class="is-active"' : '') + '>按章节顺序</button>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div class="setup-foot">' +
        '<span class="avail-note">当前条件可用 <b>' + avail + '</b> 题</span>' +
        '<button class="primary-btn" id="qStart" type="button"' + (avail ? '' : ' disabled') + '>开始演练 →</button>' +
      '</div>' +
      (history.length
        ? '<div class="history-box"><h4>最近战绩</h4>' +
            history.slice(0, 3).map(h =>
              '<div class="his-row"><span class="his-date">' + new Date(h.t).toLocaleDateString('zh-CN') + ' ' + h.label + '</span>' +
              '<span class="his-score"><b>' + h.good + '</b>/' + h.total + ' 正确' + (h.partial ? ' · ' + h.partial + ' 部分' : '') + '</span></div>').join('') +
          '</div>'
        : '') +
    '</div>';

  buildChapterSelect($('#qChapter'), s.bank, s.chapter);

  const refresh = () => {
    const n = poolFor(s.bank, s.types, s.chapter).length;
    $('.avail-note b', stage).textContent = n;
    $('#qStart').disabled = !n;
  };
  $$('#qBank button', stage).forEach(b => b.addEventListener('click', () => {
    s.bank = b.dataset.bank;
    $$('#qBank button', stage).forEach(x => x.classList.toggle('is-active', x === b));
    buildChapterSelect($('#qChapter'), s.bank, s.chapter);
    refresh();
  }));
  $$('#qTypes .chip', stage).forEach(c => c.addEventListener('click', () => {
    s.types[c.dataset.type] = !s.types[c.dataset.type];
    c.classList.toggle('is-on');
    refresh();
  }));
  $('#qChapter').addEventListener('change', e => { s.chapter = e.target.value; refresh(); });
  $('#qCount').addEventListener('change', e => { s.count = +e.target.value; });
  $$('#qOrder button', stage).forEach(b => b.addEventListener('click', () => {
    s.shuffle = b.dataset.shuffle === '1';
    $$('#qOrder button', stage).forEach(x => x.classList.toggle('is-active', x === b));
  }));
  $('#qStart').addEventListener('click', () => startQuiz());
}

function startQuiz(questions) {
  const s = state.quizSetup;
  let list = questions || poolFor(s.bank, s.types, s.chapter);
  if (!questions) {
    list = list.slice();
    if (s.shuffle) shuffle(list);
    if (s.count > 0) list = list.slice(0, s.count);
  }
  if (!list.length) return;
  state.quiz = { list, idx: 0, results: [], startedAt: Date.now(), answered: false, grade: null, done: false, saved: false };
  renderQuizQuestion();
}
function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
}

/* ----- 答题页 ----- */
function renderQuizQuestion() {
  const quiz = state.quiz;
  const q = quiz.list[quiz.idx];
  const tm = TYPE_META[q.type];
  const stage = $('#quizStage');
  const total = quiz.list.length;

  let bodyHTML = '';
  if (q.type === 'choice') {
    bodyHTML = '<div class="opt-list">' +
      (q.options || []).map((o, i) =>
        '<button type="button" class="opt" data-i="' + i + '"><span class="opt-letter">' + 'ABCDEFGH'[i] + '</span><span>' + escapeHtml(o) + '</span></button>'
      ).join('') + '</div>';
  } else if (q.type === 'judge') {
    bodyHTML = '<div class="opt-list judge-list">' +
      '<button type="button" class="opt judge-opt j-yes" data-i="0"><span class="opt-letter">✓</span><span>正确</span></button>' +
      '<button type="button" class="opt judge-opt j-no" data-i="1"><span class="opt-letter">✗</span><span>错误</span></button>' +
      '</div><div class="judge-hint">判断上面的陈述是否正确</div>';
  } else if (q.type === 'fill') {
    /* 题干在上文已用＿＿＿＿标出空位，此处只渲染逐空输入框 */
    bodyHTML = '<div class="fill-inputs">' + buildFillFlow(q) + '</div>';
  } else {
    bodyHTML = '<textarea class="ans-textarea" id="ansText" placeholder="' +
      (q.type === 'term' ? '默写该术语的定义…' :
       q.type === 'comp' ? '综合题：分点作答，尽量覆盖各关键要点，可用 ①②③…' :
       '分点默写答案要点，可用 ①②③…') + '"></textarea>';
  }

  stage.innerHTML =
    '<div class="quiz-live">' +
      '<div class="quiz-topbar">' +
        '<span class="quiz-progress-num"><b>' + (quiz.idx + 1) + '</b> / ' + total + '</span>' +
        '<div class="quiz-bar"><i style="width:' + (quiz.idx / total * 100) + '%"></i></div>' +
        '<button class="quit-btn" id="qQuit" type="button">退出</button>' +
      '</div>' +
      '<div class="quiz-card" id="quizCard" style="--tc:' + tm.color + '">' +
        '<div class="quiz-meta">' +
          '<span class="tag t-type">' + tm.full + '</span>' +
          '<span class="tag t-chap">' + escapeHtml(q.chapter || '') + '</span>' +
          '<span class="tag t-bank">' + BANK_NAME[q.bank] + '</span>' +
        '</div>' +
        '<div class="quiz-q">' + (q.type === 'fill' ? escapeHtml(String(q.question).replace(/_{4,}/g, '＿＿＿＿')) : blankify(questionDisplayText(q))) + '</div>' +
        bodyHTML +
        '<div class="quiz-actions">' +
          '<span class="hint-keys">' +
            (q.type === 'choice' ? '快捷键：1-4 选选项 · Enter 提交/下一题' :
             q.type === 'judge' ? '快捷键：1 选正确 · 2 选错误 · Enter 提交/下一题' :
             '快捷键：Enter 提交/下一题') + '</span>' +
          '<div style="display:flex;gap:10px;align-items:center">' +
            '<button class="skip-btn" id="qSkip" type="button">跳过</button>' +
            '<button class="primary-btn" id="qSubmit" type="button">提 交</button>' +
          '</div>' +
        '</div>' +
        '<div id="fbSlot"></div>' +
      '</div>' +
    '</div>';

  $('#qQuit').addEventListener('click', () => {
    if (confirm('确定退出本次练习？当前进度将不保存。')) { state.quiz = null; renderQuizSetup(); }
  });
  $('#qSkip').addEventListener('click', () => { if (!quiz.answered) submitAnswer(true); });
  $('#qSubmit').addEventListener('click', () => {
    if (!quiz.answered) submitAnswer(false);
    else nextQuestion();
  });

  if (q.type === 'choice' || q.type === 'judge') {
    $$('.opt', stage).forEach(btn => btn.addEventListener('click', () => {
      if (quiz.answered) return;
      $$('.opt', stage).forEach(x => x.classList.remove('is-picked'));
      btn.classList.add('is-picked');
      quiz.picked = +btn.dataset.i;
    }));
  }
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function buildFillFlow(q) {
  const n = (q.answers || []).length;
  let html = '';
  for (let i = 0; i < n; i++) {
    html += '<input class="fill-in" data-i="' + i + '" type="text" placeholder="第 ' + (i + 1) + ' 空答案…" autocomplete="off">';
  }
  html += '<div class="fill-hint">提示：写出原文关键术语即可，多余文字不影响判定</div>';
  return html;
}

/* ----- 判分与反馈 ----- */
function submitAnswer(skipped) {
  const quiz = state.quiz;
  const q = quiz.list[quiz.idx];
  let verdict, grade = null, picked = null, values = null, text = null;

  if (q.type === 'choice') {
    picked = quiz.picked;
    if (skipped || picked == null) verdict = 'bad';
    else verdict = picked === q.answer ? 'good' : 'bad';
  } else if (q.type === 'judge') {
    /* picked: 0=正确 1=错误；q.answer: true/false */
    picked = quiz.picked;
    if (skipped || picked == null) verdict = 'bad';
    else verdict = picked === (q.answer ? 0 : 1) ? 'good' : 'bad';
  } else if (q.type === 'fill') {
    values = $$('#quizCard .fill-in').map(inp => inp.value);
    if (skipped || values.every(v => !v.trim())) verdict = 'bad';
    else { grade = gradeFill(q, values); verdict = grade.ok ? 'good' : 'bad'; }
  } else {
    text = skipped ? '' : ($('#ansText') ? $('#ansText').value : '');
    grade = gradeKeywords(q, text);
    if (grade.empty) verdict = 'bad';
    else if (grade.ratio >= 0.6) verdict = 'good';
    else if (grade.ratio >= 0.3) verdict = 'partial';
    else verdict = 'bad';
  }

  const result = { uid: q.uid, type: q.type, verdict };
  quiz.results.push(result);
  quiz.answered = true;
  quiz.grade = { verdict, grade, picked, values, text, skipped };

  /* 锁定输入 */
  $('#quizCard').classList.add('locked');
  if (q.type === 'judge') {
    const rightIdx = q.answer ? 0 : 1;
    $$('#quizCard .judge-opt').forEach((btn, i) => {
      if (i === rightIdx) btn.classList.add('is-right');
      else if (i === picked) btn.classList.add('is-wrong');
    });
  } else {
    $$('.opt', $('#quizCard')).forEach((btn, i) => {
      if (i === q.answer) btn.classList.add('is-right');
      else if (i === picked) btn.classList.add('is-wrong');
    });
  }
  $$('#quizCard .fill-in').forEach((inp, i) => {
    if (grade && grade.perBlank && grade.perBlank[i]) inp.classList.add('ok');
    else inp.classList.add('no');
  });

  showFeedback(q, result);
  const last = quiz.idx === quiz.list.length - 1;
  $('#qSubmit').textContent = last ? '查看结果 →' : '下一题 →';
  $('#qSkip').style.display = 'none';
}

function showFeedback(q, result) {
  const quiz = state.quiz;
  const info = quiz.grade;
  let head = '', body = '';

  if (result.verdict === 'good') head = '<div class="fb-head"><span class="fb-ico">✓</span>回答正确，继续保持！</div>';
  else if (result.verdict === 'partial') head = '<div class="fb-head"><span class="fb-ico">△</span>部分正确 · 命中了部分关键点</div>';
  else if (info.skipped) head = '<div class="fb-head"><span class="fb-ico">○</span>已跳过 · 请记住参考答案</div>';
  else head = '<div class="fb-head"><span class="fb-ico">✗</span>回答错误 · 对照参考答案记忆</div>';

  body += '<div class="ref-block"><div class="ref-label">参考答案</div><div class="ref-content">' +
    (q.type === 'fill'
      ? escapeHtml((q.answers || []).map(b => b[0]).join('　；　'))
      : escapeHtml(refAnswerText(q))) + '</div></div>';

  if ((q.type === 'term' || q.type === 'short' || q.type === 'comp') && info.grade && !info.skipped) {
    const g = info.grade;
    body += '<div><div class="ref-label" style="font-family:var(--font-mono);font-size:11.5px;letter-spacing:.18em;color:var(--teal);margin-bottom:5px">关键词命中 ' +
      g.matched.length + '/' + (g.matched.length + g.missed.length) + '</div><div class="kw-chips">' +
      g.matched.map(k => '<span class="kw-chip hit">' + escapeHtml(k) + '</span>').join('') +
      g.missed.map(k => '<span class="kw-chip miss">' + escapeHtml(k) + '</span>').join('') +
      '</div></div>';
  }
  if (q.explanation) {
    body += '<div class="qa-exp" style="margin-top:0"><b>解析</b> ' + escapeHtml(q.explanation) + '</div>';
  }
  if (q.type === 'term' || q.type === 'short' || q.type === 'comp' || q.type === 'fill') {
    body += '<div class="override-row">觉得判得不准？' +
      '<button class="mini-btn ov-yes" id="ovYes" type="button">✓ 算我对</button>' +
      '<button class="mini-btn ov-no" id="ovNo" type="button">✗ 算我错</button></div>';
  }

  const cls = result.verdict === 'good' ? 'fb-good' : result.verdict === 'partial' ? 'fb-warn' : 'fb-bad';
  const fb = document.createElement('div');
  fb.className = 'feedback ' + cls;
  fb.id = 'fbPanel';
  fb.innerHTML = head + '<div class="fb-body">' + body + '</div>';
  $('#fbSlot').appendChild(fb);

  const ovYes = $('#ovYes'), ovNo = $('#ovNo');
  if (ovYes) ovYes.addEventListener('click', () => overrideVerdict(result, 'good'));
  if (ovNo) ovNo.addEventListener('click', () => overrideVerdict(result, 'bad'));
  fb.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
function overrideVerdict(result, verdict) {
  result.verdict = verdict;
  const fb = $('#fbPanel');
  fb.className = 'feedback ' + (verdict === 'good' ? 'fb-good' : 'fb-bad');
  $('.fb-head', fb).innerHTML = '<span class="fb-ico">' + (verdict === 'good' ? '✓' : '✗') + '</span>' +
    (verdict === 'good' ? '已改判为正确' : '已改判为错误');
  const row = $('.override-row', fb);
  if (row) row.innerHTML = '<span>已按你的自评记录。</span>';
}

function nextQuestion() {
  const quiz = state.quiz;
  quiz.idx++;
  quiz.answered = false;
  quiz.picked = null;
  quiz.grade = null;
  if (quiz.idx >= quiz.list.length) {
    quiz.done = true;
    renderQuizSummary();
  } else {
    renderQuizQuestion();
  }
}

/* ----- 结果页 ----- */
function renderQuizSummary() {
  const quiz = state.quiz;
  const total = quiz.results.length;
  const good = quiz.results.filter(r => r.verdict === 'good').length;
  const partial = quiz.results.filter(r => r.verdict === 'partial').length;
  const bad = total - good - partial;
  const pct = total ? Math.round(good / total * 100) : 0;
  const mins = Math.max(1, Math.round((Date.now() - quiz.startedAt) / 60000));

  if (!quiz.saved) {
    quiz.saved = true;
    const s = state.quizSetup;
    const history = load(LS_HISTORY, []);
    history.unshift({ t: Date.now(), label: bankLabel(s.bank) + (s.chapter !== 'all' ? ' · ' + s.chapter : ''), total, good, partial });
    store(LS_HISTORY, history.slice(0, 10));
  }

  const typeRows = TYPES.filter(t => quiz.results.some(r => r.type === t)).map(t => {
    const rs = quiz.results.filter(r => r.type === t);
    const g = rs.filter(r => r.verdict === 'good').length;
    const w = rs.length ? Math.round(g / rs.length * 100) : 0;
    return '<div class="qr-type-row"><span class="tn">' + TYPE_META[t].full + '</span>' +
      '<div class="tb"><i style="width:' + w + '%"></i></div>' +
      '<span class="tv">' + g + ' / ' + rs.length + '</span></div>';
  }).join('');

  const wrongs = quiz.results.filter(r => r.verdict !== 'good').map(r => {
    const q = findQ(r.uid);
    if (!q) return '';
    return '<div class="wrong-item"><div class="wq">[' + TYPE_META[q.type].full + '] ' + escapeHtml(questionDisplayText(q)) + '</div>' +
      '<div class="wa">正确答案：<b>' + escapeHtml(refAnswerText(q).length > 120 ? refAnswerText(q).slice(0, 120) + '…' : refAnswerText(q)) + '</b></div></div>';
  }).join('');

  const C = 2 * Math.PI * 65;
  $('#quizStage').innerHTML =
    '<div class="quiz-result">' +
      '<div class="qr-head"><h2>演练完成</h2></div>' +
      '<div class="ring-wrap"><div class="ring">' +
        '<svg width="158" height="158" viewBox="0 0 158 158">' +
          '<circle class="ring-bg" cx="79" cy="79" r="65"></circle>' +
          '<circle class="ring-fg" cx="79" cy="79" r="65" stroke-dasharray="' + C + '" stroke-dashoffset="' + (C * (1 - (total ? good / total : 0))) + '"></circle>' +
        '</svg>' +
        '<div class="ring-txt"><span class="ring-num">' + pct + '%</span><span class="ring-cap">正确率</span></div>' +
      '</div></div>' +
      '<div class="qr-stats">' +
        '<div class="qr-stat s-total"><b>' + total + '</b><span>总题数</span></div>' +
        '<div class="qr-stat s-good"><b>' + good + '</b><span>正确</span></div>' +
        '<div class="qr-stat s-part"><b>' + partial + '</b><span>部分正确</span></div>' +
        '<div class="qr-stat s-bad"><b>' + bad + '</b><span>错误</span></div>' +
      '</div>' +
      '<div style="text-align:center" class="avail-note">用时约 <b>' + mins + '</b> 分钟</div>' +
      '<div class="qr-type-table">' + typeRows + '</div>' +
      (wrongs ? '<div class="wrong-box"><h4>✗ 错题回顾（' + (total - good) + '）</h4>' + wrongs + '</div>' :
        '<div class="wrong-box"><h4 style="color:var(--good)">✓ 全部正确，干得漂亮！</h4></div>') +
      '<div class="qr-actions">' +
        (bad + partial > 0 ? '<button class="primary-btn" id="rWrong" type="button">只练错题（' + (bad + partial) + '）</button>' : '') +
        '<button class="ghost-btn" id="rAgain" type="button">↻ 再来一轮</button>' +
        '<button class="ghost-btn" id="rSetup" type="button">调整设置</button>' +
      '</div>' +
    '</div>';

  const rWrong = $('#rWrong');
  if (rWrong) rWrong.addEventListener('click', () => {
    const wrongQs = quiz.results.filter(r => r.verdict !== 'good').map(r => findQ(r.uid)).filter(Boolean);
    shuffle(wrongQs);
    startQuiz(wrongQs);
  });
  $('#rAgain').addEventListener('click', () => startQuiz());
  $('#rSetup').addEventListener('click', () => { state.quiz = null; renderQuizSetup(); });
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* ============================================================
   知识库
   ============================================================ */
function mdLite(src) {
  let s = escapeHtml(src || '');
  const fences = [];
  s = s.replace(/```([\s\S]*?)```/g, (m, code) => {
    fences.push('<pre><code>' + code.replace(/^\n+|\n+$/g, '') + '</code></pre>');
    return '\u0000F' + (fences.length - 1) + '\u0000';
  });
  /* 图片（加密库内嵌）：![](img:key) + 可选 *图注* */
  const figs = [];
  s = s.replace(/!\[\]\(img:([a-zA-Z0-9_]+)\)(?:\n+\*([^*\n]+)\*)?/g, (m, key, cap) => {
    const uri = (state.images && state.images[key]) || '';
    figs.push('<figure class="kb-fig">' +
      '<img class="kb-img" src="' + uri + '" alt="' + (cap || '') + '" data-key="' + key + '" loading="lazy">' +
      (cap ? '<figcaption>' + cap + '</figcaption>' : '') +
      '</figure>');
    return '\u0000G' + (figs.length - 1) + '\u0000';
  });
  s = s.replace(/`([^`\n]+)`/g, '<code>$1</code>');
  s = s.replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>');

  const lines = s.split('\n');
  let html = '', inList = false, para = [];
  const flushPara = () => { if (para.length) { html += '<p>' + para.join('<br>') + '</p>'; para = []; } };
  const closeList = () => { if (inList) { html += '</ul>'; inList = false; } };
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) { flushPara(); closeList(); continue; }
    const fm = line.match(/^\u0000F(\d+)\u0000$/);
    if (fm) { flushPara(); closeList(); html += fences[+fm[1]]; continue; }
    const gm = line.match(/^\u0000G(\d+)\u0000$/);
    if (gm) { flushPara(); closeList(); html += figs[+gm[1]]; continue; }
    const li = line.match(/^[-•]\s+(.*)$/);
    if (li) { flushPara(); if (!inList) { html += '<ul>'; inList = true; } html += '<li>' + li[1] + '</li>'; continue; }
    closeList();
    para.push(line);
  }
  flushPara(); closeList();
  html = html.replace(/\u0000F(\d+)\u0000/g, (m, i) => fences[+i] || '');
  html = html.replace(/\u0000G(\d+)\u0000/g, (m, i) => figs[+i] || '');
  return html;
}
function highlight(text, query) {
  if (!query) return text;
  const re = new RegExp('(' + query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi');
  /* 只在标签外的文本片段中高亮，避免破坏HTML结构 */
  return text.replace(/(<[^>]+>)|([^<]+)/g, (m, tag, txt) => {
    if (tag) return tag;
    return txt.replace(re, '<mark>$1</mark>');
  });
}
function renderKB() {
  /* 子页签：原文知识库 / 文档中心 */
  const isDocs = state.kb.view === 'docs';
  $$('#kbSubtabs button').forEach(b => b.classList.toggle('is-active', b.dataset.view === state.kb.view));
  $('#kbControls').hidden = isDocs;
  $('#kbStage').hidden = isDocs;
  $('#docsStage').hidden = !isDocs;
  if (isDocs) { renderDocs(); return; }
  const bank = state.kb.bank;
  const query = state.kb.search.trim();
  const stage = $('#kbStage');
  const banks = banksOf(bank);
  let secIdx = 0, blockTotal = 0;
  let html = '';

  banks.forEach(b => {
    const kb = state.data[b].kb;
    if (!kb || !kb.sections) return;
    kb.sections.forEach(sec => {
      const blocks = (sec.blocks || []).filter(bl => {
        if (!query) return true;
        return ((bl.subtitle || '') + ' ' + (bl.content || '')).toLowerCase().includes(query.toLowerCase());
      });
      if (!blocks.length) return;
      blockTotal += blocks.length;
      secIdx++;
      html +=
        '<div class="kb-sec' + (query ? ' open' : '') + '">' +
          '<button class="kb-sec-head" type="button">' +
            '<span class="kb-sec-idx">' + String(secIdx).padStart(2, '0') + '</span>' +
            '<span class="kb-sec-title">' + escapeHtml(sec.title) + '</span>' +
            '<span class="kb-sec-cnt">' + blocks.length + ' 节</span>' +
            '<span class="kb-chev"></span>' +
          '</button>' +
          '<div class="kb-sec-body">' +
            blocks.map(bl =>
              '<div class="kb-block">' +
                '<div class="kb-block-title">' + escapeHtml(bl.subtitle || '') + '</div>' +
                '<div class="kb-content">' + (query ? highlight(mdLite(bl.content || ''), query) : mdLite(bl.content || '')) + '</div>' +
              '</div>'
            ).join('') +
          '</div>' +
        '</div>';
    });
  });

  stage.innerHTML = html || '<div class="kb-empty">' + (query ? '没有匹配「' + escapeHtml(query) + '」的原文内容' : '知识库为空') + '</div>';
  $('#kbCount').textContent = query ? '命中 ' + blockTotal + ' 节' : '共 ' + secIdx + ' 章 · ' + blockTotal + ' 节';

  $$('.kb-sec-head', stage).forEach(head => {
    head.addEventListener('click', () => head.parentElement.classList.toggle('open'));
  });
}

/* ============================================================
   文档中心（站点加密文档 + 本机上传文档）
   ============================================================ */
function fmtSize(n) {
  if (n >= 1048576) return (n / 1048576).toFixed(1) + ' MB';
  if (n >= 1024) return Math.round(n / 1024) + ' KB';
  return n + ' B';
}
function extOf(name) {
  const m = String(name || '').toLowerCase().match(/\.([a-z0-9]+)$/);
  return m ? m[1] : '';
}
function mimeFromName(name) {
  return { pdf: 'application/pdf',
    docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    doc: 'application/msword',
    xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp' }[extOf(name)] || 'application/octet-stream';
}
/* ---------- IndexedDB（我的上传，仅本机浏览器） ---------- */
function idb() {
  return new Promise((res, rej) => {
    const rq = indexedDB.open('fw_docs_v1', 1);
    rq.onupgradeneeded = () => { rq.result.createObjectStore('docs', { keyPath: 'id' }); };
    rq.onsuccess = () => res(rq.result);
    rq.onerror = () => rej(rq.error || new Error('idb-open-failed'));
  });
}
async function idbAll() {
  try {
    const db = await idb();
    return await new Promise((res, rej) => {
      const rq = db.transaction('docs').objectStore('docs').getAll();
      rq.onsuccess = () => res(rq.result || []);
      rq.onerror = () => rej(rq.error);
    });
  } catch (e) { return []; }
}
async function idbPut(rec) {
  const db = await idb();
  return new Promise((res, rej) => {
    const rq = db.transaction('docs', 'readwrite').objectStore('docs').put(rec);
    rq.onsuccess = res; rq.onerror = () => rej(rq.error);
  });
}
async function idbDel(id) {
  const db = await idb();
  return new Promise((res, rej) => {
    const rq = db.transaction('docs', 'readwrite').objectStore('docs').delete(id);
    rq.onsuccess = res; rq.onerror = () => rej(rq.error);
  });
}
/* ---------- 文档 blob URL 管理 ---------- */
function b64ToBlob(b64, mime) {
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return new Blob([u8], { type: mime });
}
function docUrl(d, src) {
  if (state.docs.urls[d.id]) return Promise.resolve(state.docs.urls[d.id]);
  return new Promise((res) => {
    if (src === 'mine' && d.blob) {
      const u = URL.createObjectURL(d.blob);
      state.docs.urls[d.id] = u; res(u);
    } else if (d.b64) {
      const u = URL.createObjectURL(b64ToBlob(d.b64, d.mime || mimeFromName(d.name)));
      state.docs.urls[d.id] = u; res(u);
    } else res('');
  });
}
/* ---------- 渲染 ---------- */
function docCardHTML(d, src) {
  const ext = d.ext || extOf(d.name);
  const icoMap = { pdf: ['pdf', 'PDF'], docx: ['doc', 'DOC'], doc: ['doc', 'DOC'], xlsx: ['xls', 'XLS'], pptx: ['ppt', 'PPT'] };
  const ico = icoMap[ext] || ['file', (ext || 'FILE').toUpperCase().slice(0, 4)];
  const date = d.added ? new Date(d.added).toLocaleDateString('zh-CN') : '';
  const meta = fmtSize(d.size) + (date ? ' · ' + date : '') + (d.desc ? ' · ' + escapeHtml(d.desc) : '');
  return '<div class="doc-card" data-id="' + d.id + '" data-src="' + src + '">' +
    '<div class="doc-ico ' + ico[0] + '">' + ico[1] + '</div>' +
    '<div class="doc-info"><div class="doc-name">' + escapeHtml(d.name) + '</div>' +
    '<div class="doc-meta">' + meta + '</div></div>' +
    '<div class="doc-acts">' +
      '<button class="mini-btn" data-act="preview" type="button">👁 预览</button>' +
      '<button class="mini-btn" data-act="download" type="button">⬇ 下载</button>' +
      (src === 'mine' ? '<button class="mini-btn doc-del" data-act="delete" type="button">🗑</button>' : '') +
    '</div></div>';
}
async function renderDocs() {
  const list = $('#docList');
  if (!state.docs.loaded) {
    if (state.docs.loading) return;
    state.docs.loading = true;
    list.innerHTML = '<div class="docs-loading"><span class="spin"></span> 正在解密文档库…（约 10MB，首次稍慢）</div>';
    try {
      const dv = await fetchDocsVault(state.password);
      state.docs.site = dv.files || [];
      state.docs.loaded = true;
      state.docs.loading = false;
    } catch (e) {
      state.docs.loading = false;
      const why = e.message === 'vault-missing' ? 'docs.enc 文件不存在' : e.message === 'vault-format' ? '文档库格式异常' : '解密失败';
      list.innerHTML = '<div class="docs-empty">⚠ 文档库加载失败：' + why + '<br><br><button class="ghost-btn" id="docsRetry" type="button">重新加载</button></div>';
      const rb = $('#docsRetry'); if (rb) rb.addEventListener('click', renderDocs);
      return;
    }
  }
  state.docs.mine = await idbAll();
  const siteHTML = state.docs.site.map(d => docCardHTML(d, 'site')).join('');
  const mineHTML = state.docs.mine.map(d => docCardHTML(d, 'mine')).join('');
  list.innerHTML =
    '<section class="doc-group"><h3 class="dg-title">📚 站点文档<span class="dg-cnt">' + state.docs.site.length + '</span></h3>' +
      (siteHTML || '<div class="docs-empty">暂无</div>') + '</section>' +
    '<section class="doc-group"><h3 class="dg-title">📎 我的上传<span class="dg-cnt">' + state.docs.mine.length + '</span><span class="dg-note">存于本机浏览器</span></h3>' +
      (mineHTML || '<div class="docs-empty">还没有上传文档——把老师补充的资料拖到上方虚线框即可</div>') + '</section>';
}
async function saveFiles(fileList) {
  const files = Array.from(fileList || []);
  if (!files.length) return;
  for (const f of files) {
    const rec = {
      id: 'u' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      name: f.name, mime: f.type || mimeFromName(f.name), size: f.size,
      added: Date.now(), blob: f,
    };
    try { await idbPut(rec); } catch (e) { alert('保存失败：' + f.name); }
  }
  renderDocs();
}
async function downloadDoc(d, src) {
  const url = await docUrl(d, src);
  if (!url) return;
  const a = document.createElement('a');
  a.href = url; a.download = d.name;
  document.body.appendChild(a); a.click(); a.remove();
}
/* ---------- mammoth（DOCX 预览）懒加载 ---------- */
function loadMammoth() {
  if (window.mammoth) return Promise.resolve(window.mammoth);
  return new Promise((res, rej) => {
    const s = document.createElement('script');
    s.src = MAMMOTH_URL;
    s.onload = () => window.mammoth ? res(window.mammoth) : rej(new Error('加载异常'));
    s.onerror = () => rej(new Error('mammoth 脚本加载失败'));
    document.head.appendChild(s);
  });
}
/* ---------- 预览弹层 ---------- */
async function openPreview(d, src) {
  const modal = $('#pvModal');
  $('#pvName').textContent = d.name;
  $('#pvBody').innerHTML = '<div class="docs-loading"><span class="spin"></span> 准备预览…</div>';
  modal.hidden = false;
  document.body.classList.add('no-scroll');
  const url = await docUrl(d, src);
  const newBtn = $('#pvNew');
  newBtn.onclick = () => { if (url) window.open(url, '_blank'); };
  const ext = d.ext || extOf(d.name);
  if (!url) {
    $('#pvBody').innerHTML = '<div class="docs-empty">无法读取该文档</div>';
    return;
  }
  if (ext === 'pdf') {
    $('#pvBody').innerHTML = '<iframe class="pv-frame" src="' + url + '" title="PDF 预览"></iframe>';
  } else if (ext === 'docx') {
    try {
      const m = await loadMammoth();
      const ab = await (await fetch(url)).arrayBuffer();
      const r = await m.convertToHtml({ arrayBuffer: ab });
      $('#pvBody').innerHTML = '<div class="docx-view">' + r.value + '</div>';
    } catch (e) {
      $('#pvBody').innerHTML = '<div class="docs-empty">DOCX 预览失败（' + e.message + '），请下载后查看</div>';
    }
  } else if (/^image\//.test(d.mime || mimeFromName(d.name))) {
    $('#pvBody').innerHTML = '<img class="pv-img" src="' + url + '" alt="">';
  } else {
    $('#pvBody').innerHTML = '<div class="docs-empty">该类型（' + escapeHtml(ext || '未知') + '）暂不支持在线预览<br><br>' +
      '<button class="primary-btn" id="pvDl" type="button">⬇ 下载文件</button></div>';
    const b = $('#pvDl'); if (b) b.addEventListener('click', () => downloadDoc(d, src));
  }
}
function closePreview() {
  $('#pvModal').hidden = true;
  $('#pvBody').innerHTML = '';
  document.body.classList.remove('no-scroll');
}
/* ---------- 知识库图片灯箱 ---------- */
function openLightbox(src) {
  $('#lbImg').src = src;
  $('#lightbox').hidden = false;
  document.body.classList.add('no-scroll');
}
function closeLightbox() {
  $('#lightbox').hidden = true;
  $('#lbImg').src = '';
  document.body.classList.remove('no-scroll');
}

/* ============================================================
   事件绑定与启动
   ============================================================ */
function bindStatic() {
  $$('#modeTabs .mode-tab').forEach(b => b.addEventListener('click', () => setMode(b.dataset.mode)));
  $$('#bottomNav .bn-item').forEach(b => b.addEventListener('click', () => setMode(b.dataset.mode)));

  /* 密码锁定 */
  $('#lockForm').addEventListener('submit', e => {
    e.preventDefault();
    const v = $('#lockInput').value;
    if (!v) { $('#lockInput').focus(); return; }
    attemptUnlock(v);
  });
  $('#lockBtn').addEventListener('click', () => {
    if (confirm('锁定网站？锁定后需重新输入密码才能继续使用。')) {
      try { localStorage.removeItem(LS_AUTH); } catch (e) { /* 忽略 */ }
      location.reload();
    }
  });

  /* 知识库子页签 */
  $$('#kbSubtabs button').forEach(b => b.addEventListener('click', () => {
    state.kb.view = b.dataset.view;
    renderKB();
  }));

  /* 知识库图片 → 灯箱 */
  $('#kbStage').addEventListener('click', e => {
    const img = e.target.closest('img.kb-img');
    if (img && img.src) openLightbox(img.src);
  });
  $('#lightbox').addEventListener('click', closeLightbox);

  /* 文档中心：上传区 */
  const zone = $('#uploadZone'), fileInput = $('#fileInput');
  if (zone && fileInput) {
    zone.addEventListener('click', e => {
      if (e.target === fileInput) return; /* 防止程序化click冒泡造成循环 */
      fileInput.click();
    });
    fileInput.addEventListener('change', async () => { await saveFiles(fileInput.files); fileInput.value = ''; });
    ['dragover', 'dragenter'].forEach(ev => zone.addEventListener(ev, e => { e.preventDefault(); zone.classList.add('is-over'); }));
    zone.addEventListener('dragleave', e => { e.preventDefault(); zone.classList.remove('is-over'); });
    zone.addEventListener('drop', async e => {
      e.preventDefault();
      zone.classList.remove('is-over');
      if (e.dataTransfer && e.dataTransfer.files.length) await saveFiles(e.dataTransfer.files);
    });
  }

  /* 文档卡片操作（事件委托） */
  $('#docList').addEventListener('click', async e => {
    const btn = e.target.closest('[data-act]');
    if (!btn) return;
    const card = btn.closest('.doc-card');
    if (!card) return;
    const id = card.dataset.id, src = card.dataset.src;
    const d = (src === 'site' ? state.docs.site : state.docs.mine).find(x => x.id === id);
    if (!d) return;
    const act = btn.dataset.act;
    if (act === 'preview') openPreview(d, src);
    else if (act === 'download') downloadDoc(d, src);
    else if (act === 'delete') {
      if (confirm('删除「' + d.name + '」？')) {
        try { await idbDel(id); } catch (err) { /* 忽略 */ }
        if (state.docs.urls[id]) { URL.revokeObjectURL(state.docs.urls[id]); delete state.docs.urls[id]; }
        renderDocs();
      }
    }
  });

  /* 预览弹层关闭 */
  $('#pvClose').addEventListener('click', closePreview);
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      if (!$('#lightbox').hidden) closeLightbox();
      else if (!$('#pvModal').hidden) closePreview();
    }
  });

  /* 背诵模式控件 */
  $$('#reciteBank button').forEach(b => b.addEventListener('click', () => {
    state.recite.bank = b.dataset.bank;
    $$('#reciteBank button').forEach(x => x.classList.toggle('is-active', x === b));
    buildChapterSelect($('#reciteChapter'), state.recite.bank, state.recite.chapter);
    state.recite.limit = 40;
    renderRecite();
  }));
  $$('#reciteTypes .chip').forEach(c => c.addEventListener('click', () => {
    state.recite.types[c.dataset.type] = !state.recite.types[c.dataset.type];
    c.classList.toggle('is-on');
    state.recite.limit = 40;
    renderRecite();
  }));
  $('#reciteChapter').addEventListener('change', e => { state.recite.chapter = e.target.value; state.recite.limit = 40; renderRecite(); });
  $('#reciteMastery').addEventListener('change', e => { state.recite.mastery = e.target.value; state.recite.limit = 40; renderRecite(); });
  $('#reciteSearch').addEventListener('input', e => { state.recite.search = e.target.value; state.recite.limit = 40; renderRecite(); });
  $('#reciteHideToggle').addEventListener('click', () => {
    state.recite.hide = !state.recite.hide;
    const btn = $('#reciteHideToggle');
    btn.setAttribute('aria-pressed', state.recite.hide);
    $('.gh-txt', btn).textContent = state.recite.hide ? '显示答案' : '遮挡答案';
    renderRecite();
  });
  $('#reciteMore').addEventListener('click', () => { state.recite.limit += 40; renderRecite(); });

  /* 知识库控件 */
  $$('#kbBank button').forEach(b => b.addEventListener('click', () => {
    state.kb.bank = b.dataset.bank;
    $$('#kbBank button').forEach(x => x.classList.toggle('is-active', x === b));
    renderKB();
  }));
  $('#kbSearch').addEventListener('input', e => { state.kb.search = e.target.value; renderKB(); });

  /* 键盘快捷键 */
  document.addEventListener('keydown', e => {
    if (state.mode !== 'quiz' || !state.quiz || state.quiz.done) return;
    const tag = (e.target.tagName || '').toUpperCase();
    if (tag === 'TEXTAREA' || tag === 'SELECT') return;
    if (tag === 'INPUT' && !e.target.classList.contains('fill-in')) return;
    const q = state.quiz.list[state.quiz.idx];
    if (!q) return;
    if (!state.quiz.answered) {
      if (q.type === 'choice' && /^[1-4]$/.test(e.key)) {
        const idx = +e.key - 1;
        const btn = $$('#quizCard .opt')[idx];
        if (btn) btn.click();
      } else if (q.type === 'judge' && /^[12]$/.test(e.key)) {
        const idx = +e.key - 1;
        const btn = $$('#quizCard .judge-opt')[idx];
        if (btn) btn.click();
      } else if (e.key === 'Enter') {
        e.preventDefault();
        submitAnswer(false);
      }
    } else if (e.key === 'Enter') {
      e.preventDefault();
      nextQuestion();
    }
  });
}

/* ============================================================
   密码解锁流程
   ============================================================ */
function showLock() {
  $('#bootMask').hidden = true;
  $('#lockScreen').hidden = false;
  setTimeout(() => { const inp = $('#lockInput'); if (inp) inp.focus(); }, 60);
}
function lockError(text) {
  const err = $('#lockErr');
  err.textContent = text;
  err.hidden = false;
}
async function unlockWith(password) {
  const vault = await fetchVault(password);
  state.password = password;
  distributeVault(vault);
  try { localStorage.setItem(LS_AUTH, password); } catch (e) { /* 忽略 */ }
  $('#lockScreen').hidden = true;
  buildChapterSelect($('#reciteChapter'), state.recite.bank, state.recite.chapter);
  setMode('recite');
  const mask = $('#bootMask');
  mask.classList.add('gone');
  setTimeout(() => mask.remove(), 500);
}
async function attemptUnlock(password) {
  const btn = $('#lockScreen .lock-btn');
  const box = $('#lockScreen .lock-box');
  $('#lockErr').hidden = true;
  btn.disabled = true;
  btn.textContent = '解密中…';
  try {
    await unlockWith(password);
    /* 成功：unlockWith 已隐藏锁定层 */
  } catch (e) {
    btn.disabled = false;
    btn.textContent = '解锁要塞';
    if (e.message === 'vault-missing') lockError('数据文件 vault.enc 加载失败，请检查部署');
    else if (e.message === 'vault-format') lockError('数据文件格式异常，请重新部署');
    else lockError('密码不正确，请重试');
    box.classList.remove('is-shake');
    void box.offsetWidth;
    box.classList.add('is-shake');
    const inp = $('#lockInput');
    inp.select();
  }
}

async function init() {
  state.data = { outline: { choice: [], fill: [], term: [], short: [], kb: null }, experiment: { choice: [], fill: [], term: [], short: [], kb: null } };
  bindStatic();
  /* Web Crypto 仅在安全上下文（HTTPS / localhost）可用 */
  if (!window.crypto || !crypto.subtle) {
    showLock();
    lockError('当前访问地址不支持解密（需 HTTPS 或 localhost），请通过正式链接访问');
    $('#lockInput').disabled = true;
    $('#lockScreen .lock-btn').disabled = true;
    return;
  }
  const saved = localStorage.getItem(LS_AUTH);
  if (saved) {
    try {
      await unlockWith(saved);
      return;
    } catch (e) {
      try { localStorage.removeItem(LS_AUTH); } catch (err) { /* 忽略 */ }
    }
  }
  showLock();
}
init();
