import {
  systemMapSvg,
  settlementSvg,
  flowSvg,
  privacySvg,
  covenantStateSvg,
  lifecycleSvg,
  verifierSvg,
  pairingSvg,
  provePathSvg,
} from './diagrams.js';

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

/* ---------- Mobile nav ---------- */
const nav = $('.nav');
$('#navToggle')?.addEventListener('click', () => {
  nav?.classList.toggle('open');
});
$$('.nav-links a').forEach((a) => {
  a.addEventListener('click', () => nav?.classList.remove('open'));
});

/* ---------- Active nav on scroll ---------- */
const links = $$('.nav-links a');
const sections = links.map((a) => $(a.getAttribute('href'))).filter(Boolean);
function syncNav() {
  let cur = sections[0];
  for (const s of sections) {
    if (s.getBoundingClientRect().top <= 110) cur = s;
  }
  links.forEach((a) => {
    a.classList.toggle('active', a.getAttribute('href') === `#${cur?.id}`);
  });
}
window.addEventListener('scroll', syncNav, { passive: true });
syncNav();

/* ---------- Scroll reveal ---------- */
const io = new IntersectionObserver(
  (entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting) e.target.classList.add('in');
    });
  },
  { threshold: 0.12, rootMargin: '0px 0px -40px 0px' },
);
$$('.reveal').forEach((el) => io.observe(el));

/* ---------- Segmented controls / panes ---------- */
$$('.seg').forEach((seg) => {
  const group = seg.dataset.group;
  const panes = $$(`.pane[data-group="${group}"]`);
  seg.querySelectorAll('button').forEach((btn) => {
    btn.addEventListener('click', () => {
      seg.querySelectorAll('button').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      panes.forEach((p) => p.classList.toggle('active', p.dataset.pane === btn.dataset.pane));
      // flow diagram
      if (group === 'flow' && btn.dataset.pane) {
        const el = $('#diag-flow');
        if (el) el.innerHTML = flowSvg(btn.dataset.pane);
      }
      if (group === 'covlife' && btn.dataset.pane) {
        const el = $('#diag-lifecycle');
        if (el) el.innerHTML = lifecycleSvg(btn.dataset.pane);
      }
    });
  });
});

/* ---------- Diagrams ---------- */
const mount = (id, html) => {
  const el = document.getElementById(id);
  if (el) el.innerHTML = html;
};
mount('diag-map', systemMapSvg());
mount('diag-settle', settlementSvg());
mount('diag-flow', flowSvg('deposit'));
mount('diag-privacy', privacySvg());
mount('diag-covenant', covenantStateSvg());
mount('diag-lifecycle', lifecycleSvg('genesis'));
mount('diag-verifier', verifierSvg());
mount('diag-pairing', pairingSvg());
mount('diag-prove-path', provePathSvg());

/* Hotspot details on system map */
const HOT = {
  'local-secrets': {
    t: 'Wallet secrets',
    d: 'Spend key sk and note randomness ρ, r never go on-chain. Only you (or anyone who steals your seed) can open notes.',
  },
  'local-prove': {
    t: 'Groth16 prove',
    d: 'Local snarkjs + pin zkey (often ~10–30s). Public input is two limbs of SHA256 of the 752-byte SCAR action packet — not your note secrets. Prove+unlock together often land in 30–90s.',
  },
  'local-unlock': {
    t: 'Unlock build',
    d: 'densFuel pin compiles ~30s into 7 verifier unlock bytecodes (lengths fixed by pin). Short TMPDIR avoids Unix socket path limits.',
  },
  'local-assemble': {
    t: 'Assemble',
    d: 'Complete PREP funds 7 PF7 + binding + fee; SETTLE spends tip + unlocks + fee. Change is fixed-point so fee = wireBytes × 1 sat.',
  },
  'chain-prep': {
    t: 'Preparation tx',
    d: 'Exactly 10 outputs: PF7 exec0–4, genesis, terminal (0–6), binding (7), fee funding (8), P2PKH change (9). Does not spend the tip. Required before every settle (deposit, transfer, withdraw).',
  },
  'chain-settle': {
    t: 'Settlement tx',
    d: 'Exactly 10 inputs: exec0–4, genesis, terminal, binding (SCAR packet unlock), state tip, fee. Wire size is pin/kind-dependent (example ~57kB, hard cap ≤59kB). Only one can spend the current tip.',
  },
  'chain-state': {
    t: 'State NFT tip',
    d: 'Single mutable CashToken NFT. Value = 1080 + reserveSats. NFT commitment encodes instanceId + Poseidon stateCommitment + actionSequence. Logical fields: noteRoot, nullifierRoot, nextLeafIndex, liveNoteCount, reserveSats, maximumReserve.',
  },
  'chain-record': {
    t: 'Encrypted record',
    d: '192-byte ciphertext on chain. Plaintext ρ/r only for the recipient. Location is public; content is not (under encryption assumptions).',
  },
  'chain-null': {
    t: 'Nullifier',
    d: 'Public spent marker. Does not open to a commitment without secrets. Observer learns “one of N live notes was spent,” not which — if N > 1.',
  },
};

/* Covenant tip layer details */
const COV = {
  'cov-lock': {
    t: 'State trampoline lock',
    d: 'P2S locking bytecode from the PF7 settlement kernel (bindingLock + stateHelper). Every successor tip must reuse this exact lock. Project limit ≤190 bytes. No admin key inside.',
  },
  'cov-token': {
    t: 'Mutable State NFT',
    d: 'CashToken NFT, fungible amount 0, capability mutable, category fixed at genesis (derived from the category-creating input). Only one live tip UTXO may exist for the instance.',
  },
  'cov-nft': {
    t: '80-byte SHST commitment',
    d: 'Encode: magic “SHST”, version 1, network id, 32-byte instanceId, 32-byte Poseidon stateCommitment, u64le actionSequence. Project cap ≤120 B; implemented size 80. Pre-state on spend must match packet.preState; post on create matches packet.postState.',
  },
  'cov-value': {
    t: 'Carrier + reserve',
    d: 'stateCarrierBase = 1080 sats (BCH-2026 dust/standardness floor for this P2S). Plus reserveSats which always equals liveNoteCount × 10_000_000. Deposit moves bulk on the binding input into reserve; withdraw peels 10M to a transparent output.',
  },
};

function showHot(id) {
  const box = $('#hot-detail');
  if (!box) return;
  const h = HOT[id];
  if (!h) {
    box.innerHTML = '<h4>Click a region</h4><p>Explore what stays local vs what lands on Bitcoin Cash.</p>';
    return;
  }
  box.innerHTML = `<h4>${h.t}</h4><p>${h.d}</p>`;
  $$('#diag-map .hotspot').forEach((g) => {
    g.classList.toggle('focus', g.getAttribute('data-hot') === id);
  });
}
showHot(null);
document.getElementById('diag-map')?.addEventListener('click', (e) => {
  const g = e.target.closest('[data-hot]');
  if (g) showHot(g.getAttribute('data-hot'));
});
document.getElementById('diag-map')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') {
    const g = e.target.closest('[data-hot]');
    if (g) showHot(g.getAttribute('data-hot'));
  }
});

function showCov(id) {
  const box = $('#cov-detail');
  if (!box) return;
  const h = COV[id];
  if (!h) {
    box.innerHTML = '<h4>Click a layer</h4><p>UTXO value, NFT commitment bytes, and Poseidon-bound logical fields.</p>';
    return;
  }
  box.innerHTML = `<h4>${h.t}</h4><p>${h.d}</p>`;
  $$('#diag-covenant .hotspot').forEach((g) => {
    g.classList.toggle('focus', g.getAttribute('data-hot') === id);
  });
}
showCov(null);
document.getElementById('diag-covenant')?.addEventListener('click', (e) => {
  const g = e.target.closest('[data-hot]');
  if (g) showCov(g.getAttribute('data-hot'));
});

/* Role tooltips on settlement */
const ROLES = [
  'exec0 — densFuel verifier lane (PF7)',
  'exec1 — densFuel verifier lane (PF7)',
  'exec2 — densFuel verifier lane (PF7)',
  'exec3 — densFuel verifier lane (PF7)',
  'exec4 — densFuel verifier lane (PF7)',
  'genesis — densFuel genesis carrier (PF7)',
  'terminal — densFuel terminal unlock (PF7)',
  'binding — P2S; unlock = PUSHDATA2 + 752-byte SCAR packet',
  'state — previous State NFT tip (mutable, value 1080+preReserve)',
  'fee — transparent P2PKH fee input (prep out[8] sibling of binding)',
];
const roleHint = $('#role-hint');
document.getElementById('diag-settle')?.addEventListener('mouseover', (e) => {
  const g = e.target.closest('[data-role]');
  if (g && roleHint) {
    const i = Number(g.getAttribute('data-role'));
    roleHint.textContent = ROLES[i] || '';
  }
});

/* ---------- Anonymity lab ---------- */
const CAP = 16;
/** Live notes in the tip. mine=true ⇒ this wallet can spend; others enlarge the set only. */
let notes = [];
let nid = 1;
const pool = $('#pool-stage');
const setSize = $('#set-size');
const meter = $('#set-meter');
const grade = $('#set-grade');
const feed = $('#lab-feed');
const pickMode = $('#pick-mode');

function log(html, priv = false) {
  if (!feed) return;
  const el = document.createElement('div');
  el.className = `item${priv ? ' priv' : ''}`;
  el.innerHTML = `<div class="time">${new Date().toLocaleTimeString()}</div><div>${html}</div>`;
  feed.prepend(el);
}

function mineNotes() {
  return notes.map((n, i) => ({ n, i })).filter(({ n }) => n.mine);
}

function renderNotes() {
  if (!pool) return;
  $$('.note', pool).forEach((n) => n.remove());
  pool.classList.toggle('has-notes', notes.length > 0);
  notes.forEach((n, i) => {
    const chip = document.createElement('span');
    chip.className = n.mine ? 'note' : 'note note-other';
    const who = n.mine ? 'yours' : 'other';
    chip.innerHTML = `<span class="who">${who}</span> #${n.id} · slot ${i + 1}`;
    chip.title = n.mine
      ? `Local wallet entry — not a chain label. seed …${n.seed}`
      : 'Another operator’s note — enlarges the live set; you cannot spend it';
    pool.appendChild(chip);
  });
  const n = notes.length;
  const mine = mineNotes().length;
  if (setSize) setSize.textContent = String(n);
  if (meter) meter.style.width = `${(n / CAP) * 100}%`;
  if (grade) {
    const g = n <= 1 ? 'trivial' : n < 8 ? 'thin' : 'meaningful';
    grade.textContent = mine < n ? `${g} · ${mine} yours` : g;
    grade.className = `tag ${n <= 1 ? 'tag-bad' : n < 8 ? 'tag-warn' : 'tag-ok'}`;
  }
}

function pickMineIndex() {
  const mine = mineNotes();
  if (mine.length === 0) return -1;
  const mode = pickMode?.value || 'newest';
  if (mode === 'oldest') return mine[0].i;
  if (mode === 'random') return mine[Math.floor(Math.random() * mine.length)].i;
  return mine[mine.length - 1].i; // newest among mine
}

/** Occasionally seed an “other” deposit so the lab shows multi-user set growth. */
function maybeOtherDeposit() {
  if (notes.length >= CAP) return;
  if (Math.random() > 0.45) return;
  const id = nid++;
  notes.push({ id, mine: false, seed: Math.random().toString(16).slice(2, 8) });
  log(`<span class="tag tag-pub">chain</span> Someone else deposited. Live set = <strong>${notes.length}</strong> (their note is not yours).`);
}

$('#btn-dep')?.addEventListener('click', () => {
  if (notes.length >= CAP) {
    log(`At capacity (${CAP}). Raise --max-notes only via new genesis.`);
    return;
  }
  const id = nid++;
  notes.push({ id, mine: true, seed: Math.random().toString(16).slice(2, 8) });
  log(`<span class="tag tag-pub">chain</span> Your deposit settled. <strong>Live set = ${notes.length}</strong>. Reserve +0.1 BCH. Root updated. Your wallet stores this open note privately.`);
  maybeOtherDeposit();
  renderNotes();
});

$('#btn-xfer')?.addEventListener('click', () => {
  const i = pickMineIndex();
  if (i < 0) {
    log('No open note in this wallet. Deposit first (gray chips are not yours).');
    return;
  }
  const old = notes[i];
  const neu = { id: nid++, mine: true, seed: Math.random().toString(16).slice(2, 8), from: old.id };
  notes.splice(i, 1, neu);
  log(
    `<span class="tag tag-priv">wallet pick</span> Transfer spent note #${old.id} (selection: <em>${pickMode?.value}</em>) → new note #${neu.id}. Live count still <strong>${notes.length}</strong> (includes others). Nullifier public; which note is not.`,
    true,
  );
  renderNotes();
});

$('#btn-wd')?.addEventListener('click', () => {
  const i = pickMineIndex();
  if (i < 0) {
    log('No open note in this wallet. Deposit first (gray chips are not yours).');
    return;
  }
  const before = notes.length;
  const [gone] = notes.splice(i, 1);
  log(
    `<span class="tag tag-pub">chain</span> Withdraw. Wallet selected note #${gone.id} via <em>${pickMode?.value || 'newest'}</em> (local policy only). On-chain: one nullifier among <strong>${before}</strong> live notes → now ${notes.length}. Observer does not see “newest” as a label.`,
  );
  renderNotes();
});

$('#btn-reset')?.addEventListener('click', () => {
  notes = [];
  nid = 1;
  log('Pool journal reset (demo only).');
  renderNotes();
});

pickMode?.addEventListener('change', () => {
  log(`Wallet selection policy set to <strong>${pickMode.value}</strong> — still not visible on-chain.`, true);
});

renderNotes();

/* ---------- Fee calculator ---------- */
const feeBytes = $('#fee-bytes');
const feeOut = $('#fee-out');
const feeBar = $('#fee-bar');
function updateFee() {
  const b = Number(feeBytes?.value || 57000);
  if (feeOut) feeOut.textContent = `${b.toLocaleString()} sats`;
  if (feeBar) feeBar.style.width = `${Math.min(100, (b / 59000) * 100)}%`;
  const bch = $('#fee-bch');
  if (bch) {
    bch.textContent = `≈ ${(b / 1e8).toFixed(8)} BCH · real settles vary; cap ≤ 59,000 B`;
  }
}
feeBytes?.addEventListener('input', updateFee);
updateFee();

/* ---------- Capacity slider ---------- */
const capRange = $('#cap-range');
const capOut = $('#cap-out');
const capBch = $('#cap-bch');
function updateCap() {
  const n = Number(capRange?.value || 16);
  if (capOut) capOut.textContent = String(n);
  // Avoid float noise: N × 0.1 BCH
  const bch = (n / 10).toFixed(1);
  if (capBch) capBch.textContent = `${bch} BCH max reserve if full (N × 0.1 BCH)`;
  const gradeEl = $('#cap-grade');
  if (gradeEl) {
    let g;
    if (n <= 1) g = 'trivial set if full — not product privacy';
    else if (n < 8) g = 'thin set even if full';
    else if (n === 16) g = 'product default — real set only if filled';
    else if (n <= 64) g = 'large set (if filled); heavier to fund & replay';
    else if (n < 1024) g = 'CLI-allowed; ops cost grows with N';
    else g = 'CLI soft max (1024) — raise constant in pool-capacity.mjs to go higher';
    gradeEl.textContent = g;
  }
}
capRange?.addEventListener('input', updateCap);
updateCap();

/* ---------- Settlement canvas: sequential verify sweep (not a fee pulse) ---------- */
const canvas = $('#settleCanvas');
if (canvas && canvas.getContext) {
  const ctx = canvas.getContext('2d');
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const W = 900;
  const H = 280;
  canvas.width = W * dpr;
  canvas.height = H * dpr;
  ctx.scale(dpr, dpr);
  const roles = [
    { n: 'e0', c: '#2ee6c8' }, { n: 'e1', c: '#2ee6c8' }, { n: 'e2', c: '#2ee6c8' },
    { n: 'e3', c: '#2ee6c8' }, { n: 'e4', c: '#2ee6c8' }, { n: 'gen', c: '#f0c14b' },
    { n: 'term', c: '#f0c14b' }, { n: 'bind', c: '#b49cff' }, { n: 'st', c: '#6eb6ff' }, { n: 'fee', c: '#ff7a93' },
  ];
  let t = 0;
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  // One full pass across 10 inputs, then hold, then repeat
  const STEP = 0.55; // seconds per input
  const HOLD = 1.2;  // seconds after all verified

  function frame(ts) {
    if (!reduce) t = ts / 1000;
    ctx.clearRect(0, 0, W, H);
    ctx.fillStyle = '#070c14';
    ctx.fillRect(0, 0, W, H);

    ctx.fillStyle = '#eef3fb';
    ctx.font = '600 13px Inter, system-ui, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('How a settle is checked — each input in order', W / 2, 24);

    const cycle = roles.length * STEP + HOLD;
    const phase = reduce ? roles.length : (t % cycle);
    const active = Math.min(roles.length, Math.floor(phase / STEP));
    const frac = reduce ? 1 : Math.min(1, phase / (roles.length * STEP));

    const bw = 70;
    const gap = 10;
    const start = (W - (roles.length * bw + (roles.length - 1) * gap)) / 2;

    roles.forEach((r, i) => {
      const x = start + i * (bw + gap);
      const done = i < active;
      const current = i === active && active < roles.length;
      ctx.globalAlpha = 1;
      ctx.fillStyle = '#121c2c';
      ctx.strokeStyle = done || current ? r.c : '#2a3548';
      ctx.lineWidth = current ? 2.4 : 1.4;
      rr(ctx, x, 48, bw, 100, 10);
      ctx.fill();
      ctx.stroke();
      if (done) {
        ctx.fillStyle = r.c + '22';
        rr(ctx, x, 48, bw, 100, 10);
        ctx.fill();
      }
      ctx.fillStyle = done || current ? r.c : '#64748b';
      ctx.font = '12px JetBrains Mono, monospace';
      ctx.textAlign = 'center';
      ctx.fillText(r.n, x + bw / 2, 98);
      ctx.fillStyle = '#64748b';
      ctx.font = '10px Inter, sans-serif';
      ctx.fillText(`in[${i}]`, x + bw / 2, 118);
      if (done) {
        ctx.fillStyle = '#5ee9a8';
        ctx.font = '14px sans-serif';
        ctx.fillText('✓', x + bw / 2, 138);
      } else if (current) {
        ctx.fillStyle = r.c;
        ctx.font = '10px Inter, sans-serif';
        ctx.fillText('check…', x + bw / 2, 138);
      }
    });

    const label = active >= roles.length
      ? 'All inputs accepted → tip advances'
      : `Verifying input ${active} (${roles[active].n})…`;
    ctx.fillStyle = '#93a4bd';
    ctx.font = '12px Inter, sans-serif';
    ctx.fillText(label, W / 2, 175);
    ctx.fillText('example wire ~57kB → fee = wireBytes sats (exactly 1 sat/byte; cap ≤59kB)', W / 2, 196);

    // Progress = verification sweep across 10 inputs (not a fee “pulse”)
    const barX = 100;
    const barW = W - 200;
    ctx.fillStyle = '#141c2a';
    rr(ctx, barX, 220, barW, 10, 5);
    ctx.fill();
    ctx.fillStyle = '#2ee6c8';
    rr(ctx, barX, 220, barW * frac, 10, 5);
    ctx.fill();
    ctx.fillStyle = '#64748b';
    ctx.font = '11px Inter, sans-serif';
    ctx.fillText('Verification progress (illustrative sequence — not a live node)', W / 2, 250);

    if (!reduce) requestAnimationFrame(frame);
  }
  function rr(c, x, y, w, h, r) {
    c.beginPath();
    c.moveTo(x + r, y);
    c.arcTo(x + w, y, x + w, y + h, r);
    c.arcTo(x + w, y + h, x, y + h, r);
    c.arcTo(x, y + h, x, y, r);
    c.arcTo(x, y, x + w, y, r);
    c.closePath();
  }
  if (reduce) frame(0);
  else requestAnimationFrame(frame);
}

console.info('%cShieldKit Explainer', 'color:#2ee6c8;font-weight:bold', '— system map for humans');
