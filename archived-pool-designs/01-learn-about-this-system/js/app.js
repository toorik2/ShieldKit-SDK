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

// CSS may use this opt-in for enhanced-only presentation. Content remains usable
// when this module cannot load or a browser lacks an enhancement API.
document.documentElement.classList.add('js');

const makeId = (value) => String(value).replace(/[^a-z0-9_-]+/gi, '-').replace(/^-+|-+$/g, '');
const setText = (element, text) => {
  if (element) element.textContent = text;
};

/* ---------- Mobile nav ---------- */
const nav = $('.nav');
const navToggle = $('#navToggle');
const navLinks = $('.nav-links');
if (navToggle) {
  if (navLinks && !navLinks.id) navLinks.id = 'primary-nav-links';
  navToggle.setAttribute('aria-expanded', String(nav?.classList.contains('open') || false));
  if (navLinks) navToggle.setAttribute('aria-controls', navLinks.id);
  navToggle.addEventListener('click', () => {
    const open = !nav?.classList.contains('open');
    nav?.classList.toggle('open', open);
    navToggle.setAttribute('aria-expanded', String(open));
  });
}
function closeNav() {
  nav?.classList.remove('open');
  navToggle?.setAttribute('aria-expanded', 'false');
}
$$('.nav-links a').forEach((a) => a.addEventListener('click', closeNav));
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && nav?.classList.contains('open')) {
    closeNav();
    navToggle?.focus();
  }
});
document.addEventListener('pointerdown', (event) => {
  if (nav?.classList.contains('open') && !nav.contains(event.target)) closeNav();
});

/* ---------- Active nav on scroll ---------- */
const links = $$('.nav-links a');
const sections = [...new Set(links.map((a) => $(a.getAttribute('href'))).filter(Boolean))]
  .sort((a, b) => {
    if (a === b) return 0;
    return a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1;
  });
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
const reveal = $$('.reveal');
if ('IntersectionObserver' in window) {
  const io = new IntersectionObserver(
    (entries) => entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add('in');
        io.unobserve(entry.target);
      }
    }),
    { threshold: 0.12, rootMargin: '0px 0px -40px 0px' },
  );
  reveal.forEach((el) => io.observe(el));
} else {
  // Fail open: the explanatory content must never depend on animation support.
  reveal.forEach((el) => el.classList.add('in'));
}

/* ---------- Segmented controls / panes ---------- */
$$('.seg').forEach((seg, segIndex) => {
  const group = seg.dataset.group;
  const panes = $$(`.pane[data-group="${group}"]`);
  const buttons = $$('button', seg);
  const groupId = makeId(group || `seg-${segIndex}`);
  seg.setAttribute('role', 'tablist');
  seg.setAttribute('aria-label', `${groupId.replace(/-/g, ' ')} views`);

  function activate(btn, { focus = false } = {}) {
    const paneName = btn.dataset.pane;
    buttons.forEach((button) => {
      const selected = button === btn;
      button.classList.toggle('active', selected);
      button.setAttribute('aria-selected', String(selected));
      button.tabIndex = selected ? 0 : -1;
    });
    panes.forEach((pane) => {
      const selected = pane.dataset.pane === paneName;
      pane.classList.toggle('active', selected);
      pane.hidden = !selected;
    });
    if (focus) btn.focus();
    // Keep the action and lifecycle diagrams synchronized with their tabs.
    if (group === 'flow' && paneName) {
      const el = $('#diag-flow');
      if (el) el.innerHTML = flowSvg(paneName);
    }
    if (group === 'covlife' && paneName) {
      const el = $('#diag-lifecycle');
      if (el) el.innerHTML = lifecycleSvg(paneName);
    }
  }

  buttons.forEach((btn, buttonIndex) => {
    const paneName = btn.dataset.pane || `pane-${buttonIndex + 1}`;
    const pane = panes.find((candidate) => candidate.dataset.pane === btn.dataset.pane);
    btn.id ||= `${groupId}-tab-${makeId(paneName)}`;
    btn.setAttribute('role', 'tab');
    if (pane) {
      pane.id ||= `${groupId}-panel-${makeId(paneName)}`;
      pane.setAttribute('role', 'tabpanel');
      pane.setAttribute('aria-labelledby', btn.id);
      btn.setAttribute('aria-controls', pane.id);
    }
    btn.addEventListener('click', () => activate(btn));
    btn.addEventListener('keydown', (event) => {
      const current = buttons.indexOf(btn);
      let next = null;
      if (event.key === 'ArrowRight' || event.key === 'ArrowDown') next = (current + 1) % buttons.length;
      if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') next = (current - 1 + buttons.length) % buttons.length;
      if (event.key === 'Home') next = 0;
      if (event.key === 'End') next = buttons.length - 1;
      if (next !== null) {
        event.preventDefault();
        activate(buttons[next], { focus: true });
      }
    });
  });
  const initial = buttons.find((button) => button.classList.contains('active')) || buttons[0];
  if (initial) activate(initial);
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
    d: '192-byte ciphertext on chain. Plaintext ρ/r is available only to the intended note owner under the recovery-key design. Location is public; content is not (under encryption assumptions).',
  },
  'chain-null': {
    t: 'Nullifier',
    d: 'Public spent marker. It does not open to a commitment without secrets. The proof hides which compatible live note was spent only while more than one independently plausible candidate remains.',
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

function setDetail(box, detail, fallback) {
  if (!box) return;
  const heading = document.createElement('h4');
  const copy = document.createElement('p');
  heading.textContent = detail?.t || fallback.t;
  copy.textContent = detail?.d || fallback.d;
  box.replaceChildren(heading, copy);
}

function bindHotspots(containerId, detailId, dictionary, fallback) {
  const container = document.getElementById(containerId);
  const detail = document.getElementById(detailId);
  if (!container) return;
  if (detail) {
    detail.setAttribute('aria-live', 'polite');
    detail.setAttribute('aria-atomic', 'true');
  }

  function show(id) {
    setDetail(detail, dictionary[id], fallback);
    $$('[data-hot]', container).forEach((hotspot) => {
      const selected = hotspot.getAttribute('data-hot') === id;
      hotspot.classList.toggle('focus', selected);
      hotspot.setAttribute('aria-pressed', String(selected));
      hotspot.setAttribute('aria-controls', detailId);
    });
  }

  $$('[data-hot]', container).forEach((hotspot) => {
    hotspot.setAttribute('role', 'button');
    hotspot.tabIndex = 0;
    hotspot.setAttribute('aria-controls', detailId);
    const key = hotspot.getAttribute('data-hot');
    if (dictionary[key]) hotspot.setAttribute('aria-label', `Show details: ${dictionary[key].t}`);
  });
  show(null);
  container.addEventListener('click', (event) => {
    const hotspot = event.target.closest('[data-hot]');
    if (hotspot && container.contains(hotspot)) show(hotspot.getAttribute('data-hot'));
  });
  container.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    const hotspot = event.target.closest('[data-hot]');
    if (hotspot && container.contains(hotspot)) {
      event.preventDefault();
      show(hotspot.getAttribute('data-hot'));
    }
  });
}

bindHotspots('diag-map', 'hot-detail', HOT, {
  t: 'Select a region',
  d: 'Explore what stays on your machine and what is broadcast to Bitcoin Cash.',
});
bindHotspots('diag-covenant', 'cov-detail', COV, {
  t: 'Select a layer',
  d: 'Explore the UTXO value, NFT commitment bytes, and Poseidon-bound logical fields.',
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
const settleDiagram = document.getElementById('diag-settle');
if (roleHint) {
  roleHint.setAttribute('aria-live', 'polite');
  roleHint.setAttribute('aria-atomic', 'true');
}
function showRole(role) {
  const index = Number(role);
  setText(roleHint, ROLES[index] || 'Select an input to hear its settlement role.');
  $$('[data-role]', settleDiagram).forEach((hotspot) => {
    const selected = Number(hotspot.getAttribute('data-role')) === index;
    hotspot.classList.toggle('focus', selected);
    hotspot.setAttribute('aria-pressed', String(selected));
    hotspot.setAttribute('aria-controls', 'role-hint');
  });
}
if (settleDiagram) {
  $$('[data-role]', settleDiagram).forEach((hotspot) => {
    hotspot.setAttribute('role', 'button');
    hotspot.tabIndex = 0;
    hotspot.setAttribute('aria-controls', 'role-hint');
  });
  const activateRole = (event) => {
    const hotspot = event.target.closest('[data-role]');
    if (hotspot && settleDiagram.contains(hotspot)) showRole(hotspot.getAttribute('data-role'));
  };
  settleDiagram.addEventListener('mouseover', activateRole);
  settleDiagram.addEventListener('focusin', activateRole);
  settleDiagram.addEventListener('click', activateRole);
  settleDiagram.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    const hotspot = event.target.closest('[data-role]');
    if (hotspot && settleDiagram.contains(hotspot)) {
      event.preventDefault();
      showRole(hotspot.getAttribute('data-role'));
    }
  });
}

/* ---------- Anonymity lab ---------- */
const CAP = 32;
/** Live notes in the tip. mine=true ⇒ this wallet can spend; others enlarge the set only. */
let notes = [];
let nid = 1;
const pool = $('#pool-stage');
const setSize = $('#set-size');
const meter = $('#set-meter');
const grade = $('#set-grade');
const feed = $('#lab-feed');
const pickMode = $('#pick-mode');

function log(message, { privateEvent = false, kind = 'chain' } = {}) {
  if (!feed) return;
  const el = document.createElement('div');
  el.className = `item${privateEvent ? ' priv' : ''}`;
  const time = document.createElement('div');
  time.className = 'time';
  time.textContent = new Date().toLocaleTimeString();
  const body = document.createElement('div');
  const tag = document.createElement('span');
  const tagKinds = {
    chain: ['tag', 'tag-pub', 'chain'],
    wallet: ['tag', 'tag-priv', 'wallet'],
  };
  const [base, modifier, label] = tagKinds[kind] || tagKinds.chain;
  tag.className = `${base} ${modifier}`;
  tag.textContent = label;
  body.append(tag, document.createTextNode(` ${message}`));
  el.append(time, body);
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
    const owner = document.createElement('span');
    owner.className = 'who';
    owner.textContent = who;
    chip.append(owner, document.createTextNode(` #${n.id} · slot ${i + 1}`));
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
    const g = n <= 1 ? 'candidate set: trivial' : n < 8 ? 'candidate set: thin' : 'candidate set: broader';
    grade.textContent = mine < n ? `${g} · ${mine} yours` : g;
    grade.className = `tag ${n <= 1 ? 'tag-bad' : n < 8 ? 'tag-warn' : 'tag-ok'}`;
    grade.title = 'A larger live set is only one privacy condition. Timing, prior knowledge, and other metadata can still reduce plausible candidates.';
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
  log(`Someone else deposited. Live set: ${notes.length}. Their note is not yours.`);
}

const labCapLabel = $('#lab [data-lab-cap]');
setText(labCapLabel, 'cap 32 (playground model)');
if (pool) pool.setAttribute('aria-label', 'Illustrated live notes in the 32-note playground model');
if (setSize) setSize.setAttribute('aria-live', 'polite');
if (grade) {
  grade.setAttribute('aria-live', 'polite');
  grade.setAttribute('aria-label', 'Candidate-set assessment');
}
if (feed) {
  feed.setAttribute('aria-live', 'polite');
  feed.setAttribute('aria-relevant', 'additions text');
}
const rotateButton = $('#btn-xfer');
if (rotateButton) {
  rotateButton.textContent = '⇄ Rotate note (my selection)';
  rotateButton.setAttribute('aria-label', 'Internally rotate one of my notes');
}

$('#btn-dep')?.addEventListener('click', () => {
  if (notes.length >= CAP) {
    log(`At capacity (${CAP}). Capacity is fixed at genesis; a new pool is required to change it.`);
    return;
  }
  const id = nid++;
  notes.push({ id, mine: true, seed: Math.random().toString(16).slice(2, 8) });
  log(`Your deposit settled. Live set: ${notes.length}. Reserve increased by 0.1 BCH; your wallet stores the new open note privately.`);
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
    `Internal note rotation spent note #${old.id} using ${pickMode?.value || 'newest'} selection and created note #${neu.id}. Live count remains ${notes.length}; the nullifier is public, but the selected note is not.`,
    { privateEvent: true, kind: 'wallet' },
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
    `Withdrawal selected note #${gone.id} via ${pickMode?.value || 'newest'} (a local policy). On-chain: the public live count was ${before}, one nullifier appeared, and ${notes.length} notes remain. “Newest” is not a chain label.`,
  );
  renderNotes();
});

$('#btn-reset')?.addEventListener('click', () => {
  notes = [];
  nid = 1;
  log('Pool journal reset (illustration only).', { kind: 'wallet', privateEvent: true });
  renderNotes();
});

pickMode?.addEventListener('change', () => {
  log(`Wallet selection policy set to ${pickMode.value}; it is not visible on-chain.`, { privateEvent: true, kind: 'wallet' });
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
  canvas.setAttribute('role', 'img');
  canvas.setAttribute('aria-label', 'Illustrative sequential verification of the ten settlement inputs. The diagram is not live node telemetry.');
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
  let frameId = 0;
  let running = false;
  let onScreen = true;
  const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  // One full pass across 10 inputs, then hold, then repeat
  const STEP = 0.55; // seconds per input
  const HOLD = 1.2;  // seconds after all verified

  function draw(ts) {
    const reduce = motionQuery.matches;
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
      ctx.fillStyle = done || current ? r.c : '#91a4bd';
      ctx.font = '12px JetBrains Mono, monospace';
      ctx.textAlign = 'center';
      ctx.fillText(r.n, x + bw / 2, 98);
      ctx.fillStyle = '#91a4bd';
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
    ctx.fillStyle = '#91a4bd';
    ctx.font = '11px Inter, sans-serif';
    ctx.fillText('Verification progress (illustrative sequence — not a live node)', W / 2, 250);

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
  function frame(ts) {
    frameId = 0;
    if (!running || document.hidden || !onScreen || motionQuery.matches) return;
    draw(ts);
    frameId = requestAnimationFrame(frame);
  }
  function updateAnimation() {
    const shouldRun = !motionQuery.matches && onScreen && !document.hidden;
    if (!shouldRun) {
      running = false;
      if (frameId) cancelAnimationFrame(frameId);
      frameId = 0;
      if (motionQuery.matches) draw(0);
      return;
    }
    if (!running) {
      running = true;
      frameId = requestAnimationFrame(frame);
    }
  }
  if ('IntersectionObserver' in window) {
    new IntersectionObserver((entries) => {
      onScreen = entries.some((entry) => entry.isIntersecting);
      updateAnimation();
    }, { threshold: 0.05 }).observe(canvas);
  }
  document.addEventListener('visibilitychange', updateAnimation);
  motionQuery.addEventListener?.('change', updateAnimation);
  if (motionQuery.matches) draw(0);
  else updateAnimation();
}

// SVG diagrams are mounted after the browser's first fragment calculation and
// can change the height above a deep-linked section. Re-apply the initial hash
// once the enhanced layout has settled.
if (location.hash.length > 1) {
  requestAnimationFrame(() => requestAnimationFrame(() => {
    let id;
    try {
      id = decodeURIComponent(location.hash.slice(1));
    } catch {
      id = location.hash.slice(1);
    }
    document.getElementById(id)?.scrollIntoView({ block: 'start' });
  }));
}

console.info('%cShieldKit Explainer', 'color:#2ee6c8;font-weight:bold', '— system map for humans');
