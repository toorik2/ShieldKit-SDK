/** SVG builders */

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function box(x, y, w, h, fill, stroke, lines, id) {
  const arr = Array.isArray(lines) ? lines : [lines];
  const ty = y + h / 2 - (arr.length - 1) * 7.5 + 4;
  const texts = arr.map((ln, i) =>
    `<text x="${x + w / 2}" y="${ty + i * 15}" text-anchor="middle" fill="#eef3fb" font-size="12.5" font-family="Inter,Segoe UI,sans-serif">${esc(ln)}</text>`
  ).join('');
  const hid = id ? ` data-hot="${id}" class="hotspot"` : '';
  return `<g${hid}><rect x="${x}" y="${y}" width="${w}" height="${h}" rx="12" fill="${fill}" stroke="${stroke}" stroke-width="1.5"/>${texts}</g>`;
}

export function systemMapSvg() {
  return `<svg viewBox="0 0 920 440" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="ShieldKit system map">
  <defs>
    <linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#16324a"/><stop offset="100%" stop-color="#101a2a"/></linearGradient>
    <linearGradient id="arrg" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stop-color="#2ee6c8"/><stop offset="100%" stop-color="#b49cff"/></linearGradient>
    <marker id="m" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#2ee6c8"/></marker>
    <filter id="glow"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
  </defs>
  <rect width="920" height="440" rx="16" fill="#070c14"/>

  <rect x="36" y="36" width="250" height="368" rx="16" fill="url(#lg)" stroke="#2a4058"/>
  <text x="161" y="68" text-anchor="middle" fill="#f0c14b" font-size="13" font-weight="650" font-family="Inter,sans-serif">YOUR MACHINE</text>
  <text x="161" y="88" text-anchor="middle" fill="#64748b" font-size="11">offline · secrets · prove</text>
  ${box(58, 110, 206, 48, '#1a2438', '#b49cff', ['Wallet secrets  ρ · r · sk'], 'local-secrets')}
  ${box(58, 174, 206, 48, '#1a2438', '#b49cff', ['Groth16 prove  ~10s'], 'local-prove')}
  ${box(58, 238, 206, 48, '#1a2438', '#b49cff', ['Unlock build densFuel ~30s'], 'local-unlock')}
  ${box(58, 302, 206, 48, '#1a2438', '#2ee6c8', ['Assemble PREP + SETTLE'], 'local-assemble')}

  <line x1="296" y1="220" x2="368" y2="220" stroke="url(#arrg)" stroke-width="2.5" marker-end="url(#m)"/>
  <text x="332" y="208" text-anchor="middle" fill="#64748b" font-size="10">broadcast</text>

  <rect x="380" y="36" width="504" height="368" rx="16" fill="#0a121c" stroke="#2a4058"/>
  <text x="632" y="68" text-anchor="middle" fill="#6eb6ff" font-size="13" font-weight="650" font-family="Inter,sans-serif">BITCOIN CASH · PUBLIC</text>
  <text x="632" y="88" text-anchor="middle" fill="#64748b" font-size="11">consensus-visible · no note secrets</text>

  ${box(410, 115, 210, 54, '#152238', '#6eb6ff', ['PREP  10 outs · PF7+bind+fee'], 'chain-prep')}
  ${box(650, 115, 210, 54, '#152238', '#2ee6c8', ['SETTLE  ~57kB · 10 inputs'], 'chain-settle')}
  <line x1="620" y1="142" x2="650" y2="142" stroke="#2ee6c8" stroke-width="2" marker-end="url(#m)"/>

  ${box(410, 195, 450, 72, '#121c2c', '#f0c14b', ['State NFT tip (mutable)', 'value=1080+reserve · SHST commitment'], 'chain-state')}
  ${box(410, 290, 210, 70, '#1a1528', '#b49cff', ['Encrypted note record', 'ciphertext only'], 'chain-record')}
  ${box(650, 290, 210, 70, '#152238', '#6eb6ff', ['Nullifier', 'spent marker · not which note'], 'chain-null')}

  <text x="632" y="385" text-anchor="middle" fill="#64748b" font-size="11">Click a box · observer sees shape &amp; roots, not ownership</text>
</svg>`;
}

export function settlementSvg() {
  const roles = [
    ['e0', '#2ee6c8'], ['e1', '#2ee6c8'], ['e2', '#2ee6c8'], ['e3', '#2ee6c8'], ['e4', '#2ee6c8'],
    ['gen', '#f0c14b'], ['term', '#f0c14b'], ['bind', '#b49cff'], ['st', '#6eb6ff'], ['fee', '#ff7a93'],
  ];
  const w = 74, g = 8, start = 40;
  const boxes = roles.map(([n, c], i) => {
    const x = start + i * (w + g);
    return `<g data-role="${i}" class="hotspot">
      <rect x="${x}" y="78" width="${w}" height="108" rx="10" fill="#121c2c" stroke="${c}" stroke-width="1.5"/>
      <text x="${x + w / 2}" y="125" text-anchor="middle" fill="${c}" font-size="11" font-family="JetBrains Mono,monospace">${n}</text>
      <text x="${x + w / 2}" y="145" text-anchor="middle" fill="#64748b" font-size="10">in[${i}]</text>
    </g>`;
  }).join('');
  return `<svg viewBox="0 0 920 260" xmlns="http://www.w3.org/2000/svg">
    <rect width="920" height="260" rx="16" fill="#070c14"/>
    <text x="460" y="34" text-anchor="middle" fill="#eef3fb" font-size="14" font-weight="650">Settlement — exactly 10 inputs</text>
    <text x="460" y="54" text-anchor="middle" fill="#64748b" font-size="11">PF7 densFuel · binding(+SCAR packet unlock) · state tip · fee  ·  fee = wireBytes × 1</text>
    ${boxes}
    <text x="460" y="220" text-anchor="middle" fill="#64748b" font-size="11">Outputs: successor State NFT · change · (withdraw: + transparent 0.1 BCH before change)</text>
    <text x="460" y="242" text-anchor="middle" fill="#f0c14b" font-size="11">Only one settle can spend the tip — concurrent acts race; one wins</text>
  </svg>`;
}

/** Layered tip anatomy — UTXO · NFT commitment · Poseidon state */
export function covenantStateSvg() {
  // Multi-line rows: explicit tspans so nothing clips the rounded rects.
  const layers = [
    {
      id: 'cov-lock',
      fill: '#152238',
      stroke: '#6eb6ff',
      title: 'Lock · state trampoline P2S',
      lines: [
        'Profile kernel lock (≤190 B).',
        'Successor out[0] must preserve exact bytecode.',
      ],
    },
    {
      id: 'cov-token',
      fill: '#1a1528',
      stroke: '#b49cff',
      title: 'Token · CashToken mutable NFT',
      lines: [
        'amount = 0 · capability = mutable',
        'category = genesis category · sole tip UTXO',
      ],
    },
    {
      id: 'cov-nft',
      fill: '#121c2c',
      stroke: '#f0c14b',
      title: 'NFT commitment · 80 B SHST',
      lines: [
        'magic SHST · v1 · network · instanceId',
        'stateCommitment (Poseidon) · actionSequence',
      ],
    },
    {
      id: 'cov-value',
      fill: '#0f1a14',
      stroke: '#2ee6c8',
      title: 'Value · satoshis',
      lines: [
        'valueSatoshis = 1080 (carrier base) + reserveSats',
        'reserve = liveNoteCount × 10M',
      ],
    },
  ];

  const padX = 56;
  const boxW = 808;
  const titleH = 22;
  const lineH = 18;
  const padTop = 18;
  const padBot = 16;
  const gap = 12;
  let y = 68;
  const rows = layers.map((L) => {
    const h = padTop + titleH + L.lines.length * lineH + padBot;
    const titleY = y + padTop + 14;
    const body = L.lines.map((ln, i) =>
      `<tspan x="${padX + 20}" dy="${i === 0 ? lineH + 4 : lineH}">${esc(ln)}</tspan>`
    ).join('');
    const g = `<g data-hot="${L.id}" class="hotspot">
      <rect x="${padX}" y="${y}" width="${boxW}" height="${h}" rx="14"
        fill="${L.fill}" stroke="${L.stroke}" stroke-width="1.5"/>
      <text x="${padX + 20}" y="${titleY}" fill="${L.stroke}" font-size="13.5"
        font-weight="650" font-family="Inter,Segoe UI,sans-serif">${esc(L.title)}</text>
      <text x="${padX + 20}" y="${titleY}" fill="#eef3fb" font-size="12.5"
        font-family="Inter,Segoe UI,sans-serif">${body}</text>
    </g>`;
    y += h + gap;
    return g;
  }).join('');

  const totalH = y + 16;
  return `<svg viewBox="0 0 920 ${totalH}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="State tip layers">
    <rect width="920" height="${totalH}" rx="16" fill="#070c14"/>
    <text x="460" y="28" text-anchor="middle" fill="#eef3fb" font-size="14"
      font-weight="650" font-family="Inter,Segoe UI,sans-serif">State tip = one covenant UTXO</text>
    <text x="460" y="48" text-anchor="middle" fill="#64748b" font-size="11.5"
      font-family="Inter,Segoe UI,sans-serif">Click a layer · same locking bytecode every successor</text>
    ${rows}
  </svg>`;
}

/** Groth16 + densFuel overview */
export function verifierSvg() {
  return `<svg viewBox="0 0 920 300" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Verifier stack">
    <rect width="920" height="300" rx="16" fill="#070c14"/>
    <text x="460" y="28" text-anchor="middle" fill="#eef3fb" font-size="14" font-weight="650">From secrets to a BCH-checked proof</text>

    <rect x="36" y="48" width="200" height="200" rx="14" fill="#161022" stroke="#b49cff" stroke-width="1.5"/>
    <text x="136" y="78" text-anchor="middle" fill="#b49cff" font-size="12" font-weight="650">WITNESS</text>
    <text x="136" y="108" text-anchor="middle" fill="#eef3fb" font-size="12">sk · ρ · r</text>
    <text x="136" y="130" text-anchor="middle" fill="#eef3fb" font-size="12">paths · records</text>
    <text x="136" y="152" text-anchor="middle" fill="#64748b" font-size="11">never on chain</text>
    <text x="136" y="190" text-anchor="middle" fill="#64748b" font-size="11">BabyJub + Poseidon</text>
    <text x="136" y="212" text-anchor="middle" fill="#64748b" font-size="11">in the circuit</text>

    <path d="M248 148 L300 148" stroke="#2ee6c8" stroke-width="2.5" marker-end="url(#vm)"/>
    <defs><marker id="vm" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#2ee6c8"/></marker></defs>

    <rect x="312" y="48" width="220" height="200" rx="14" fill="#121c2c" stroke="#2ee6c8" stroke-width="1.5"/>
    <text x="422" y="78" text-anchor="middle" fill="#2ee6c8" font-size="12" font-weight="650">GROTH16 · BN254</text>
    <text x="422" y="112" text-anchor="middle" fill="#eef3fb" font-size="12">relation v2</text>
    <text x="422" y="134" text-anchor="middle" fill="#eef3fb" font-size="12">prove ~10s local</text>
    <text x="422" y="168" text-anchor="middle" fill="#f0c14b" font-size="12">π  +  public limbs</text>
    <text x="422" y="200" text-anchor="middle" fill="#64748b" font-size="11">public = SHA256(SCAR)</text>
    <text x="422" y="220" text-anchor="middle" fill="#64748b" font-size="11">two u128 limbs only</text>

    <path d="M544 148 L596 148" stroke="#2ee6c8" stroke-width="2.5" marker-end="url(#vm)"/>

    <rect x="608" y="48" width="276" height="200" rx="14" fill="#0f1a14" stroke="#6eb6ff" stroke-width="1.5"/>
    <text x="746" y="78" text-anchor="middle" fill="#6eb6ff" font-size="12" font-weight="650">BCH densFuel · PF7</text>
    <text x="746" y="112" text-anchor="middle" fill="#eef3fb" font-size="12">7 P2SH32 unlocks</text>
    <text x="746" y="134" text-anchor="middle" fill="#eef3fb" font-size="12">exec0–4 · gen · term</text>
    <text x="746" y="168" text-anchor="middle" fill="#eef3fb" font-size="12">pairing check on-chain</text>
    <text x="746" y="200" text-anchor="middle" fill="#64748b" font-size="11">+ binding packet + state tip</text>
    <text x="746" y="220" text-anchor="middle" fill="#64748b" font-size="11">consensus does the math</text>
  </svg>`;
}

/** Pairing / public-input bridge */
export function pairingSvg() {
  return `<svg viewBox="0 0 920 220" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Public input bridge">
    <rect width="920" height="220" rx="16" fill="#070c14"/>
    <text x="460" y="30" text-anchor="middle" fill="#eef3fb" font-size="13" font-weight="650">Tiny public surface · fat private witness</text>

    <rect x="40" y="55" width="260" height="130" rx="12" fill="#161022" stroke="#b49cff"/>
    <text x="170" y="90" text-anchor="middle" fill="#b49cff" font-size="12" font-weight="650">PRIVATE</text>
    <text x="170" y="120" text-anchor="middle" fill="#eef3fb" font-size="12">full witness</text>
    <text x="170" y="142" text-anchor="middle" fill="#64748b" font-size="11">thousands of field values</text>
    <text x="170" y="164" text-anchor="middle" fill="#64748b" font-size="11">only in the prover</text>

    <text x="340" y="125" text-anchor="middle" fill="#2ee6c8" font-size="20">→</text>

    <rect x="380" y="55" width="200" height="130" rx="12" fill="#152238" stroke="#2ee6c8"/>
    <text x="480" y="90" text-anchor="middle" fill="#2ee6c8" font-size="12" font-weight="650">PUBLIC</text>
    <text x="480" y="120" text-anchor="middle" fill="#eef3fb" font-size="12">limb₀ · limb₁</text>
    <text x="480" y="148" text-anchor="middle" fill="#64748b" font-size="11">SHA256(SCAR) split</text>
    <text x="480" y="168" text-anchor="middle" fill="#64748b" font-size="11">into two Fr limbs</text>

    <text x="620" y="125" text-anchor="middle" fill="#2ee6c8" font-size="20">→</text>

    <rect x="660" y="55" width="220" height="130" rx="12" fill="#121c2c" stroke="#f0c14b"/>
    <text x="770" y="90" text-anchor="middle" fill="#f0c14b" font-size="12" font-weight="650">PACKET ON WIRE</text>
    <text x="770" y="120" text-anchor="middle" fill="#eef3fb" font-size="12">752 B SCAR</text>
    <text x="770" y="142" text-anchor="middle" fill="#64748b" font-size="11">in binding unlock</text>
    <text x="770" y="164" text-anchor="middle" fill="#64748b" font-size="11">covenant re-hashes</text>
  </svg>`;
}

/** Offline prove → on-chain verify path */
export function provePathSvg() {
  const steps = [
    ['1', 'Witness', '#b49cff'],
    ['2', 'Prove', '#2ee6c8'],
    ['3', 'Unlock\ndensFuel', '#f0c14b'],
    ['4', 'Assemble\nSETTLE', '#6eb6ff'],
    ['5', 'Broadcast', '#ff7a93'],
  ];
  const boxes = steps.map(([n, label, c], i) => {
    const x = 40 + i * 175;
    const lines = label.split('\n');
    const texts = lines.map((ln, j) =>
      `<text x="${x + 75}" y="${120 + j * 16}" text-anchor="middle" fill="#eef3fb" font-size="12.5">${ln}</text>`
    ).join('');
    return `<g>
      <rect x="${x}" y="70" width="150" height="100" rx="12" fill="#121c2c" stroke="${c}" stroke-width="1.5"/>
      <circle cx="${x + 28}" cy="98" r="12" fill="none" stroke="${c}"/>
      <text x="${x + 28}" y="102" text-anchor="middle" fill="${c}" font-size="11" font-weight="650">${n}</text>
      ${texts}
    </g>`;
  }).join('');
  return `<svg viewBox="0 0 920 210" xmlns="http://www.w3.org/2000/svg">
    <rect width="920" height="210" rx="16" fill="#070c14"/>
    <text x="460" y="36" text-anchor="middle" fill="#eef3fb" font-size="13" font-weight="650">Operator path · prove stays local</text>
    ${boxes}
    <text x="460" y="195" text-anchor="middle" fill="#64748b" font-size="11">Miners / nodes only evaluate unlocks — they never see ρ, r, or sk</text>
  </svg>`;
}

/** Lifecycle stages for covenants section */
export function lifecycleSvg(stage = 'genesis') {
  const stages = {
    genesis: {
      t: 'GENESIS — mint the tip',
      c: '#f0c14b',
      L: ['Category input', 'tokenless vout 0'],
      M: ['Genesis tx', 'fee = wire × 1'],
      R: ['State NFT tip', 'empty roots · live 0', 'value 1080'],
    },
    prep: {
      t: 'PREP — fund next settle (does not move tip)',
      c: '#6eb6ff',
      L: ['Hot fee UTXO', 'P2PKH funding'],
      M: ['10 outputs', 'PF7 0–6 · bind 7', 'fee 8 · change 9'],
      R: ['Carriers ready', 'deposit bind +10M', 'tip still old'],
    },
    settle: {
      t: 'SETTLE — spend tip · recreate tip',
      c: '#2ee6c8',
      L: ['7 densFuel', 'bind+packet', 'old tip · fee'],
      M: ['10 inputs', 'SCAR 752 B', 'PF7 + covenants'],
      R: ['New tip', 'post commitment', 'reserve ±0/±10M'],
    },
    journal: {
      t: 'JOURNAL — wallet openNotes (off-chain)',
      c: '#b49cff',
      L: ['Secrets ρ r sk', 'leaf indices'],
      M: ['openNotes[]', 'local only'],
      R: ['Roots public', 'notes not listed', 'recover via record'],
    },
  };
  const f = stages[stage] || stages.genesis;
  const mid = (lines, x, y) => lines.map((ln, i) =>
    `<text x="${x}" y="${y + i * 16}" text-anchor="middle" fill="#eef3fb" font-size="12.5">${esc(ln)}</text>`
  ).join('');
  return `<svg viewBox="0 0 920 200" xmlns="http://www.w3.org/2000/svg">
    <defs><marker id="lc" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="${f.c}"/></marker></defs>
    <rect width="920" height="200" rx="16" fill="#070c14"/>
    <text x="460" y="30" text-anchor="middle" fill="${f.c}" font-size="13" font-weight="650">${esc(f.t)}</text>
    <rect x="60" y="55" width="210" height="110" rx="14" fill="#121c2c" stroke="${f.c}"/>
    ${mid(f.L, 165, 95)}
    <path d="M285 110 L360 110" stroke="${f.c}" stroke-width="2.5" marker-end="url(#lc)"/>
    <rect x="370" y="55" width="180" height="110" rx="14" fill="#152238" stroke="#2ee6c8"/>
    ${mid(f.M, 460, 88)}
    <path d="M560 110 L635 110" stroke="${f.c}" stroke-width="2.5" marker-end="url(#lc)"/>
    <rect x="645" y="55" width="220" height="110" rx="14" fill="#121c2c" stroke="${f.c}"/>
    ${mid(f.R, 755, 88)}
  </svg>`;
}

export function flowSvg(kind) {
  const F = {
    deposit: {
      t: 'DEPOSIT — transparent BCH enters; a new open note is created',
      L: ['Your wallet', '0.1 BCH in'],
      M: ['PREP + SETTLE', 'wire ≈ 57kB'],
      R: ['Reserve +0.1', 'Open notes +1', 'Encrypted receipt'],
      c: '#2ee6c8',
    },
    transfer: {
      t: 'TRANSFER — reserve unchanged; ownership secrets change',
      L: ['Open note A', '(you pick which)'],
      M: ['SETTLE', 'nullifier A'],
      R: ['Open note B', 'new secrets', 'live count same'],
      c: '#b49cff',
    },
    withdraw: {
      t: 'WITHDRAW — BCH out; live set shrinks by one',
      L: ['Open note', 'wallet selects'],
      M: ['SETTLE', 'nullifier'],
      R: ['Transparent', '0.1 BCH out', 'open notes −1'],
      c: '#f0c14b',
    },
  };
  const f = F[kind] || F.deposit;
  const mid = (lines, x, y) => lines.map((ln, i) =>
    `<text x="${x}" y="${y + i * 16}" text-anchor="middle" fill="#eef3fb" font-size="12.5">${esc(ln)}</text>`
  ).join('');
  return `<svg viewBox="0 0 920 200" xmlns="http://www.w3.org/2000/svg">
    <defs><marker id="a2" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="${f.c}"/></marker></defs>
    <rect width="920" height="200" rx="16" fill="#070c14"/>
    <text x="460" y="30" text-anchor="middle" fill="${f.c}" font-size="13" font-weight="650">${esc(f.t)}</text>
    <rect x="60" y="55" width="210" height="100" rx="14" fill="#121c2c" stroke="${f.c}"/>
    ${mid(f.L, 165, 95)}
    <path d="M285 105 L360 105" stroke="${f.c}" stroke-width="2.5" marker-end="url(#a2)"/>
    <rect x="370" y="55" width="180" height="100" rx="14" fill="#152238" stroke="#2ee6c8"/>
    ${mid(f.M, 460, 95)}
    <path d="M560 105 L635 105" stroke="${f.c}" stroke-width="2.5" marker-end="url(#a2)"/>
    <rect x="645" y="55" width="220" height="100" rx="14" fill="#121c2c" stroke="${f.c}"/>
    ${mid(f.R, 755, 88)}
  </svg>`;
}

export function privacySvg() {
  return `<svg viewBox="0 0 920 300" xmlns="http://www.w3.org/2000/svg">
    <rect width="920" height="300" rx="16" fill="#070c14"/>
    <rect x="40" y="40" width="400" height="220" rx="16" fill="#121c2c" stroke="#6eb6ff"/>
    <text x="240" y="72" text-anchor="middle" fill="#6eb6ff" font-size="13" font-weight="650">PUBLIC on chain</text>
    <text x="64" y="108" fill="#eef3fb" font-size="12.5">• Profile, instance, genesis</text>
    <text x="64" y="132" fill="#eef3fb" font-size="12.5">• Tx graph, timing, absolute fee</text>
    <text x="64" y="156" fill="#eef3fb" font-size="12.5">• Boundary amounts (0.1 BCH)</text>
    <text x="64" y="180" fill="#eef3fb" font-size="12.5">• Roots, live count, nullifiers</text>
    <text x="64" y="204" fill="#eef3fb" font-size="12.5">• Ciphertext note records</text>
    <text x="64" y="228" fill="#64748b" font-size="11">Fee rate fixed at 1 sat/B — no rate fingerprint</text>

    <rect x="480" y="40" width="400" height="220" rx="16" fill="#161022" stroke="#b49cff"/>
    <text x="680" y="72" text-anchor="middle" fill="#b49cff" font-size="13" font-weight="650">HIDDEN by design</text>
    <text x="504" y="108" fill="#eef3fb" font-size="12.5">• Which live note a nullifier opens</text>
    <text x="504" y="132" fill="#eef3fb" font-size="12.5">• Deposit → later withdraw link*</text>
    <text x="504" y="156" fill="#eef3fb" font-size="12.5">• Transfer internal ownership</text>
    <text x="504" y="180" fill="#eef3fb" font-size="12.5">• ρ, r, sk, recovery keys</text>
    <text x="504" y="214" fill="#64748b" font-size="11">* only if live set &gt; 1 and timing does not collapse it</text>
    <text x="504" y="236" fill="#64748b" font-size="11">Wallet pick order is not a chain label</text>
  </svg>`;
}
