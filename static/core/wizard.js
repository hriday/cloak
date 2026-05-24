async function loadAlgorithmModules(slug) {
  const base = `/static/algorithms/${slug}`;
  // Cache-bust per page load. Chromium aggressively caches ES modules and a
  // normal reload doesn't refetch them; without this, validators.js stays
  // stale across deploys until the user hard-refreshes.
  const v = `?v=${(window.CLOAK_ASSETS_VERSION || Date.now())}`;
  const [validators, codegen] = await Promise.all([
    import(`${base}/validators.js${v}`),
    import(`${base}/codegen.js${v}`),
  ]);
  let tables = null;
  try { tables = await import(`${base}/tables.js${v}`); } catch (_e) { /* not all algorithms have tables */ }
  return { validators, codegen, tables };
}

function wizardComponent(initial) {
  return {
    algorithmSlug: initial.algorithmSlug,
    lessonSlug: initial.lessonSlug,
    steps: initial.steps,
    state: initial.state || {},
    currentStepOrder: initial.currentStepOrder || 1,
    inputValue: "",
    multiInput: {},
    hint: "",
    fullScriptOpen: false,
    fullScript: "",
    validators: null,
    codegen: null,
    tables: null,
    aesSBOX: [],
    aesOneRoundStates: [],
    coprimeOptions: [],
    inlineCode: "",
    stuckLevel: 0,
    walkthroughHtml: "",
    sentenceInput: "",        // bound to the input-text textarea on step 12
    playgroundSentence: "",   // ephemeral, step 15 only — not persisted
    playgroundEncoded: [],    // ephemeral derived array for the playground table
    playgroundDecoded: "",    // ephemeral derived string
    cheatFlash: false,        // brief toast shown when Konami code activates
    _cheatInstalled: false,   // guards _installCheatCode against double-install

    async init() {
      const mods = await loadAlgorithmModules(this.algorithmSlug);
      this.validators = mods.validators;
      this.codegen = mods.codegen;
      this.tables = mods.tables;
      if (mods.tables?.SBOX) this.aesSBOX = mods.tables.SBOX;
      if (mods.tables?.SBOX && mods.tables?.mixColumn) {
        this.aesOneRoundStates = this._computeOneRound(mods.tables);
      }
      this.refreshInlineCode();
      this.maybeRefreshCoprimeOptions();
      if (this.currentStep?.slug === "done") {
        this.fullScript = this.codegen.full_script(this.state);
        if (!this.playgroundSentence && this.state.sentence) {
          this.playgroundSentence = this.state.sentence;
          this.recomputePlayground();
        }
      }
      this._installCheatCode();
      this.persistLocal();
    },

    _installCheatCode() {
      if (this._cheatInstalled) return;
      this._cheatInstalled = true;
      // Konami: ↑↑↓↓←→←→BA. Match against `event.key` (the actual character
      // typed, layout-aware) rather than `event.code` (the physical QWERTY
      // position), so Dvorak / Colemak / international layouts work too.
      const seq = ["ArrowUp", "ArrowUp", "ArrowDown", "ArrowDown",
                   "ArrowLeft", "ArrowRight", "ArrowLeft", "ArrowRight",
                   "b", "a"];
      let buf = [];
      document.addEventListener("keydown", (e) => {
        const tag = e.target?.tagName;
        if (tag === "INPUT" || tag === "TEXTAREA") return;  // don't intercept typing
        // Single-char keys → lowercase; named keys (ArrowUp etc.) → as-is
        const k = e.key.length === 1 ? e.key.toLowerCase() : e.key;
        buf.push(k);
        if (buf.length > seq.length) buf.shift();
        if (buf.length === seq.length && buf.every((kk, i) => kk === seq[i])) {
          buf = [];
          this._activateCheat();
        }
      });
    },

    _computeOneRound(tables) {
      const { SBOX, mixColumn } = tables;
      // Fixed lesson input (16 bytes) — using a memorable byte pattern
      const input = [0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31, 0x37, 0xf6, 0x30, 0x98, 0x07, 0xa8, 0x8d, 0xa2, 0x34];
      // Fixed round key — for clarity (matches Add-Round-Key step's key byte)
      const roundKey = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
      // 1. SubBytes
      const afterSub = input.map((b) => SBOX[b]);
      // 2. ShiftRows: state laid out row-major for visualization; shift row i by i.
      const afterShift = [...afterSub];
      // row 1: indices 4,5,6,7 → shift left by 1 → 5,6,7,4
      [afterShift[4], afterShift[5], afterShift[6], afterShift[7]] = [afterSub[5], afterSub[6], afterSub[7], afterSub[4]];
      // row 2: indices 8,9,10,11 → shift left by 2 → 10,11,8,9
      [afterShift[8], afterShift[9], afterShift[10], afterShift[11]] = [afterSub[10], afterSub[11], afterSub[8], afterSub[9]];
      // row 3: indices 12,13,14,15 → shift left by 3 → 15,12,13,14
      [afterShift[12], afterShift[13], afterShift[14], afterShift[15]] = [afterSub[15], afterSub[12], afterSub[13], afterSub[14]];
      // 3. MixColumns: 4 columns, each [row0, row1, row2, row3]
      const afterMix = [...afterShift];
      for (let c = 0; c < 4; c++) {
        const col = [afterShift[c], afterShift[c + 4], afterShift[c + 8], afterShift[c + 12]];
        const mixed = mixColumn(col);
        afterMix[c] = mixed[0];
        afterMix[c + 4] = mixed[1];
        afterMix[c + 8] = mixed[2];
        afterMix[c + 12] = mixed[3];
      }
      // 4. AddRoundKey
      const afterArk = afterMix.map((b, i) => b ^ roundKey[i]);
      return [input, afterSub, afterShift, afterMix, afterArk];
    },

    _activateCheat() {
      const fn = this.validators?.cheatState;
      if (typeof fn !== "function") return;
      const { targetStepOrder, state } = fn();
      this.state = { ...this.state, ...state };
      this.currentStepOrder = targetStepOrder;
      this.inputValue = "";
      this.sentenceInput = "";
      this.multiInput = {};
      this.hint = "";
      this.stuckLevel = 0;
      this.walkthroughHtml = "";
      this.refreshInlineCode();
      this.cheatFlash = true;
      setTimeout(() => { this.cheatFlash = false; }, 2500);
      this.persistLocal();
      this.syncServer();
    },

    get currentStep() {
      return this.steps.find((s) => s.order === this.currentStepOrder);
    },
    get progressBar() {
      const hasOptedIn = this.currentStepOrder > 10 || !!this.state.sentence;
      const total = hasOptedIn ? this.steps.length : Math.min(10, this.steps.length);
      const visible = this.steps.slice(0, total);
      return visible.map((s) => {
        if (s.order < this.currentStepOrder) return "done";
        if (s.order === this.currentStepOrder) return "current";
        return "pending";
      });
    },
    get displayedStepTotal() {
      const hasOptedIn = this.currentStepOrder > 10 || !!this.state.sentence;
      return hasOptedIn ? this.steps.length : Math.min(10, this.steps.length);
    },
    get isLast() {
      return this.currentStepOrder >= this.steps.length;
    },
    get conversionRows() {
      // Used by step 12 (live as user types), 13–14 (locked sentence + encrypted), and 15 (playground).
      const slug = this.currentStep?.slug;
      let source, encArray;
      if (slug === "type-sentence") {
        source = this.sentenceInput; encArray = [];
      } else if (slug === "done") {
        source = this.playgroundSentence; encArray = this.playgroundEncoded;
      } else {
        source = this.state.sentence || ""; encArray = this.state.encrypted || [];
      }
      if (!source) return [];
      const rows = [];
      for (let i = 0; i < source.length; i++) {
        const code = source.charCodeAt(i);
        rows.push({
          ch: source[i],
          code,
          bin: code.toString(2).padStart(8, "0"),
          enc: encArray[i] !== undefined ? encArray[i] : null,
        });
      }
      return rows;
    },
    get messageRoundtrip() {
      // Shows the message at each stage: original text, encrypted as a single string,
      // and (when available) the decrypted recovery. On the playground (step 15) we
      // derive from playgroundSentence/Encoded/Decoded; elsewhere from locked state.
      const slug = this.currentStep?.slug;
      const onPlayground = slug === "done";
      const original = onPlayground ? this.playgroundSentence : (this.state.sentence || "");
      const encArray = onPlayground ? this.playgroundEncoded : (this.state.encrypted || []);
      if (!original || !Array.isArray(encArray) || encArray.length === 0) return null;
      const encrypted = encArray.join(", ");
      let decrypted = null;
      if (onPlayground) {
        decrypted = this.playgroundDecoded || null;
      } else if (this.state.decrypted) {
        decrypted = this.state.decrypted;
      }
      return { original, encrypted, decrypted };
    },
    get recoveredText() {
      // Used by step 14 (decrypt-sentence) to show the actual roundtrip.
      // Decrypts state.encrypted with d2/n2 and assembles the string.
      const enc = this.state.encrypted;
      if (!Array.isArray(enc) || !this.state.d2 || !this.state.n2) return "";
      const d2 = BigInt(this.state.d2), n2 = BigInt(this.state.n2);
      const modPow = (base, exp, mod) => {
        let r = 1n; base = ((base % mod) + mod) % mod;
        while (exp > 0n) { if (exp & 1n) r = (r * base) % mod; exp >>= 1n; base = (base * base) % mod; }
        return r;
      };
      return enc.map((c) => String.fromCharCode(Number(modPow(BigInt(c), d2, n2)))).join("");
    },
    get recoveredMatchesOriginal() {
      return this.recoveredText === (this.state.sentence || "");
    },

    refreshInlineCode() {
      const step = this.currentStep;
      if (!step || !this.codegen) { this.inlineCode = ""; return; }
      const fn = this.codegen[step.codegen_key];
      this.inlineCode = (fn && this.stepValuesPresent(step)) ? fn(this.state) : "";
    },

    substituteState(html) {
      if (!html) return "";
      return html.replace(/\{\{\s*state\.(\w+)\s*\}\}/g, (_, key) =>
        key in this.state ? String(this.state[key]) : "_"
      );
    },

    stepValuesPresent(step) {
      const map = {
        pick_pq: ["p", "q"], compute_n: ["n"], compute_phi: ["phi"],
        pick_e: ["e"], compute_d: ["d"], pick_message: ["m"],
        encrypt: ["c"], decrypt: ["m_decrypted"], info: [],
        encode_sentence: ["sentence", "e2", "n2"],
      };
      const keys = map[step.codegen_key] || [];
      return keys.every((k) => k in this.state);
    },

    maybeRefreshCoprimeOptions() {
      if (this.currentStep?.kind === "choose-from-list" && this.currentStep.slug === "pick-e" && "phi" in this.state) {
        const v = `?v=${(window.CLOAK_ASSETS_VERSION || Date.now())}`;
        import(`/static/algorithms/${this.algorithmSlug}/math.js${v}`).then((m) => {
          this.coprimeOptions = m.coprimeCandidates(BigInt(this.state.phi), 12).map((b) => Number(b));
        });
      }
    },

    async check() {
      const step = this.currentStep;
      if (!step) return;
      let input;
      // simulated-hsm has kind='input-text' but the UI is multi-field (op + message + signature),
      // so route it through multiInput like the input-multi kinds.
      if (step.kind === "input-multi" || step.slug === "simulated-hsm") input = { ...this.multiInput };
      else if (step.kind === "input-text") input = this.sentenceInput;
      else input = this.inputValue;
      const fn = this.validators[step.validator_key];
      const result = await fn(input, this.state);
      if (!result.ok) { this.hint = result.hint; return; }
      this.hint = "";
      this.state = { ...this.state, ...result.value };
      this.refreshInlineCode();
      // simulated-hsm is exploratory — let the user run sign/verify multiple times
      // before manually advancing via the Continue button.
      if (step.slug === "simulated-hsm") {
        this.persistLocal();
        this.syncServer();
        return;
      }
      this.advance();
    },

    advance() {
      if (this.currentStepOrder < this.steps.length) {
        this.currentStepOrder += 1;
      } else {
        this.currentStepOrder = this.steps.length;
      }
      this.inputValue = "";
      this.sentenceInput = "";
      this.multiInput = {};
      this.hint = "";
      this.stuckLevel = 0;
      this.walkthroughHtml = "";
      this.refreshInlineCode();
      this.maybeRefreshCoprimeOptions();
      if (this.currentStep?.slug === "done" && this.codegen) {
        this.fullScript = this.codegen.full_script(this.state);
        // Pre-populate the playground with the locked sentence so the user
        // immediately sees their full encrypt/decrypt roundtrip on arrival.
        if (!this.playgroundSentence && this.state.sentence) {
          this.playgroundSentence = this.state.sentence;
          this.recomputePlayground();
        }
      }
      this.persistLocal();
      this.syncServer();
    },

    back() {
      if (this.currentStepOrder > 1) {
        this.currentStepOrder -= 1;
        this.inputValue = "";
        this.sentenceInput = "";
        this.hint = "";
        this.stuckLevel = 0;
        this.walkthroughHtml = "";
        this.refreshInlineCode();
        this.maybeRefreshCoprimeOptions();
      }
    },

    hasWalkthrough() {
      const step = this.currentStep;
      if (!step || !this.validators?.walkthroughs) return false;
      return typeof this.validators.walkthroughs[step.validator_key] === "function";
    },

    walkthroughLabel() {
      // Escalating label costs the learner a little more pride per click.
      return ["I don't know how", "Still stuck", "Just show me"][this.stuckLevel] || "";
    },

    showWalkthrough() {
      const step = this.currentStep;
      const fn = this.validators?.walkthroughs?.[step?.validator_key];
      if (!fn) return;
      let rungs;
      try { rungs = fn(this.state); } catch (_e) { return; }
      if (!Array.isArray(rungs) || rungs.length === 0) return;
      const idx = Math.min(this.stuckLevel, rungs.length - 1);
      const accumulated = rungs.slice(0, idx + 1).join("\n\n");
      // Tiny markdown: **bold** + newlines → <br>. Escape HTML first.
      const escape = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
      this.walkthroughHtml = escape(accumulated)
        .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
        .replace(/\n/g, "<br>");
      if (this.stuckLevel < rungs.length - 1) this.stuckLevel += 1;
    },

    showFullScript() {
      this.fullScript = this.codegen.full_script(this.state);
      this.fullScriptOpen = true;
    },

    copyFullScript() {
      navigator.clipboard.writeText(this.fullScript);
    },

    downloadFullScript() {
      const blob = new Blob([this.fullScript], { type: "text/x-python" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `${this.algorithmSlug}_lesson.py`; a.click();
      URL.revokeObjectURL(url);
    },

    recomputePlayground() {
      const s = this.playgroundSentence || "";
      if (!s || !this.state.e2 || !this.state.d2 || !this.state.n2) {
        this.playgroundEncoded = []; this.playgroundDecoded = ""; return;
      }
      // Reject non-printable or oversize input; show invalid marker rather than half-encrypting
      for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        if (c < 32 || c > 126 || s.length > 500) {
          this.playgroundEncoded = []; this.playgroundDecoded = "(invalid input)"; return;
        }
      }
      const e2 = BigInt(this.state.e2), n2 = BigInt(this.state.n2), d2 = BigInt(this.state.d2);
      // Local modPow (the validators module's modPow isn't directly exposed on this.validators).
      const modPow = (base, exp, mod) => {
        let r = 1n; base = ((base % mod) + mod) % mod;
        while (exp > 0n) { if (exp & 1n) r = (r * base) % mod; exp >>= 1n; base = (base * base) % mod; }
        return r;
      };
      const enc = [];
      for (let i = 0; i < s.length; i++) enc.push(Number(modPow(BigInt(s.charCodeAt(i)), e2, n2)));
      this.playgroundEncoded = enc;
      this.playgroundDecoded = enc.map((c) => String.fromCharCode(Number(modPow(BigInt(c), d2, n2)))).join("");
    },

    persistLocal() {
      const key = `cloak.progress.${this.algorithmSlug}.${this.lessonSlug}`;
      localStorage.setItem(key, JSON.stringify({
        state: this.state,
        current_step_order: this.currentStepOrder,
        updated_at: new Date().toISOString(),
      }));
    },

    async syncServer() {
      if (!initial.loggedIn) return;
      const csrf = document.querySelector("meta[name=csrf-token]")?.content;
      await fetch(`/api/progress/${this.algorithmSlug}/${this.lessonSlug}/`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrf },
        body: JSON.stringify({ state: this.state, current_step_order: this.currentStepOrder }),
      });
    },
  };
}

window.wizardComponent = wizardComponent;
