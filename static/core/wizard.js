async function loadAlgorithmModules(slug) {
  const base = `/static/algorithms/${slug}`;
  const [validators, codegen] = await Promise.all([
    import(`${base}/validators.js`),
    import(`${base}/codegen.js`),
  ]);
  return { validators, codegen };
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
    coprimeOptions: [],
    inlineCode: "",
    stuckLevel: 0,
    walkthroughHtml: "",
    sentenceInput: "",        // bound to the input-text textarea on step 12
    playgroundSentence: "",   // ephemeral, step 15 only — not persisted
    playgroundEncoded: [],    // ephemeral derived array for the playground table
    playgroundDecoded: "",    // ephemeral derived string
    cheatFlash: false,        // brief toast shown when Konami code activates

    async init() {
      const mods = await loadAlgorithmModules(this.algorithmSlug);
      this.validators = mods.validators;
      this.codegen = mods.codegen;
      this.refreshInlineCode();
      this.maybeRefreshCoprimeOptions();
      if (this.currentStep?.slug === "done") {
        this.fullScript = this.codegen.full_script(this.state);
      }
      this._installCheatCode();
      this.persistLocal();
    },

    _installCheatCode() {
      // Konami: ↑↑↓↓←→←→BA
      const seq = ["ArrowUp", "ArrowUp", "ArrowDown", "ArrowDown",
                   "ArrowLeft", "ArrowRight", "ArrowLeft", "ArrowRight",
                   "KeyB", "KeyA"];
      let buf = [];
      document.addEventListener("keydown", (e) => {
        const tag = e.target?.tagName;
        if (tag === "INPUT" || tag === "TEXTAREA") return;  // don't intercept typing
        buf.push(e.code);
        if (buf.length > seq.length) buf.shift();
        if (buf.length === seq.length && buf.every((k, i) => k === seq[i])) {
          buf = [];
          this._activateCheat();
        }
      });
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
        import(`/static/algorithms/${this.algorithmSlug}/math.js`).then((m) => {
          this.coprimeOptions = m.coprimeCandidates(BigInt(this.state.phi), 12).map((b) => Number(b));
        });
      }
    },

    async check() {
      const step = this.currentStep;
      if (!step) return;
      let input;
      if (step.kind === "input-multi") input = { ...this.multiInput };
      else if (step.kind === "input-text") input = this.sentenceInput;
      else input = this.inputValue;
      const fn = this.validators[step.validator_key];
      const result = fn(input, this.state);
      if (!result.ok) { this.hint = result.hint; return; }
      this.hint = "";
      this.state = { ...this.state, ...result.value };
      this.refreshInlineCode();
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
