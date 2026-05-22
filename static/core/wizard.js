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

    async init() {
      const mods = await loadAlgorithmModules(this.algorithmSlug);
      this.validators = mods.validators;
      this.codegen = mods.codegen;
      this.refreshInlineCode();
      this.maybeRefreshCoprimeOptions();
      if (this.currentStep?.slug === "done") {
        this.fullScript = this.codegen.full_script(this.state);
      }
      this.persistLocal();
    },

    get currentStep() {
      return this.steps.find((s) => s.order === this.currentStepOrder);
    },
    get progressBar() {
      return this.steps.map((s) => {
        if (s.order < this.currentStepOrder) return "done";
        if (s.order === this.currentStepOrder) return "current";
        return "pending";
      });
    },
    get isLast() {
      return this.currentStepOrder >= this.steps.length;
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
      const input = step.kind === "input-multi" ? { ...this.multiInput } : this.inputValue;
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
      this.multiInput = {};
      this.hint = "";
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
        this.hint = "";
        this.refreshInlineCode();
        this.maybeRefreshCoprimeOptions();
      }
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
