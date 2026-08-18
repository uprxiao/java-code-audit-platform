(() => {
  "use strict";

  const API = "/api/v1";
  const TERMINAL = new Set(["COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED", "CANCELLED", "INTERRUPTED"]);
  const STATUS_LABELS = {
    QUEUED: "排队中", ACQUIRING_SOURCE: "接收源码", PREFLIGHT: "项目预检",
    RUNNING: "扫描中", FINALIZING: "生成报告", COMPLETED: "已完成",
    COMPLETED_WITH_ERRORS: "部分完成", FAILED: "扫描失败", CANCELLED: "已取消", INTERRUPTED: "已中断"
  };
  const PHASE_LABELS = {
    ACCEPTED: "任务已接收", SOURCE: "正在接收源码", PREFLIGHT: "正在验证项目",
    ENGINES: "正在执行扫描引擎", REPORTING: "正在归一化报告", TERMINAL: "代码审计已结束"
  };
  const ENGINE_LABELS = {
    PENDING: "等待", READY: "就绪", RUNNING: "运行中", SUCCEEDED: "完成", PARTIAL: "部分完成",
    FAILED: "失败", TIMED_OUT: "超时", SKIPPED: "跳过", CANCELLED: "取消"
  };
  const DISPOSITION_LABELS = { ACTIONABLE: "需处理", CONDITIONAL: "待确认", ADVISORY: "建议项" };

  const $ = (id) => document.getElementById(id);
  const elements = {
    form: $("scan-form"), file: $("source-file"), dropZone: $("drop-zone"), fileTitle: $("file-title"),
    fileDetail: $("file-detail"), displayName: $("display-name"), mavenProfiles: $("maven-profiles"),
    mavenProperties: $("maven-properties"), submit: $("submit-button"), formError: $("form-error"),
    health: $("service-health"), healthText: $("health-text"), emptyJob: $("empty-job"), activeJob: $("active-job"),
    clearJob: $("clear-job"), jobPanel: $("job-panel"), jobProfile: $("job-profile"), jobTitle: $("job-title"),
    jobId: $("job-id"), jobStatus: $("job-status"), phaseText: $("phase-text"), progressDetail: $("progress-detail"),
    progressPercent: $("progress-percent"), progressBar: $("progress-bar"), progressTrack: document.querySelector(".progress-track"),
    metricActionable: $("metric-actionable"), metricConditional: $("metric-conditional"), metricAdvisory: $("metric-advisory"),
    metricTotal: $("metric-total"), failureBox: $("failure-box"), failureTitle: $("failure-title"),
    failureMessage: $("failure-message"), engineList: $("engine-list"), engineCounter: $("engine-counter"),
    cancel: $("cancel-button"), refresh: $("refresh-button"), result: $("result-section"), resultCopy: $("result-copy"),
    archive: $("download-archive"), html: $("download-html"), json: $("download-json"), sarif: $("download-sarif"),
    findingList: $("finding-list"), findingNote: $("finding-preview-note"), toast: $("toast")
  };

  const state = { scanId: localStorage.getItem("audit.currentScanId") || "", timer: null, polling: false, selectedFile: null, health: null };

  function text(value, fallback = "") {
    return value === null || value === undefined || value === "" ? fallback : String(value);
  }

  function number(value) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes < 0) return "";
    if (bytes < 1024) return `${bytes} B`;
    const units = ["KB", "MB", "GB"];
    let value = bytes / 1024;
    let unit = units[0];
    for (let index = 1; value >= 1024 && index < units.length; index += 1) {
      value /= 1024;
      unit = units[index];
    }
    return `${value >= 10 ? value.toFixed(1) : value.toFixed(2)} ${unit}`;
  }

  function formatDuration(milliseconds) {
    const value = number(milliseconds);
    if (value < 1000) return value > 0 ? `${value}ms` : "";
    if (value < 60000) return `${Math.round(value / 1000)}s`;
    return `${Math.floor(value / 60000)}m ${Math.round((value % 60000) / 1000)}s`;
  }

  function errorMessage(error) {
    if (error && error.payload) {
      const code = error.payload.code ? `[${error.payload.code}] ` : "";
      return `${code}${error.payload.message || error.message}`;
    }
    return error instanceof Error ? error.message : String(error);
  }

  async function request(path, options = {}) {
    let response;
    try {
      response = await fetch(path, { cache: "no-store", ...options });
    } catch (cause) {
      throw new Error("无法连接审计服务，请确认 JAR 仍在运行。", { cause });
    }
    const contentType = response.headers.get("content-type") || "";
    const payload = contentType.includes("json") ? await response.json().catch(() => null) : null;
    if (!response.ok) {
      const error = new Error(payload?.message || `请求失败（HTTP ${response.status}）`);
      error.payload = payload;
      error.status = response.status;
      throw error;
    }
    return payload;
  }

  function showFormError(message) {
    elements.formError.textContent = message;
    elements.formError.hidden = false;
  }

  function hideFormError() {
    elements.formError.hidden = true;
    elements.formError.textContent = "";
  }

  let toastTimer;
  function toast(message) {
    clearTimeout(toastTimer);
    elements.toast.textContent = message;
    elements.toast.hidden = false;
    toastTimer = setTimeout(() => { elements.toast.hidden = true; }, 4200);
  }

  function chooseFile(file) {
    hideFormError();
    if (!file) {
      state.selectedFile = null;
      elements.dropZone.classList.remove("has-file");
      elements.fileTitle.textContent = "选择或拖入项目 ZIP";
      elements.fileDetail.textContent = "上传包内应只有一个 Maven 根项目，最大 1 GB";
      return;
    }
    if (!file.name.toLowerCase().endsWith(".zip")) {
      elements.file.value = "";
      state.selectedFile = null;
      showFormError("请选择 .zip 格式的项目压缩包。");
      return;
    }
    if (file.size <= 0) {
      showFormError("上传的 ZIP 文件不能为空。");
      return;
    }
    if (file.size > 1024 * 1024 * 1024) {
      showFormError("文件超过当前服务 1 GB 的上传上限。");
      return;
    }
    state.selectedFile = file;
    elements.dropZone.classList.add("has-file");
    elements.fileTitle.textContent = file.name;
    elements.fileDetail.textContent = `${formatBytes(file.size)} · 已准备上传`;
    if (!elements.displayName.value) elements.displayName.value = file.name.replace(/\.zip$/i, "");
  }

  function parseProperties(raw) {
    const properties = {};
    const lines = raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    for (const line of lines) {
      const separator = line.indexOf("=");
      if (separator < 1) throw new Error(`Maven 属性“${line}”必须使用 key=value 格式。`);
      const key = line.slice(0, separator).trim();
      const value = line.slice(separator + 1).trim();
      if (Object.hasOwn(properties, key)) throw new Error(`Maven 属性“${key}”重复。`);
      properties[key] = value;
    }
    return properties;
  }

  function selectedProfile() {
    return document.querySelector('input[name="profile"]:checked')?.value || "QUICK";
  }

  async function loadHealth() {
    try {
      const health = await request(`${API}/health`);
      state.health = health;
      const status = text(health.status, "DOWN").toUpperCase();
      elements.health.className = `health-chip ${status.toLowerCase()}`;
      elements.healthText.textContent = status === "UP" ? "服务与全部档位可用" : status === "DEGRADED" ? "服务可用，部分能力受限" : "服务不可用";
      const profiles = health.profiles || {};
      for (const profile of ["QUICK", "STANDARD", "DEEP"]) {
        const availability = text(profiles[profile], "UNAVAILABLE").toUpperCase();
        const input = document.querySelector(`input[name="profile"][value="${profile}"]`);
        const label = document.querySelector(`[data-profile-health="${profile}"]`);
        const available = availability === "AVAILABLE";
        input.disabled = !available;
        label.textContent = available ? "当前可用" : "当前不可用";
        label.className = `profile-availability ${available ? "available" : "unavailable"}`;
      }
      const selected = document.querySelector('input[name="profile"]:checked');
      if (!selected || selected.disabled) {
        const fallback = [...document.querySelectorAll('input[name="profile"]')].find((item) => !item.disabled);
        if (fallback) fallback.checked = true;
      }
    } catch (error) {
      elements.health.className = "health-chip down";
      elements.healthText.textContent = "无法连接服务";
      for (const label of document.querySelectorAll("[data-profile-health]")) {
        label.textContent = "未能确认";
        label.className = "profile-availability unavailable";
      }
    }
  }

  function setSubmitting(submitting) {
    elements.submit.disabled = submitting;
    elements.submit.querySelector("span").textContent = submitting ? "正在上传项目…" : "开始代码审计";
  }

  async function submitScan(event) {
    event.preventDefault();
    hideFormError();
    const file = state.selectedFile || elements.file.files[0];
    if (!file) {
      showFormError("请先选择一个 Java/Maven 项目 ZIP。");
      elements.dropZone.focus();
      return;
    }
    const profile = selectedProfile();
    const profileInput = document.querySelector(`input[name="profile"][value="${profile}"]`);
    if (profileInput?.disabled) {
      showFormError(`${profile} 档位当前不可用，请选择可用档位或检查后台工具配置。`);
      return;
    }

    let mavenProperties;
    try {
      mavenProperties = parseProperties(elements.mavenProperties.value);
    } catch (error) {
      showFormError(error.message);
      return;
    }
    const mavenProfiles = elements.mavenProfiles.value.split(",").map((item) => item.trim()).filter(Boolean);
    const scanRequest = { displayName: elements.displayName.value.trim(), profile, mavenProfiles, mavenProperties };
    const formData = new FormData();
    formData.append("source", file, file.name);
    formData.append("request", new Blob([JSON.stringify(scanRequest)], { type: "application/json" }), "request.json");

    setSubmitting(true);
    try {
      const created = await request(`${API}/scans/zip`, { method: "POST", body: formData });
      state.scanId = created.scanId;
      localStorage.setItem("audit.currentScanId", state.scanId);
      localStorage.setItem(`audit.scanName.${state.scanId}`, scanRequest.displayName || file.name);
      showJob();
      renderCreated(created);
      toast("项目已上传，审计任务已进入队列。");
      await pollScan(true);
      elements.jobPanel.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
      showFormError(errorMessage(error));
    } finally {
      setSubmitting(false);
    }
  }

  function showJob() {
    elements.emptyJob.hidden = true;
    elements.activeJob.hidden = false;
    elements.clearJob.hidden = false;
    elements.jobPanel.classList.remove("idle");
  }

  function renderCreated(created) {
    elements.jobProfile.textContent = text(created.profile, selectedProfile());
    elements.jobTitle.textContent = localStorage.getItem(`audit.scanName.${created.scanId}`) || "代码审计任务";
    elements.jobId.textContent = created.scanId;
    elements.jobStatus.textContent = STATUS_LABELS[created.status] || created.status;
    renderEngines((created.plannedEngines || []).map((engineId) => ({ engineId, status: "PENDING" })));
  }

  function statusClass(status) {
    if (status === "COMPLETED") return "success";
    if (status === "COMPLETED_WITH_ERRORS") return "warning";
    if (["FAILED", "CANCELLED", "INTERRUPTED"].includes(status)) return "error";
    return "";
  }

  function calculateProgress(view) {
    const progress = view.progress || {};
    const total = number(progress.enginesTotal);
    const terminal = number(progress.enginesTerminal);
    if (view.status === "COMPLETED" || view.status === "COMPLETED_WITH_ERRORS") return 100;
    if (["FAILED", "CANCELLED", "INTERRUPTED"].includes(view.status)) return total ? Math.round((terminal / total) * 100) : 0;
    if (view.status === "FINALIZING") return 96;
    if (!total) return 4;
    return Math.min(94, Math.max(7, Math.round((terminal / total) * 88) + (number(progress.enginesRunning) ? 4 : 0)));
  }

  function renderView(view) {
    showJob();
    elements.jobProfile.textContent = text(view.profile, "QUICK");
    elements.jobTitle.textContent = localStorage.getItem(`audit.scanName.${view.scanId}`) || "代码审计任务";
    elements.jobId.textContent = view.scanId;
    elements.jobStatus.textContent = STATUS_LABELS[view.status] || view.status;
    elements.jobStatus.className = `status-badge ${statusClass(view.status)}`;

    const progress = view.progress || {};
    const percent = calculateProgress(view);
    elements.phaseText.textContent = PHASE_LABELS[view.phase] || STATUS_LABELS[view.status] || "正在处理";
    elements.progressDetail.textContent = `${number(progress.enginesTerminal)} / ${number(progress.enginesTotal)} 个引擎已终止，${number(progress.enginesRunning)} 个正在运行`;
    elements.progressPercent.textContent = `${percent}%`;
    elements.progressBar.style.width = `${percent}%`;
    elements.progressTrack.setAttribute("aria-valuenow", String(percent));
    elements.progressTrack.classList.toggle("indeterminate", ["QUEUED", "ACQUIRING_SOURCE", "PREFLIGHT"].includes(view.status) && number(progress.enginesTotal) === 0);

    const summary = view.summary || {};
    elements.metricActionable.textContent = number(summary.actionableFindingCount);
    elements.metricConditional.textContent = number(summary.conditionalFindingCount);
    elements.metricAdvisory.textContent = number(summary.advisoryFindingCount);
    elements.metricTotal.textContent = number(summary.uniqueFindingCount);

    const failed = ["FAILED", "CANCELLED", "INTERRUPTED"].includes(view.status);
    elements.failureBox.hidden = !failed;
    if (failed) {
      elements.failureTitle.textContent = view.status === "CANCELLED" ? "任务已取消" : view.status === "INTERRUPTED" ? "任务被中断" : text(view.failure?.code, "扫描失败");
      elements.failureMessage.textContent = text(view.failure?.message, "可在后端日志中查看详细原因。");
    }

    const terminal = TERMINAL.has(view.status);
    elements.cancel.disabled = terminal;
    elements.cancel.hidden = terminal;
    if (view.links && view.links.archive) renderReports(view);
    else elements.result.hidden = true;
  }

  function renderEngines(engines) {
    elements.engineList.replaceChildren();
    const terminal = engines.filter((engine) => ["SUCCEEDED", "PARTIAL", "FAILED", "TIMED_OUT", "SKIPPED", "CANCELLED"].includes(engine.status)).length;
    elements.engineCounter.textContent = `${terminal} / ${engines.length} 完成`;
    if (!engines.length) {
      const empty = document.createElement("div");
      empty.className = "finding-empty";
      empty.textContent = "引擎计划正在准备。";
      elements.engineList.append(empty);
      return;
    }
    for (const engine of engines) {
      const item = document.createElement("div");
      item.className = "engine-item";
      item.title = engine.failure?.message || `${engine.engineId}: ${ENGINE_LABELS[engine.status] || engine.status}`;
      const stateDot = document.createElement("span");
      stateDot.className = `engine-state ${text(engine.status).toLowerCase()}`;
      const name = document.createElement("span");
      name.className = "engine-name";
      name.textContent = engine.engineId;
      const duration = document.createElement("span");
      duration.className = "engine-duration";
      duration.textContent = formatDuration(engine.durationMillis) || ENGINE_LABELS[engine.status] || engine.status;
      item.append(stateDot, name, duration);
      elements.engineList.append(item);
    }
  }

  function reportLink(view, type) {
    return view.links?.[type] || `${API}/scans/${view.scanId}/reports/${type}`;
  }

  function renderReports(view) {
    elements.archive.href = reportLink(view, "archive");
    elements.html.href = reportLink(view, "html");
    elements.json.href = reportLink(view, "json");
    elements.sarif.href = reportLink(view, "sarif");
    elements.result.hidden = false;
    const summary = view.summary || {};
    const count = number(summary.uniqueFindingCount);
    elements.resultCopy.textContent = count
      ? `共归一化出 ${count} 个问题，其中 ${number(summary.actionableFindingCount)} 个建议优先处理。`
      : "本次扫描未发现需要报告的问题，仍可下载完整覆盖报告。";
  }

  function renderFindings(findings, total) {
    elements.findingList.replaceChildren();
    elements.findingNote.textContent = total > findings.length ? `显示 ${findings.length} / ${total} 项` : `共 ${total} 项`;
    if (!findings.length) {
      const empty = document.createElement("div");
      empty.className = "finding-empty";
      empty.textContent = "未发现需展示的问题。请查看报告了解扫描覆盖情况。";
      elements.findingList.append(empty);
      return;
    }
    for (const finding of findings) {
      const item = document.createElement("div");
      item.className = "finding-item";
      const severity = document.createElement("span");
      severity.className = `severity ${text(finding.severity, "P3").toLowerCase()}`;
      severity.textContent = text(finding.severity, "P3");
      const content = document.createElement("span");
      content.className = "finding-content";
      const title = document.createElement("strong");
      title.textContent = text(finding.titleZh, finding.titleOriginal || "未命名问题");
      const meta = document.createElement("small");
      const location = finding.location ? `${finding.location.path}:${finding.location.startLine}` : text(finding.module, "项目级");
      const engine = finding.evidence?.[0]?.engine || finding.ruleFamily || "scanner";
      meta.textContent = `${engine} · ${location}`;
      content.append(title, meta);
      const disposition = finding.governance?.disposition || "ACTIONABLE";
      const badge = document.createElement("span");
      badge.className = `finding-disposition ${disposition.toLowerCase()}`;
      badge.textContent = DISPOSITION_LABELS[disposition] || disposition;
      item.append(severity, content, badge);
      elements.findingList.append(item);
    }
  }

  async function loadFindings(view) {
    try {
      const findings = await request(`${API}/scans/${view.scanId}/findings?page=0&size=12`);
      renderFindings(Array.isArray(findings) ? findings : [], number(view.summary?.uniqueFindingCount));
    } catch (error) {
      renderFindings([], 0);
      toast(`问题预览加载失败：${errorMessage(error)}`);
    }
  }

  async function pollScan(immediate = false) {
    clearTimeout(state.timer);
    if (!state.scanId || state.polling) return;
    state.polling = true;
    try {
      const [view, engines] = await Promise.all([
        request(`${API}/scans/${state.scanId}`),
        request(`${API}/scans/${state.scanId}/engines`).catch(() => [])
      ]);
      renderView(view);
      renderEngines(Array.isArray(engines) ? engines : []);
      if (TERMINAL.has(view.status)) {
        if (view.links?.archive) await loadFindings(view);
        return;
      }
      state.timer = setTimeout(() => pollScan(), immediate ? 800 : 1700);
    } catch (error) {
      if (error.status === 404 || error.status === 410) {
        clearCurrentJob(false);
      }
      toast(errorMessage(error));
      if (state.scanId) state.timer = setTimeout(() => pollScan(), 3500);
    } finally {
      state.polling = false;
    }
  }

  async function cancelScan() {
    if (!state.scanId || elements.cancel.disabled) return;
    elements.cancel.disabled = true;
    try {
      const view = await request(`${API}/scans/${state.scanId}/cancel`, { method: "POST" });
      renderView(view);
      toast("取消请求已提交。");
      await pollScan(true);
    } catch (error) {
      elements.cancel.disabled = false;
      toast(errorMessage(error));
    }
  }

  function clearCurrentJob(showMessage = true) {
    clearTimeout(state.timer);
    state.scanId = "";
    state.polling = false;
    localStorage.removeItem("audit.currentScanId");
    elements.emptyJob.hidden = false;
    elements.activeJob.hidden = true;
    elements.clearJob.hidden = true;
    elements.result.hidden = true;
    elements.engineList.replaceChildren();
    if (showMessage) toast("已清除当前页面的任务记录，后端任务和报告不会被删除。");
  }

  elements.file.addEventListener("change", () => chooseFile(elements.file.files[0]));
  elements.dropZone.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); elements.file.click(); }
  });
  for (const name of ["dragenter", "dragover"]) {
    elements.dropZone.addEventListener(name, (event) => { event.preventDefault(); elements.dropZone.classList.add("dragging"); });
  }
  for (const name of ["dragleave", "drop"]) {
    elements.dropZone.addEventListener(name, (event) => { event.preventDefault(); elements.dropZone.classList.remove("dragging"); });
  }
  elements.dropZone.addEventListener("drop", (event) => {
    const file = event.dataTransfer?.files?.[0];
    if (file) chooseFile(file);
  });
  elements.form.addEventListener("submit", submitScan);
  elements.cancel.addEventListener("click", cancelScan);
  elements.refresh.addEventListener("click", () => pollScan(true));
  elements.clearJob.addEventListener("click", () => clearCurrentJob());

  for (const link of [elements.archive, elements.html, elements.json, elements.sarif]) {
    link.addEventListener("click", () => toast("报告下载已开始。"));
  }

  loadHealth();
  if (state.scanId) {
    showJob();
    elements.jobId.textContent = state.scanId;
    elements.jobTitle.textContent = localStorage.getItem(`audit.scanName.${state.scanId}`) || "正在恢复上次任务";
    pollScan(true);
  }
})();
