// SQL editor of the dbgateway web UI (/console).
//
// Progressive enhancement: the page is a plain form that works without
// JavaScript. This script replaces the <textarea> with CodeMirror (syntax
// highlighting, completion from the schema the viewer may see, Mod-Enter
// to run), adds tabs whose drafts stay in this browser, lets the schema
// panel insert names, and sorts result tables. Nothing here is a security
// boundary: every statement still goes through the gateway on the server.

import { EditorState, Compartment } from "@codemirror/state";
import {
  EditorView, keymap, lineNumbers, highlightActiveLine, highlightActiveLineGutter,
  drawSelection, placeholder,
} from "@codemirror/view";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { bracketMatching, indentOnInput, syntaxHighlighting, HighlightStyle } from "@codemirror/language";
import { autocompletion, completionKeymap, closeBrackets, closeBracketsKeymap } from "@codemirror/autocomplete";
import { sql, PostgreSQL, MySQL } from "@codemirror/lang-sql";
import { tags } from "@lezer/highlight";


function readJSON(id) {
  const el = document.getElementById(id);
  if (!el) return null;
  try { return JSON.parse(el.textContent); } catch { return null; }
}

// Browser storage can be missing or throw (private windows, blocked
// site data); the editor then works without remembering drafts.
const store = {
  get(area, key) { try { return JSON.parse(window[area].getItem(key)); } catch { return null; } },
  set(area, key, v) { try { window[area].setItem(key, JSON.stringify(v)); } catch { /* ignore */ } },
};

const highlight = HighlightStyle.define([
  { tag: tags.keyword, color: "var(--cm-keyword)" },
  { tag: [tags.number, tags.bool, tags.null], color: "var(--cm-number)" },
  { tag: [tags.string, tags.special(tags.string)], color: "var(--cm-string)" },
  { tag: [tags.comment, tags.lineComment, tags.blockComment], color: "var(--cm-comment)", fontStyle: "italic" },
  { tag: [tags.operator, tags.punctuation], color: "var(--cm-punct)" },
  { tag: tags.typeName, color: "var(--cm-type)" },
]);

const theme = EditorView.theme({
  "&": { fontSize: "13.5px", backgroundColor: "var(--surface)", color: "var(--text)" },
  "&.cm-focused": { outline: "none" },
  ".cm-scroller": { fontFamily: "var(--mono)", lineHeight: "1.75", minHeight: "11em", maxHeight: "50vh" },
  ".cm-content": { padding: "12px 0", caretColor: "var(--text)" },
  ".cm-gutters": { backgroundColor: "var(--surface-2)", color: "var(--text-faint)", border: "none", borderRight: "1px solid var(--border-subtle)" },
  ".cm-activeLine": { backgroundColor: "var(--cm-active-line)" },
  ".cm-activeLineGutter": { backgroundColor: "var(--cm-active-line)" },
  "&.cm-focused .cm-selectionBackground, .cm-selectionBackground": { backgroundColor: "var(--cm-selection) !important" },
  ".cm-matchingBracket": { backgroundColor: "var(--cm-selection)", outline: "1px solid var(--accent)" },
  ".cm-placeholder": { color: "var(--text-faint)" },
  ".cm-tooltip": { border: "1px solid var(--border)", borderRadius: "8px", backgroundColor: "var(--surface)", boxShadow: "var(--shadow)" },
  ".cm-tooltip-autocomplete > ul": { fontFamily: "var(--sans)", maxHeight: "16em" },
  ".cm-tooltip-autocomplete > ul > li": { padding: "4px 8px !important" },
  ".cm-tooltip-autocomplete > ul > li[aria-selected]": { backgroundColor: "var(--accent-soft)", color: "var(--text)" },
  ".cm-completionDetail": { color: "var(--text-muted)", fontStyle: "normal", marginLeft: "1em" },
});

function init(root) {
  const form = document.getElementById("console-form");
  const textarea = document.getElementById("sql-editor");
  const dbSelect = document.getElementById("db-run");
  const reason = document.getElementById("sql-reason");
  const runSQL = form && form.querySelector("input[name=run_sql]");
  const runBtn = form && form.querySelector("button[value=run]");
  const explainBtn = form && form.querySelector("button[value=explain]");
  if (!form || !textarea || !dbSelect || !reason) return;

  const text = readJSON("console-text") || {};
  const schema = readJSON("console-schema") || { dialect: "postgres", tables: {} };
  const key = "dbgw.console." + (root.dataset.storageKey || "default");
  const pageDB = root.dataset.db;
  const posted = root.dataset.posted === "1";
  const prefill = root.dataset.prefill || "";

  // --- tabs (drafts in this browser) ---
  let state = store.get("localStorage", key);
  if (!state || !Array.isArray(state.tabs) || state.tabs.length === 0) {
    state = { active: null, tabs: [] };
  }
  const newTab = (fields) => {
    const n = state.tabs.reduce((m, t) => Math.max(m, t.n || 0), 0) + 1;
    const t = { id: "t" + Date.now().toString(36) + Math.random().toString(36).slice(2, 6), n,
      name: fields.name || (text.tab || "Query %d").replace("%d", n),
      sql: fields.sql || "", db: fields.db || pageDB, reason: fields.reason || "" };
    state.tabs.push(t);
    state.active = t.id;
    return t;
  };
  const current = () => state.tabs.find((t) => t.id === state.active) || state.tabs[0];
  const fromForm = { sql: textarea.value, db: dbSelect.value, reason: reason.value };

  if (state.tabs.length === 0) {
    newTab(fromForm);
  } else if (posted) {
    // The page shows the result of the tab that was submitted.
    const id = store.get("sessionStorage", key + ".submitted");
    const t = state.tabs.find((x) => x.id === id) || current();
    Object.assign(t, fromForm);
    state.active = t.id;
  } else if (prefill) {
    // Opened from history or a saved query: a new tab with its contents.
    newTab({ ...fromForm, name: root.dataset.prefillName || "" });
  }
  let tab = current();
  state.active = tab.id;
  // A tab remembers its database; the schema panel follows the page's.
  if (!posted && !prefill && tab.db !== pageDB && hasOption(dbSelect, tab.db)) {
    store.set("localStorage", key, state);
    location.replace("/console?db=" + encodeURIComponent(tab.db));
    return;
  }
  tab.db = pageDB;
  const save = () => store.set("localStorage", key, state);
  save();

  // --- CodeMirror ---
  const tables = {};
  for (const [name, cols] of Object.entries(schema.tables || {})) {
    tables[name] = cols.map((c) => ({
      label: c.name, type: "property",
      detail: c.type + (c.class === "masked" ? " · " + (text.masked || "masked") : c.class === "no_ai" ? " · " + (text.noAI || "no AI") : ""),
    }));
  }
  const language = new Compartment();
  const runKeys = [
    { key: "Mod-Enter", preventDefault: true, run: () => { submit("run"); return true; } },
    { key: "Mod-Shift-Enter", preventDefault: true, run: () => { submit("explain"); return true; } },
  ];
  const view = new EditorView({
    parent: textarea.parentNode,
    state: EditorState.create({
      doc: tab.sql,
      extensions: [
        keymap.of(runKeys),
        EditorView.cspNonce.of(document.querySelector("meta[name=dbgw-style-nonce]")?.content || ""),
        lineNumbers(), highlightActiveLineGutter(), highlightActiveLine(), history(), drawSelection(),
        indentOnInput(), bracketMatching(), closeBrackets(), autocompletion({ icons: false }),
        syntaxHighlighting(highlight), theme, EditorView.lineWrapping, placeholder(textarea.placeholder || ""),
        language.of(sql({ dialect: schema.dialect === "mysql" ? MySQL : PostgreSQL, schema: tables, upperCaseKeywords: true })),
        keymap.of([...closeBracketsKeymap, ...defaultKeymap, ...historyKeymap, ...completionKeymap, indentWithTab]),
        EditorView.contentAttributes.of({ "aria-label": "SQL", "aria-multiline": "true" }),
        EditorView.updateListener.of((u) => {
          if (u.docChanged) { tab.sql = u.state.doc.toString(); textarea.value = tab.sql; saveSoon(); }
        }),
      ],
    }),
  });
  textarea.parentNode.insertBefore(view.dom, textarea);
  textarea.hidden = true;
  textarea.required = false;
  textarea.value = tab.sql;
  reason.value = tab.reason;
  root.classList.add("enhanced");

  let timer = 0;
  function saveSoon() { clearTimeout(timer); timer = setTimeout(save, 300); }
  reason.addEventListener("input", () => { tab.reason = reason.value; saveSoon(); });
  dbSelect.addEventListener("change", () => {
    tab.db = dbSelect.value;
    save();
    location.assign("/console?db=" + encodeURIComponent(dbSelect.value));
  });

  function submit(action) {
    const btn = action === "explain" ? explainBtn : runBtn;
    if (btn) form.requestSubmit(btn);
  }
  form.addEventListener("submit", () => {
    textarea.value = view.state.doc.toString();
    const sel = view.state.selection.main;
    if (runSQL) runSQL.value = sel.empty ? "" : view.state.sliceDoc(sel.from, sel.to);
    tab.sql = textarea.value;
    tab.reason = reason.value;
    save();
    store.set("sessionStorage", key + ".submitted", tab.id);
  });

  // The result below belongs to the tab that produced it.
  const result = document.getElementById("console-result");
  if (result) result.dataset.tab = posted ? tab.id : "";
  const showResult = () => { if (result) result.hidden = result.dataset.tab !== "" && result.dataset.tab !== tab.id; };

  // --- tab strip ---
  const strip = document.getElementById("editor-tabs");
  function renderTabs() {
    if (!strip) return;
    strip.replaceChildren();
    for (const t of state.tabs) {
      const item = document.createElement("div");
      item.className = "editor-tab" + (t.id === tab.id ? " is-active" : "");
      const b = document.createElement("button");
      b.type = "button";
      b.setAttribute("role", "tab");
      b.setAttribute("aria-selected", String(t.id === tab.id));
      b.textContent = t.name;
      b.title = text.rename || "";
      b.addEventListener("click", () => switchTo(t.id));
      b.addEventListener("dblclick", () => rename(t, b));
      item.append(b);
      if (state.tabs.length > 1) {
        const x = document.createElement("button");
        x.type = "button";
        x.className = "editor-tab-close";
        x.setAttribute("aria-label", (text.close || "Close %s").replace("%s", t.name));
        x.textContent = "×";
        x.addEventListener("click", () => closeTab(t.id));
        item.append(x);
      }
      strip.append(item);
    }
    const add = document.createElement("button");
    add.type = "button";
    add.className = "editor-tab-add";
    add.setAttribute("aria-label", text.newTab || "New tab");
    add.textContent = "+";
    add.addEventListener("click", () => { newTab({ db: pageDB }); switchTo(state.active); });
    strip.append(add);
  }
  function switchTo(id) {
    const t = state.tabs.find((x) => x.id === id);
    if (!t) return;
    state.active = id;
    save();
    if (t.db !== pageDB && hasOption(dbSelect, t.db)) {
      location.assign("/console?db=" + encodeURIComponent(t.db));
      return;
    }
    t.db = pageDB;
    tab = t;
    view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: t.sql } });
    reason.value = t.reason;
    renderTabs();
    showResult();
    view.focus();
  }
  function closeTab(id) {
    const i = state.tabs.findIndex((x) => x.id === id);
    if (i < 0 || state.tabs.length === 1) return;
    state.tabs.splice(i, 1);
    if (tab.id === id) switchTo(state.tabs[Math.max(0, i - 1)].id);
    else { save(); renderTabs(); }
  }
  function rename(t, el) {
    el.contentEditable = "true";
    el.focus();
    document.getSelection().selectAllChildren(el);
    const done = (commit) => {
      el.contentEditable = "false";
      const v = el.textContent.trim().slice(0, 60);
      if (commit && v) t.name = v;
      save();
      renderTabs();
    };
    el.addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); done(true); }
      if (e.key === "Escape") { e.preventDefault(); done(false); }
    });
    el.addEventListener("blur", () => done(true), { once: true });
  }
  renderTabs();
  showResult();

  // --- schema panel: insert names at the cursor ---
  document.querySelectorAll("[data-insert]").forEach((el) => {
    el.addEventListener("click", (e) => {
      e.preventDefault();
      const s = el.dataset.insert;
      view.dispatch(view.state.replaceSelection(s));
      view.focus();
    });
  });

  // Focus the first field of a popover (save, export) when it opens.
  document.querySelectorAll("details.popover").forEach((d) => {
    d.addEventListener("toggle", () => {
      if (d.open) d.querySelector(".popover-body input:not([type=hidden])")?.focus();
    });
  });

  // Fill the save and export forms from the editor when they are sent.
  document.querySelectorAll("form[data-from-editor]").forEach((f) => {
    f.addEventListener("submit", () => {
      const set = (name, v) => { const i = f.querySelector(`input[name=${name}]`); if (i) i.value = v; };
      set("sql", view.state.doc.toString());
      set("db", pageDB);
      set("reason", reason.value);
    });
  });
}

function hasOption(select, value) {
  return Array.from(select.options).some((o) => o.value === value);
}

// Sorts a result table by a column when its header button is pressed.
function makeSortable(table) {
  const body = table.tBodies[0];
  if (!body) return;
  const original = Array.from(body.rows);
  table.querySelectorAll("thead th").forEach((th, col) => {
    const btn = th.querySelector("button.sort");
    if (!btn) return;
    btn.addEventListener("click", () => {
      const cur = th.getAttribute("aria-sort");
      const next = cur === "ascending" ? "descending" : cur === "descending" ? "none" : "ascending";
      table.querySelectorAll("thead th").forEach((h) => h.removeAttribute("aria-sort"));
      if (next === "none") { body.replaceChildren(...original); return; }
      th.setAttribute("aria-sort", next);
      const dir = next === "ascending" ? 1 : -1;
      const val = (row) => {
        const cell = row.cells[col];
        if (!cell || cell.dataset.null === "1") return null;
        return cell.textContent.trim();
      };
      const rows = original.slice().sort((a, b) => {
        const x = val(a), y = val(b);
        if (x === null || y === null) return x === y ? 0 : x === null ? 1 : -1; // NULLs last
        const nx = Number(x), ny = Number(y);
        if (x !== "" && y !== "" && !Number.isNaN(nx) && !Number.isNaN(ny)) return (nx - ny) * dir;
        return x.localeCompare(y, undefined, { numeric: true }) * dir;
      });
      body.replaceChildren(...rows);
    });
  });
}

// Start once everything above is defined.
const root = document.getElementById("console-root");
if (root) init(root);
document.querySelectorAll("table[data-sortable]").forEach(makeSortable);
