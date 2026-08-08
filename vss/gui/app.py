from __future__ import annotations
import threading
import queue
import os
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from ..core.engine import analyze, Options
from ..core.model import SEVERITY_LABEL, Severity, VERDICT_COLOR, Verdict
from ..core import urlcheck, updater
from ..dynamic import sandbox
from ..version import __version__

try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
    _BASE = TkinterDnD.Tk
    _HAS_DND = True
except Exception:
    _BASE = tk.Tk
    _HAS_DND = False

BG = "#0f1216"
BG2 = "#171b21"
BG3 = "#232a33"
LINE = "#2a323d"
FG = "#e8ebf0"
MUTED = "#8791a0"
ACCENT = "#4a9eff"

SEV_COLOR = {
    Severity.OK: "#2ecc71", Severity.INFO: "#5dade2", Severity.LOW: "#58c0d0",
    Severity.MEDIUM: "#f1a33c", Severity.HIGH: "#e8743b", Severity.CRITICAL: "#e74c3c",
}
SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


class App(_BASE):
    def __init__(self):
        super().__init__()
        self.title("Voids Secure System")
        self.geometry("960x740")
        self.minsize(820, 620)
        self.configure(bg=BG)
        self.q: queue.Queue = queue.Queue()
        self.report = None
        self.target = tk.StringVar(value="")
        self._build()
        self.after(80, self._poll)

    def _build(self):
        self._style()
        top = tk.Frame(self, bg=BG)
        top.pack(fill="x", padx=26, pady=(20, 6))
        tk.Label(top, text="🛡  Voids Secure System", bg=BG, fg=FG,
                 font=("Segoe UI Semibold", 21)).pack(anchor="w")
        tk.Label(top, text="Detects miners, viruses and hidden executables in games and repacks · YARA + PE + Defender engine",
                 bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w")

        self.update_bar = tk.Frame(self, bg="#1e2f45", highlightbackground=ACCENT, highlightthickness=1)

        drop = tk.Frame(self, bg=BG2, highlightbackground=LINE, highlightthickness=1)
        drop.pack(fill="x", padx=26, pady=12)
        self.drop = drop
        inner = tk.Frame(drop, bg=BG2)
        inner.pack(fill="x", padx=16, pady=14)
        hint = "Drop a file, ISO or folder here" if _HAS_DND else "Choose a file, ISO or folder"
        self.drop_lbl = tk.Label(inner, text=hint, bg=BG2, fg=MUTED, font=("Segoe UI", 11))
        self.drop_lbl.pack(side="left")
        tk.Button(inner, text="Choose file…", command=self._pick_file, **self._btn()).pack(side="right")
        tk.Button(inner, text="Folder…", command=self._pick_folder, **self._btn(sub=True)).pack(side="right", padx=8)
        self.path_lbl = tk.Label(drop, textvariable=self.target, bg=BG2, fg=FG,
                                 font=("Consolas", 9), anchor="w")
        self.path_lbl.pack(fill="x", padx=16, pady=(0, 12))
        if _HAS_DND:
            for w in (drop, inner, self.drop_lbl, self.path_lbl):
                w.drop_target_register(DND_FILES)
                w.dnd_bind("<<Drop>>", self._on_drop)

        opts = tk.Frame(self, bg=BG)
        opts.pack(fill="x", padx=26)
        self.opt_defender = tk.BooleanVar(value=True)
        self.opt_deep = tk.BooleanVar(value=True)
        self.opt_vt = tk.BooleanVar(value=False)
        self._check(opts, "Windows Defender", self.opt_defender).pack(side="left")
        self._check(opts, "Deep analysis (ISO)", self.opt_deep).pack(side="left", padx=(14, 0))
        self._check(opts, "VirusTotal", self.opt_vt, self._toggle_vt).pack(side="left", padx=(14, 0))
        self.vt_entry = tk.Entry(opts, width=20, bg=BG3, fg=FG, insertbackground=FG,
                                 relief="flat", font=("Consolas", 9))

        urlrow = tk.Frame(self, bg=BG)
        urlrow.pack(fill="x", padx=26, pady=(8, 0))
        tk.Label(urlrow, text="🔗  Check a link:", bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(side="left")
        self.url_entry = tk.Entry(urlrow, bg=BG3, fg=FG, insertbackground=FG, relief="flat",
                                  font=("Consolas", 10))
        self.url_entry.pack(side="left", fill="x", expand=True, padx=8, ipady=4)
        self.url_entry.bind("<Return>", lambda e: self._check_url())
        tk.Button(urlrow, text="Analyze link", command=self._check_url, **self._btn(sub=True)).pack(side="right")

        action = tk.Frame(self, bg=BG)
        action.pack(fill="x", padx=26, pady=10)
        self.analyze_btn = tk.Button(action, text="ANALYZE", command=self._start, **self._btn(big=True))
        self.analyze_btn.pack(side="left")
        self.progress = ttk.Progressbar(action, mode="determinate", maximum=100, length=360)
        self.progress.pack(side="left", padx=16, fill="x", expand=True)
        self.status = tk.Label(self, text="Ready.", bg=BG, fg=MUTED, font=("Segoe UI", 9), anchor="w")
        self.status.pack(fill="x", padx=26)

        head = tk.Frame(self, bg=BG)
        head.pack(fill="x", padx=26, pady=(8, 2))
        self.gauge = tk.Canvas(head, width=132, height=132, bg=BG, highlightthickness=0)
        self.gauge.pack(side="left")
        vbox = tk.Frame(head, bg=BG)
        vbox.pack(side="left", fill="x", expand=True, padx=16)
        self.verdict_lbl = tk.Label(vbox, text="", bg=BG, fg=FG, font=("Segoe UI Semibold", 22), anchor="w")
        self.verdict_lbl.pack(anchor="w", pady=(22, 0))
        self.meta_lbl = tk.Label(vbox, text="", bg=BG, fg=MUTED, font=("Segoe UI", 9),
                                 anchor="w", justify="left")
        self.meta_lbl.pack(anchor="w")
        self.hash_lbl = tk.Label(vbox, text="", bg=BG, fg="#5a6472", font=("Consolas", 8), anchor="w")
        self.hash_lbl.pack(anchor="w")

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=26, pady=(6, 6))
        self.canvas = tk.Canvas(body, bg=BG, highlightthickness=0)
        sb = ttk.Scrollbar(body, orient="vertical", command=self.canvas.yview)
        self.results = tk.Frame(self.canvas, bg=BG)
        self.results.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self._win = self.canvas.create_window((0, 0), window=self.results, anchor="nw")
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig(self._win, width=e.width))
        self.canvas.configure(yscrollcommand=sb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.canvas.bind_all("<MouseWheel>", lambda e: self.canvas.yview_scroll(int(-e.delta / 120), "units"))

        foot = tk.Frame(self, bg=BG)
        foot.pack(fill="x", padx=26, pady=(0, 16))
        self.save_btn = tk.Button(foot, text="Save report…", command=self._save, state="disabled", **self._btn(sub=True))
        self.save_btn.pack(side="left")
        self.sandbox_btn = tk.Button(foot, text="🧪 Live test (Sandbox)", command=self._run_sandbox,
                                     state="disabled", **self._btn(sub=True))
        self.sandbox_btn.pack(side="left", padx=(8, 0))
        eng = "YARA on" if _yara_ok() else "YARA off"
        sbx = "Sandbox ready" if sandbox.is_available() else "Sandbox off"
        tk.Label(foot, text=f"v{__version__} · {eng} · {sbx}", bg=BG, fg=MUTED,
                 font=("Segoe UI", 8)).pack(side="right")
        tk.Button(foot, text="Check for updates", command=lambda: self._check_updates(manual=True),
                  **self._btn(sub=True)).pack(side="right", padx=(0, 10))
        self._draw_gauge(0, MUTED, "")
        self._check_updates()

    def _style(self):
        s = ttk.Style()
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure("TProgressbar", troughcolor=BG3, background=ACCENT, borderwidth=0, thickness=8)
        s.configure("Vertical.TScrollbar", background=BG3, troughcolor=BG, borderwidth=0, arrowcolor=MUTED)

    def _btn(self, big=False, sub=False):
        return dict(bg=(ACCENT if big else (BG3 if sub else "#2b333d")),
                    fg="#ffffff" if big else FG, activebackground="#3d8ce0" if big else BG3,
                    activeforeground="#ffffff", relief="flat", bd=0, cursor="hand2",
                    font=("Segoe UI Semibold", 12 if big else 10),
                    padx=18 if big else 12, pady=10 if big else 6)

    def _check(self, parent, text, var, cmd=None):
        return tk.Checkbutton(parent, text=text, variable=var, command=cmd, bg=BG, fg=FG,
                              selectcolor=BG3, activebackground=BG, activeforeground=FG,
                              font=("Segoe UI", 9), highlightthickness=0, bd=0)

    def _draw_gauge(self, score, color, center_text):
        c = self.gauge
        c.delete("all")
        cx, cy, r = 66, 66, 52
        c.create_oval(cx - r, cy - r, cx + r, cy + r, outline=BG3, width=11)
        if score > 0:
            c.create_arc(cx - r, cy - r, cx + r, cy + r, start=90, extent=-3.6 * score,
                         style="arc", outline=color, width=11)
        c.create_text(cx, cy - 8, text=str(score), fill=FG, font=("Segoe UI Semibold", 27))
        c.create_text(cx, cy + 20, text="risk /100", fill=MUTED, font=("Segoe UI", 8))

    def _toggle_vt(self):
        if self.opt_vt.get():
            self.vt_entry.pack(side="left", padx=(6, 0))
            self.vt_entry.delete(0, "end")
            self.vt_entry.insert(0, "API key…")
        else:
            self.vt_entry.pack_forget()

    def _on_drop(self, event):
        raw = event.data.strip()
        if raw.startswith("{") and raw.endswith("}"):
            raw = raw[1:-1]
        raw = raw.split("} {")[0].strip("{}")
        if os.path.exists(raw):
            self.target.set(raw)
            self._start()

    def _pick_file(self):
        p = filedialog.askopenfilename(title="Choose the installer, ISO or executable",
                                       filetypes=[("All", "*.*")])
        if p:
            self.target.set(p)

    def _pick_folder(self):
        p = filedialog.askdirectory(title="Choose the game folder")
        if p:
            self.target.set(p)

    def _start(self):
        path = self.target.get()
        if not path or not os.path.exists(path):
            messagebox.showwarning("Voids Secure System", "Choose a valid file or folder first.")
            return
        self.analyze_btn.configure(state="disabled", text="ANALYZING…")
        self.save_btn.configure(state="disabled")
        self.sandbox_btn.configure(state="disabled")
        for w in self.results.winfo_children():
            w.destroy()
        self.verdict_lbl.configure(text="")
        self.meta_lbl.configure(text="")
        self.hash_lbl.configure(text="")
        self._draw_gauge(0, MUTED, "")
        self.progress["value"] = 0
        opt = Options(defender=self.opt_defender.get(), deep=self.opt_deep.get(),
                      reputation=self.opt_vt.get(),
                      vt_key=self.vt_entry.get().strip() if self.opt_vt.get() else "")
        threading.Thread(target=self._worker, args=(path, opt), daemon=True).start()

    def _worker(self, path, opt):
        try:
            rep = analyze(path, opt, lambda m, f: self.q.put(("progress", m, f)))
            self.q.put(("done", rep))
        except Exception as ex:
            self.q.put(("error", str(ex)))

    def _check_url(self):
        u = self.url_entry.get().strip()
        if not u:
            return
        self.analyze_btn.configure(state="disabled")
        self.save_btn.configure(state="disabled")
        self.sandbox_btn.configure(state="disabled")
        for w in self.results.winfo_children():
            w.destroy()
        self.verdict_lbl.configure(text="")
        self.meta_lbl.configure(text="")
        self.hash_lbl.configure(text="")
        self._draw_gauge(0, MUTED, "")
        self.status.configure(text="Checking link…")
        vt = self.vt_entry.get().strip() if self.opt_vt.get() else ""
        threading.Thread(target=self._url_worker, args=(u, vt), daemon=True).start()

    def _url_worker(self, u, vt):
        try:
            rep = urlcheck.analyze_url(u, vt)
            self.q.put(("done", rep))
        except Exception as ex:
            self.q.put(("error", str(ex)))

    def _check_updates(self, manual=False):
        threading.Thread(target=self._update_worker, args=(manual,), daemon=True).start()
        if not manual:
            self.after(3600 * 1000, self._check_updates)

    def _update_worker(self, manual):
        info = updater.check()
        if info.get("ok") and info.get("update"):
            self.q.put(("update", info))
        elif manual:
            self.q.put(("noupdate", info))

    def _poll(self):
        try:
            while True:
                item = self.q.get_nowait()
                if item[0] == "progress":
                    self.status.configure(text=item[1])
                    if item[2] is not None:
                        self.progress["value"] = int(item[2] * 100)
                elif item[0] == "done":
                    self._render(item[1])
                elif item[0] == "sandbox":
                    self._render_sandbox(item[1])
                elif item[0] == "update":
                    self._show_update(item[1])
                elif item[0] == "noupdate":
                    messagebox.showinfo("Voids Secure System", f"You already have the latest version (v{__version__}).")
                elif item[0] == "updateres":
                    self._after_update(item[1])
                elif item[0] == "error":
                    messagebox.showerror("Voids Secure System", f"Error: {item[1]}")
                    self.analyze_btn.configure(state="normal", text="ANALYZE")
        except queue.Empty:
            pass
        self.after(80, self._poll)

    def _show_update(self, info):
        for w in self.update_bar.winfo_children():
            w.destroy()
        self.update_bar.pack(fill="x", padx=26, pady=(6, 0), before=self.drop)
        inner = tk.Frame(self.update_bar, bg="#1e2f45")
        inner.pack(fill="x", padx=12, pady=8)
        txt = f"New version available: v{info.get('latest')}"
        notes = info.get("notes", "")
        if notes:
            txt += f" — {notes}"
        tk.Label(inner, text="⬆  " + txt, bg="#1e2f45", fg=FG, font=("Segoe UI", 9),
                 anchor="w").pack(side="left", fill="x", expand=True)
        tk.Button(inner, text="Update now", command=lambda: self._do_update(info),
                  **self._btn()).pack(side="right")

    def _do_update(self, info):
        if not updater.is_frozen():
            messagebox.showinfo("Update",
                                "Auto-update works in the installed app (.exe). "
                                "In source mode, update from the repository.")
            return
        if not messagebox.askyesno("Update",
                                   f"Download and install version v{info.get('latest')}?\n"
                                   "The app will restart when done."):
            return
        self.status.configure(text="Downloading update…")
        self.progress["value"] = 0
        threading.Thread(target=self._apply_update, args=(info,), daemon=True).start()

    def _apply_update(self, info):
        res = updater.download_and_apply(
            info, progress=lambda f: self.q.put(("progress", "Downloading update…", f)))
        self.q.put(("updateres", res))

    def _after_update(self, res):
        if res.get("ok") and res.get("restart"):
            messagebox.showinfo("Update", "Download complete. The app will close and reopen updated.")
            self.destroy()
        else:
            messagebox.showerror("Update", f"Could not update: {res.get('reason', '')}")

    def _render(self, rep):
        self.report = rep
        d = rep.to_dict()
        self.progress["value"] = 100
        self.status.configure(text=f"Completed in {d['duration_s']}s · {len(d['findings'])} findings")
        self.analyze_btn.configure(state="normal", text="ANALYZE")
        self.save_btn.configure(state="normal")
        if sandbox.is_available():
            self.sandbox_btn.configure(state="normal")
        color = VERDICT_COLOR[Verdict(d["verdict"])]
        self._draw_gauge(d["score"], color, "")
        self.verdict_lbl.configure(text=d["verdict_label"], fg=color)
        m = d["meta"]
        bits = [f"Type: {d['kind']}"]
        if m.get("size_human"):
            bits.append(m["size_human"])
        if m.get("iso_files"):
            bits.append(f"{m['iso_files']} files")
        if m.get("folder_files"):
            bits.append(f"{m['folder_files']} files")
        if m.get("hidden_exes"):
            bits.append(f"{m['hidden_exes']} hidden")
        if m.get("defender_ran"):
            bits.append("Defender ✓")
        self.meta_lbl.configure(text="   ·   ".join(bits))
        hsh = m.get("sha256", "")
        imph = ""
        for v in (m.get("peplus") or {}).values():
            if v.get("imphash"):
                imph = f"   imphash {v['imphash'][:16]}"
                break
        if hsh:
            self.hash_lbl.configure(text=f"SHA256 {hsh}{imph}")
        groups = {}
        for f in d["findings"]:
            groups.setdefault(Severity(f["severity"]), []).append(f)
        for sev in SEV_ORDER:
            for f in groups.get(sev, []):
                self._card(f)
        if not d["findings"]:
            tk.Label(self.results, text="No findings.", bg=BG, fg=MUTED).pack(anchor="w")

    def _card(self, f):
        sev = Severity(f["severity"])
        card = tk.Frame(self.results, bg=BG2, highlightbackground=LINE, highlightthickness=1)
        card.pack(fill="x", pady=4)
        bar = tk.Frame(card, bg=SEV_COLOR[sev], width=4)
        bar.pack(side="left", fill="y")
        inner = tk.Frame(card, bg=BG2)
        inner.pack(side="left", fill="x", expand=True, padx=12, pady=9)
        row = tk.Frame(inner, bg=BG2)
        row.pack(fill="x")
        tk.Label(row, text=f" {SEVERITY_LABEL[sev].upper()} ", bg=SEV_COLOR[sev], fg="#0b0d10",
                 font=("Segoe UI Semibold", 8)).pack(side="left")
        tk.Label(row, text="  " + f["title"], bg=BG2, fg=FG, font=("Segoe UI Semibold", 11),
                 anchor="w").pack(side="left", fill="x", expand=True)
        if f["detail"]:
            tk.Label(inner, text=f["detail"], bg=BG2, fg=MUTED, font=("Segoe UI", 9),
                     anchor="w", justify="left", wraplength=760).pack(fill="x", pady=(3, 0))
        for ev in f["evidence"][:8]:
            tk.Label(inner, text="· " + ev[:130], bg=BG2, fg="#c39a5b",
                     font=("Consolas", 8), anchor="w").pack(fill="x")

    def _run_sandbox(self):
        if not sandbox.is_available():
            messagebox.showinfo("Windows Sandbox",
                                "The advanced mode needs Windows Sandbox (Windows 10/11 Pro).\n\n"
                                "Enable it in: Turn Windows features on or off → "
                                "'Windows Sandbox'. Restart and try again.")
            return
        path = self.target.get()
        if not path or not os.path.exists(path):
            return
        if not messagebox.askyesno("Live test",
                                   "This will RUN the file inside an isolated environment (Windows Sandbox) "
                                   "to observe its behavior.\n\nContinue?"):
            return
        self.sandbox_btn.configure(state="disabled", text="🧪 In sandbox…")
        self.status.configure(text="Preparing Windows Sandbox…")
        threading.Thread(target=self._sandbox_worker, args=(path,), daemon=True).start()

    def _sandbox_worker(self, path):
        try:
            data = sandbox.run(path, progress=lambda m, f: self.q.put(("progress", m, f)))
            self.q.put(("sandbox", data))
        except Exception as ex:
            self.q.put(("error", str(ex)))

    def _render_sandbox(self, data):
        self.sandbox_btn.configure(state="normal", text="🧪 Live test (Sandbox)")
        verdict, detail = sandbox.summarize(data)
        labels = {"clean": "✅ CLEAN in the live test", "malicious": "❌ MALICIOUS",
                  "review": "⚠️ REVIEW", "unavailable": "Sandbox unavailable",
                  "no_result": "No result", "not_run": "Could not run"}
        self.status.configure(text=f"Sandbox: {labels.get(verdict, verdict)}")
        messagebox.showinfo("Live test (Sandbox)", f"{labels.get(verdict, verdict)}\n\n{detail}")

    def _save(self):
        if not self.report:
            return
        p = filedialog.asksaveasfilename(defaultextension=".json",
                                         filetypes=[("JSON", "*.json")], initialfile="vss_report.json")
        if not p:
            return
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(self.report.to_dict(), fh, ensure_ascii=False, indent=2)
        messagebox.showinfo("Voids Secure System", "Report saved.")


def _yara_ok():
    try:
        from ..core import yarascan
        return yarascan.available()
    except Exception:
        return False


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
