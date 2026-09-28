import csv
import re
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk
from collections import defaultdict
from datetime import datetime, timezone


# ── Threat severity weights (higher = more dangerous) ─────────────────────
THREAT_SEVERITY = {
    "terrorism":               10,
    "self_harm":               10,
    "extremism":               8,
    "incitement":              8,
    "hate_speech":             7,
    "doxxing":                 6,
    "targeted_harassment":     6,
    "cyberbullying":           5,
    "organized_misinformation":4,
    "spam_bot":                1,
}

# Colour shown per category in the GUI output panel
SEVERITY_COLORS = {
    "terrorism":               "#ff4444",
    "self_harm":               "#ff4444",
    "extremism":               "#ff8800",
    "incitement":              "#ff8800",
    "hate_speech":             "#ff8800",
    "doxxing":                 "#ffcc00",
    "targeted_harassment":     "#ffcc00",
    "cyberbullying":           "#ffcc00",
    "organized_misinformation":"#88aaff",
    "spam_bot":                "#aaaaaa",
}

THREAT_KEYWORDS = {
    "incitement": {
        "attack", "burn", "destroy", "kill", "riot", "violence",
        "murder", "assault", "massacre", "lynching", "torch", "rampage"
    },
    "targeted_harassment": {
        "find him", "find her", "expose him", "expose her",
        "go after", "threat", "follow him", "follow her",
        "hunt him", "hunt her", "make him pay", "make her pay",
        "teach him a lesson", "teach her a lesson", "get him", "get her"
    },
    "organized_misinformation": {
        "breaking", "confirmed", "secret", "fake news",
        "they are hiding", "share this", "mainstream media wont tell",
        "suppressed", "cover up", "hoax", "the truth is",
        "wake up sheeple", "do your research"
    },
    "hate_speech": {
        "all muslims", "all hindus", "all christians", "all jews",
        "all blacks", "all whites", "sub-human", "vermin", "parasites",
        "cleanse", "exterminate", "inferior race", "filthy", "savages",
        "go back to your country"
    },
    "terrorism": {
        "jihad", "martyr", "infidel", "caliphate", "bomb threat",
        "explosive device", "terror attack", "suicide bomb",
        "allahu akbar kill", "death to", "blow up", "detonate"
    },
    "cyberbullying": {
        "you are worthless", "nobody likes you", "kill yourself",
        "you should die", "loser", "ugly freak", "no one cares about you",
        "go away forever", "you are pathetic", "everyone hates you"
    },
    "doxxing": {
        "home address", "phone number", "personal info", "lives at",
        "works at", "real name is", "ip address", "location leaked",
        "private details", "dox", "doxxed", "family address"
    },
    "self_harm": {
        "want to die", "end my life", "kill myself", "suicide",
        "not worth living", "better off dead", "cut myself",
        "no reason to live", "final goodbye", "can't go on"
    },
    "extremism": {
        "white power", "white supremacy", "great replacement",
        "ethnic cleansing", "fascist", "nazi", "fourth reich",
        "race war", "boogaloo", "accelerationism", "red pill truth"
    },
    "spam_bot": {
        "click here now", "limited offer", "earn money fast",
        "free followers", "buy now", "dm for promo", "win prize",
        "claim your reward", "100% guaranteed", "miracle cure",
        "lose weight fast", "get rich quick"
    },
}

USER_PROFILE_FIELDS = [
    "username", "display_name", "email", "phone",
    "location", "ip_address", "join_date",
    "follower_count", "following_count", "bio",
]


# ── Text helpers ──────────────────────────────────────────────────────────

def normalize(text):
    text = text.lower()
    text = re.sub(r"https?://\S+", "<URL>", text)
    text = re.sub(r"[^\w\s#@<>]", "", text)
    return re.sub(r"\s+", " ", text).strip()


def classify(text):
    norm = normalize(text)
    scores = {cat: sum(1 for t in terms if t in norm)
              for cat, terms in THREAT_KEYWORDS.items()}
    best = max(scores, key=scores.get)
    return ("unclassified", 0) if scores[best] == 0 else (best, scores[best])


# ── Data loading ──────────────────────────────────────────────────────────

def load_posts(path):
    posts = []
    with open(path, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            row["timestamp"] = datetime.fromisoformat(
                row["timestamp"].replace("Z", "+00:00"))
            row["text"] = row["text"].strip()
            posts.append(row)
    return posts


# ── Core analysis ─────────────────────────────────────────────────────────

def danger_score(flagged_posts):
    """
    Weighted danger score for one actor:
      sum of (threat_severity_weight × keyword_hit_count) across all their flagged posts.
    """
    total = 0
    for cat, hits in flagged_posts:
        total += THREAT_SEVERITY.get(cat, 1) * hits
    return total


def analyse(posts):
    """
    Returns a list of actor dicts, sorted most-dangerous first.
    Each actor dict:
      profile   – user profile fields (username, email, …)
      flagged   – list of {post_id, timestamp, category, keyword_hits, text}
      danger    – numeric danger score
      worst_cat – highest-severity category this actor triggered
    """
    # group posts by account
    by_account = defaultdict(list)
    for p in posts:
        by_account[p["account_id"]].append(p)

    actors = []
    for aid, account_posts in by_account.items():
        flagged = []
        for p in account_posts:
            cat, hits = classify(p["text"])
            if cat == "unclassified":
                continue
            flagged.append({
                "post_id":      p.get("post_id", "?"),
                "timestamp":    p["timestamp"].strftime("%Y-%m-%d %H:%M UTC"),
                "category":     cat,
                "keyword_hits": hits,
                "text":         p["text"],
            })

        if not flagged:
            continue  # benign account – skip entirely

        # pull profile only from the first post of this account
        first = account_posts[0]
        profile = {f: first.get(f, "N/A") for f in USER_PROFILE_FIELDS}
        profile["account_id"] = aid

        score = danger_score([(f["category"], f["keyword_hits"]) for f in flagged])
        worst = max(flagged, key=lambda f: THREAT_SEVERITY.get(f["category"], 0))["category"]

        actors.append({
            "profile":   profile,
            "flagged":   flagged,
            "danger":    score,
            "worst_cat": worst,
        })

    actors.sort(key=lambda a: a["danger"], reverse=True)
    return actors


# ── Report formatter ──────────────────────────────────────────────────────

SEP  = "═" * 72
THIN = "─" * 72
MID  = "·" * 72


def format_report(actors, total_posts, generated_at):
    lines = []

    # ── Legend / schema header (one time only) ──────────────────────────
    lines += [
        SEP,
        "  OSINT SOCIAL MEDIA THREAT INTELLIGENCE TOOL",
        f"  Scanned {total_posts} posts  |  {len(actors)} threat actor(s) found  |  {generated_at}",
        SEP,
        "",
        "  HOW TO READ THIS REPORT",
        THIN,
        "  Each block below is ONE THREAT ACTOR.  Layout per block:",
        "",
        "    ACTOR #n  [DANGER SCORE: x]  — overall danger rank",
        "    ── PROFILE ─────────────────────────────────────────",
        "    Username / Display Name / Email / Phone / Location /",
        "    IP Address / Joined / Followers / Following / Bio",
        "",
        "    ── FLAGGED POST #n ──────────────────────────────────",
        "    Post ID | Timestamp | Category | Keyword hits",
        '    "> " followed by the exact post text',
        "",
        "  COLOUR CODING  (category name is highlighted in this colour)",
        THIN,
        "  🔴  #ff4444  terrorism, self_harm          — CRITICAL",
        "  🟠  #ff8800  extremism, incitement,         — HIGH",
        "               hate_speech",
        "  🟡  #ffcc00  doxxing, targeted_harassment,  — MEDIUM",
        "               cyberbullying",
        "  🔵  #88aaff  organized_misinformation       — LOW",
        "  ⚪  #aaaaaa  spam_bot                       — INFO",
        "",
        "  Actors are sorted from MOST dangerous (top) to LEAST dangerous (bottom).",
        "  Danger score = sum of (severity weight × keyword hits) across all posts.",
        "",
        "  ⚠  ANALYST NOTE: automated triage only — human review required.",
        SEP,
        "",
    ]

    if not actors:
        lines.append("  No threat actors detected in this dataset.")
        return "\n".join(lines)

    for rank, actor in enumerate(actors, 1):
        p   = actor["profile"]
        cat = actor["worst_cat"]
        lines += [
            f"  ACTOR #{rank}  [DANGER SCORE: {actor['danger']}]"
            f"  ▸ worst category: {cat.upper()}",
            THIN,
            "  ── PROFILE " + "─" * 61,
            f"  Username      : {p.get('username',      'N/A')}",
            f"  Display Name  : {p.get('display_name',  'N/A')}",
            f"  Email         : {p.get('email',         'N/A')}",
            f"  Phone         : {p.get('phone',         'N/A')}",
            f"  Location      : {p.get('location',      'N/A')}",
            f"  IP Address    : {p.get('ip_address',    'N/A')}",
            f"  Joined        : {p.get('join_date',     'N/A')}",
            f"  Followers     : {p.get('follower_count','N/A')}",
            f"  Following     : {p.get('following_count','N/A')}",
            f"  Bio           : {p.get('bio',           'N/A')}",
            "",
        ]

        for i, fp in enumerate(actor["flagged"], 1):
            lines += [
                f"  ── FLAGGED POST #{i} " + "─" * 54,
                f"  Post ID  : {fp['post_id']}   "
                f"Timestamp : {fp['timestamp']}",
                f"  Category : {fp['category'].upper():<28}  "
                f"Keyword hits: {fp['keyword_hits']}",
                f"  > {fp['text']}",
                "",
            ]

        lines += [SEP, ""]

    return "\n".join(lines)


# ── GUI ───────────────────────────────────────────────────────────────────

def run_gui():
    root = tk.Tk()
    root.title("OSINT Threat Intelligence Tool")
    root.geometry("1050x740")
    root.configure(bg="#1e1e2e")

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("TButton", background="#4f46e5", foreground="white",
                    font=("Segoe UI", 10, "bold"), padding=6)
    style.map("TButton", background=[("active", "#6366f1")])

    # Header
    hdr = tk.Frame(root, bg="#12122a", pady=10)
    hdr.pack(fill=tk.X)
    tk.Label(hdr, text="🔍  OSINT Threat Intelligence",
             font=("Segoe UI", 15, "bold"), bg="#12122a", fg="#e0e0ff").pack()
    tk.Label(hdr, text="Social-media threat actor detection  —  CSV input",
             font=("Segoe UI", 9), bg="#12122a", fg="#888899").pack()

    # File row
    frow = tk.Frame(root, bg="#1e1e2e", pady=8)
    frow.pack(fill=tk.X, padx=16)
    file_var = tk.StringVar(value="No file selected")
    tk.Label(frow, text="CSV File:", bg="#1e1e2e", fg="#c0c0d0",
             font=("Segoe UI", 10)).pack(side=tk.LEFT)
    tk.Label(frow, textvariable=file_var, bg="#1e1e2e", fg="#a0d0ff",
             font=("Segoe UI", 10), width=58, anchor="w").pack(side=tk.LEFT, padx=8)

    def browse():
        path = filedialog.askopenfilename(
            title="Select CSV file",
            filetypes=[("CSV files", "*.csv")])
        if path:
            file_var.set(path)

    ttk.Button(frow, text="Browse…", command=browse).pack(side=tk.LEFT)

    # Controls
    ctrl = tk.Frame(root, bg="#1e1e2e", pady=4)
    ctrl.pack(fill=tk.X, padx=16)
    status_var = tk.StringVar(value="Ready.")
    tk.Label(ctrl, textvariable=status_var, bg="#1e1e2e", fg="#88cc88",
             font=("Segoe UI", 9)).pack(side=tk.LEFT)

    def clear_output():
        out.configure(state=tk.NORMAL)
        out.delete("1.0", tk.END)
        out.configure(state=tk.DISABLED)
        status_var.set("Cleared.")

    ttk.Button(ctrl, text="Clear", command=clear_output).pack(side=tk.RIGHT, padx=(4, 0))

    def run_analysis():
        path = file_var.get()
        if path == "No file selected" or not path:
            status_var.set("⚠  Please select a CSV file first.")
            return
        status_var.set("Analysing…")
        root.update_idletasks()
        try:
            posts  = load_posts(path)
            actors = analyse(posts)
            ts     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            report = format_report(actors, len(posts), ts)

            out.configure(state=tk.NORMAL)
            out.delete("1.0", tk.END)
            out.insert(tk.END, report)

            # Colour-highlight every occurrence of each category name
            for cat, colour in SEVERITY_COLORS.items():
                start = "1.0"
                while True:
                    pos = out.search(cat, start, stopindex=tk.END, nocase=True)
                    if not pos:
                        break
                    end = f"{pos}+{len(cat)}c"
                    out.tag_add(cat, pos, end)
                    out.tag_config(cat, foreground=colour, font=("Consolas", 10, "bold"))
                    start = end

            out.configure(state=tk.DISABLED)
            status_var.set(
                f"Done — {len(posts)} post(s) scanned, "
                f"{len(actors)} threat actor(s) found.")
        except FileNotFoundError:
            status_var.set("⚠  File not found.")
        except Exception as exc:
            status_var.set(f"⚠  Error: {exc}")

    ttk.Button(ctrl, text="▶  Run Analysis", command=run_analysis).pack(
        side=tk.RIGHT, padx=(0, 4))

    # Output panel
    out_frame = tk.Frame(root, bg="#1e1e2e")
    out_frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 12))
    out = scrolledtext.ScrolledText(
        out_frame, state=tk.DISABLED, bg="#0d0d1a", fg="#d4d4d4",
        insertbackground="white", font=("Consolas", 10),
        relief=tk.FLAT, wrap=tk.NONE)
    out.pack(fill=tk.BOTH, expand=True)

    root.mainloop()


if __name__ == "__main__":
    run_gui()
