import csv
import re
import hashlib
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk
from collections import Counter, defaultdict
from datetime import datetime, timezone
from difflib import SequenceMatcher


# ============================================================
# CONFIGURATION
# ============================================================

COORDINATION_THRESHOLD = 0.62
SIMILARITY_THRESHOLD = 0.78
TIME_WINDOW_MINUTES = 30

# Demonstration-only mappings.
# These are NOT legal conclusions.
LEGAL_MAP = {
    "incitement": {
        "BNS": [
            "§353 — Statements conducing to public mischief"
        ],
        "IPC_legacy": [
            "§505 — Statements conducing to public mischief"
        ]
    },

    "targeted_harassment": {
        "BNS": [
            "§351 — Criminal intimidation, where the facts satisfy its elements",
            "§352 — Intentional insult with intent to provoke breach of peace, "
            "where applicable"
        ],
        "IPC_legacy": [
            "§503 — Criminal intimidation",
            "§504 — Intentional insult with intent to provoke breach of peace"
        ]
    },

    "organized_misinformation": {
        "BNS": [
            "§353 — Statements conducing to public mischief, "
            "where the statutory elements are satisfied"
        ],
        "IPC_legacy": [
            "§505 — Statements conducing to public mischief"
        ]
    },

    "hate_speech": {
        "BNS": [
            "§196 — Promoting enmity between groups"
        ],
        "IPC_legacy": [
            "§153A — Promoting enmity between different groups"
        ]
    },

    "terrorism": {
        "BNS": [
            "§113 — Terrorist act"
        ],
        "IPC_legacy": [
            "UAPA §15 — Terrorist act"
        ]
    },

    "cyberbullying": {
        "BNS": [
            "§351 — Criminal intimidation"
        ],
        "IPC_legacy": [
            "§66A IT Act — Offensive communication (reference only; struck down)"
        ]
    },

    "doxxing": {
        "BNS": [
            "§351 — Criminal intimidation"
        ],
        "IPC_legacy": [
            "§503 — Criminal intimidation",
            "§72 IT Act — Breach of confidentiality and privacy"
        ]
    },

    "self_harm": {
        "BNS": [],
        "IPC_legacy": [
            "§306 — Abetment of suicide (if applicable)"
        ]
    },

    "extremism": {
        "BNS": [
            "§196 — Promoting enmity between groups",
            "§113 — Terrorist act (if applicable)"
        ],
        "IPC_legacy": [
            "§153A — Promoting enmity between different groups",
            "UAPA §13 — Unlawful activities"
        ]
    },

    "spam_bot": {
        "BNS": [],
        "IPC_legacy": [
            "§66 IT Act — Computer-related offences (if applicable)"
        ]
    }
}


# ============================================================
# DATA LOADING
# ============================================================

# User profile fields carried from CSV into post records.
# Older CSVs without these columns are still accepted gracefully.
USER_PROFILE_FIELDS = [
    "username", "display_name", "email", "phone",
    "location", "ip_address", "join_date",
    "follower_count", "following_count", "bio",
]


def load_posts(filename):
    posts = []

    with open(filename, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for row in reader:
            row["timestamp"] = datetime.fromisoformat(
                row["timestamp"].replace("Z", "+00:00")
            )

            row["text"] = row["text"].strip()

            posts.append(row)

    return posts


# ============================================================
# TEXT NORMALIZATION
# ============================================================

def normalize_text(text):
    text = text.lower()

    # Remove URLs
    text = re.sub(r"https?://\S+", "<URL>", text)

    # Remove punctuation
    text = re.sub(r"[^\w\s#@<>]", "", text)

    # Collapse whitespace
    text = re.sub(r"\s+", " ", text)

    return text.strip()


def extract_hashtags(text):
    return set(re.findall(r"#\w+", text.lower()))


def extract_urls(text):
    return set(re.findall(r"https?://\S+", text.lower()))


# ============================================================
# SIMILARITY
# ============================================================

def text_similarity(a, b):
    return SequenceMatcher(
        None,
        normalize_text(a),
        normalize_text(b)
    ).ratio()


# ============================================================
# COORDINATION SIGNALS
# ============================================================

def temporal_proximity(posts):
    """
    Finds posts from different accounts occurring within
    TIME_WINDOW_MINUTES of one another.
    """

    signals = []

    ordered = sorted(posts, key=lambda x: x["timestamp"])

    for i in range(len(ordered)):
        for j in range(i + 1, len(ordered)):

            delta = (
                ordered[j]["timestamp"] -
                ordered[i]["timestamp"]
            ).total_seconds() / 60

            if delta > TIME_WINDOW_MINUTES:
                break

            if ordered[i]["account_id"] != ordered[j]["account_id"]:
                signals.append({
                    "type": "temporal_proximity",
                    "accounts": [
                        ordered[i]["account_id"],
                        ordered[j]["account_id"]
                    ],
                    "delta_minutes": round(delta, 2)
                })

    return signals


def similarity_signals(posts):

    signals = []

    for i in range(len(posts)):
        for j in range(i + 1, len(posts)):

            if posts[i]["account_id"] == posts[j]["account_id"]:
                continue

            similarity = text_similarity(
                posts[i]["text"],
                posts[j]["text"]
            )

            if similarity >= SIMILARITY_THRESHOLD:

                signals.append({
                    "type": "high_text_similarity",
                    "accounts": [
                        posts[i]["account_id"],
                        posts[j]["account_id"]
                    ],
                    "similarity": round(similarity, 3)
                })

    return signals


def shared_hashtag_signals(posts):

    hashtag_accounts = defaultdict(set)

    for post in posts:
        for tag in extract_hashtags(post["text"]):
            hashtag_accounts[tag].add(post["account_id"])

    signals = []

    for tag, accounts in hashtag_accounts.items():

        if len(accounts) >= 3:
            signals.append({
                "type": "shared_hashtag",
                "hashtag": tag,
                "accounts": sorted(accounts)
            })

    return signals


def shared_url_signals(posts):

    url_accounts = defaultdict(set)

    for post in posts:
        for url in extract_urls(post["text"]):
            url_accounts[url].add(post["account_id"])

    signals = []

    for url, accounts in url_accounts.items():

        if len(accounts) >= 3:
            signals.append({
                "type": "shared_url",
                "url_hash": hashlib.sha256(
                    url.encode()
                ).hexdigest()[:12],
                "accounts": sorted(accounts)
            })

    return signals


# ============================================================
# THREAT CLASSIFICATION
# ============================================================

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
    }
}


def classify_post(text):

    normalized = normalize_text(text)

    scores = {category: 0 for category in THREAT_KEYWORDS}

    for category, terms in THREAT_KEYWORDS.items():
        for term in terms:
            if term in normalized:
                scores[category] += 1

    category = max(scores, key=scores.get)

    if scores[category] == 0:
        category = "unclassified"

    return category, scores


# ============================================================
# COORDINATION SCORE
# ============================================================

def calculate_coordination_score(posts):

    signals = []

    signals.extend(temporal_proximity(posts))
    signals.extend(similarity_signals(posts))
    signals.extend(shared_hashtag_signals(posts))
    signals.extend(shared_url_signals(posts))

    if not signals:
        return 0.0, []

    score = 0

    for signal in signals:

        if signal["type"] == "temporal_proximity":
            score += 0.20

        elif signal["type"] == "high_text_similarity":
            score += 0.35

        elif signal["type"] == "shared_hashtag":
            score += 0.20

        elif signal["type"] == "shared_url":
            score += 0.25

    score = min(score, 1.0)

    return round(score, 3), signals


# ============================================================
# CLUSTER ANALYSIS
# ============================================================

def build_account_clusters(posts):

    account_posts = defaultdict(list)

    for post in posts:
        account_posts[post["account_id"]].append(post)

    clusters = []

    for account, account_data in account_posts.items():

        categories = Counter()

        for post in account_data:
            category, _ = classify_post(post["text"])
            categories[category] += 1

        clusters.append({
            "account": account,
            "post_count": len(account_data),
            "categories": dict(categories)
        })

    return clusters


# ============================================================
# LEGAL MAPPING
# ============================================================

def legal_mapping(categories):

    mappings = []

    for category in categories:

        if category in LEGAL_MAP:

            bns = LEGAL_MAP[category].get("BNS", [])
            ipc = LEGAL_MAP[category].get("IPC_legacy", [])

            if bns or ipc:
                mappings.append({
                    "threat_type": category,
                    "BNS": bns,
                    "IPC_legacy": ipc,
                    "note": (
                        "Potentially relevant only. Applicability depends "
                        "on the actual facts, statutory elements, evidence, "
                        "jurisdiction and legal review."
                    )
                })

    return mappings


# ============================================================
# ESCALATION
# ============================================================

def escalation_steps(threat_types, coordination_score):

    steps = [
        "Preserve the original mock records and associated metadata.",
        "Record collection time and maintain an evidence/hash log.",
        "Manually review the highest-signal posts.",
        "Verify whether apparent coordination has an innocent explanation.",
        "Separate factual observations from analytical assessments."
    ]

    if coordination_score >= COORDINATION_THRESHOLD:
        steps.append(
            "Escalate for human analyst review of the apparent "
            "coordination cluster."
        )

    if "incitement" in threat_types:
        steps.append(
            "If credible imminent violence is independently indicated, "
            "follow applicable emergency/law-enforcement procedures."
        )

    if "targeted_harassment" in threat_types:
        steps.append(
            "Preserve relevant threats, targets, timestamps and URLs "
            "for authorized investigators."
        )

    if "organized_misinformation" in threat_types:
        steps.append(
            "Fact-check the underlying claims against authoritative "
            "sources before treating them as misinformation."
        )

    if "terrorism" in threat_types:
        steps.append(
            "Immediately escalate to law-enforcement or relevant "
            "counter-terrorism authorities."
        )

    if "self_harm" in threat_types:
        steps.append(
            "Flag for immediate welfare check; route to crisis "
            "intervention resources."
        )

    if "doxxing" in threat_types:
        steps.append(
            "Notify affected individuals and preserve evidence of "
            "personal information disclosure."
        )

    if "extremism" in threat_types:
        steps.append(
            "Escalate to specialist counter-extremism analysts."
        )

    return steps


# ============================================================
# THREAT BRIEF
# ============================================================

def generate_brief(posts):

    generated_at = datetime.now(timezone.utc).isoformat()

    coordination_score, signals = calculate_coordination_score(posts)

    classifications = []

    for post in posts:

        category, scores = classify_post(post["text"])

        classifications.append({
            "post_id": post["post_id"],
            "account": post["account_id"],
            "category": category,
            "scores": scores
        })

    threat_types = set(
        x["category"]
        for x in classifications
        if x["category"] != "unclassified"
    )

    legal = legal_mapping(threat_types)

    clusters = build_account_clusters(posts)

    escalation = escalation_steps(
        threat_types,
        coordination_score
    )

    # Build flagged-actors map: only extract user profile data for
    # accounts whose posts were classified as a threat.
    flagged_account_ids = {
        c["account"]
        for c in classifications
        if c["category"] != "unclassified"
    }

    flagged_actors = {}
    for post in posts:
        aid = post["account_id"]
        if aid not in flagged_account_ids:
            continue
        if aid in flagged_actors:
            continue  # already recorded from a previous post
        profile = {
            field: post.get(field, "N/A")
            for field in USER_PROFILE_FIELDS
        }
        profile["account_id"] = aid
        flagged_actors[aid] = profile

    brief = {
        "brief_timestamp_utc": generated_at,

        "dataset": {
            "type": "synthetic_mock_social_media",
            "post_count": len(posts),
            "account_count": len(
                set(p["account_id"] for p in posts)
            )
        },

        "assessment": {
            "coordination_score": coordination_score,
            "coordination_signal_detected":
                coordination_score >= COORDINATION_THRESHOLD,
            "threat_types": sorted(threat_types)
        },

        "coordination_signals": signals,

        "post_classifications": classifications,

        "account_clusters": clusters,

        "legal_review": legal,

        "recommended_escalation": escalation,

        "flagged_actors": list(flagged_actors.values()),

        "analyst_warning": (
            "This is an analytical triage output, not a finding "
            "that an individual committed an offence. Automated "
            "classification can produce false positives and requires "
            "human verification."
        )
    }

    return brief


# ============================================================
# BRIEF → FORMATTED TEXT  (shared by CLI and GUI)
# ============================================================

def format_brief(brief):
    lines = []
    sep = "=" * 70
    thin = "-" * 70

    lines.append(sep)
    lines.append("OSINT THREAT BRIEF")
    lines.append(sep)
    lines.append(f"Generated : {brief['brief_timestamp_utc']}")

    dataset = brief["dataset"]
    lines.append(
        f"Posts     : {dataset['post_count']}  |  "
        f"Accounts: {dataset['account_count']}"
    )

    assessment = brief["assessment"]
    lines.append("")
    lines.append("COORDINATION")
    lines.append(thin)
    lines.append(f"Score          : {assessment['coordination_score']}")
    lines.append(f"Signal detected: {assessment['coordination_signal_detected']}")

    lines.append("")
    lines.append("THREAT TYPES DETECTED")
    lines.append(thin)
    if assessment["threat_types"]:
        for threat in assessment["threat_types"]:
            lines.append(f"  • {threat}")
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append("POST CLASSIFICATIONS")
    lines.append(thin)
    for item in brief["post_classifications"]:
        lines.append(
            f"  {item['post_id']}  |  {item['account']}  |  {item['category']}"
        )

    lines.append("")
    lines.append("LEGAL REVIEW")
    lines.append(thin)
    if brief["legal_review"]:
        for mapping in brief["legal_review"]:
            lines.append(f"\n  Threat : {mapping['threat_type']}")
            lines.append("  BNS    :")
            for section in mapping["BNS"]:
                lines.append(f"    • {section}")
            lines.append("  Legacy IPC:")
            for section in mapping["IPC_legacy"]:
                lines.append(f"    • {section}")
            lines.append(f"  NOTE   : {mapping['note']}")
    else:
        lines.append("  (no applicable legal mappings)")

    lines.append("")
    lines.append("ESCALATION STEPS")
    lines.append(thin)
    for step in brief["recommended_escalation"]:
        lines.append(f"  • {step}")

    lines.append("")
    lines.append("FLAGGED ACTORS  (user data extracted only for flagged posts)")
    lines.append(thin)
    actors = brief.get("flagged_actors", [])
    if actors:
        for actor in actors:
            lines.append(f"\n  Account ID    : {actor['account_id']}")
            lines.append(f"  Username      : {actor.get('username', 'N/A')}")
            lines.append(f"  Display Name  : {actor.get('display_name', 'N/A')}")
            lines.append(f"  Email         : {actor.get('email', 'N/A')}")
            lines.append(f"  Phone         : {actor.get('phone', 'N/A')}")
            lines.append(f"  Location      : {actor.get('location', 'N/A')}")
            lines.append(f"  IP Address    : {actor.get('ip_address', 'N/A')}")
            lines.append(f"  Joined        : {actor.get('join_date', 'N/A')}")
            lines.append(f"  Followers     : {actor.get('follower_count', 'N/A')}")
            lines.append(f"  Following     : {actor.get('following_count', 'N/A')}")
            lines.append(f"  Bio           : {actor.get('bio', 'N/A')}")
    else:
        lines.append("  (no profile data available — CSV may not include user columns)")

    lines.append("")
    lines.append("ANALYST WARNING")
    lines.append(thin)
    lines.append(brief["analyst_warning"])
    lines.append(sep)

    return "\n".join(lines)


# ============================================================
# CLI DISPLAY  (unchanged behaviour)
# ============================================================

def print_brief(brief):
    print(format_brief(brief))


# ============================================================
# GUI
# ============================================================

# Severity colours for each threat category shown in the results panel
SEVERITY_COLORS = {
    "terrorism":               "#ff4444",
    "self_harm":               "#ff4444",
    "incitement":              "#ff8800",
    "extremism":               "#ff8800",
    "hate_speech":             "#ff8800",
    "targeted_harassment":     "#ffcc00",
    "doxxing":                 "#ffcc00",
    "cyberbullying":           "#ffcc00",
    "organized_misinformation":"#88aaff",
    "spam_bot":                "#aaaaaa",
    "unclassified":            "#cccccc",
}


def run_gui():
    root = tk.Tk()
    root.title("OSINT Social Media Threat Intelligence Tool")
    root.geometry("1000x720")
    root.configure(bg="#1e1e2e")

    # ── Styles ──────────────────────────────────────────────
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(
        "TButton",
        background="#4f46e5",
        foreground="white",
        font=("Segoe UI", 10, "bold"),
        padding=6
    )
    style.map("TButton", background=[("active", "#6366f1")])

    # ── Header ──────────────────────────────────────────────
    header = tk.Frame(root, bg="#12122a", pady=10)
    header.pack(fill=tk.X)

    tk.Label(
        header,
        text="🔍  OSINT Threat Intelligence",
        font=("Segoe UI", 16, "bold"),
        bg="#12122a",
        fg="#e0e0ff"
    ).pack()

    tk.Label(
        header,
        text="Social-media coordinated threat detection",
        font=("Segoe UI", 9),
        bg="#12122a",
        fg="#888899"
    ).pack()

    # ── File picker row ──────────────────────────────────────
    file_frame = tk.Frame(root, bg="#1e1e2e", pady=8)
    file_frame.pack(fill=tk.X, padx=16)

    file_var = tk.StringVar(value="No file selected")

    tk.Label(
        file_frame,
        text="CSV File:",
        bg="#1e1e2e",
        fg="#c0c0d0",
        font=("Segoe UI", 10)
    ).pack(side=tk.LEFT)

    tk.Label(
        file_frame,
        textvariable=file_var,
        bg="#1e1e2e",
        fg="#a0d0ff",
        font=("Segoe UI", 10),
        width=55,
        anchor="w"
    ).pack(side=tk.LEFT, padx=8)

    def browse():
        path = filedialog.askopenfilename(
            title="Select CSV file",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if path:
            file_var.set(path)

    ttk.Button(file_frame, text="Browse…", command=browse).pack(side=tk.LEFT)

    # ── Threat filter checkboxes ──────────────────────────────
    filter_frame = tk.LabelFrame(
        root,
        text=" Filter threat categories ",
        bg="#1e1e2e",
        fg="#c0c0d0",
        font=("Segoe UI", 9),
        padx=8, pady=6
    )
    filter_frame.pack(fill=tk.X, padx=16, pady=(0, 4))

    filter_vars = {}
    all_categories = list(THREAT_KEYWORDS.keys()) + ["unclassified"]

    for i, cat in enumerate(all_categories):
        var = tk.BooleanVar(value=True)
        filter_vars[cat] = var
        cb = tk.Checkbutton(
            filter_frame,
            text=cat.replace("_", " ").title(),
            variable=var,
            bg="#1e1e2e",
            fg=SEVERITY_COLORS.get(cat, "#cccccc"),
            selectcolor="#2a2a3e",
            activebackground="#1e1e2e",
            font=("Segoe UI", 9)
        )
        cb.grid(row=i // 6, column=i % 6, sticky="w", padx=6, pady=1)

    # ── Control row ──────────────────────────────────────────
    ctrl_frame = tk.Frame(root, bg="#1e1e2e", pady=4)
    ctrl_frame.pack(fill=tk.X, padx=16)

    status_var = tk.StringVar(value="Ready.")

    tk.Label(
        ctrl_frame,
        textvariable=status_var,
        bg="#1e1e2e",
        fg="#88cc88",
        font=("Segoe UI", 9)
    ).pack(side=tk.LEFT)

    def clear_output():
        output_text.configure(state=tk.NORMAL)
        output_text.delete("1.0", tk.END)
        output_text.configure(state=tk.DISABLED)
        status_var.set("Cleared.")

    ttk.Button(ctrl_frame, text="Clear", command=clear_output).pack(side=tk.RIGHT, padx=(4, 0))

    def run_analysis():
        path = file_var.get()
        if path == "No file selected" or not path:
            status_var.set("⚠  Please select a CSV file first.")
            return

        status_var.set("Running analysis…")
        root.update_idletasks()

        try:
            posts = load_posts(path)
            brief = generate_brief(posts)

            # Apply category filter
            active = {cat for cat, v in filter_vars.items() if v.get()}
            brief["post_classifications"] = [
                c for c in brief["post_classifications"]
                if c["category"] in active
            ]
            brief["assessment"]["threat_types"] = [
                t for t in brief["assessment"]["threat_types"]
                if t in active
            ]

            report = format_brief(brief)

            output_text.configure(state=tk.NORMAL)
            output_text.delete("1.0", tk.END)
            output_text.insert(tk.END, report)

            # Colour-highlight threat lines
            for category, colour in SEVERITY_COLORS.items():
                if category not in active:
                    continue
                start = "1.0"
                while True:
                    pos = output_text.search(
                        category, start, stopindex=tk.END, nocase=True
                    )
                    if not pos:
                        break
                    end = f"{pos}+{len(category)}c"
                    output_text.tag_add(category, pos, end)
                    output_text.tag_config(category, foreground=colour)
                    start = end

            output_text.configure(state=tk.DISABLED)
            n = len(posts)
            threats = brief["assessment"]["threat_types"]
            status_var.set(
                f"Done — {n} post(s) analysed, "
                f"{len(threats)} threat type(s) found."
            )

        except FileNotFoundError:
            status_var.set("⚠  File not found.")
        except Exception as exc:
            status_var.set(f"⚠  Error: {exc}")

    ttk.Button(ctrl_frame, text="▶  Run Analysis", command=run_analysis).pack(
        side=tk.RIGHT, padx=(0, 4)
    )

    # ── Output panel ─────────────────────────────────────────
    out_frame = tk.Frame(root, bg="#1e1e2e")
    out_frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 12))

    output_text = scrolledtext.ScrolledText(
        out_frame,
        state=tk.DISABLED,
        bg="#0d0d1a",
        fg="#d4d4d4",
        insertbackground="white",
        font=("Consolas", 10),
        relief=tk.FLAT,
        wrap=tk.NONE
    )
    output_text.pack(fill=tk.BOTH, expand=True)

    root.mainloop()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    run_gui()
