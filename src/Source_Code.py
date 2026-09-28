import csv
import re
import hashlib
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
    }
}


# ============================================================
# DATA LOADING
# ============================================================

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

INCITEMENT_TERMS = {
    "attack",
    "burn",
    "destroy",
    "kill",
    "riot",
    "violence"
}

HARASSMENT_TERMS = {
    "find him",
    "find her",
    "expose him",
    "expose her",
    "go after",
    "threat"
}

MISINFO_TERMS = {
    "breaking",
    "confirmed",
    "secret",
    "fake news",
    "they are hiding",
    "share this"
}


def classify_post(text):

    normalized = normalize_text(text)

    scores = {
        "incitement": 0,
        "targeted_harassment": 0,
        "organized_misinformation": 0
    }

    for term in INCITEMENT_TERMS:
        if term in normalized:
            scores["incitement"] += 1

    for term in HARASSMENT_TERMS:
        if term in normalized:
            scores["targeted_harassment"] += 1

    for term in MISINFO_TERMS:
        if term in normalized:
            scores["organized_misinformation"] += 1

    category = max(scores, key=scores.get)

    # Don't classify ordinary posts merely because no category wins.
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

            mappings.append({
                "threat_type": category,
                "BNS": LEGAL_MAP[category]["BNS"],
                "IPC_legacy": LEGAL_MAP[category]["IPC_legacy"],
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

        "analyst_warning": (
            "This is an analytical triage output, not a finding "
            "that an individual committed an offence. Automated "
            "classification can produce false positives and requires "
            "human verification."
        )
    }

    return brief


# ============================================================
# DISPLAY
# ============================================================

def print_brief(brief):

    print("=" * 70)
    print("OSINT THREAT BRIEF")
    print("=" * 70)

    print("Generated:", brief["brief_timestamp_utc"])

    dataset = brief["dataset"]

    print(
        f"Posts: {dataset['post_count']} | "
        f"Accounts: {dataset['account_count']}"
    )

    assessment = brief["assessment"]

    print("\nCOORDINATION")
    print("-" * 70)
    print(
        "Score:",
        assessment["coordination_score"]
    )

    print(
        "Signal detected:",
        assessment["coordination_signal_detected"]
    )

    print("\nTHREAT TYPES")
    print("-" * 70)

    for threat in assessment["threat_types"]:
        print("•", threat)

    print("\nPOST CLASSIFICATIONS")
    print("-" * 70)

    for item in brief["post_classifications"]:
        print(
            f"{item['post_id']} | "
            f"{item['account']} | "
            f"{item['category']}"
        )

    print("\nLEGAL REVIEW")
    print("-" * 70)

    for mapping in brief["legal_review"]:

        print("\nThreat:", mapping["threat_type"])

        print("BNS:")
        for section in mapping["BNS"]:
            print("  •", section)

        print("Legacy IPC:")
        for section in mapping["IPC_legacy"]:
            print("  •", section)

        print("  NOTE:", mapping["note"])

    print("\nESCALATION")
    print("-" * 70)

    for step in brief["recommended_escalation"]:
        print("•", step)

    print("\nWARNING")
    print("-" * 70)
    print(brief["analyst_warning"])


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    posts = load_posts("mock_posts.csv")

    brief = generate_brief(posts)

    print_brief(brief)