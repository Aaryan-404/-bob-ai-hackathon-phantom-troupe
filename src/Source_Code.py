import csv
import re
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk
from collections import defaultdict
from datetime import datetime, timezone

# ── Config ─────────────────────────────────────────────────────────────────
THREAT_SEVERITY = {
    "terrorism":10,"self_harm":10,"extremism":8,"incitement":8,
    "hate_speech":7,"doxxing":6,"targeted_harassment":6,
    "cyberbullying":5,"organized_misinformation":4,"spam_bot":1,
}
SEVERITY_TIERS = {
    "CRITICAL":{"terrorism","self_harm"},"HIGH":{"extremism","incitement","hate_speech"},
    "MEDIUM":{"doxxing","targeted_harassment","cyberbullying"},
    "LOW":{"organized_misinformation"},"INFO":{"spam_bot"},
}
SEVERITY_COLORS = {
    "terrorism":"#ff4444","self_harm":"#ff4444","extremism":"#ff8800",
    "incitement":"#ff8800","hate_speech":"#ff8800","doxxing":"#ffcc00",
    "targeted_harassment":"#ffcc00","cyberbullying":"#ffcc00",
    "organized_misinformation":"#88aaff","spam_bot":"#aaaaaa",
}
THREAT_KEYWORDS = {
    "incitement":{"attack","burn","destroy","kill","riot","violence","murder","assault","massacre","lynching","torch","rampage"},
    "targeted_harassment":{"find him","find her","expose him","expose her","go after","threat","follow him","follow her","hunt him","hunt her","make him pay","make her pay","get him","get her"},
    "organized_misinformation":{"breaking","confirmed","secret","fake news","they are hiding","share this","mainstream media wont tell","suppressed","cover up","hoax","the truth is","wake up sheeple","do your research"},
    "hate_speech":{"all muslims","all hindus","all christians","all jews","all blacks","all whites","sub-human","vermin","parasites","cleanse","exterminate","inferior race","filthy","savages","go back to your country"},
    "terrorism":{"jihad","martyr","infidel","caliphate","bomb threat","explosive device","terror attack","suicide bomb","allahu akbar kill","death to","blow up","detonate"},
    "cyberbullying":{"you are worthless","nobody likes you","kill yourself","you should die","loser","ugly freak","no one cares about you","go away forever","you are pathetic","everyone hates you"},
    "doxxing":{"home address","phone number","personal info","lives at","works at","real name is","ip address","location leaked","private details","dox","doxxed","family address"},
    "self_harm":{"want to die","end my life","kill myself","suicide","not worth living","better off dead","cut myself","no reason to live","final goodbye","can't go on"},
    "extremism":{"white power","white supremacy","great replacement","ethnic cleansing","fascist","nazi","fourth reich","race war","boogaloo","accelerationism","red pill truth"},
    "spam_bot":{"click here now","limited offer","earn money fast","free followers","buy now","dm for promo","win prize","claim your reward","100% guaranteed","miracle cure","lose weight fast","get rich quick"},
}
USER_PROFILE_FIELDS = ["username","display_name","email","phone","location","ip_address","join_date","follower_count","following_count","bio"]

# ── Analysis ────────────────────────────────────────────────────────────────
def normalize(t):
    t = re.sub(r"https?://\S+","<URL>",t.lower())
    return re.sub(r"\s+"," ",re.sub(r"[^\w\s#@<>]","",t)).strip()

def classify(text):
    n = normalize(text)
    s = {c:sum(1 for t in kw if t in n) for c,kw in THREAT_KEYWORDS.items()}
    b = max(s,key=s.get)
    return ("unclassified",0) if s[b]==0 else (b,s[b])

def load_posts(path):
    posts=[]
    with open(path,"r",encoding="utf-8") as f:
        for row in csv.DictReader(f):
            row["timestamp"]=datetime.fromisoformat(row["timestamp"].replace("Z","+00:00"))
            row["text"]=row["text"].strip()
            posts.append(row)
    return posts

def analyse(posts):
    by_acc=defaultdict(list)
    for p in posts: by_acc[p["account_id"]].append(p)
    actors=[]
    for aid,acc_posts in by_acc.items():
        flagged=[{"post_id":p.get("post_id","?"),"timestamp":p["timestamp"].strftime("%Y-%m-%d %H:%M UTC"),
                  "category":c,"keyword_hits":h,"text":p["text"]}
                 for p in acc_posts for c,h in [classify(p["text"])] if c!="unclassified"]
        if not flagged: continue
        prof={f:acc_posts[0].get(f,"N/A") for f in USER_PROFILE_FIELDS}
        prof["account_id"]=aid
        score=sum(THREAT_SEVERITY.get(f["category"],1)*f["keyword_hits"] for f in flagged)
        worst=max(flagged,key=lambda f:THREAT_SEVERITY.get(f["category"],0))["category"]
        actors.append({"profile":prof,"flagged":flagged,"danger":score,"worst_cat":worst})
    actors.sort(key=lambda a:a["danger"],reverse=True)
    return actors

def format_report(actors, stored_count):
    S,T="="*72,"-"*72
    ts=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines=[S,"  PHANTOM  —  SOCIAL MEDIA THREAT INTELLIGENCE",
           f"  Scanned {stored_count} posts  |  {len(actors)} actor(s) shown  |  {ts}",
           S,"","  COLOUR GUIDE",T,
           "  RED    terrorism, self_harm          CRITICAL  (weight 10)",
           "  ORANGE extremism, incitement, hate    HIGH      (weight 7-8)",
           "  YELLOW doxxing, harassment, bully     MEDIUM    (weight 5-6)",
           "  BLUE   organized_misinformation       LOW       (weight 4)",
           "  GREY   spam_bot                       INFO      (weight 1)",
           "","  WARNING: automated triage only - human review required.",S,""]
    if not actors:
        lines.append("  No threat actors detected."); return "\n".join(lines)
    for rank,a in enumerate(actors,1):
        p,score,cat=a["profile"],a["danger"],a["worst_cat"]
        tier=next(t for t,cats in SEVERITY_TIERS.items() if cat in cats)
        lines+=[f"  ACTOR #{rank}  DANGER:{score}  TIER:{tier}  WORST:{cat.upper()}",T,
                "  -- PROFILE "+"-"*61]
        for lbl,k in [("Username","username"),("Name","display_name"),("Email","email"),
                      ("Phone","phone"),("Location","location"),("IP","ip_address"),
                      ("Joined","join_date"),("Followers","follower_count"),
                      ("Following","following_count"),("Bio","bio")]:
            lines.append(f"  |  {lbl:<11}: {p.get(k,'N/A')}")
        lines.append("  |")
        for i,fp in enumerate(a["flagged"],1):
            lines+=[f"  +- POST #{i}  [{fp['post_id']}]  {fp['timestamp']}",
                    f"  |  Category : {fp['category'].upper():<28}  Hits: {fp['keyword_hits']}",
                    f"  |  > {fp['text']}","  |"]
        lines+=["  "+"-"*71,""]
    return "\n".join(lines)

# ── GUI ─────────────────────────────────────────────────────────────────────
BG = "#0d1117"   # dark charcoal — GitHub-dark style

def run_gui():
    root=tk.Tk()
    root.title("PHANTOM  ·  Social Media Threat Intelligence")
    root.geometry("1050x740")
    root.configure(bg=BG)

    # ttk style
    st=ttk.Style(root); st.theme_use("clam")
    st.configure("TButton",background="#4f46e5",foreground="white",
                 font=("Segoe UI",10,"bold"),padding=6)
    st.map("TButton",background=[("active","#6366f1")])

    # ── Header
    hdr=tk.Frame(root,bg="#161b22",pady=10)
    hdr.pack(fill=tk.X)
    tk.Frame(hdr,bg="#238636",height=2).pack(fill=tk.X)   # green accent line
    tk.Label(hdr,text="  ⬡ PHANTOM",font=("Segoe UI",16,"bold"),
             bg="#161b22",fg="#c9d1d9").pack(side=tk.LEFT)
    tk.Label(hdr,text="Social Media Threat Intelligence  ·  Actor Detection  ·  CSV",
             font=("Segoe UI",9),bg="#161b22",fg="#484f58").pack(side=tk.LEFT,padx=12)

    # ── File row
    frow=tk.Frame(root,bg="#161b22",pady=7)
    frow.pack(fill=tk.X,padx=0)
    file_var=tk.StringVar(value="No file selected")
    tk.Label(frow,text="  CSV File:",bg="#161b22",fg="#8b949e",
             font=("Segoe UI",10)).pack(side=tk.LEFT)
    tk.Label(frow,textvariable=file_var,bg="#161b22",fg="#58a6ff",
             font=("Segoe UI",10),width=52,anchor="w").pack(side=tk.LEFT,padx=6)
    def browse():
        p=filedialog.askopenfilename(title="Select CSV",filetypes=[("CSV","*.csv")])
        if p: file_var.set(p)
    ttk.Button(frow,text="Browse...",command=browse).pack(side=tk.LEFT)

    # ── Filter pills
    fbar=tk.Frame(root,bg=BG,pady=5)
    fbar.pack(fill=tk.X,padx=20)
    tk.Label(fbar,text="FILTER:",font=("Segoe UI",8,"bold"),
             bg=BG,fg="#484f58").pack(side=tk.LEFT,padx=(0,8))

    active_filter=tk.StringVar(value="ALL")
    _stored=[]
    pill_cfg={
        "ALL":    ("#1e1e38","#c5cae9"),
        "CRITICAL":("#2a0808","#ff4444"),
        "HIGH":   ("#2a1200","#ff8800"),
        "MEDIUM": ("#2a2600","#ffcc44"),
        "LOW":    ("#081a2a","#88aaff"),
        "INFO":   ("#181818","#aaaaaa"),
    }
    pill_text={"ALL":"◉ All","CRITICAL":"● Critical","HIGH":"● High",
               "MEDIUM":"● Medium","LOW":"● Low","INFO":"● Info"}
    pills={}

    def apply_filter(tier):
        active_filter.set(tier)
        for t,b in pills.items():
            bg2,fg2=pill_cfg[t]
            b.configure(bg=fg2 if t==tier else bg2,fg="#0a0a14" if t==tier else fg2)
        if not _stored: return
        vis=_stored if tier=="ALL" else [a for a in _stored if a["worst_cat"] in SEVERITY_TIERS.get(tier,set())]
        _render(vis)

    for tier in pill_cfg:
        bg2,fg2=pill_cfg[tier]
        b=tk.Label(fbar,text=pill_text[tier],font=("Segoe UI",9,"bold"),
                   bg=bg2,fg=fg2,cursor="hand2",padx=11,pady=4)
        b.pack(side=tk.LEFT,padx=3)
        b.bind("<Button-1>",lambda e,t=tier:apply_filter(t))
        b.bind("<Enter>",lambda e,btn=b,t=tier:btn.configure(bg=pill_cfg[t][1],fg="#0a0a14"))
        b.bind("<Leave>",lambda e,btn=b,t=tier:btn.configure(
            bg=pill_cfg[t][1] if active_filter.get()==t else pill_cfg[t][0],
            fg="#0a0a14" if active_filter.get()==t else pill_cfg[t][1]))
        pills[tier]=b
    apply_filter("ALL")

    # ── Controls row
    ctrl=tk.Frame(root,bg=BG,pady=4)
    ctrl.pack(fill=tk.X,padx=20)
    status_var=tk.StringVar(value="Ready.")
    tk.Label(ctrl,textvariable=status_var,bg=BG,fg="#3fb950",
             font=("Segoe UI",9,"bold")).pack(side=tk.LEFT)

    def clear_out():
        out.configure(state=tk.NORMAL); out.delete("1.0",tk.END)
        out.configure(state=tk.DISABLED); status_var.set("Cleared.")
    ttk.Button(ctrl,text="Clear",command=clear_out).pack(side=tk.RIGHT,padx=(4,0))

    def _render(actors):
        report=format_report(actors,len(_stored))
        out.configure(state=tk.NORMAL); out.delete("1.0",tk.END)
        out.insert(tk.END,report)
        for cat,col in SEVERITY_COLORS.items():
            pos="1.0"
            while True:
                p=out.search(cat,pos,stopindex=tk.END,nocase=True)
                if not p: break
                e=f"{p}+{len(cat)}c"
                out.tag_add(cat,p,e); out.tag_config(cat,foreground=col,font=("Consolas",10,"bold"))
                pos=e
        out.configure(state=tk.DISABLED)

    def run_analysis():
        path=file_var.get()
        if path=="No file selected": status_var.set("  Select a CSV first."); return
        status_var.set("Analysing...")
        root.update_idletasks()
        try:
            posts=load_posts(path); actors=analyse(posts)
            _stored.clear(); _stored.extend(actors)
            _render(actors)
            status_var.set(f"Done  {len(posts)} posts  |  {len(actors)} actors found")
        except FileNotFoundError: status_var.set("  File not found.")
        except Exception as ex:   status_var.set(f"  Error: {ex}")

    ttk.Button(ctrl,text="Run Analysis",command=run_analysis).pack(side=tk.RIGHT,padx=(0,4))

    # ── Output console
    out=scrolledtext.ScrolledText(
        root,state=tk.DISABLED,bg="#161b22",fg="#c9d1d9",
        insertbackground="white",font=("Consolas",10),relief=tk.FLAT,
        wrap=tk.NONE,highlightthickness=1,
        highlightbackground="#30363d",highlightcolor="#58a6ff")
    out.pack(fill=tk.BOTH,expand=True,padx=16,pady=(4,16))

    root.protocol("WM_DELETE_WINDOW",root.destroy)
    root.mainloop()

if __name__=="__main__":
    run_gui()
