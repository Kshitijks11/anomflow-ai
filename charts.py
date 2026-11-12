GOOD, BAD, WARN = "#4cd7a0", "#ff6b6b", "#f2c94c"

THEMES = {
    True: {"fig": "#0b1d3a", "ax": "#12294d", "text": "#e8eefc", "muted": "#8fa3c7"},
    False: {"fig": "#ffffff", "ax": "#f4f7fb", "text": "#1b2a41", "muted": "#55657d"},
}


def _style(ax, title, t):
    ax.set_facecolor(t["ax"])
    ax.set_title(title, color=t["text"], fontsize=11, pad=8)
    ax.tick_params(colors=t["muted"], labelsize=9)
    for spine in ax.spines.values():
        spine.set_color(t["muted"])


def draw_charts(fig, df, dark=True):
    """Four plain-language charts in a 2x2 grid. Needs the columns added by insights.prepare()."""
    t = THEMES[dark]
    fig.clear()
    fig.set_facecolor(t["fig"])
    if df.empty:
        return

    n_bad = int((df["verdict"] == "Suspicious").sum())
    n_ok = len(df) - n_bad

    # 1. overall result (donut)
    ax1 = fig.add_subplot(221)
    ax1.pie([n_ok, n_bad], colors=[GOOD, BAD], startangle=90, counterclock=False,
            wedgeprops={"width": 0.42, "edgecolor": t["fig"]})
    ax1.text(0, 0, f"{n_bad / len(df):.0%}\nsuspicious", ha="center", va="center",
             color=t["text"], fontsize=11, fontweight="bold")
    ax1.set_title("Overall result", color=t["text"], fontsize=11, pad=8)
    ax1.set_xlabel(f"Normal {n_ok:,}   |   Suspicious {n_bad:,}", color=t["muted"], fontsize=9)

    # 2. traffic by type, split into normal / suspicious
    ax2 = fig.add_subplot(222)
    svc = df.groupby(["service", "verdict"]).size().unstack(fill_value=0)
    for col in ("Normal", "Suspicious"):
        if col not in svc.columns:
            svc[col] = 0
    svc = svc.assign(total=svc["Normal"] + svc["Suspicious"]).sort_values("total").tail(6)
    names = list(svc.index)
    ax2.barh(names, list(svc["Normal"]), color=GOOD)
    ax2.barh(names, list(svc["Suspicious"]), left=list(svc["Normal"]), color=BAD)
    _style(ax2, "What kind of traffic", t)

    # 3. risk levels
    ax3 = fig.add_subplot(223)
    bands = df["risk_band"].value_counts().reindex(["Low", "Medium", "High"], fill_value=0)
    ax3.bar(list(bands.index), list(bands.values), color=[GOOD, WARN, BAD])
    _style(ax3, "Risk level of each connection", t)

    # 4. what kind of attack (among flagged rows, using the model's specific guess)
    ax4 = fig.add_subplot(224)
    if "attack_type" in df.columns and n_bad:
        flagged = df[df["verdict"] == "Suspicious"]
        types = flagged["attack_type"].value_counts().head(6)
        if not types.empty:
            ax4.barh(list(types.index)[::-1], list(types.values)[::-1], color=BAD)
    _style(ax4, "Suspected attack types", t)
    if not ("attack_type" in df.columns and n_bad):
        ax4.text(0.5, 0.5, "No suspicious connections", ha="center", va="center",
                 color=t["muted"], fontsize=10, transform=ax4.transAxes)

    fig.subplots_adjust(left=0.1, right=0.97, top=0.92, bottom=0.08, wspace=0.65, hspace=0.55)


def draw_timeline(fig, history, dark=True):
    """Suspicious-flow count per capture batch, for continuous monitoring.
    history: list of {"time": str, "total": int, "suspicious": int}, most recent last."""
    t = THEMES[dark]
    fig.clear()
    fig.set_facecolor(t["fig"])
    ax = fig.add_subplot(111)
    if not history:
        ax.text(0.5, 0.5, "No captures yet", ha="center", va="center",
                 color=t["muted"], fontsize=10, transform=ax.transAxes)
        _style(ax, "Suspicious connections over time", t)
        return
    labels = [h["time"] for h in history]
    bad = [h["suspicious"] for h in history]
    colors = [BAD if v > 0 else GOOD for v in bad]
    ax.bar(range(len(history)), bad, color=colors)
    ax.set_xticks(range(len(history)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
    _style(ax, "Suspicious connections per capture", t)
    fig.subplots_adjust(left=0.07, right=0.98, top=0.82, bottom=0.32)