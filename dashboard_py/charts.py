"""Server-rendered SVG charts (pure Python, no JS). Each function returns an SVG
string the templates embed directly; HTMX re-renders them on a poll. The palette
matches the dark/purple cybersecurity-monitoring theme.

Kept dependency-free on purpose so the dashboard stays a no-build, no-JS app.
"""
import math

PURPLE = "#a855f7"
MAGENTA = "#d946ef"
TEAL = "#2dd4bf"
ORANGE = "#fb923c"
RED = "#f87171"
MUTED = "#6b6b85"
GRID = "#26263a"


def _pts(values, w, h, pad=2):
    if not values:
        return []
    lo, hi = min(values), max(values)
    rng = (hi - lo) or 1
    n = len(values)
    step = (w - 2 * pad) / max(1, n - 1)
    return [(pad + i * step, h - pad - (v - lo) / rng * (h - 2 * pad))
            for i, v in enumerate(values)]


def sparkline(values, color=PURPLE, w=160, h=56, fill=True):
    """A smooth-ish area/line sparkline."""
    if not values:
        values = [0, 0]
    pts = _pts(values, w, h)
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    gid = f"g{abs(hash((tuple(values), color))) % 99999}"
    area = ""
    if fill:
        poly = f"{pts[0][0]:.1f},{h} " + line + f" {pts[-1][0]:.1f},{h}"
        area = (f'<polygon points="{poly}" fill="url(#{gid})" opacity="0.35"/>')
    return f'''<svg viewBox="0 0 {w} {h}" width="100%" height="{h}" preserveAspectRatio="none">
  <defs><linearGradient id="{gid}" x1="0" x2="0" y1="0" y2="1">
    <stop offset="0%" stop-color="{color}"/><stop offset="100%" stop-color="{color}" stop-opacity="0"/>
  </linearGradient></defs>
  {area}<polyline points="{line}" fill="none" stroke="{color}" stroke-width="2"
    stroke-linejoin="round" stroke-linecap="round"/>
  <circle cx="{pts[-1][0]:.1f}" cy="{pts[-1][1]:.1f}" r="2.6" fill="{color}"/>
</svg>'''


def sparkbars(values, color=PURPLE, w=160, h=56):
    """A mini bar chart; the last bar is highlighted."""
    if not values:
        values = [0]
    hi = max(values) or 1
    n = len(values)
    bw = (w / n) * 0.62
    gap = (w / n) * 0.38
    bars = []
    for i, v in enumerate(values):
        bh = max(2, v / hi * (h - 4))
        x = i * (bw + gap) + gap / 2
        y = h - bh
        c = MAGENTA if i == n - 1 else color
        bars.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bw:.1f}" height="{bh:.1f}" '
                    f'rx="2" fill="{c}" opacity="{0.55 + 0.45 * (i == n - 1)}"/>')
    return f'<svg viewBox="0 0 {w} {h}" width="100%" height="{h}">{"".join(bars)}</svg>'


def gauge(pct, center_label="", sub_label="", size=210):
    """A segmented semicircular gauge (like the reference 'Risk Score'). pct 0..100."""
    pct = max(0, min(100, pct))
    cx, cy, r = size / 2, size * 0.62, size * 0.42
    n_seg = 32
    filled = round(pct / 100 * n_seg)
    segs = []
    for i in range(n_seg):
        a0 = math.pi * (1 - i / n_seg)          # 180deg -> 0deg
        a1 = math.pi * (1 - (i + 0.62) / n_seg)
        on = i < filled
        ro, ri = r, r * 0.78
        x0o, y0o = cx + ro * math.cos(a0), cy - ro * math.sin(a0)
        x1o, y1o = cx + ro * math.cos(a1), cy - ro * math.sin(a1)
        x1i, y1i = cx + ri * math.cos(a1), cy - ri * math.sin(a1)
        x0i, y0i = cx + ri * math.cos(a0), cy - ri * math.sin(a0)
        # gradient purple->magenta across the arc
        t = i / n_seg
        col = MAGENTA if on and t > 0.66 else (PURPLE if on else "#23233a")
        segs.append(f'<path d="M{x0o:.1f},{y0o:.1f} L{x1o:.1f},{y1o:.1f} '
                    f'L{x1i:.1f},{y1i:.1f} L{x0i:.1f},{y0i:.1f} Z" fill="{col}"/>')
    return f'''<svg viewBox="0 0 {size} {size*0.78}" width="100%" height="auto">
  {"".join(segs)}
  <text x="{cx}" y="{cy-6}" text-anchor="middle" fill="#f0f0f5"
        font-size="{size*0.16:.0f}" font-weight="700">{center_label}</text>
  <text x="{cx}" y="{cy+14}" text-anchor="middle" fill="{MUTED}" font-size="12">{sub_label}</text>
  <text x="{cx-r}" y="{cy+18}" text-anchor="middle" fill="{MUTED}" font-size="10">0</text>
  <text x="{cx+r}" y="{cy+18}" text-anchor="middle" fill="{MUTED}" font-size="10">100</text>
</svg>'''


def segbar(pct, color=PURPLE, segments=18):
    """A segmented horizontal progress bar (the table 'security score' style)."""
    pct = max(0, min(100, pct))
    on = round(pct / 100 * segments)
    cells = "".join(
        f'<div style="flex:1;height:10px;border-radius:2px;background:{color if i < on else "#26263a"}"></div>'
        for i in range(segments))
    return f'<div style="display:flex;gap:2px;align-items:center;min-width:90px">{cells}</div>'


def multiline(series, w=1100, h=210):
    """A trust-score-over-time chart: one line per entity. `series` is a list of
    (label, values, color); y is the 0..10 trust score. Horizontal guides mark
    the decision thresholds. The viewBox is sized close to the real display so
    uniform scaling keeps lines/text crisp (no aspect-ratio stretching)."""
    pl, pr, pt, pb = 14, 44, 16, 16
    iw, ih = w - pl - pr, h - pt - pb

    def y(v):
        return pt + (1 - max(0.0, min(10.0, v)) / 10.0) * ih

    # threshold bands + guide lines (allow 8 / stricter 5 / challenge 3 / block 1)
    bands = ""
    for lo, hi, col in [(8, 10, "rgba(45,212,191,.05)"), (5, 8, "rgba(59,130,246,.04)"),
                        (3, 5, "rgba(251,146,60,.05)"), (1, 3, "rgba(248,113,113,.05)"),
                        (0, 1, "rgba(123,36,28,.10)")]:
        bands += (f'<rect x="{pl}" y="{y(hi):.1f}" width="{iw}" '
                  f'height="{(y(lo)-y(hi)):.1f}" fill="{col}"/>')
    grid = ""
    for gv, lbl in [(8, "allow"), (5, "stricter"), (3, "challenge"), (1, "block")]:
        yy = y(gv)
        grid += (f'<line x1="{pl}" y1="{yy:.1f}" x2="{w-pr}" y2="{yy:.1f}" '
                 f'stroke="#24243a" stroke-width="1" stroke-dasharray="2 5"/>'
                 f'<text x="{w-pr+5}" y="{yy+4:.1f}" fill="#54546e" font-size="13">{gv}</text>')

    lines = ""
    for _, vals, color in series:
        if not vals:
            continue
        n = len(vals)
        if n == 1:
            pts = [(pl + iw / 2, y(vals[0]))]
        else:
            step = iw / (n - 1)
            pts = [(pl + i * step, y(v)) for i, v in enumerate(vals)]
        if n > 1:
            poly = " ".join(f"{x:.1f},{yy:.1f}" for x, yy in pts)
            lines += (f'<polyline points="{poly}" fill="none" stroke="{color}" '
                      f'stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>')
        lines += f'<circle cx="{pts[-1][0]:.1f}" cy="{pts[-1][1]:.1f}" r="4" fill="{color}"/>'

    return (f'<svg viewBox="0 0 {w} {h}" preserveAspectRatio="xMidYMid meet" '
            f'style="width:100%;height:auto;display:block">{bands}{grid}{lines}</svg>')


# A palette for per-entity lines / legends.
PALETTE = [PURPLE, TEAL, ORANGE, RED, MAGENTA, "#60a5fa", "#a3e635", "#f472b6"]


def donut(parts, size=150):
    """parts: list of (label, value, color). Renders a donut with a total in the centre."""
    total = sum(v for _, v, _ in parts) or 1
    cx = cy = size / 2
    r = size * 0.38
    sw = size * 0.16
    circ = 2 * math.pi * r
    off = 0.0
    rings = []
    for _, v, c in parts:
        frac = v / total
        dash = frac * circ
        rings.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{c}" '
            f'stroke-width="{sw}" stroke-dasharray="{dash:.1f} {circ - dash:.1f}" '
            f'stroke-dashoffset="{-off:.1f}" transform="rotate(-90 {cx} {cy})"/>')
        off += dash
    return f'''<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}">
  <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#1c1c2a" stroke-width="{sw}"/>
  {"".join(rings)}
  <text x="{cx}" y="{cy-2}" text-anchor="middle" fill="#f0f0f5" font-size="22" font-weight="700">{int(total)}</text>
  <text x="{cx}" y="{cy+16}" text-anchor="middle" fill="{MUTED}" font-size="10">requests</text>
</svg>'''
