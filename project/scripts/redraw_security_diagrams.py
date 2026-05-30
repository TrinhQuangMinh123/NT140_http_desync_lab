from __future__ import annotations

from pathlib import Path
from textwrap import wrap

from PIL import Image, ImageDraw, ImageFont


W, H = 1920, 1080
OUT = Path("outputs/redrawn_diagrams")

BLUE = "#0b55c8"
BLUE2 = "#2f80ed"
CYAN = "#14c8d8"
GREEN = "#159447"
RED = "#d72d24"
ORANGE = "#f59e0b"
YELLOW = "#ffd33d"
INK = "#101828"
MUTED = "#475467"
GRID = "#e8eef7"
PANEL = "#f7fbff"


def font(size: int, bold: bool = False, italic: bool = False) -> ImageFont.FreeTypeFont:
    base = Path("C:/Windows/Fonts")
    if bold and italic:
        name = "arialbi.ttf"
    elif bold:
        name = "arialbd.ttf"
    elif italic:
        name = "ariali.ttf"
    else:
        name = "arial.ttf"
    return ImageFont.truetype(str(base / name), size=size)


F = {
    "title": font(70, True),
    "h1": font(54, True),
    "h2": font(42, True),
    "h3": font(34, True),
    "body": font(30),
    "body_b": font(30, True),
    "small": font(24),
    "small_b": font(24, True),
    "mono": ImageFont.truetype("C:/Windows/Fonts/consolab.ttf", size=31),
    "mono_b": ImageFont.truetype("C:/Windows/Fonts/consolab.ttf", size=32),
    "big": font(96, True),
    "mega": font(132, True),
}


def person_icon(d, x, y, color=RED, attacker=True, scale=1.0):
    s = scale
    d.ellipse((x + 24 * s, y, x + 72 * s, y + 48 * s), fill=color)
    if attacker:
        d.polygon([(x + 24 * s, y + 16 * s), (x + 48 * s, y + 42 * s), (x + 72 * s, y + 16 * s)], fill="white")
    d.pieslice((x, y + 42 * s, x + 96 * s, y + 130 * s), 180, 360, fill=color)
    d.rectangle((x + 18 * s, y + 76 * s, x + 78 * s, y + 118 * s), fill=color)


def request_box(d, box, lines, accent=RED, fill="#ffffff"):
    rounded(d, box, outline="#98a2b3", fill=fill, width=3, radius=10)
    x1, y1, x2, y2 = box
    y = y1 + 18
    for line in lines:
        color = accent if line.startswith(("Trailer", "id=", "Content-Length", "forgery")) else INK
        d.text((x1 + 16, y), line, fill=color, font=font(18, True))
        y += 25


def app_box(d, box, title, rows, color=BLUE):
    x1, y1, x2, y2 = box
    rounded(d, box, outline=color, fill="white", width=4, radius=12)
    d.rounded_rectangle((x1, y1, x2, y1 + 52), radius=12, fill=color)
    d.rectangle((x1, y1 + 30, x2, y1 + 52), fill=color)
    d.text((x1 + 24, y1 + 11), title, fill="white", font=font(28, True))
    y = y1 + 74
    for text, fill in rows:
        d.rounded_rectangle((x1 + 22, y, x2 - 22, y + 48), radius=10, fill=fill)
        d.text((x1 + 38, y + 10), text, fill="white", font=font(20, True))
        y += 62


def draw_slide_19():
    im, d = new_canvas("4 Attack Techniques từ các Discrepancy")
    panels = [
        (35, 150, 940, 525, "(a) REQUEST SMUGGLING (Bypass Auth)", BLUE),
        (980, 150, 1885, 525, "(b) REQUEST CONFUSING (Bypass Logic)", BLUE),
        (35, 565, 940, 1010, "(c) RESPONSE STEALING (Đánh cắp)", RED),
        (980, 565, 1885, 1010, "(d) RESPONSE FORGERY (Giả mạo)", RED),
    ]
    for x1, y1, x2, y2, title, color in panels:
        soft_panel(d, (x1, y1, x2, y2), outline=color, fill="#ffffff", width=3, radius=16)
        d.text((x1 + 25, y1 + 22), title, fill=INK, font=font(32, True))

    # (a) Request smuggling
    person_icon(d, 70, 310, RED, True, 0.86)
    d.text((45, 425), "Attacker", fill=RED, font=font(24, True))
    request_box(d, (150, 235, 395, 355), ["HTTP/1.1", "TE: chunked", "Conn: keep-alive", "Trailer: /path2"], RED)
    arrow(d, (135, 380), (435, 380), color=RED, width=5)
    d.text((175, 402), "Attacker -> Proxy", fill=RED, font=font(24, True))
    rounded(d, (435, 230, 675, 410), outline=BLUE, fill="#eff6ff", width=4, radius=12)
    d.text((485, 245), "Proxy", fill=BLUE, font=font(30, True))
    d.text((490, 280), "ATS", fill=INK, font=font(24, True))
    server_icon(d, 470, 318, 0.8, BLUE)
    arrow(d, (675, 330), (810, 330), color=BLUE, width=5)
    server_icon(d, 805, 288, 0.95, BLUE)
    d.text((775, 390), "Backend", fill=INK, font=font(25, True))
    d.text((675, 365), "/path2 ẩn", fill=RED, font=font(23, True))

    # (b) Request confusing
    person_icon(d, 1015, 310, RED, True, 0.86)
    d.text((990, 425), "Attacker", fill=RED, font=font(24, True))
    request_box(d, (1110, 225, 1420, 370), ["POST / HTTP/1.1", "TE: Chunked", "Content-Length: 0", "Form payload", "id='1' or sleep(1);###"], RED)
    arrow(d, (1088, 382), (1440, 382), color=RED, width=5)
    server_icon(d, 1455, 310, 1.05, BLUE)
    d.text((1440, 420), "Gunicorn", fill=INK, font=font(25, True))
    arrow(d, (1545, 350), (1660, 350), color=BLUE, width=5)
    d.text((1565, 375), "Flask", fill=INK, font=font(25, True))
    app_box(d, (1660, 230, 1865, 435), "Flask", [("length = 0", BLUE), ("id = SQLi", RED)], BLUE)

    # (c) Response stealing
    person_icon(d, 70, 690, RED, True, 0.82)
    d.text((45, 805), "Attacker", fill=RED, font=font(24, True))
    person_icon(d, 72, 850, BLUE, False, 0.78)
    d.text((58, 960), "Victim", fill=BLUE, font=font(24, True))
    arrow(d, (150, 735), (470, 735), color=RED, width=5)
    d.text((225, 696), "1  Pipelined", fill=RED, font=font(25, True))
    arrow(d, (150, 895), (470, 815), color=BLUE, width=5)
    d.text((160, 850), "2", fill=BLUE, font=font(28, True))
    server_icon(d, 470, 730, 1.15, BLUE)
    d.text((455, 840), "Twisted", fill=INK, font=font(28, True))
    request_box(d, (245, 805, 455, 980), ["HTTP/1.1 200 OK", "CL: 8", "Keep-Alive", "text/html", "HTTP/1.1 200 OK", "CL: 7", "forgery"], RED)
    server_icon(d, 810, 675, 1.1, RED)
    d.text((750, 790), "Attacker Server", fill=RED, font=font(23, True))
    server_icon(d, 810, 865, 1.1, BLUE)
    d.text((785, 975), "Benign Server", fill=INK, font=font(23, True))
    arrow(d, (560, 745), (810, 705), color=BLUE, width=4)
    arrow(d, (560, 780), (810, 725), color=RED, width=4)
    arrow(d, (560, 820), (810, 885), color=RED, width=4)
    arrow(d, (810, 925), (560, 850), color=BLUE, width=4)
    d.text((650, 695), "4", fill=BLUE, font=font(27, True))
    d.text((670, 800), "Hold", fill=RED, font=font(28, True))
    d.text((690, 910), "7", fill=BLUE, font=font(27, True))

    # (d) Response forgery
    person_icon(d, 1015, 760, RED, True, 0.86)
    d.text((990, 875), "Attacker", fill=RED, font=font(24, True))
    arrow(d, (1110, 815), (1220, 815), color=RED, width=5)
    server_icon(d, 1215, 760, 1.08, RED)
    d.text((1155, 880), "Attacker-controlled\nCGI Application", fill=RED, font=font(23, True))
    request_box(d, (1315, 665, 1490, 780), ["Content-Type: text/html", "CL: 7", "HTTP/1.1 200 OK", "forgery"], RED)
    arrow(d, (1325, 815), (1510, 815), color=RED, width=5)
    server_icon(d, 1510, 760, 1.08, BLUE)
    d.text((1500, 880), "Apache", fill=INK, font=font(25, True))
    request_box(d, (1600, 650, 1765, 780), ["HTTP/1.1 200 OK", "CL: 8", "Keep-Alive", "forged HTML"], RED)
    arrow(d, (1605, 815), (1775, 815), color=RED, width=5)
    server_icon(d, 1775, 760, 1.08, BLUE)
    d.text((1745, 880), "Downstream", fill=INK, font=font(25, True))
    im.save(OUT / "19.png")


def new_canvas(title: str, subtitle: str | None = None) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    im = Image.new("RGB", (W, H), "#fbfdff")
    d = ImageDraw.Draw(im)
    for x in range(0, W, 80):
        d.line((x, 0, x, H), fill=GRID, width=1)
    for y in range(0, H, 80):
        d.line((0, y, W, y), fill=GRID, width=1)
    d.rectangle((0, 0, W - 1, H - 1), outline="#7b61ff", width=4)
    title_font = F["title"]
    for size in (70, 64, 58, 52, 46):
        candidate = font(size, True)
        if text_size(d, title, candidate)[0] <= W - 64:
            title_font = candidate
            break
    d.text((32, 24), title, fill="#0b1220", font=title_font)
    if subtitle:
        d.text((36, 105), subtitle, fill=INK, font=F["small"])
    return im, d


def rounded(d: ImageDraw.ImageDraw, box, outline=BLUE, fill="white", width=3, radius=16):
    d.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def soft_panel(d: ImageDraw.ImageDraw, box, outline=BLUE, fill=PANEL, width=3, radius=22):
    x1, y1, x2, y2 = box
    d.rounded_rectangle((x1 + 8, y1 + 10, x2 + 8, y2 + 10), radius=radius, fill="#d9e8fb")
    rounded(d, box, outline=outline, fill=fill, width=width, radius=radius)


def text_size(d: ImageDraw.ImageDraw, text: str, fnt) -> tuple[int, int]:
    b = d.textbbox((0, 0), text, font=fnt)
    return b[2] - b[0], b[3] - b[1]


def fit_lines(d: ImageDraw.ImageDraw, text: str, fnt, max_w: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    cur = ""
    for w in words:
        trial = w if not cur else f"{cur} {w}"
        if text_size(d, trial, fnt)[0] <= max_w:
            cur = trial
        else:
            if cur:
                lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


def draw_wrapped(d: ImageDraw.ImageDraw, text: str, xy, max_w: int, fnt, fill=INK, line_gap=8):
    x, y = xy
    for line in text.split("\n"):
        if not line:
            y += fnt.size + line_gap
            continue
        for part in fit_lines(d, line, fnt, max_w):
            d.text((x, y), part, fill=fill, font=fnt)
            y += fnt.size + line_gap
    return y


def arrow(d: ImageDraw.ImageDraw, start, end, color=BLUE, width=6, dashed=False):
    x1, y1 = start
    x2, y2 = end
    if dashed:
        dash = 18
        gap = 12
        total = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5
        steps = max(1, int(total // (dash + gap)))
        for i in range(steps + 1):
            a = i * (dash + gap) / total
            b = min(1, (i * (dash + gap) + dash) / total)
            d.line((x1 + (x2 - x1) * a, y1 + (y2 - y1) * a, x1 + (x2 - x1) * b, y1 + (y2 - y1) * b), fill=color, width=width)
    else:
        d.line((start, end), fill=color, width=width)
    dx, dy = x2 - x1, y2 - y1
    length = max(1, (dx * dx + dy * dy) ** 0.5)
    ux, uy = dx / length, dy / length
    px, py = -uy, ux
    size = 22
    p1 = (x2, y2)
    p2 = (x2 - ux * size + px * size * 0.55, y2 - uy * size + py * size * 0.55)
    p3 = (x2 - ux * size - px * size * 0.55, y2 - uy * size - py * size * 0.55)
    d.polygon((p1, p2, p3), fill=color)


def server_icon(d, x, y, scale=1.0, color=BLUE):
    w, h = int(78 * scale), int(28 * scale)
    for i in range(3):
        yy = y + i * int(31 * scale)
        rounded(d, (x, yy, x + w, yy + h), outline="#344054", fill="#eef7ff", width=max(2, int(2 * scale)), radius=4)
        d.line((x + 12 * scale, yy + 9 * scale, x + 44 * scale, yy + 9 * scale), fill=color, width=max(2, int(3 * scale)))
        d.ellipse((x + 58 * scale, yy + 8 * scale, x + 66 * scale, yy + 16 * scale), fill=GREEN)


def computer_icon(d, x, y, color=BLUE):
    rounded(d, (x + 28, y, x + 102, y + 60), outline=color, fill="white", width=5, radius=4)
    d.rectangle((x + 58, y + 60, x + 72, y + 78), fill=color)
    d.line((x + 42, y + 82, x + 88, y + 82), fill=color, width=5)
    d.ellipse((x, y + 28, x + 38, y + 66), fill=color)
    d.pieslice((x - 14, y + 62, x + 52, y + 120), 180, 360, fill=color)


def shield_icon(d, x, y, color=BLUE):
    pts = [(x + 42, y), (x + 82, y + 16), (x + 76, y + 78), (x + 42, y + 104), (x + 8, y + 78), (x + 2, y + 16)]
    d.polygon(pts, outline=color, fill="#eef7ff")
    d.line((x + 42, y + 12, x + 42, y + 84), fill=color, width=5)


def target_icon(d, x, y, color=GREEN):
    for r in (48, 32, 16):
        d.ellipse((x - r, y - r, x + r, y + r), outline=color, width=5)
    d.line((x - 56, y, x + 56, y), fill=color, width=4)
    d.line((x, y - 56, x, y + 56), fill=color, width=4)
    arrow(d, (x - 18, y + 20), (x + 38, y - 38), color=color, width=5)


def simple_icon(d, kind: str, x: int, y: int, color: str):
    if kind == "shuffle":
        d.line((x, y + 35, x + 36, y + 35, x + 72, y + 5), fill=color, width=10)
        d.line((x, y + 75, x + 36, y + 75, x + 72, y + 105), fill=color, width=10)
        arrow(d, (x + 54, y + 5), (x + 104, y + 5), color=color, width=8)
        arrow(d, (x + 54, y + 105), (x + 104, y + 105), color=color, width=8)
    elif kind == "finger":
        d.rounded_rectangle((x + 22, y + 8, x + 82, y + 96), radius=28, outline=color, width=6)
        for off in (0, 16, 32):
            d.arc((x + 10 + off, y + 8 + off, x + 94 - off, y + 104 - off), 210, 500, fill=color, width=5)
    elif kind == "split":
        arrow(d, (x, y + 75), (x + 74, y + 30), color=color, width=10)
        arrow(d, (x, y + 75), (x + 74, y + 118), color=color, width=10)
    elif kind == "radar":
        target_icon(d, x + 60, y + 60, color)
    elif kind == "warning":
        d.polygon([(x + 60, y), (x + 120, y + 105), (x, y + 105)], outline=color, fill="#fff7ed")
        d.line((x + 60, y + 36, x + 60, y + 70), fill=color, width=8)
        d.ellipse((x + 55, y + 82, x + 65, y + 92), fill=color)
    elif kind == "gear":
        d.ellipse((x + 15, y + 15, x + 105, y + 105), outline=color, width=12)
        d.ellipse((x + 45, y + 45, x + 75, y + 75), outline=color, width=8)
        d.line((x + 60, y - 5, x + 60, y + 20), fill=color, width=10)
        d.line((x + 60, y + 100, x + 60, y + 125), fill=color, width=10)
        d.line((x - 5, y + 60, x + 20, y + 60), fill=color, width=10)
        d.line((x + 100, y + 60, x + 125, y + 60), fill=color, width=10)
    elif kind == "bell":
        d.pieslice((x + 16, y + 15, x + 104, y + 112), 180, 360, fill=color)
        d.rectangle((x + 22, y + 60, x + 98, y + 100), fill=color)
        d.ellipse((x + 52, y + 98, x + 70, y + 116), fill=color)
    elif kind == "shield":
        shield_icon(d, x + 12, y + 4, color)


def draw_slide_21():
    im, d = new_canvas("Thực nghiệm: 4 môi trường × 5 RNG seeds")
    soft_panel(d, (60, 175, 820, 865), outline=BLUE, fill="#f8fbff")
    d.text((175, 215), "Sơ đồ Mạng lưới Môi trường", fill=INK, font=font(40, True))
    pairs = [
        ("NGINX 1.25", "Gunicorn"),
        ("HAProxy 2.9", "Gunicorn"),
        ("ATS 9.2", "gevent"),
        ("Apache HTTPD", "Tomcat 10"),
    ]
    y = 300
    for proxy, server in pairs:
        server_icon(d, 205, y, 0.74, CYAN)
        server_icon(d, 645, y, 0.74, CYAN)
        arrow(d, (325, y + 38), (592, y + 38), color=CYAN, width=6)
        d.text((155, y + 82), "[Icon Proxy]", fill=MUTED, font=font(22, True))
        d.text((160, y + 108), proxy, fill=INK, font=font(22, True))
        d.text((605, y + 82), "[Icon Server]", fill=MUTED, font=font(22, True))
        d.text((616, y + 108), server, fill=INK, font=font(22, True))
        y += 130

    cards = [
        (880, 175, 1325, 480, "RNG Seeds", "1337, 1338, 1339, 1340, 1341\nPaper-style diversity", CYAN, "dice"),
        (1380, 175, 1845, 480, "Mutations/Seed", "3 mutations + 1 original", BLUE, "dna"),
        (880, 520, 1325, 865, "Detection\nRules", "9 rules\n(HDHUNTER 7 + R8 Order + R9 body_hash)", BLUE2, "target"),
        (1380, 520, 1845, 865, "Snapshot\nIsolation", "Reset container\nmỗi 24 tests", GREEN, "reset"),
    ]
    for x1, y1, x2, y2, title, body, color, kind in cards:
        soft_panel(d, (x1, y1, x2, y2), outline=color, fill="white")
        if kind == "target":
            target_icon(d, x1 + 92, y1 + 108, color)
        else:
            rounded(d, (x1 + 35, y1 + 40, x1 + 170, y1 + 175), outline=color, fill="#eef7ff", width=4)
            if kind == "dice":
                d.regular_polygon((x1 + 82, y1 + 110, 42), n_sides=6, outline=color, fill=None)
                d.rectangle((x1 + 100, y1 + 72, x1 + 150, y1 + 122), outline=color, width=4)
            elif kind == "dna":
                d.arc((x1 + 65, y1 + 58, x1 + 140, y1 + 160), 90, 270, fill=color, width=5)
                d.arc((x1 + 65, y1 + 58, x1 + 140, y1 + 160), 270, 90, fill=color, width=5)
            elif kind == "reset":
                d.arc((x1 + 65, y1 + 67, x1 + 145, y1 + 147), 30, 320, fill=color, width=10)
                d.rectangle((x1 + 115, y1 + 128, x1 + 152, y1 + 165), outline=color, width=5)
        draw_wrapped(d, title, (x1 + 205, y1 + 68), x2 - x1 - 225, font(32, True), fill=INK)
        body_font = font(27, True)
        body_color = GREEN if ("Reset" in body or "1337" in body) else INK
        draw_wrapped(d, body, (x1 + 90, y1 + 205), x2 - x1 - 130, body_font, fill=body_color)

    rounded(d, (60, 900, 1860, 1030), outline=CYAN, fill="#effcff", width=5, radius=18)
    d.text((180, 938), "1360", fill=CYAN, font=font(102, True))
    d.text((430, 962), "logical test cases = ", fill=INK, font=font(38, True))
    d.text((900, 962), "960", fill=GREEN, font=font(38, True))
    d.text((1000, 962), "Request-side + ", fill=INK, font=font(38, True))
    d.text((1320, 962), "400", fill=GREEN, font=font(38, True))
    d.text((1420, 962), "Response-side", fill=INK, font=font(38, True))
    im.save(OUT / "21.png")


def draw_slide_22():
    im, d = new_canvas("920 discrepancies / 1360 tests = 67.6%")
    top = [
        (95, 215, 610, 560, "Request-side", "56.9%", "(546 / 960 tests)", CYAN),
        (675, 170, 1245, 605, "Overall Hit Rate", "67.6%", "(920 / 1360 tests)", "#667085"),
        (1310, 215, 1825, 560, "Response-side", "93.5%", "(374 / 400 tests)", "#ff4d2e"),
    ]
    for x1, y1, x2, y2, title, pct, sub, color in top:
        soft_panel(d, (x1, y1, x2, y2), outline=color, fill="white", width=5, radius=20)
        d.text((x1 + 130, y1 + 55), title, fill=INK, font=F["h2"])
        d.text((x1 + 105, y1 + 135), pct, fill=color, font=F["big"])
        d.text((x1 + 125, y1 + 260), sub, fill=MUTED, font=F["h3"])
    arrow(d, (360, 560), (360, 650), color=CYAN, width=6)
    arrow(d, (1560, 560), (1560, 650), color="#ff4d2e", width=6)
    soft_panel(d, (95, 690, 1035, 985), outline=CYAN, fill="white", width=5, radius=20)
    d.text((135, 730), "Response-side tạo tín hiệu dày đặc hơn Request-side.", fill=INK, font=F["h3"])
    d.rectangle((140, 820, 650, 930), fill="#20e0df")
    d.rectangle((650, 820, 995, 930), fill="#ff4d2e")
    d.text((370, 846), "546\nRequest-side", fill=INK, font=F["body_b"], anchor="ma")
    d.text((820, 846), "374\nResponse-side", fill=INK, font=F["body_b"], anchor="ma")
    soft_panel(d, (1120, 690, 1825, 985), outline="#ff4d2e", fill="#fff4f2", width=5, radius=20)
    simple_icon(d, "warning", 1185, 745, "#ff4d2e")
    d.text((1315, 735), "CẢNH BÁO:", fill=INK, font=F["h2"])
    d.text((1315, 795), "Discrepancy ≠ Vulnerability", fill=RED, font=font(38, True))
    draw_wrapped(d, "Đây là tín hiệu hệ thống cần replay/verify, chưa phải CVE.", (1315, 870), 420, F["body"], fill=INK)
    im.save(OUT / "22.png")


def draw_table(d, x, y, col_w, row_h, headers, rows):
    total_w = sum(col_w)
    header_h = 112
    rounded(d, (x, y, x + total_w, y + header_h + row_h * len(rows)), outline=BLUE, fill="white", width=3, radius=8)
    xx = x
    for i, h in enumerate(headers):
        d.rectangle((xx, y, xx + col_w[i], y + header_h), fill="#eaf3ff", outline="#9ab7df", width=2)
        draw_wrapped(d, h, (xx + 18, y + 28), col_w[i] - 36, F["small_b"], fill=INK)
        xx += col_w[i]
    for r, row in enumerate(rows):
        yy = y + header_h + r * row_h
        xx = x
        for c, val in enumerate(row):
            fill = "white"
            color = INK
            if c == 2 and val == "100%":
                fill = "#ff4d2e"
            if c == 3 and val == "21":
                fill = "#09e82b"
            if c == 4 and val == "31.0%":
                fill = "#ffc928"
            d.rectangle((xx, yy, xx + col_w[c], yy + row_h), fill=fill, outline="#9ab7df", width=2)
            f = F["body_b"] if c < 5 else F["small_b"]
            draw_wrapped(d, val, (xx + 18, yy + 28), col_w[c] - 36, f, fill=color)
            xx += col_w[c]


def draw_slide_23():
    im, d = new_canvas("Hành vi 4 server pair khác nhau")
    headers = ["Môi trường", "Request hit", "Response hit", "Diversity", "Low\nconfidence", "Tín hiệu nổi bật"]
    rows = [
        ["NGINX -> Gunicorn", "68.8%", "90%", "14", "0%", "R8 Order rất mạnh"],
        ["HAProxy -> Gunicorn", "45.0%", "100%", "15", "3.7%", "Reject CL tốt,\nresponse forward thô"],
        ["ATS -> gevent", "52.5%", "84%", "21", "31.0%", "Diversity cao nhất"],
        ["Apache -> Tomcat", "61.3%", "100%", "7", "23.8%", "TE/CL conflict cao"],
    ]
    draw_table(d, 85, 210, [370, 225, 225, 210, 260, 410], 120, headers, rows)
    pills = [
        (90, 910, 610, 1015, "[NGINX]: Nhạy request-side", CYAN),
        (690, 910, 1245, 1015, "[ATS]: Đáng replay sâu nhất", "#0eea28"),
        (1285, 890, 1845, 1025, "[HAProxy + Apache]:\nResponse-side 100% (No Sanitize)", "#ff4d2e"),
    ]
    for x1, y1, x2, y2, text, color in pills:
        d.rounded_rectangle((x1, y1, x2, y2), radius=52, fill=color)
        draw_wrapped(d, text, (x1 + 70, y1 + 20), x2 - x1 - 120, font(26, True), fill=INK)
    im.save(OUT / "23.png")


def rule_card(d, box, title, body, color, icon):
    x1, y1, x2, y2 = box
    soft_panel(d, box, outline=color, fill="white", width=5, radius=14)
    simple_icon(d, icon, x1 + 45, y1 + 60, color)
    d.text((x1 + 220, y1 + 80), title, fill=color, font=F["h3"])
    draw_wrapped(d, body, (x1 + 220, y1 + 150), x2 - x1 - 260, F["body"], fill=INK)


def draw_slide_24():
    im, d = new_canvas("Rule nào tạo tín hiệu mạnh?")
    rule_card(d, (95, 190, 955, 520), "R8 response_order (NGINX = 119)", "Bắt lỗi thứ tự response (Desync-Id) mà length-only oracle bỏ sót hoàn toàn.", CYAN, "shuffle")
    rule_card(d, (985, 190, 1825, 520), "R9 body_hash (HAProxy = 27)", "Nội dung parse ra khác biệt dù độ dài (length) hoàn toàn trùng khớp.", "#d89b55", "finger")
    rule_card(d, (95, 555, 955, 885), "R4 + R5 (Apache = 145)", "Bất đồng nghiêm trọng trong xử lý Transfer-Encoding và Content-Length.", "#ff4d2e", "split")
    rule_card(d, (985, 555, 1825, 885), "Unique Signatures (ATS = 21)", "Sinh ra nhiều mẫu pattern dị thường nhất do forward raw, ưu tiên replay.", "#60d94e", "radar")
    rounded(d, (100, 925, 1820, 1018), outline=BLUE, fill="#effcff", width=4, radius=8)
    d.text((170, 950), "Không chỉ đếm lượng discrepancy: Pattern của rule định hướng chính xác vị trí cần đào sâu.", fill=INK, font=F["h3"])
    im.save(OUT / "24.png")


def draw_slide_25():
    im, d = new_canvas("Từ discrepancy đến ứng viên lỗ hổng")
    x_icon, x_text = 155, 365
    steps = [
        ("gear", "1. Fuzz (1360 tests)"),
        ("bell", "2. Detect Discrepancy\n(920 tín hiệu)"),
        ("server", "3. Replay Persistent\nConnection"),
        ("shield", "4. Verify Security\nImpact (CVE)"),
    ]
    y_positions = [235, 430, 625, 820]
    for i, ((kind, label), y) in enumerate(zip(steps, y_positions)):
        if kind == "server":
            server_icon(d, x_icon + 25, y - 12, 0.9, CYAN)
        else:
            simple_icon(d, kind, x_icon, y - 20, CYAN)
        d.text((x_text, y + 10), label, fill=INK, font=font(40, True))
        if i < len(y_positions) - 1:
            arrow(d, (x_icon + 60, y + 120), (x_icon + 60, y_positions[i + 1] - 20), color=CYAN, width=6)
    d.line((780, 230, 780, 930), fill="#98a2b3", width=3)
    cards = [
        ("[Priority 1] ATS -> gevent", "• Lý do: Diversity 21 (cao nhất), xuất hiện nhiều pattern lạ.\n• Action: Replay sâu + tcpdump.", "#ff4d2e"),
        ("[Priority 2] NGINX -> Gunicorn", "• Lý do: R8 Order = 119 (Tín hiệu cực mạnh).\n• Action: Kiểm tra response ordering bypass.", "#d89b55"),
        ("[Priority 3] Apache -> Tomcat", "• Lý do: R4 + R5 = 145.\n• Action: Replay TE/CL conflict.", "#f4d03f"),
        ("[Priority 4] HAProxy / Apache (Response-side)", "• Lý do: Response hit 100%.\n• Action: Verify sanitize behavior qua fake_upstream.", "#98a2b3"),
    ]
    y = 200
    for title, body, color in cards:
        soft_panel(d, (840, y, 1820, y + 165), outline=color, fill="white", width=5, radius=12)
        d.text((875, y + 28), title, fill=color, font=F["h3"])
        draw_wrapped(d, body, (910, y + 82), 850, F["body"], fill=INK)
        y += 195
    d.text((190, 1005), "Discrepancy là điểm xuất phát; vulnerability chỉ được xác nhận khi chứng minh được security impact qua replay.", fill=MUTED, font=F["small_b"])
    im.save(OUT / "25.png")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    draw_slide_19()
    draw_slide_21()
    draw_slide_22()
    draw_slide_23()
    draw_slide_24()
    draw_slide_25()
    print(f"Wrote diagrams to {OUT.resolve()}")


if __name__ == "__main__":
    main()
