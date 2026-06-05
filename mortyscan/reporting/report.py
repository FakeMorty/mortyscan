"""Генераторы отчётов: JSON / HTML / PDF — всё на русском, с человеческими пояснениями."""
from __future__ import annotations

import html
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from ..core import Finding, ScanContext, Severity
from ..i18n import SEVERITY_RU, SEVERITY_EXPLAIN, VERDICT_RU, explanation_for


def write_json(ctx: ScanContext, out: Path) -> Path:
    payload = {
        "инструмент":       "MortyScan",
        "версия":           "17.0.0",
        "создан":           datetime.utcnow().isoformat() + "Z",
        "цель":             ctx.target,
        "адрес":            ctx.base_url,
        "ip":               ctx.ip,
        "очки_риска":       ctx.risk_score(),
        "вердикт":          ctx.verdict(),
        "вердикт_текст":    ctx.verdict_ru(),
        "технологии":       ctx.tech,
        "обойдено_страниц": sorted(ctx.crawled_urls),
        "разрешения":       ctx.permissions,
        "находки":          [f.to_dict() for f in ctx.findings],
    }
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str),
                   encoding="utf-8")
    return out


_HTML_TPL = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><title>Отчёт MortyScan — {target}</title>
<style>
  :root {{ color-scheme: dark light; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: "Inter", "Segoe UI", system-ui, -apple-system, Roboto, sans-serif;
          margin: 0; padding: 0; background:#0f1115; color:#e6e6e6; line-height:1.55; }}
  header {{ background: linear-gradient(135deg, #5b21b6, #b91c1c); padding: 32px 36px; }}
  header h1 {{ margin: 0; font-size: 30px; }}
  header .meta {{ opacity: .85; margin-top: 8px; font-size: 14px; }}
  .verdict {{ display:inline-block; padding:8px 16px; border-radius:8px; font-weight:700;
              background:#0a0d12; margin-top:14px; font-size:16px; }}
  main {{ padding: 28px 36px; max-width: 1100px; margin: 0 auto; }}
  .summary {{ background:#161a22; padding:18px 22px; border-radius:10px; margin-bottom:24px; }}
  .summary h2 {{ margin: 0 0 10px 0; font-size: 18px; }}
  .stats {{ display:flex; gap:10px; flex-wrap:wrap; margin: 12px 0; }}
  .pill {{ padding:10px 14px; border-radius:8px; background:#1b1f27; font-size:13px; min-width:90px; }}
  .pill b {{ font-size:20px; display:block; }}
  .CRITICAL {{ color:#fda4af; }} .HIGH {{ color:#fbbf24; }} .MEDIUM {{ color:#fcd34d; }}
  .LOW {{ color:#93c5fd; }} .INFO {{ color:#a5b4fc; }}
  h2 {{ margin-top: 36px; border-bottom: 1px solid #2a2f3a; padding-bottom:8px; font-size:22px; }}
  h2 .count {{ font-size:14px; opacity:.6; font-weight:normal; margin-left:8px; }}
  .sev-explain {{ font-size:13px; opacity:.7; margin-top:-4px; margin-bottom:14px; }}
  .f {{ background:#161a22; border-left: 4px solid #444; padding:16px 18px;
        margin: 12px 0; border-radius:8px; }}
  .f.CRITICAL {{ border-color:#dc2626; }}
  .f.HIGH     {{ border-color:#f59e0b; }}
  .f.MEDIUM   {{ border-color:#eab308; }}
  .f.LOW      {{ border-color:#3b82f6; }}
  .f.INFO     {{ border-color:#6366f1; }}
  .f h3 {{ margin: 0 0 6px 0; font-size: 17px; }}
  .f .sub {{ font-size: 12px; opacity: .65; margin-bottom: 10px; }}
  .f .desc {{ margin: 6px 0; }}
  .explain {{ background:#0d1117; padding:12px 14px; border-radius:6px; margin-top:10px;
              border-left: 3px solid #5b21b6; }}
  .explain .row {{ margin:6px 0; }}
  .explain .label {{ display:inline-block; min-width:140px;
                     font-weight:600; opacity:.85; }}
  .explain .label.what {{ color:#a5b4fc; }}
  .explain .label.why {{ color:#a5b4fc; }}
  .explain .label.analogy {{ color:#fcd34d; }}
  .explain .label.danger {{ color:#fda4af; }}
  .explain .label.fix {{ color:#86efac; }}
  .f pre {{ background:#0a0d12; padding:10px; border-radius:6px; overflow-x:auto;
           font-size: 12px; white-space: pre-wrap; word-break: break-all;
           font-family: "JetBrains Mono", Consolas, monospace; }}
  .f .fix {{ background:#0a2a16; padding:10px 14px; border-radius:6px;
            font-size: 13px; margin-top:10px; border-left:3px solid #16a34a; }}
  details summary {{ cursor:pointer; opacity:.85; padding:4px 0; }}
  a {{ color:#93c5fd; }}
  footer {{ text-align:center; padding:24px; opacity:.5; font-size:12px; }}
  .toc {{ background:#161a22; padding:14px 18px; border-radius:8px; margin-bottom:20px; }}
  .toc a {{ margin-right:12px; }}
  .tldr {{ background:#1b1f27; padding:16px 20px; border-radius:8px; margin-bottom:24px;
           border-left:4px solid #b91c1c; }}
  .tldr h3 {{ margin:0 0 10px 0; }}
  .tldr ol {{ margin:8px 0 0 18px; padding:0; }}
  .tldr li {{ margin:6px 0; }}
</style></head>
<body>
<header>
  <h1>🔬 MortyScan — отчёт по аудиту безопасности</h1>
  <div class="meta">Цель: <b>{target}</b> ({ip}) · {date}</div>
  <div class="verdict" style="background:{verdict_color}">ВЕРДИКТ: {verdict_ru} · риск {risk}</div>
</header>
<main>

  <div class="summary">
    <h2>Сводка</h2>
    <div>Просканировано страниц: <b>{pages}</b> · технологий обнаружено: <b>{techs}</b></div>
    <div class="stats">{stats}</div>
    <div style="font-size:13px;opacity:.7;margin-top:6px;">
      «Очки риска» — это сумма весов всех найденных проблем. Чем больше — тем серьёзнее ситуация.
    </div>
  </div>

  {tldr}

  <div class="toc">
    <b>Перейти к разделу:</b> {toc}
  </div>

  {sections}
</main>
<footer>
  Создано MortyScan v17 «Инквизитор» · {date}<br>
  Этот отчёт предназначен для авторизованного тестирования. Используйте его для исправления уязвимостей.
</footer>
</body></html>
"""


def _verdict_color(verdict_ru: str) -> str:
    return {
        "КАТАСТРОФА":        "#7f1d1d",
        "КРИТИЧЕСКИЙ РИСК":  "#991b1b",
        "ВЫСОКИЙ РИСК":      "#9a3412",
        "СРЕДНИЙ РИСК":      "#854d0e",
        "НИЗКИЙ РИСК":       "#1e3a8a",
        "ЧИСТО":             "#14532d",
    }.get(verdict_ru, "#1f2937")


def _build_tldr(ctx: ScanContext) -> str:
    """«Самое важное в трёх пунктах» — для управленцев / занятых людей."""
    crit = [f for f in ctx.findings if f.severity == Severity.CRITICAL]
    high = [f for f in ctx.findings if f.severity == Severity.HIGH]
    top = crit[:3] + high[:max(0, 3 - len(crit))]
    if not top:
        return ('<div class="tldr"><h3>Что главное</h3>'
                'Критических и высоких рисков не обнаружено. '
                'Проверьте находки уровня «средний» и «низкий» — их тоже стоит исправить.</div>')
    items = "".join(
        f"<li><b>{html.escape(f.title)}</b>"
        + (f' — <a href="#{_anchor(f)}">подробнее</a>' if True else '')
        + "</li>"
        for f in top
    )
    return (
        '<div class="tldr">'
        '<h3>⚡ Что главное (исправить в первую очередь)</h3>'
        f'<ol>{items}</ol>'
        '</div>'
    )


def _anchor(f: Finding) -> str:
    import re
    s = re.sub(r"[^a-zA-Zа-яА-Я0-9]+", "-", f.title).strip("-")[:60]
    return f"f-{abs(hash((f.module, f.title, f.url))) & 0xfffff}-{s}"


def write_html(ctx: ScanContext, out: Path) -> Path:
    by_sev: dict[str, list[Finding]] = defaultdict(list)
    for f in ctx.findings:
        by_sev[f.severity.label].append(f)

    counts = Counter(f.severity.label for f in ctx.findings)
    stats = "".join(
        f'<div class="pill {lab}"><b>{counts.get(lab,0)}</b>{SEVERITY_RU[lab]}</div>'
        for lab in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )

    toc_parts = []
    for lab in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = counts.get(lab, 0)
        if n:
            toc_parts.append(f'<a href="#sec-{lab}">{SEVERITY_RU[lab]} ({n})</a>')
    toc = " · ".join(toc_parts) or "—"

    sections = []
    for lab in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        fs = by_sev.get(lab, [])
        if not fs:
            continue
        sections.append(
            f'<h2 id="sec-{lab}" class="{lab}">{SEVERITY_RU[lab]} '
            f'<span class="count">· {len(fs)} находок(и)</span></h2>'
            f'<div class="sev-explain">{SEVERITY_EXPLAIN[lab]}</div>'
        )
        for f in fs:
            anchor = _anchor(f)
            ev = html.escape(f.evidence) if f.evidence else ""
            desc = html.escape(f.description).replace("\n", "<br>") if f.description else ""
            sub_parts = [f"<b>модуль:</b> {html.escape(f.module)}"]
            if f.url: sub_parts.append(
                f'<b>URL:</b> <a href="{html.escape(f.url)}">{html.escape(f.url)}</a>')
            if f.cwe: sub_parts.append(f"<b>CWE:</b> {html.escape(f.cwe)}")
            if f.cvss: sub_parts.append(f"<b>CVSS:</b> {f.cvss}")
            sub = " · ".join(sub_parts)
            fix_html = (f'<div class="fix">💊 <b>Как исправить:</b> '
                        f'{html.escape(f.remediation)}</div>'
                        if f.remediation else "")
            refs_html = ""
            if f.references:
                refs_html = ('<div class="sub" style="margin-top:8px;">📎 ссылки: '
                             + " ".join(
                                f'<a href="{html.escape(r)}">{html.escape(r)}</a>'
                                for r in f.references
                            ) + '</div>')
            ev_html = (f'<details><summary>📋 показать улики (evidence)</summary>'
                       f'<pre>{ev}</pre></details>' if ev else "")

            # Человеческое пояснение — только для НЕ-INFO находок,
            # либо для INFO с явной проблемой в названии
            explain = explanation_for(f.title)
            explain_html = ""
            # не показываем «как чинить XSS» для info-сообщения «GraphQL не обнаружен»
            skip_explain = (
                f.severity == Severity.INFO
                and any(neg in f.title.lower() for neg in
                        ("не обнаружен", "не найдено", "пропущен",
                         "завершён", "завершен", "тестируется", "обнаружено"))
            )
            if explain and not skip_explain:
                explain_html = '<div class="explain">'
                for label_key, label_text, css_cls in (
                    ("что", "Что это:", "what"),
                    ("аналогия", "Аналогия:", "analogy"),
                    ("чем грозит", "Чем грозит:", "danger"),
                    ("как чинить", "Как чинить:", "fix"),
                ):
                    val = explain.get(label_key)
                    if val:
                        explain_html += (
                            f'<div class="row"><span class="label {css_cls}">{label_text}</span>'
                            f'{html.escape(val)}</div>'
                        )
                explain_html += '</div>'

            sections.append(
                f'<div id="{anchor}" class="f {lab}">'
                f'<h3>{html.escape(f.title)}</h3>'
                f'<div class="sub">{sub}</div>'
                f'<div class="desc">{desc}</div>'
                f'{explain_html}'
                f'{ev_html}{fix_html}{refs_html}'
                f'</div>'
            )

    techs = len(ctx.tech) or "—"
    pages = len(ctx.crawled_urls) or "—"

    html_doc = _HTML_TPL.format(
        target=html.escape(ctx.target),
        ip=html.escape(ctx.ip or "?"),
        date=datetime.utcnow().strftime("%d.%m.%Y %H:%M UTC"),
        verdict_ru=ctx.verdict_ru(),
        verdict_color=_verdict_color(ctx.verdict_ru()),
        risk=ctx.risk_score(),
        stats=stats,
        toc=toc,
        sections="\n".join(sections) or "<p>Находок нет.</p>",
        pages=pages, techs=techs,
        tldr=_build_tldr(ctx),
    )
    out.write_text(html_doc, encoding="utf-8")
    return out


# ============================== PDF ==============================

_UNI_MAP = str.maketrans({
    "—": "-", "–": "-", "‒": "-", "−": "-",
    "“": '"', "”": '"', "„": '"', "‟": '"',
    "‘": "'", "’": "'", "‚": "'", "‛": "'",
    "«": '"', "»": '"',
    "•": "*", "·": "-", "→": "->", "←": "<-",
    "…": "...", "©": "(c)", "®": "(R)", "™": "(TM)",
    "✓": "[v]", "✗": "[!]", "✘": "[!]",
    "🔬": "", "💊": "fix:", "⚡": "!",
    "№": "No.",
})


def _safe(s: str) -> str:
    """fpdf2 со встроенными шрифтами не поддерживает кириллицу.
    Чтобы pdf не падал, делаем транслит → latin-1.
    Это исключительно для совместимости; HTML и JSON остаются на русском."""
    if not s:
        return ""
    s = s.translate(_UNI_MAP)
    # Транслит кириллицы (упрощённый)
    cyr = {
        "а":"a","б":"b","в":"v","г":"g","д":"d","е":"e","ё":"yo","ж":"zh","з":"z","и":"i","й":"y",
        "к":"k","л":"l","м":"m","н":"n","о":"o","п":"p","р":"r","с":"s","т":"t","у":"u","ф":"f",
        "х":"h","ц":"ts","ч":"ch","ш":"sh","щ":"sch","ъ":"","ы":"y","ь":"","э":"e","ю":"yu","я":"ya",
        "А":"A","Б":"B","В":"V","Г":"G","Д":"D","Е":"E","Ё":"Yo","Ж":"Zh","З":"Z","И":"I","Й":"Y",
        "К":"K","Л":"L","М":"M","Н":"N","О":"O","П":"P","Р":"R","С":"S","Т":"T","У":"U","Ф":"F",
        "Х":"H","Ц":"Ts","Ч":"Ch","Ш":"Sh","Щ":"Sch","Ъ":"","Ы":"Y","Ь":"","Э":"E","Ю":"Yu","Я":"Ya",
    }
    s = "".join(cyr.get(ch, ch) for ch in s)
    try:
        s.encode("latin-1")
        return s
    except UnicodeEncodeError:
        return s.encode("latin-1", "replace").decode("latin-1")


def _multi(pdf, w, h, text: str):
    pdf.multi_cell(w, h, text=_safe(text), new_x="LMARGIN", new_y="NEXT")


# Английская подпись серьёзности для PDF (т.к. с латиницей нет проблем)
SEV_LATIN = {
    "INFO":     "INFO",
    "LOW":      "LOW",
    "MEDIUM":   "MEDIUM",
    "HIGH":     "HIGH",
    "CRITICAL": "CRITICAL",
}


def write_pdf(ctx: ScanContext, out: Path) -> Path | None:
    try:
        from fpdf import FPDF
    except ImportError:
        return None

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Заголовок
    pdf.set_font("helvetica", "B", 20)
    pdf.set_text_color(120, 0, 60)
    pdf.cell(0, 12, text=_safe("MortyScan v17 - Otchyot po auditu bezopasnosti"),
             new_x="LMARGIN", new_y="NEXT", align="C")

    pdf.set_font("helvetica", "B", 14)
    color = (200, 0, 0) if ctx.risk_score() >= 100 else \
            (200, 140, 0) if ctx.risk_score() >= 40 else (0, 120, 0)
    pdf.set_text_color(*color)
    pdf.cell(0, 9,
             text=_safe(f"Verdikt: {ctx.verdict_ru()}  ·  Ochki riska: {ctx.risk_score()}"),
             new_x="LMARGIN", new_y="NEXT", align="C")

    pdf.set_font("courier", size=9)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 6,
             text=_safe(f"Tsel: {ctx.target} ({ctx.ip or '?'}) | "
                        f"Data: {datetime.utcnow().strftime('%d.%m.%Y %H:%M UTC')}"),
             new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(3)

    # Примечание о шрифте
    pdf.set_font("helvetica", "I", 8)
    pdf.set_text_color(120, 120, 120)
    _multi(pdf, 180, 4,
           "Vnimanie: PDF-otchyot ispolzuet translit kirillitsy (vstroennye shrifty fpdf "
           "ne podderzhivayut Unicode). Polnotsennyy russkiy otchyot smotrite v fayle report.html.")
    pdf.ln(2)
    pdf.set_text_color(0, 0, 0)

    counts = Counter(f.severity.label for f in ctx.findings)
    pdf.set_font("helvetica", "B", 11)
    _multi(pdf, 180, 6, "Svodka:  " + "  |  ".join(
        f"{SEV_LATIN[lab]}: {counts.get(lab, 0)}"
        for lab in ("CRITICAL","HIGH","MEDIUM","LOW","INFO")
    ))
    pdf.ln(3)

    by_sev: dict[str, list[Finding]] = defaultdict(list)
    for f in ctx.findings:
        by_sev[f.severity.label].append(f)

    for lab in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        fs = by_sev.get(lab, [])
        if not fs: continue
        pdf.set_font("helvetica", "B", 13)
        if lab in ("CRITICAL", "HIGH"):
            pdf.set_text_color(150, 0, 0)
        elif lab == "MEDIUM":
            pdf.set_text_color(150, 100, 0)
        else:
            pdf.set_text_color(40, 40, 80)
        pdf.ln(3)
        pdf.cell(0, 8, text=_safe(f"=== {SEV_LATIN[lab]} ({len(fs)}) ==="),
                 new_x="LMARGIN", new_y="NEXT")
        for f in fs:
            pdf.set_font("helvetica", "B", 10)
            pdf.set_text_color(20, 20, 20)
            _multi(pdf, 180, 5, f"• {f.title}")
            pdf.set_font("courier", size=8)
            pdf.set_text_color(60, 60, 60)
            line = f"  [{f.module}]"
            if f.cwe:  line += f" {f.cwe}"
            if f.cvss: line += f" CVSS {f.cvss}"
            if f.url:  line += f" {f.url}"
            _multi(pdf, 180, 4, line)
            if f.description:
                pdf.set_font("helvetica", size=9); pdf.set_text_color(30, 30, 30)
                _multi(pdf, 180, 4, f.description[:600])
            if f.evidence:
                pdf.set_font("courier", size=8); pdf.set_text_color(80, 80, 80)
                _multi(pdf, 180, 4, f"evidence: {f.evidence[:400]}")
            if f.remediation:
                pdf.set_font("helvetica", "I", 9); pdf.set_text_color(0, 100, 0)
                _multi(pdf, 180, 4, f"fix: {f.remediation}")
            pdf.ln(1)

    pdf.output(str(out))
    return out
