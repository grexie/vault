#!/usr/bin/env python3
"""Render the maintained, trusted Markdown setup and architecture pages."""
from pathlib import Path
import html
import re

ROOT = Path(__file__).resolve().parents[1]


def inline(text):
    text = html.escape(text)
    text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
    text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', text)
    def link(match):
        label, target = match.groups()
        if not target.startswith(('https://', '/', '#')):
            target = 'https://github.com/grexie/vault/blob/main/docs/' + target
        return f'<a href="{target}">{label}</a>'
    return re.sub(r'\[([^\]]+)\]\(([^)]+)\)', link, text)


def render(text):
    out, paragraph, code, listing = [], [], None, False
    def flush():
        if paragraph:
            out.append('<p>' + inline(' '.join(paragraph)) + '</p>')
            paragraph.clear()
    for line in text.splitlines():
        if line.startswith('```'):
            flush()
            if code is None:
                code = []
            else:
                out.append('<pre><code>' + html.escape('\n'.join(code)) + '</code></pre>')
                code = None
            continue
        if code is not None:
            code.append(line)
            continue
        item = re.match(r'^[-*] (.*)$', line)
        if listing and not item:
            out.append('</ul>')
            listing = False
        if not line.strip():
            flush()
        elif line.startswith('#'):
            flush()
            heading = re.match(r'^(#{1,6}) (.*)$', line)
            if heading:
                level, title = len(heading[1]), heading[2]
                anchor = re.sub(r'[^a-z0-9]+', '-', title.lower()).strip('-')
                out.append(f'<h{level} id="{anchor}">{inline(title)}</h{level}>')
        elif item:
            flush()
            if not listing:
                out.append('<ul>')
                listing = True
            out.append('<li>' + inline(item[1]) + '</li>')
        else:
            paragraph.append(line)
    flush()
    if listing:
        out.append('</ul>')
    return '\n'.join(out)


for source, filename, title in [('setup.md', 'guide.html', 'Set up Vault'), ('vault-architecture.md', 'architecture.html', 'Vault architecture'), ('browser-wallet.md', 'browser-wallet.html', 'Chrome Web3 wallet'), ('hyperliquid.md', 'hyperliquid.html', 'Hyperliquid'), ('chrome-wallet-privacy.md', 'chrome-wallet-privacy.html', 'Chrome wallet privacy')]:
    body = render((ROOT / 'docs' / source).read_text())
    page = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title} — Grexie Vault</title><meta name="description" content="Setup and architecture for Grexie Vault, an encrypted keychain for you and your agents."><link rel="icon" href="/favicon-32.png"><link rel="stylesheet" href="/style.css"><link rel="stylesheet" href="/home.css"><link rel="stylesheet" href="/guide.css"></head><body class="landing"><header class="global-nav"><a class="vault-brand" href="/"><img src="/icon-180.png" alt="" width="28" height="28">Vault<span class="by-grexie"> by Grexie</span></a><nav aria-label="Main navigation"><a href="/guide.html">Setup</a><a href="/architecture.html">Architecture</a><a class="nav-open" href="/app/">Open Vault</a></nav></header><main class="guide"><p class="guide-eyebrow">GREXIE VAULT / DOCUMENTATION</p>{body}<p class="guide-bottom"><a href="https://github.com/grexie/vault/blob/main/docs/{source}">Read on GitHub ↗</a> · <a href="/SKILL.md">AI agent instructions ↗</a></p></main></body></html>'''
    (ROOT / 'web' / 'vault' / filename).write_text(page + '\n')
print('Rendered setup and architecture pages.')
