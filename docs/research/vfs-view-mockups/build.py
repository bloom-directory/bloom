#!/usr/bin/env python3
"""Offline research renderer. No wallet, network, or authorization access.

snapshot.json is fictional. Run here with Python 3: build.py [--check].
The committed HTML is usable without Python or JavaScript. --check never writes.
"""
import argparse
from decimal import Decimal
from html import escape
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NAV = [('index', 'Today'), ('markets', 'Markets'), ('chains', 'Chains'),
       ('portfolio', 'Wallet'), ('next-moves', 'Next moves'), ('activity', 'Activity'),
       ('receive', 'Receive'), ('permissions', 'Access')]


def text(value):
    return escape(str(value), quote=True)


def money(value):
    return 'Not priced' if value is None else f'${Decimal(value):,.2f}'


def compact(value):
    if value is None:
        return 'Not covered'
    value = Decimal(value)
    return f'${value / Decimal("1000000000"):.1f}B'


def change(value):
    if value is None:
        return 'Not available'
    number = Decimal(value)
    return f'<span class="{"negative" if number < 0 else "positive"}">{number:+.2f}%</span>'


def badge(label, kind=''):
    return f'<span class="badge {kind}">{text(label)}</span>'


def details(title, body):
    return f'<details><summary>{text(title)}</summary>{body}</details>'


def head(title, subtitle=''):
    return f'<div class="section-head"><h2>{text(title)}</h2><p>{text(subtitle)}</p></div>'


def card(title, body, eyebrow='', link=None):
    result = f'<article class="card"><p class="eyebrow">{text(eyebrow)}</p><h3>{text(title)}</h3><p>{text(body)}</p>'
    if link:
        result += f'<a class="link" href="{text(link[0])}">{text(link[1])} →</a>'
    return result + '</article>'


def ranked_tokens(data):
    return sorted([t for t in data['tokens'] if t['status'] == 'fresh' and t['volume'] is not None],
                  key=lambda t: (-Decimal(t['volume']), t['id']))


def ranked_chains(data):
    return sorted([c for c in data['chains'] if c['volume'] is not None],
                  key=lambda c: (-Decimal(c['volume']), c['id']))


def token_table(tokens):
    rows = []
    for token in tokens:
        identity = f'<div class="token"><span class="token-mark" aria-hidden="true">{text(token["symbol"][:3])}</span><div><a href="markets.html#{text(token["id"])}"><strong>{text(token["name"])}</strong></a><small>{text(token["symbol"])} · {"You hold this" if token["held"] else "Not held"}</small></div></div>'
        rows.append(f'<tr><td>{identity}</td><td class="numeric money" data-label="Price">{money(token["price"])}</td><td class="numeric" data-label="24h change">{change(token["change"])}</td><td class="numeric money" data-label="24h volume">{compact(token["volume"])}</td></tr>')
    return '<div class="table-wrap"><table><caption>Illustrative token subset · sorted by reported 24h market volume</caption><thead><tr><th scope="col">Asset</th><th scope="col" class="numeric">Price</th><th scope="col" class="numeric">24h change</th><th scope="col" class="numeric">24h volume</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>'


def chain_table(chains):
    rows = []
    maximum = max((Decimal(c['volume']) for c in chains), default=Decimal(1)) or Decimal(1)
    for chain in chains:
        volume = Decimal(chain['volume'])
        previous = chain['previous_volume']
        pct = (volume / Decimal(previous) - 1) * 100 if previous and Decimal(previous) else None
        bar = f'<div class="bar" aria-hidden="true"><span style="--fill:{volume / maximum * 100:.2f}%"></span></div>'
        rows.append(f'<tr><td><a href="chains.html#{text(chain["id"].replace(":", "-"))}"><strong>{text(chain["name"])}</strong></a>{bar}</td><td class="numeric money" data-label="Daily DEX volume">{compact(chain["volume"])}</td><td class="numeric" data-label="Vs previous day">{change(pct)}</td><td class="numeric money" data-label="Your assets">{money(chain["wallet_value"])}</td></tr>')
    return '<div class="table-wrap"><table><caption>Example subset · completed UTC day, 4 September 2026 · spot DEX volume</caption><thead><tr><th scope="col">Chain</th><th scope="col" class="numeric">DEX volume</th><th scope="col" class="numeric">Vs prior day</th><th scope="col" class="numeric">Your assets</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>'


def action_list(actions):
    return ''.join(f'<article class="action" id="{text(a["id"])}"><span class="action-number" aria-hidden="true">{i:02d}</span><div>{badge(a["status"], "warn" if a["lane"] == "needs" else "good")}<h3>{text(a["title"])}</h3><p>{text(a["body"])}</p><small>{text(a["source"])}</small></div><a href="{text(a["target"])}">{text(a["cta"])} →</a></article>' for i, a in enumerate(actions, 1))


def coverage(data):
    body = ''.join(f'<p><strong>{text(s["label"])}</strong> · {text(s["status"])}<br>{text(s["coverage"])}<br>Source time: {text(s["source_time"])}. Window: {text(s["window"])}.</p>' for s in data['sources'])
    return '<section class="coverage">' + details('Sources, freshness & what is missing', body) + '</section>'


def page(name, title, lede, body, data):
    nav = ''.join(f'<a href="{slug}.html"{" aria-current=\"page\"" if slug == name else ""}>{label}</a>' for slug, label in NAV)
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#f4efe6"><meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self'; base-uri 'none'; form-action 'none'">
<title>{text(title)} · Bloom</title><link rel="icon" href="bloom-primary.svg" type="image/svg+xml"><link rel="stylesheet" href="bloom.css"></head>
<body><a class="skip" href="#main">Skip to content</a>
<div class="demo">Research prototype · fictional data · no wallet connected · no actions execute</div>
<div class="shell"><header class="masthead"><a class="brand" href="index.html" aria-label="Bloom today"><img src="bloom-primary.svg" width="32" height="32" alt=""><strong>/bloom</strong></a><span class="edition">The wallet fieldnotes<br>Example edition / 05 Sep 2026</span></header>
<nav aria-label="Wallet views">{nav}</nav>
<main id="main"><div class="intro"><div><p class="eyebrow">Your place in the ecosystem</p><h1>{text(title)}</h1></div><p class="lede">{text(lede)}</p></div>
{body}
{coverage(data)}
</main><footer><span>Illustrative snapshot · 05 Sep 2026, 17:00 UTC<br>{text(data['snapshot_id'])}</span><span><a href="snapshot.md">Text version</a><a href="snapshot.json">Example data</a><a href="states.html">Empty & failure states</a><a href="../2026-07-17-vfs-view-decision.md">Design notes</a></span></footer></div></body></html>
'''


def render(data):
    total = sum(Decimal(h['value']) for h in data['holdings'] if h['value'] is not None)
    needs = [a for a in data['actions'] if a['lane'] == 'needs']
    optional = [a for a in data['actions'] if a['lane'] == 'optional']
    tokens = ranked_tokens(data)
    chains = ranked_chains(data)
    bodies = {}
    bodies['index'] = ('A little clarity.', 'What is moving, where you stand, and the few things that need you. Start here; go deeper when something matters.', f'''
<section class="hero"><div><p class="eyebrow">The market, in a moment</p><h2>ETH leads volume.<br>SOL leads price gains.</h2><p>In this example, ETH leads the covered tokens by trading volume. SOL has the largest price rise. Those are different signals; neither tells you what to buy.</p><div class="links"><a class="button" href="markets.html">Understand the market →</a></div></div><div class="hero-aside"><span class="label">Alex’s observed wallet value</span><div class="metric">{money(total)}</div><p>Across wallet assets and positions. One unpriced asset is excluded; Solana’s last balance needs a fresh check.</p><a class="link" href="portfolio.html">See what you own →</a></div></section>
<div class="stats"><div class="stat"><span class="label">Needs your attention</span><strong>{len(needs)} next steps</strong><small>A transfer to review; a paused deposit.</small></div><div class="stat"><span class="label">Market coverage</span><strong>4 tokens · 4 chains</strong><small>Illustrative subset, not the entire market.</small></div><div class="stat"><span class="label">You have room to pause</span><strong>No trade required</strong><small>A price move is context, not an instruction.</small></div></div>
<section>{head('First, the things that need you.', 'Existing operations, not new trade ideas')}{action_list(needs)}</section>
<section>{head('What is moving?', 'Different signals, explained simply')}<div class="grid">{card('ETH leads trading volume', 'Volume measures how much changed hands. It does not prove new buyers, deep liquidity, or a good entry price.', '01 / Tokens', ('markets.html', 'Explore tokens'))}{card('Ethereum leads this chain sample', 'DEX volume measures on-chain exchange activity. Your network connection and wallet permissions are shown separately.', '02 / Networks', ('chains.html', 'Explore chains'))}</div></section>
''')
    token_details = ''.join(f'<article class="card" id="{text(t["id"])}"><p class="eyebrow">{text(t["kind"])} · {text(t["symbol"])}</p><h3>{text(t["name"])}</h3><p>{text(t["explanation"])}</p>{details("Identity & source", f"<p>Example provider ID: <code>{text(t['id'])}</code>. Market identity is distinct from each chain’s contract or mint. These figures are fictional, not fetched quotes.</p>")}</article>' for t in data['tokens'])
    bodies['markets'] = ('What is moving?', '“Hot” can mean price movement, trading activity, or attention. Here, the ranking means trading volume. You can see exactly what it measures.', f'''
<section class="callout"><strong>Read the signal, not just the number.</strong><p>Price change compares now with 24 hours earlier. Volume measures trading over that period. Neither is your wallet’s profit or a forecast.</p></section>
<section>{head('Most traded in this example', '4 eligible tokens / 5 observed · USD')}{token_table(tokens)}{details('How this ranking works', '<p>Descending provider-reported 24h USD market volume, then provider ID. Missing or stale observations cannot rank. This four-token subset is fictional and includes USDC; it is not the world’s four most-traded assets. Search attention and decentralized-exchange volume are different measures.</p>')}</section>
<section>{head('What it means for you', 'Wallet relevance does not change the order')}<div class="grid">{token_details}</div></section>
''')
    chain_details = ''.join(f'<article class="card" id="{text(c["id"].replace(":", "-"))}"><p class="eyebrow">{text(c["name"])} · {text(c["health"])}</p><h3>{money(c["wallet_value"])} in your assets</h3><p>{text(c["note"])}</p><p>{badge(c["access"], "warn" if c["name"] in ["Robinhood", "Solana"] else "")}</p>{details("Scope & evidence", f"<p>Example chain scope: <code>{text(c['id'])}</code>. DEX volume: {compact(c['volume'])}. Wallet assets exclude venue accounts; source coverage is below.</p>")}</article>' for c in data['chains'])
    bodies['chains'] = ('Where activity lives.', 'A chain is a network where assets and transactions live. Compare trading activity, then check what you hold there and whether Bloom can help.', f'''
<section>{head('Networks by exchange activity', 'One completed UTC day · same metric')}{chain_table(chains)}<p class="muted">Robinhood is outside the volume ranking because comparable data is missing. Its wallet assets remain visible below.</p></section>
<section>{head('The networks in your wallet', 'Popularity, connection and permission are different facts')}<div class="grid">{chain_details}</div></section>
<section class="callout"><strong>Before moving between networks</strong><p>Check the destination network and token. Moving value between chains may require a supported bridge route, a fresh quote, and an owner-approved transaction.</p></section>
''')
    wallet_rows = ''.join(f'<tr><td><strong>{text(h["name"])}</strong><small>{text(h["quantity"])}</small></td><td data-label="Where">{text(h["scope"])}</td><td class="numeric money" data-label="Observed value">{money(h["value"])}</td><td><small>{text(h["source"])}</small>{details("How this is counted", f"<p>{text(h['note'])}</p>")}</td></tr>' for h in data['holdings'])
    bodies['portfolio'] = ('Your wallet, in context.', 'Assets you can hold, positions you have opened, and what we cannot value yet. Each network and venue keeps its own account of your money.', f'''
<section class="hero"><div><span class="label">Observed priced value · Alex</span><div class="metric">{money(total)}</div><p>10 priced rows · 1 unpriced asset · mixed observation times</p></div><div class="hero-aside"><h3>Value is not spendable cash.</h3><p>Some value sits in a vault or trading position. Withdrawability, fees, and price movement can change what you receive.</p><div class="links"><a class="button secondary" href="receive.html">Find a receiving address</a></div></div></section>
<section id="positions">{head('What you own', 'Expand a row to understand its value')}<div class="table-wrap"><table><caption>Fictional native and Petal observations; private pool value and service credit excluded</caption><thead><tr><th scope="col">Asset or position</th><th scope="col">Where</th><th scope="col" class="numeric">Value</th><th scope="col">Source & accounting</th></tr></thead><tbody>{wallet_rows}</tbody></table></div></section>
<section class="grid">{card('Equity, not borrowed exposure', 'Your Hyperliquid account contributes $2,100 once. Its $3,000 BTC exposure describes how much price risk you have; it is not another $3,000 in assets.', 'Understand your positions')}{card('A vault is a claim on assets', 'The $1,000 Morpho claim is counted once. Its receipt token is not also added as another holding. The separate $50 pending deposit has not completed.', 'Avoid double counting')}</section>
''')
    bodies['next-moves'] = ('A short list. A clear next step.', 'Your pending decisions come first. Market curiosity can wait. Each item says what happened, why it is here, and what you can do next.', f'''
<section>{head('Needs you', f'{len(needs)} operations · no new trade suggestions')}{action_list(needs)}</section>
<section>{head('Worth a look', 'Optional; not part of your attention count')}{action_list(optional)}</section>
<section class="callout warn"><strong>One thing we cannot check right now</strong><p>The Solana connection is delayed. Last-observed balances remain visible, but current transfer readiness is unknown. No resend is suggested.</p></section>
<section>{details('How this list is built', '<p>Items come from known operations and public provider state. A successful signature is not settlement. Expired reviews need a current request. An unknown broadcast outcome stays in reconciliation until Bloom can prove what happened. Market rankings never create urgent wallet tasks.</p>')}</section>
''')
    bodies['receive'] = ('A place for your funds.', 'First choose the network and account. Then match the sender’s network and asset to the full receiving address. Similar-looking addresses are not interchangeable.', '''
<section class="callout warn"><strong>Example addresses only — do not send funds.</strong><p>This prototype has no connected wallet. Copy and QR actions are intentionally absent.</p></section>
<section class="grid"><article class="card"><p class="eyebrow">Base / EVM account</p><h3>Receive on Base</h3><p>For a supported asset sent on Base. This address also has an Ethereum route, but the sender must explicitly choose Base.</p><code class="address">0x1234567890123456789012345678901234567890</code><p>Example address · network ID 8453</p></article><article class="card"><p class="eyebrow">Ethereum / EVM account</p><h3>Receive on Ethereum</h3><p>The same account address on a different network. ETH and token balances here remain separate from Base balances.</p><code class="address">0x1234567890123456789012345678901234567890</code><p>Example address · network ID 1</p></article></section>
<section class="grid"><article class="card"><p class="eyebrow">Solana / account selection</p><h3>Choose the exact account</h3><p>With more than one derived Solana account, Bloom needs the selected account’s full fingerprint. No address is shown until that account is resolved.</p><p><span class="badge warn">Account selection required · conditional native stack</span></p></article><article class="card"><p class="eyebrow">Venue funding</p><h3>Fund the right destination</h3><p>Polymarket needs a currently verified deposit route. Hyperliquid funding needs a supported workflow; a shared bridge contract is not your personal receiving address.</p><p><span class="badge">No verified venue destination in this example</span></p></article></section>
''')
    bodies['send'] = ('Know what comes next.', 'A prepared transfer, explained before you reach the trusted approval page. This information view cannot authorize or send it.', '''
<section class="review card"><p class="eyebrow">Transfer review / transfer-01</p><h2>100 USDC to Sam</h2><p><span class="badge warn">Awaiting owner approval · nothing sent</span></p><dl><div><dt>From</dt><dd>Alex · Base EVM account</dd></div><div><dt>Recipient label</dt><dd>Sam · illustrative saved contact</dd></div><div><dt>Full destination</dt><dd><code>0x2345678901234567890123456789012345678901</code></dd></div><div><dt>Asset</dt><dd>USDC on Base<br><code>0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913</code></dd></div><div><dt>Estimated network fee</dt><dd>0.00001 ETH · about $0.03<br><small>Illustrative estimate, not a guarantee</small></dd></div><div><dt>Expected transfer</dt><dd>−100 USDC from Alex<br>+100 USDC to the displayed recipient</dd></div><div><dt>Example approval expiry</dt><dd>05 Sep 2026, 17:10 UTC<br><small>Historical fixture time; not a live countdown</small></dd></div></dl>
<details><summary>Simulation & limits</summary><p>The example simulation predicts the standard token transfer above. It does not guarantee inclusion or the recipient’s identity. The trusted ceremony must bind the actual staged bytes and terms; these fixture labels have no authority.</p></details>
<div class="links"><a class="button" href="#handoff">Understand the approval step →</a><a class="button secondary" href="next-moves.html">Back to next moves</a></div></section>
<section class="review callout" id="handoff"><strong>Your passkey step happens in Bloom’s ceremony.</strong><p>In a connected wallet, open the current Broker-issued ceremony from the pending operation. Review the exact terms there, then use your passkey. This prototype has no ceremony URL and cannot approve anything.</p><p>After approval, Bloom still needs to submit the transfer and check its outcome. <a href="activity.html">See how progress is shown →</a></p></section>
''')
    bodies['activity'] = ('The story of your actions.', 'See what completed, what is waiting, and what remains uncertain. One workflow can have several steps; a completed approval is not a completed deposit.', '''
<section><div class="section-head"><h2>In progress</h2><p>Example operations · current at the fixture timestamp</p></div><div class="grid"><article class="card"><p class="eyebrow">Base transfer</p><h3>100 USDC still awaits you</h3><p>Prepared → <strong>Owner review</strong> → Submit → Confirm. Nothing sent.</p><a class="link" href="send.html">Inspect transfer →</a></article><article class="card" id="morpho"><p class="eyebrow">Morpho / deposit-02</p><h3>Approval done. Deposit paused.</h3><p>Step 1: the token approval completed. Step 2: the 50 USDC deposit review expired before signing. The existing $1,000 position has not grown by $50.</p><details><summary>What continuing means</summary><p>Use the current Morpho action status and supported retry path to obtain a new deposit review. The completed token approval is not repeated. The new review must reflect current terms.</p></details></article></div></section>
<section><div class="section-head"><h2>Recent outcomes</h2><p>Linked by operation IDs, not nearby timestamps</p></div><div class="timeline"><article class="event"><span class="label">16:35 UTC / Enso swap-04</span><h3>Swapped 0.05 ETH for 150 USDC</h3><p>Completed on Ethereum. The source receipt contains the attributable token movement and the operation’s supported settlement check passed in this example.</p><details><summary>Why this is one card</summary><p>The approval and swap belong to the same Enso workflow ID. Its earlier approval is a step, not another payment. These are fictional receipt facts, not a live transaction hash.</p></details></article><article class="event"><span class="label">15:10 UTC / Robinhood transfer-05</span><h3>Received 5 Apple stock tokens</h3><p>Observed on Robinhood Chain. The position is valued at the illustrative issuer quote. The incoming sender is not offered as a contact or future payment target.</p></article></div></section>
<section class="callout"><strong>History has a boundary.</strong><p>This example shows local workflows and selected provider outcomes, not every transaction the wallet has ever made. Unsolicited token metadata is not a trusted link or a payment instruction.</p></section>
''')
    bodies['permissions'] = ('Access, made understandable.', 'See the permissions Bloom knows about, and the boundaries it cannot verify. Installing a Petal, allowing a wallet to use it, and approving an operation are separate steps.', '''
<section class="grid"><article class="card"><p class="eyebrow">Wallet policy / Robinhood</p><h3>Visible, but transfers are blocked.</h3><p>You can read your stock-token position. This wallet’s Robinhood transfer policy is deny-all in the example. A policy change needs its existing owner approval ceremony.</p><details><summary>Policy is advisory here</summary><p>The per-chain policy projection explains the current scope. Broker rechecks authoritative policy before signing; reading this card does not grant access.</p></details></article><article class="card"><p class="eyebrow">Hyperliquid / bounded agent</p><h3>Local stop is not remote revocation.</h3><p>An agent can be stopped in Bloom while venue authorization remains unknown. Verify the venue state before labeling it revoked. This example cannot establish the remote status.</p><p><span class="badge warn">Remote authorization unknown</span></p></article><article class="card"><p class="eyebrow">Petals / capability context</p><h3>Installed does not mean allowed.</h3><p>Enso, Morpho, and Robinhood integrations offer different operations. Check the installed package’s routes and this wallet’s eligibility before preparing a new action.</p></article><article class="card"><p class="eyebrow">Recovery / owner only</p><h3>Use the existing custody ceremony.</h3><p>Wallet export and recovery use Bloom’s trusted Broker/Signer workflow. A view may explain how to start it; it never asks for or displays a key, recovery phrase, or secret.</p></article></section>
<section class="callout warn"><strong>This is not a complete approval inventory.</strong><p>Unknown token allowances, other apps, and external venue access may exist. Bloom should say exactly what it checked, not assign a “secure” score.</p></section>
''')
    bodies['states'] = ('Useful, even when incomplete.', 'The same visual language should help when a wallet is empty, data is missing, or a workflow needs care. These are independent scenarios, not simultaneous live alerts.', '''
<section class="grid"><article class="card"><p class="eyebrow">01 / No wallet connected</p><h3>Explore first. Connect when ready.</h3><p>Public market context can still be useful. Personal balances and next moves are absent, not shown as $0.</p><a class="link" href="markets.html">Explore the example market →</a></article><article class="card"><p class="eyebrow">02 / Empty checked wallet</p><h3>No assets in the sources checked.</h3><p>No funding or trading is required. If you want to receive funds, first choose the network. Unchecked sources are listed separately.</p><a class="link" href="receive.html">Understand receiving →</a></article><article class="card"><p class="eyebrow">03 / Market provider unavailable</p><h3>Market activity is unavailable.</h3><p>No stale leaderboard is presented as current. Wallet operations can still be inspected independently. Missing volume is not zero volume.</p><a class="link" href="next-moves.html">See pending wallet work →</a></article><article class="card"><p class="eyebrow">04 / Unknown price</p><h3>25 units. Dollar value unknown.</h3><p>Preserve the quantity and network, exclude it from the priced total, and avoid provider-supplied links. “Unpriced” does not mean worthless.</p></article><article class="card"><p class="eyebrow">05 / No pending work</p><h3>Nothing needs you in the sources checked.</h3><p>Show coverage and stop there. Do not fill the empty space with a trade, gas top-up, or urgent market recommendation.</p></article><article class="card"><p class="eyebrow">06 / Expired approval</p><h3>This review can no longer be used.</h3><p>Remove the dead ceremony link. If the canonical state proves nothing was signed, use the supported refresh path and review the new terms.</p><a class="link" href="activity.html#morpho">See the paused deposit →</a></article><article class="card"><p class="eyebrow">07 / Ambiguous broadcast</p><h3>Checking whether the transfer landed.</h3><p>A response was lost after dispatch. Reconcile the recorded transaction or signature. Do not suggest resend, cancel, or restaging while the result is uncertain.</p><p><span class="badge warn">Outcome unknown · no retry action</span></p></article><article class="card"><p class="eyebrow">08 / Private input</p><h3>The next step is yours, privately.</h3><p>The Privacy Pools workflow needs owner input in Bloom’s ceremony. No recipient, note, proof, or recovery secret appears here or in chat.</p></article><article class="card"><p class="eyebrow">09 / Unsupported Petal</p><h3>This integration is not available here.</h3><p>A repository or demo is not an installed capability. Keep supported native views available and explain the missing route. Do not render a broken action button.</p></article><article class="card"><p class="eyebrow">10 / Multiple Solana accounts</p><h3>Select the account before preparing.</h3><p>Resolve the exact full fingerprint, address, and network. An alias or first item in a list cannot choose the signing account.</p></article></section>
''')
    outputs = {name + '.html': page(name, title, lede, body, data) for name, (title, lede, body) in bodies.items()}
    md = ['# Bloom · fictional example snapshot', '', f"Snapshot: {data['snapshot_id']} · {data['observed_at']}", '', '**No wallet connected. No live prices. No actions execute.**', '', f'Observed priced wallet value: **{money(total)}**. One unpriced asset is excluded. Mixed observation times; Solana read delayed.', '', '## Needs you', '']
    for action in needs + optional:
        md += [f"### {action['title']} ({action['lane']})", action['body'], f"Evidence: {action['source']}", f"[Context]({action['target']})", '']
    md += ['## Tokens by illustrative 24h market volume', '', '| Token | Price | 24h change | Volume |', '| --- | ---: | ---: | ---: |']
    md += [f"| {t['name']} | {money(t['price'])} | {Decimal(t['change']):+.2f}% | {compact(t['volume'])} |" for t in tokens]
    md += ['', '## Chains by illustrative completed-day DEX volume', '', '| Chain | Volume | Your assets |', '| --- | ---: | ---: |']
    md += [f"| {c['name']} | {compact(c['volume'])} | {money(c['wallet_value'])} |" for c in chains]
    md += ['', 'Robinhood volume: not covered. Its $1,000 wallet value remains included.', '', '## Holdings', '', '| Asset | Quantity | Scope | Value |', '| --- | --- | --- | ---: |']
    md += [f"| {h['name']} | {h['quantity']} | {h['scope']} | {money(h['value'])} |" for h in data['holdings']]
    md += ['', '## Sources and coverage', '']
    md += [f"- {s['label']}: {s['status']}. {s['coverage']}. Source time {s['source_time']}; {s['window']}." for s in data['sources']]
    md += ['', 'Prototype support: [Receive](receive.html), [Transfer review](send.html), [Activity](activity.html), [Access](permissions.html), [Empty and failure states](states.html).', '']
    outputs['snapshot.md'] = '\n'.join(md)
    return outputs


def validate(data):
    # The fixed narrative contains amounts; fail if the shared fixture drifts.
    assert sum(Decimal(h['value']) for h in data['holdings'] if h['value'] is not None) == Decimal('13303')
    for chain in data['chains']:
        subtotal = sum(Decimal(h['value']) for h in data['holdings'] if h['scope'] == chain['name'] and h['value'] is not None)
        assert subtotal == Decimal(chain['wallet_value']), chain['name']
    assert len({t['id'] for t in data['tokens']}) == len(data['tokens'])
    assert len([a for a in data['actions'] if a['lane'] == 'needs']) == 2
    assert len(ranked_tokens(data)) == 4
    assert len(ranked_chains(data)) == 4
    assert text('<script>"&') == '&lt;script&gt;&quot;&amp;'
    # Metamorphic checks: unknown/stale observations cannot enter a ranking.
    changed = json.loads(json.dumps(data))
    changed['tokens'][0]['status'] = 'stale'
    assert all(t['id'] != 'ethereum' for t in ranked_tokens(changed))
    changed['tokens'][0]['status'] = 'fresh'
    changed['tokens'][0]['volume'] = None
    assert all(t['id'] != 'ethereum' for t in ranked_tokens(changed))
    assert money(None) != money('0')
    # All action targets are authored local prototype pages, never provider URLs.
    assert all(a['target'] in {'send.html', 'activity.html#morpho', 'portfolio.html#positions'} for a in data['actions'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Check deterministic output without writing')
    args = parser.parse_args()
    data = json.loads((ROOT / 'snapshot.json').read_text())
    validate(data)
    outputs = render(data)
    differences = []
    for name, content in outputs.items():
        path = ROOT / name
        if args.check:
            if not path.exists() or path.read_text() != content:
                differences.append(name)
        else:
            path.write_text(content)
    if differences:
        raise SystemExit('Regenerate stale outputs: ' + ', '.join(differences))
    print(f'{"Checked" if args.check else "Rendered"} {len(outputs)} artifacts; fixture accounting and ranking checks passed.')


if __name__ == '__main__':
    main()
