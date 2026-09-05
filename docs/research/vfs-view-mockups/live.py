#!/usr/bin/env python3
"""Render a private, read-only capture from a running Bloom daemon.

python3 live.py --socket /path/to/machine.sock --out /private/local/directory
Only list/read IPC methods are implemented. No wallet writes or ceremonies.
Wallet data belongs in --out, never in the repository or a public PR.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import json
import os
from pathlib import Path
import re
import socket
import urllib.request
from urllib.parse import quote

from build import text, money, badge, details, head, card, change

ROOT = Path(__file__).resolve().parent
SAFE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$')
ADDRESS = re.compile(r'^0x[0-9a-fA-F]{40}$')
CHAIN_MARKETS = {'ethereum':'Ethereum','base':'Base','arbitrum':'Arbitrum','robinhood':'Robinhood Chain','solana-mainnet':'Solana'}
NAV = [('index','Today'),('markets','Markets'),('chains','Chains'),('portfolio','Wallets'),('next-moves','Next moves'),('activity','Activity'),('receive','Receive'),('permissions','Access')]


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def number(value):
    try:
        result = Decimal(str(value))
        return result if result.is_finite() else None
    except (InvalidOperation, ValueError):
        return None


def compact(value):
    value = number(value)
    if value is None:
        return 'Unavailable'
    for scale, suffix in [(10**9,'B'),(10**6,'M'),(10**3,'K')]:
        if abs(value) >= scale:
            return f'${value / scale:,.2f}{suffix}'
    return money(value)


def names(record):
    value = record.get('data', [])
    return [x['name'] for x in value if x.get('kind') == 'dir' and SAFE.fullmatch(x.get('name',''))] if isinstance(value,list) else []


def data(record):
    return record.get('data', {}) if record and record.get('status') == 'ok' else {}


class Reader:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.records = {}

    def request(self, method, path):
        if method not in ('read','list'):
            raise ValueError('Only read-only VFS methods are supported')
        result = {'source': path, 'method': method, 'fetched_at': now()}
        try:
            with socket.socket(socket.AF_UNIX) as conn:
                conn.settimeout(60)
                conn.connect(self.endpoint)
                conn.sendall((json.dumps({'jsonrpc':'2.0','id':1,'bloom_protocol':{'current':1,'min':1,'max':1},'method':method,'params':{'path':path}})+'\n').encode())
                with conn.makefile('rb') as stream:
                    while True:
                        line = stream.readline(8*1024*1024+1)
                        if not line or len(line)>8*1024*1024:
                            raise ValueError('Missing or oversized IPC response')
                        response = json.loads(line)
                        if response.get('id') != 1:
                            continue
                        if response.get('bloom_protocol',{}).get('current') != 1:
                            raise ValueError('Unsupported IPC response protocol')
                        if 'error' in response:
                            raise ValueError(response['error'].get('message','Read unavailable'))
                        value = response['result']
                        if method == 'read':
                            value = base64.b64decode(value['bytes_b64'],validate=True).decode()
                            try:
                                value = json.loads(value, parse_float=str)
                            except ValueError:
                                pass
                        result.update(status='ok',data=value)
                        break
        except Exception as exc:
            # Do not copy upstream errors containing URLs/credentials into the view.
            result.update(status='unavailable',error=type(exc).__name__ + ': read unavailable')
        result['completed_at'] = now()
        return result

    def batch(self, tasks):
        tasks = [task for task in dict.fromkeys(tasks) if self.records.get(task,{}).get('status') != 'ok']
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {pool.submit(self.request,*task):task for task in tasks}
            for future in as_completed(futures):
                task = futures[future]
                self.records[task] = future.result()
        print(f'Captured {len(self.records)} VFS observations ({sum(r["status"] != "ok" for r in self.records.values())} unavailable)',flush=True)

    def get(self, method, path):
        return self.records.get((method,path),{})


def fetch(url):
    result = {'source':url,'fetched_at':now()}
    try:
        request = urllib.request.Request(url,headers={'User-Agent':'Bloom-local-views/1.0','Accept':'application/json'})
        with urllib.request.urlopen(request,timeout=25) as response:
            result.update(status='ok',data=json.load(response,parse_float=str))
    except Exception as exc:
        result.update(status='unavailable',error=type(exc).__name__)
    result['completed_at'] = now()
    return result


def collect(endpoint):
    reader = Reader(endpoint)
    reader.batch([('list','/wallets'),('list','/chains'),('list','/petals'),('read','/next.md'),('list','/outbox/pending'),('list','/outbox/sent'),('list','/outbox/failed')])
    wallets = [w for w in names(reader.get('list','/wallets')) if w != 'registrations']
    if not wallets:
        raise SystemExit('No wallet projections available; refusing to render a fictional or empty substitute.')
    evm_chains = names(reader.get('list','/chains'))
    petals = names(reader.get('list','/petals'))
    reader.batch([(method,f'/wallets/{w}/{leaf}') for w in wallets for method,leaf in [('read','addresses.json'),('read','accounts.json'),('list','chains')]])
    scopes = [(w,c) for w in wallets for c in names(reader.get('list',f'/wallets/{w}/chains'))]
    if any(not names(reader.get('list',f'/wallets/{w}/chains')) for w in wallets):
        raise SystemExit('A wallet chain listing failed; retry the capture before displaying wallet totals.')
    tasks = [('read',f'/status/chains/{c}/connected') for c in sorted({c for _,c in scopes})]
    for w,c in scopes:
        if c in evm_chains:
            tasks += [('read',f'/wallets/{w}/chains/{c}/policy.json')]
            owner = data(reader.get('read',f'/wallets/{w}/addresses.json')).get('owner','')
            if ADDRESS.fullmatch(owner):
                tasks += [('read',f'/chains/{c}/addresses/{owner}/balance.json'),('read',f'/chains/{c}/addresses/{owner}/tokens/known.json')]
        else:
            accounts = data(reader.get('read',f'/wallets/{w}/accounts.json')).get('accounts',[])
            for account in accounts:
                fingerprint=account.get('public_key_fingerprint','')
                if account.get('lifecycle')=='ACTIVE' and account.get('derivation_profile')=='bip44-solana-slip10-ed25519-v1' and re.fullmatch('[a-f0-9]{64}',fingerprint):
                    tasks.append(('read',f'/wallets/{w}/chains/{c}/accounts/{fingerprint}/balance.json'))
        tasks += [('list',f'/wallets/{w}/chains/{c}/outbox/{state}') for state in ['pending','sent','failed']]
    reader.batch(tasks)
    tasks=[]
    token_scopes=[]
    for w,c in scopes:
        owner=data(reader.get('read',f'/wallets/{w}/addresses.json')).get('owner','')
        known=data(reader.get('read',f'/chains/{c}/addresses/{owner}/tokens/known.json'))
        candidates = [t for t in known.get('known',[]) if t.get('symbol') in ['USDC','USDT','WETH','DAI']]+known.get('discovered',[])[:30]
        for token in candidates:
            address=token.get('address','')
            if ADDRESS.fullmatch(address):
                path=f'/chains/{c}/addresses/{owner}/tokens/{address}/balance.json'
                tasks.append(('read',path));token_scopes.append((w,c,path))
    for w in wallets:
        if 'robinhood' in petals:
            tasks.append(('read',f'/petals/robinhood/portfolio/{w}.json'))
        if 'morpho' in petals:
            tasks += [('read',f'/petals/morpho/{c}/positions/{w}.json') for c in evm_chains]
        owner=data(reader.get('read',f'/wallets/{w}/addresses.json')).get('owner','')
        if 'hyperliquid' in petals and ADDRESS.fullmatch(owner):
            tasks += [('read',f'/petals/hyperliquid/mainnet/users/{owner}/{leaf}.json') for leaf in ['clearinghouse','spot_state','open_orders']]
        if 'pumpfun' in petals:
            tasks.append(('list',f'/petals/pumpfun/sessions/{w}/sessions'))
    # Canonical IDs only. Bound recent history; sent is not called confirmed.
    operation_scopes=[]
    for w,c in scopes:
        if c in evm_chains:
            continue
        for state in ['pending','sent','failed']:
            parent=f'/wallets/{w}/chains/{c}/outbox/{state}'
            entries=data(reader.get('list',parent))
            entries=entries if isinstance(entries,list) else []
            ids=[e['name'] for e in sorted(entries,key=lambda e:(e.get('modified_ms') or 0,e['name']),reverse=True) if e.get('kind')=='dir' and SAFE.fullmatch(e.get('name',''))]
            for op in ids[:(30 if state=='pending' else 5)]:
                prefix=f'{parent}/{op}'
                operation_scopes.append((w,c,state,op,prefix))
                tasks += [('read',prefix+'/status.json'),('read',prefix+'/receipt.json')]
    central=[]
    for state in ['pending','sent','failed']:
        entries=data(reader.get('list','/outbox/'+state))
        entries=entries if isinstance(entries,list) else []
        for entry in sorted(entries,key=lambda e:(e.get('modified_ms') or 0,e['name']),reverse=True)[:30]:
            if entry.get('kind')=='dir' and SAFE.fullmatch(entry.get('name','')):
                path=f'/outbox/{state}/{entry["name"]}'
                central.append((state,entry['name'],path))
                tasks += [('read',path+'/'+leaf) for leaf in ['status.json','result.json','plan.md']]
    reader.batch(tasks)
    receipt_tasks=[]
    for state,oid,path in central:
        plan=data(reader.get('read',path+'/plan.md'))
        plan=plan if isinstance(plan,str) else ''
        wallet=re.search(r'^Wallet:\s+(\S+)',plan,re.M)
        chain=re.search(r'^Chain:\s+(\S+)',plan,re.M)
        w=wallet.group(1) if wallet else 'Wallet not reported'
        c=chain.group(1) if chain else 'Chain not reported'
        operation_scopes.append((w,c,state,oid,path))
        tx_hash=data(reader.get('read',path+'/status.json')).get('tx_hash','')
        if c in evm_chains and re.fullmatch('0x[0-9a-fA-F]{64}',tx_hash):
            receipt_tasks.append(('read',f'/chains/{c}/tx/{tx_hash}/receipt.json'))
    reader.batch(receipt_tasks)
    # Public session metadata only; never request signatures or private inputs.
    tasks=[]
    for w in wallets:
        for session in names(reader.get('list',f'/petals/pumpfun/sessions/{w}/sessions'))[:15]:
            tasks.append(('read',f'/petals/pumpfun/sessions/{w}/sessions/{session}/session.json'))
    # Contract-qualified prices for held ERC-20s and vault underlying assets.
    for w,c,path in dict.fromkeys(token_scopes):
        balance=data(reader.get('read',path))
        if (number(balance.get('raw')) or 0)>0:
            tasks.append(('read',f'/prices/spot/{c}:{balance["address"]}'))
    for w in wallets:
        for c in evm_chains:
            for pos in data(reader.get('read',f'/petals/morpho/{c}/positions/{w}.json')).get('positions',[]):
                if ADDRESS.fullmatch(pos.get('asset') or ''):
                    tasks.append(('read',f'/prices/spot/{c}:{pos["asset"]}'))
    tasks += [('read','/prices/spot/eth'),('read','/prices/spot/coingecko:solana')]
    reader.batch(tasks)
    urls={'market':'https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&order=volume_desc&per_page=20&page=1&sparkline=false&price_change_percentage=24h'}
    for c in sorted({c for _,c in scopes}):
        if c in CHAIN_MARKETS:
            urls[c]='https://api.llama.fi/overview/dexs/'+quote(CHAIN_MARKETS[c])+'?excludeTotalDataChart=true&excludeTotalDataChartBreakdown=true'
    with ThreadPoolExecutor(max_workers=4) as pool:
        markets=dict(zip(urls,pool.map(fetch,urls.values())))
    return {'captured_at':now(),'wallets':wallets,'chains':sorted({c for _,c in scopes}),'evm_chains':evm_chains,'petals':petals,'scopes':scopes,'token_scopes':list(dict.fromkeys(token_scopes)),'operations':operation_scopes,'records':list(reader.records.values()),'markets':markets}


def observed_price(record, captured_at):
    quote=data(record)
    price=number(quote.get('price'))
    stamp=number(quote.get('timestamp'))
    if price is None or price<0 or stamp is None:
        return None
    current=Decimal(str(datetime.fromisoformat(captured_at).timestamp()))
    # One hour is a valuation bound, not a claim that every provider updates hourly.
    return price if 0 <= current-stamp <= 3600 else None


def normalize(snapshot):
    records={(r['method'],r['source']):r for r in snapshot['records']}
    get=lambda method,path:records.get((method,path),{})
    holdings=[];covered=set()
    def add(wallet,chain,name,quantity,value,source,identity,note='',reference=False):
        owner=data(get('read',f'/wallets/{wallet}/addresses.json')).get('owner',wallet)
        account=identity if chain.startswith('solana') and identity.startswith('native:') else owner.lower()
        key=(account,chain,identity.lower())
        if key in covered:return
        covered.add(key)
        holdings.append(dict(wallet=wallet,chain=chain,name=name,quantity=quantity,value=str(value) if value is not None else None,source=source,identity=identity,note=note,reference=reference))
    for w in snapshot['wallets']:
        for c in snapshot['evm_chains']:
            path=f'/petals/morpho/{c}/positions/{w}.json'
            for p in data(get('read',path)).get('positions',[]):
                price=observed_price(get('read',f'/prices/spot/{c}:{p.get("asset")}'),snapshot['captured_at'])
                qty=number(p.get('assets_display'))
                value=qty*price if qty is not None and price is not None else None
                add(w,c,p.get('name') or 'Morpho vault',str(p.get('assets_display') or 'Unknown')+' '+str(p.get('asset_symbol') or ''),value,path,p['vault'],'Underlying claim; receipt shares are not added again. '+('Withdrawal liquidity is limited.' if p.get('fully_withdrawable') is False else ''))
        path=f'/petals/robinhood/portfolio/{w}.json'
        for p in data(get('read',path)).get('positions',[]):
            add(w,'robinhood',p.get('name') or p['symbol'],str(p.get('tokens'))+' '+p['symbol'],number(p.get('reference_underlying_value_usd',p.get('usd_value'))),path,p['token'],'Issuer underlying-share reference, not a realizable stock-token market quote.',True)
        owner=data(get('read',f'/wallets/{w}/addresses.json')).get('owner','')
        path=f'/petals/hyperliquid/mainnet/users/{owner}/clearinghouse.json'
        hl=data(get('read',path))
        if isinstance(hl,dict):
            equity=number(hl.get('marginSummary',{}).get('accountValue'))
            if equity is not None and equity!=0:
                add(w,'Hyperliquid','Trading account equity','Account equity',equity,path,'hl-equity','Includes unrealized P&L; position notional is not added again.')
    for w in snapshot['wallets']:
        owner=data(get('read',f'/wallets/{w}/addresses.json')).get('owner','')
        path=f'/petals/hyperliquid/mainnet/users/{owner}/spot_state.json'
        for b in data(get('read',path)).get('balances',[]):
            quantity=number(b.get('total'))
            if quantity and quantity>0:
                add(w,'Hyperliquid',str(b.get('coin'))+' spot',str(quantity)+' '+str(b.get('coin')),None,path,'hl-spot:'+str(b.get('token')),'Spot quantity observed; excluded from value until overlap with account equity is verified.')
    for r in snapshot['records']:
        if r['method']!='read' or r['status']!='ok' or not r['source'].endswith('/balance.json') or r['data'].get('asset')!='native':continue
        p=r['source'].split('/');b=r['data']
        if p[1]=='wallets':
            w,c=p[2],p[4]
        else:
            c=p[2]
            matches=[w for w in snapshot['wallets'] if data(get('read',f'/wallets/{w}/addresses.json')).get('owner','').lower()==p[4].lower()]
            if not matches:continue
            w=matches[0]
        raw=number(b.get('raw',b.get('lamports')))
        if raw is None or raw==0:continue
        qty=number(b.get('formatted'))
        symbol=b.get('symbol','SOL' if c.startswith('solana') else 'ETH')
        if qty is None:qty=raw/(Decimal(10)**(9 if symbol=='SOL' else 18))
        testnet='devnet' in c or 'testnet' in c
        price=None if testnet else observed_price(get('read','/prices/spot/coingecko:solana' if symbol=='SOL' else '/prices/spot/'+symbol.lower()),snapshot['captured_at'])
        fingerprint=b.get('account_fingerprint','native')
        add(w,c,symbol,f'{qty:f} {symbol}',qty*price if price is not None else None,r['source'],'native:'+fingerprint,'Test network; excluded from dollar value.' if testnet else 'Native balance read through Bloom.')
    for w,c,path in snapshot['token_scopes']:
        b=data(get('read',path));raw=number(b.get('raw'))
        if raw is None or raw==0:continue
        qty=number(b.get('formatted')); price=observed_price(get('read',f'/prices/spot/{c}:{b["address"]}'),snapshot['captured_at'])
        add(w,c,b.get('symbol') or 'Unidentified token',b.get('display') or str(raw)+' raw units',qty*price if qty is not None and price is not None else None,path,b['address'],'Known/discovered ERC-20; token identity is its chain and contract.')
    return holdings,get


def render(snapshot):
    holdings,get=normalize(snapshot)
    priced=[h for h in holdings if h['value'] is not None and not h['reference']]
    total=sum((Decimal(h['value']) for h in priced),Decimal(0)) if priced else None
    unpriced=[h for h in holdings if h['value'] is None and 'devnet' not in h['chain']]
    unavailable=[r for r in snapshot['records'] if r['status']!='ok']
    market=data(snapshot['markets'].get('market'))
    market=market if isinstance(market,list) else []
    cutoff=datetime.fromisoformat(snapshot['captured_at']).timestamp()-3600
    def fresh(t):
        try:return cutoff<=datetime.fromisoformat(t['last_updated'].replace('Z','+00:00')).timestamp()<=datetime.fromisoformat(snapshot['captured_at']).timestamp()
        except (ValueError,KeyError,TypeError):return False
    eligible=[t for t in market if fresh(t) and number(t.get('total_volume')) is not None]
    eligible.sort(key=lambda t:(-Decimal(str(t['total_volume'])),t['id']))
    movers=sorted([t for t in eligible if number(t.get('price_change_percentage_24h')) is not None],key=lambda t:-Decimal(str(t['price_change_percentage_24h'])))
    pending=[o for o in snapshot['operations'] if o[2]=='pending']
    pending_sources=[r for r in snapshot['records'] if r['method']=='list' and r['source'].endswith('/outbox/pending')]
    pending_complete=bool(pending_sources) and all(r['status']=='ok' for r in pending_sources) and all(get('list',f'/wallets/{w}/chains').get('status')=='ok' for w in snapshot['wallets'])
    bodies={}
    def evidence(path):return details('Source & observation',f'<p><code>{text(path)}</code><br>Read during the capture ending {text(snapshot["captured_at"])}.</p>')
    def table(headers,rows):
        return '<div class="table-wrap"><table><thead><tr>'+''.join(f'<th scope="col">{text(h)}</th>' for h in headers)+'</tr></thead><tbody>'+''.join('<tr>'+''.join(f'<td>{cell}</td>' for cell in row)+'</tr>' for row in rows)+'</tbody></table></div>'
    def holding_rows(items):
        return [[f'<strong>{text(h["name"])}</strong><small>{text(h["quantity"])}</small>',f'{text(h["wallet"])}<small>{text(h["chain"])}</small>',money(h['value'])+('<small>Reference only</small>' if h['reference'] else ''),details('Details',f'<p>{text(h["note"])}</p><p><code>{text(h["identity"])}</code></p><p><code>{text(h["source"])}</code></p>')] for h in items]
    trend=(f'{text(eligible[0]["symbol"].upper())} leads reported volume.' if eligible else 'Market data is unavailable.')
    movement=(f'{text(movers[0]["symbol"].upper())} has the largest signed 24h change in this sample ({change(movers[0]["price_change_percentage_24h"])}).' if movers else 'No current price-movement ranking is available.')
    attention=f'{len(pending)} staged operations' if pending else ('No staged operations awaiting review' if pending_complete else 'Pending operations could not all be checked')
    wallet_cards=''.join(card(w,f'{money(sum((Decimal(h["value"]) for h in priced if h["wallet"]==w),Decimal(0)) if any(h["wallet"]==w for h in priced) else None)} priced assets · {sum(h["wallet"]==w for h in holdings)} nonzero holdings observed.','Wallet',('portfolio.html#'+w,'Inspect wallet')) for w in snapshot['wallets'])
    bodies['index']=('Your wallet, right now.','A read-only capture from your running Bloom triad, with current market context and the actual state of your wallets.',f'<section class="hero"><div><p class="eyebrow">Market context</p><h2>{trend}</h2><p>{movement}</p><p>Among the provider’s 20-token volume sample. Market activity is context, not a required trade.</p><div class="links"><a class="button" href="markets.html">Explore current markets →</a></div></div><div class="hero-aside"><span class="label">Observed priced assets</span><div class="metric">{money(total)}</div><p>{len(priced)} priced holdings · {len(unpriced)} unpriced. Issuer reference values, test funds, and unchecked sources are excluded.</p><a href="portfolio.html">See your balances →</a></div></section><div class="stats"><div class="stat"><span class="label">Your wallets</span><strong>{len(snapshot["wallets"])}</strong><small>Discovered from the running daemon.</small></div><div class="stat"><span class="label">Pending work</span><strong>{len(pending) if pending_complete else "Unknown"}</strong><small>{text(attention)}</small></div><div class="stat"><span class="label">Installed integrations</span><strong>{len(snapshot["petals"])}</strong><small>{text(", ".join(snapshot["petals"]))}</small></div></div><section>{head("Your accounts") }<div class="grid">{wallet_cards}</div></section><section class="callout"><strong>{text(attention)}</strong><p><a href="next-moves.html">See what was checked and any gaps →</a></p></section>')
    token_rows=[[f'<strong>{text(t["name"])}</strong><small>{text(t["symbol"].upper())}</small>',money(t.get('current_price')),change(t.get('price_change_percentage_24h')),compact(t.get('total_volume'))] for t in eligible]
    bodies['markets']=('What is moving?','Real provider observations. Volume, price movement, and your exposure answer different questions.',f'<section>{head("Most traded in the provider sample",str(len(eligible))+" fresh rows · CoinGecko · 24h reported volume")}{table(["Token","Price","24h change","24h volume"],token_rows) if token_rows else "<p>The market provider did not return usable current data.</p>"}</section><section class="callout"><strong>Price movement is not your personal return.</strong><p>Volume is aggregate trading reported by CoinGecko, not available liquidity. Stablecoins remain in this volume ranking. Quotes older than one hour are excluded.</p></section><section>{details("Source & timestamps", "<p><code>https://api.coingecko.com/api/v3/coins/markets</code></p>"+"".join(f"<p>{text(t['name'])}: {text(t.get('last_updated'))}</p>" for t in eligible))}</section>')
    chain_rows=[]
    for c in snapshot['chains']:
        dex=data(snapshot['markets'].get(c));vol=dex.get('total24h');pct=dex.get('change_1d')
        health=data(get('read',f'/status/chains/{c}/connected'))
        health='Connected' if str(health).strip().lower()=='true' else 'Connection unverified'
        owned=sum((Decimal(h['value']) for h in priced if h['chain']==c),Decimal(0))
        chain_rows.append((number(vol),[f'<strong>{text(c)}</strong><small>{health}</small>',compact(vol),change(pct),money(owned)]))
    chain_rows.sort(key=lambda x:-(x[0] if x[0] is not None else Decimal(-1)))
    bodies['chains']=('Where your assets live.','Trading activity comes from DefiLlama. Connection health comes from Bloom. Neither grants this wallet permission to transact.',f'<section>{head("Your configured networks","Provider-reported 24h spot DEX volume; not a global chain ranking")}{table(["Network","DEX volume","Vs previous period","Priced assets"],[r for _,r in chain_rows])}</section><section class="callout"><strong>Different sources have different clocks.</strong><p>DefiLlama’s total24h and change_1d are provider-reported rolling/daily aggregates, not a synchronized completed UTC-day comparison. Missing coverage is “Unavailable”, not zero. Test-network balances have no dollar valuation.</p></section>')
    wallet_sections=''.join(f'<section id="{text(w)}">{head(w)}{table(["Asset / quantity","Account / network","Observed value","Evidence"],holding_rows([h for h in holdings if h["wallet"]==w])) if any(h["wallet"]==w for h in holdings) else "<p>No nonzero balances in the sources that answered. Unavailable sources are listed below.</p>"}</section>' for w in snapshot['wallets'])
    bodies['portfolio']=('Your actual holdings.','Native balances, selected ERC-20s, and supported Petal positions read from your daemon. Missing quotes stay unpriced.',f'<section class="hero"><div><span class="label">Observed priced assets</span><div class="metric">{money(total)}</div></div><div class="hero-aside"><h3>Coverage stays visible.</h3><p>Known USDC, USDT, WETH and DAI plus up to 30 discovered tokens per wallet/network. Vault receipt shares count once. Robinhood issuer reference values are separate from market-valued assets.</p></div></section>'+wallet_sections)
    def op_card(op):
        w,c,state,oid,path=op
        status=data(get('read',path+'/status.json'));receipt=data(get('read',path+'/receipt.json'))
        observed=status.get('status',status.get('state',state)) if isinstance(status,dict) else state
        chain_receipt=data(get('read',f'/chains/{c}/tx/{status.get("tx_hash", "")}/receipt.json')) if isinstance(status,dict) else {}
        if isinstance(chain_receipt,dict) and chain_receipt.get('status') in ['0x1',1,True]:
            observed='Confirmed on chain'
            receipt=chain_receipt
        elif isinstance(chain_receipt,dict) and chain_receipt.get('status') in ['0x0',0,False]:
            observed='Reverted on chain'
            receipt=chain_receipt
        petal=status.get('petal_id','') if isinstance(status,dict) else ''
        label=str(observed)+((' · '+petal.removeprefix('petal:')) if petal else '')
        summary='Staged; inspect current operation before approving.' if state=='pending' else ('Recorded as sent; this alone does not prove confirmation.' if state=='sent' else 'Recorded in the failed outbox.')
        if observed=='Confirmed on chain':summary='The chain receipt reports successful execution.'
        elif observed=='Reverted on chain':summary='The chain receipt reports a revert; execution did not complete successfully.'
        plan=data(get('read',path+'/plan.md'))
        terms=[]
        if isinstance(plan,str):
            terms=[line for line in plan.splitlines() if line.startswith(('To:','Value:','Nonce:','Chain:'))]
        body=f'<article class="card"><p class="eyebrow">{text(w)} / {text(c)}</p><h3>{text(label)}</h3><p>{summary}</p><small>{text(oid)}</small>'
        if terms:body+=details('Transfer terms', '<p>'+ '<br>'.join(text(t) for t in terms)+'</p>')
        facts={k:v for k,v in status.items() if k in ['status','state','tx_hash','created_ms','updated_ms','chain','error','failure_reason']} if isinstance(status,dict) else {}
        receipt_facts={k:v for k,v in receipt.items() if k in ['status','outcome','slot','block_number','blockNumber','gasUsed','effectiveGasPrice','transactionHash','transaction_hash','tx_hash','error']} if isinstance(receipt,dict) else {}
        return body+details('Recorded status & receipt',f'<p><code>{text(json.dumps(facts))}</code></p><p><code>{text(json.dumps(receipt_facts))}</code></p><p><code>{text(path)}</code></p>')+'</article>'
    bodies['next-moves']=('What needs you.','This list comes from your current staged operations. It does not invent a trade, claim, or deposit to fill the page.',f'<section>{head(attention)}<div class="grid">'+''.join(op_card(o) for o in pending)+'</div>'+('<p>No confirmation is waiting in the outbox sources that answered.</p>' if not pending else '')+'</section><section class="callout"><strong>Other obligations may exist.</strong><p>Pending outbox reads do not establish that every venue position is safe or every session has been cleaned up. Unavailable reads and session metadata are visible under Access.</p></section>')
    bodies['activity']=('Recorded operation history.','Recent IDs from each wallet outbox. This is a bounded local history, not a complete chain explorer. Sent and confirmed remain different states.',f'<section><div class="grid">'+''.join(op_card(o) for o in snapshot['operations'])+'</div>'+('<p>No operations were returned by the outboxes checked.</p>' if not snapshot['operations'] else '')+'</section>')
    receive=[]
    for w,c in snapshot['scopes']:
        if c in snapshot['evm_chains']:
            addr=data(get('read',f'/wallets/{w}/addresses.json')).get('owner')
            if addr:receive.append(card(w+' · '+c,'Use the exact network and supported asset shown here. The same EVM address on another network has a separate balance.','Receiving account')[:-10]+f'<code class="address">{text(addr)}</code></article>')
        else:
            for account in data(get('read',f'/wallets/{w}/accounts.json')).get('accounts',[]):
                if account.get('lifecycle')=='ACTIVE':
                    for projection in account.get('chain_projections',[]):
                        if projection.get('chain_family')=='solana':
                            receive.append(f'<article class="card"><p class="eyebrow">{text(w)} / {text(c)}</p><h3>SOL receiving account</h3><code class="address">{text(projection["address"])}</code><p>Match the sender’s network. Native SOL support does not imply support for every SPL token.</p>{details("Exact account",f"<p><code>{text(account['public_key_fingerprint'])}</code></p>")}</article>')
    bodies['receive']=('Your receiving accounts.','Public addresses from your current wallet/account projections. Choose the network first and verify the full address before sending.',f'<section><div class="grid">{"".join(receive)}</div></section>')
    access=[]
    for w in snapshot['wallets']:
        projection=data(get('read',f'/wallets/{w}/addresses.json'))
        access.append(card(w,'Policy status: '+str(projection.get('policy_status','unavailable'))+'. Policy version: '+str(projection.get('policy_version','unknown'))+'. A public projection explains state; Broker still authorizes each operation.','Wallet policy'))
    for r in snapshot['records']:
        if r['source'].endswith('/policy.json') and r['status']=='ok':
            p=r['data'];facts={k:v for k,v in p.items() if k in ['effect','summary','chain','wallet','chain_id']} if isinstance(p,dict) else {}
            access.append(f'<article class="card"><p class="eyebrow">Chain policy</p><p><code>{text(r["source"])}</code></p><p>{text(facts.get('summary',json.dumps(facts)))}</p></article>')
        if r['source'].endswith('/session.json') and r['status']=='ok':
            p=r['data'];facts={k:v for k,v in p.items() if k in ['id','address','status','state','expires_at_ms','expires_ms','stopped','created_at_ms']}
            access.append(f'<article class="card"><p class="eyebrow">Pump.fun session / public state</p><p>{text(json.dumps(facts))}</p><p>Session balance and token inventory are not included in this capture. Read metadata is not evidence that funds were swept.</p></article>')
    bodies['permissions']=('Your current access.','Known wallet policy and public integration state. This is not a complete inventory of external approvals.',f'<section><div class="grid">{"".join(access)}</div></section>')
    coverage='<section class="coverage">'+details('Read coverage, unavailable sources & valuation limits',f'<p>{len(snapshot["records"])} VFS observations; {len(unavailable)} unavailable. Native balance and quote reads are not atomic across chains. Quotes without a usable timestamp, or older than one hour, are excluded from dollar totals. No SPL inventory, Pump.fun session balances, Hyperliquid spot valuation, or general allowance scan is claimed.</p>'+''.join(f'<p><code>{text(r["source"])}</code> · unavailable</p>' for r in unavailable))+'</section>'
    pages={}
    for name,(title,lede,body) in bodies.items():
        nav=''.join(f'<a href="{slug}.html"'+(' aria-current="page"' if slug==name else '')+f'>{label}</a>' for slug,label in NAV)
        pages[name+'.html']=f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self'; base-uri 'none'; form-action 'none'"><title>{text(title)} · Bloom</title><link rel="stylesheet" href="bloom.css"><link rel="icon" href="bloom-primary.svg"></head><body><a class="skip" href="#main">Skip to content</a><div class="demo">Your Bloom data · captured {text(snapshot['captured_at'])} · read-only snapshot</div><div class="shell"><header class="masthead"><a class="brand" href="index.html"><img src="bloom-primary.svg" alt="" width="32" height="32"><strong>/bloom</strong></a><span class="edition">Your wallet fieldnotes<br>{len(snapshot['wallets'])} wallets · actual observations</span></header><nav aria-label="Wallet views">{nav}</nav><main id="main"><div class="intro"><div><p class="eyebrow">Your place in the ecosystem</p><h1>{text(title)}</h1></div><p class="lede">{text(lede)}</p></div>{body}{coverage}</main><footer><span>Captured {text(snapshot['captured_at'])}. This page does not refresh automatically.</span><a href="observations.json">Local source observations</a></footer></div></body></html>'''
    return pages,holdings


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket',required=True,type=Path)
    parser.add_argument('--out',required=True,type=Path)
    parser.add_argument('--render-only',action='store_true',help='Render a previous private capture without fetching')
    args=parser.parse_args()
    output=args.out.resolve()
    # Prevent personal observations from entering this checkout.
    if ROOT.parent.parent.parent in [output,*output.parents]:
        raise SystemExit('Choose a private output directory outside the repository')
    os.umask(0o077);output.mkdir(parents=True,exist_ok=True)
    if args.render_only:
        snapshot=json.loads((output/'observations.json').read_text())
    else:
        snapshot=collect(str(args.socket))
        (output/'observations.json').write_text(json.dumps(snapshot,indent=2))
    pages,holdings=render(snapshot)
    for name,content in pages.items():(output/name).write_text(content)
    for name in ['bloom.css','bloom-primary.svg']:(output/name).write_bytes((ROOT/name).read_bytes())
    (output/'holdings.json').write_text(json.dumps(holdings,indent=2))
    print(f'Rendered {len(pages)} real-data views at {output / "index.html"}',flush=True)


if __name__=='__main__':
    main()
