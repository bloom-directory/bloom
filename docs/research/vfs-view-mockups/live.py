#!/usr/bin/env python3
"""Render a private, read-only capture from a running Bloom daemon.

python3 live.py --socket /path/to/machine.sock --out /private/local/directory
Only list/read IPC methods are implemented. No wallet writes or ceremonies.
Wallet data belongs in --out, never in the repository or a public PR.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
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
NAV = [('index','Today'),('markets','Markets'),('chains','Chains'),('fees','Fees'),('portfolio','Wallets'),('next-moves','Next moves'),('activity','Activity'),('receive','Receive'),('permissions','Access')]


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
                tasks += [('read',prefix+'/plan.md'),('read',prefix+'/receipt.json')]
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


# Public context is fetched at capture time, never by the browser. Wallet reads
# remain on the daemon; the public RPCs only resolve already-known transactions.
PUBLIC_RPC = {
    'ethereum': ('https://ethereum-rpc.publicnode.com', 1, 12),
    'base': ('https://mainnet.base.org', 8453, 2),
    'arbitrum': ('https://arb1.arbitrum.io/rpc', 42161, .25),
    'robinhood': ('https://rpc.mainnet.chain.robinhood.com', 4663, .25),
}
FEE_SLUGS = {'ethereum':'ethereum', 'base':'base', 'arbitrum':'arbitrum', 'robinhood':'robinhood-chain', 'solana-mainnet':'solana'}
TOKEN_ICONS = {
    ('ethereum','0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'):'usd-coin',
    ('base','0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'):'usd-coin',
    ('ethereum','0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2'):'weth',
}


def integer(value):
    try:
        if isinstance(value,bool): return int(value)
        return int(value,16) if isinstance(value,str) and value.startswith('0x') else int(str(value))
    except (ValueError,TypeError): return None


def rpc(chain, method, params):
    if method not in ['eth_chainId','eth_getBlockByNumber','eth_getTransactionReceipt','eth_getTransactionByHash']:
        raise ValueError('Read-only public RPC method required')
    url=PUBLIC_RPC[chain][0]
    record={'source':url,'method':method,'params':params,'fetched_at':now()}
    try:
        request=urllib.request.Request(url,data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),headers={'Content-Type':'application/json','User-Agent':'Bloom-local-views/1.0'})
        with urllib.request.urlopen(request,timeout=20) as response:
            body=response.read(8*1024*1024+1)
        if len(body)>8*1024*1024: raise ValueError('Oversized response')
        value=json.loads(body,parse_float=str)
        if value.get('error') or value.get('result') is None: raise ValueError('Unavailable response')
        result=value['result']
        if method=='eth_getBlockByNumber':
            result={k:result[k] for k in ['number','timestamp','baseFeePerGas','hash'] if k in result}
        record.update(status='ok',data=result)
    except Exception as exc:
        record.update(status='unavailable',error=type(exc).__name__)
    record['completed_at']=now()
    return record


def enrich(snapshot):
    """Add public chain context without changing the wallet capture timestamp."""
    with ThreadPoolExecutor(max_workers=4) as pool:
        chains=[c for c in snapshot['chains'] if c in FEE_SLUGS]
        values=pool.map(lambda c:fetch('https://api.llama.fi/summary/fees/'+FEE_SLUGS[c]+'?dataType=dailyFees'),chains)
        snapshot['fee_history']=dict(zip(chains,values))
    records={(r['method'],r['source']):r for r in snapshot['records']}
    public={};gas={}
    def chain_context(c):
        identity=rpc(c,'eth_chainId',[])
        if integer(data(identity))!=PUBLIC_RPC[c][1]:
            return c,{}, {'status':'unavailable','source':PUBLIC_RPC[c][0],'fetched_at':now(),'points':[]}
        readings={}
        head=rpc(c,'eth_getBlockByNumber',['latest',False]);block=data(head)
        points=[head] if head['status']=='ok' else []
        height=integer(block.get('number')) if isinstance(block,dict) else None
        # Sample 25 actual block headers over approximately 24 hours. The chart
        # uses returned timestamps, not assumed hourly timestamps or averages.
        if height is not None:
            step=round(3600/PUBLIC_RPC[c][2])
            probe=rpc(c,'eth_getBlockByNumber',[hex(max(0,height-step)),False])
            earlier=data(probe)
            elapsed=(integer(block.get('timestamp')) or 0)-(integer(earlier.get('timestamp')) or 0)
            distance=height-(integer(earlier.get('number')) or height)
            if elapsed>0 and distance>0:step=max(1,round(3600*distance/elapsed))
            with ThreadPoolExecutor(max_workers=2) as pool:
                points+=list(pool.map(lambda n:rpc(c,'eth_getBlockByNumber',[hex(n),False]),[height-step*i for i in range(1,25) if height-step*i>=0]))
        for w,chain,state,oid,path in snapshot['operations']:
            if chain!=c: continue
            status=data(records.get(('read',path+'/status.json')))
            tx=status.get('tx_hash','') if isinstance(status,dict) else ''
            if not re.fullmatch('0x[0-9a-fA-F]{64}',tx):continue
            # Always label this as a later receipt observation, not part of the
            # original wallet snapshot. Do not infer confirmation from 'sent'.
            readings[tx]={'receipt':rpc(c,'eth_getTransactionReceipt',[tx]),'transaction':rpc(c,'eth_getTransactionByHash',[tx])}
            receipt=data(readings[tx]['receipt'])
            if isinstance(receipt,dict) and receipt.get('blockNumber'):
                readings[tx]['block']=rpc(c,'eth_getBlockByNumber',[receipt['blockNumber'],False])
        return c,readings,{'status':'ok' if points else 'unavailable','source':PUBLIC_RPC[c][0],'fetched_at':now(),'points':points}
    with ThreadPoolExecutor(max_workers=3) as pool:
        for c,readings,series in pool.map(chain_context,[c for c in snapshot['evm_chains'] if c in PUBLIC_RPC]):
            public[c]=readings;gas[c]=series
    snapshot.update(public_transactions=public,gas_history=gas,context_at=now())
    return snapshot


def cache_icons(snapshot, output):
    """Cache provider raster marks locally; no tracking or SVG from remote data."""
    sources={}
    for c,record in snapshot.get('fee_history',{}).items():
        logo=data(record).get('logo')
        if logo:sources['chain:'+c]=logo.replace('icons.llamao.fi/chains/','icons.llamao.fi/icons/chains/')
    # Hyperliquid trading equity is not represented as HyperEVM chain fees.
    sources['chain:Hyperliquid']='https://icons.llamao.fi/icons/chains/rsz_hyperliquid%20l1.jpg'
    market=data(snapshot.get('markets',{}).get('market'))
    for t in market if isinstance(market,list) else []:
        if SAFE.fullmatch(t.get('id','')) and t.get('image'):sources['token:'+t['id']]=t['image']
    # WETH uses its own token mark rather than pretending to be native ETH.
    sources.setdefault('token:weth','https://assets.coingecko.com/coins/images/2518/small/weth.png')
    icons={};folder=output/'icons';folder.mkdir(exist_ok=True)
    def download(item):
        key,url=item
        from urllib.parse import urlsplit
        parsed=urlsplit(url)
        if parsed.scheme!='https' or parsed.hostname not in ['icons.llamao.fi','assets.coingecko.com','coin-images.coingecko.com']:return None
        try:
            request=urllib.request.Request(url.replace(' ','%20'),headers={'User-Agent':'Bloom-local-views/1.0'})
            with urllib.request.urlopen(request,timeout=15) as response:
                if urlsplit(response.url).hostname not in ['icons.llamao.fi','assets.coingecko.com','coin-images.coingecko.com']:return None
                body=response.read(512*1024+1)
            if len(body)>512*1024:return None
            ext='png' if body.startswith(b'\x89PNG\r\n\x1a\n') else 'jpg' if body.startswith(b'\xff\xd8\xff') else 'webp' if body[:4]==b'RIFF' and body[8:12]==b'WEBP' else None
            if not ext:return None
            name=key.replace(':','-')+'.'+ext
            (folder/name).write_bytes(body)
            return key,{'file':'icons/'+name,'source':url,'fetched_at':now()}
        except Exception:return None
    with ThreadPoolExecutor(max_workers=4) as pool:
        for result in pool.map(download,sources.items()):
            if result:icons[result[0]]=result[1]
    snapshot['icons']=icons


def activity_items(snapshot,get):
    items=[]
    for w,c,state,oid,path in snapshot['operations']:
        status=data(get('read',path+'/status.json'))
        status=status if isinstance(status,dict) else {}
        tx=status.get('tx_hash','')
        public=snapshot.get('public_transactions',{}).get(c,{}).get(tx,{})
        receipt=data(public.get('receipt')) or data(get('read',f'/chains/{c}/tx/{tx}/receipt.json')) or data(get('read',path+'/receipt.json'))
        receipt=receipt if isinstance(receipt,dict) else {}
        transaction=data(public.get('transaction'));transaction=transaction if isinstance(transaction,dict) else {}
        if tx and c in PUBLIC_RPC and str(receipt.get('transactionHash','')).lower()!=tx.lower():receipt={}
        if tx and transaction and str(transaction.get('hash','')).lower()!=tx.lower():transaction={}
        outcome=integer(receipt.get('status'))
        # Native Solana receipts use outcome/confirmation_status rather than EVM status.
        native_confirmed=receipt.get('outcome')=='success' and receipt.get('confirmation_status') in ['confirmed','finalized']
        native_failed=receipt.get('outcome') in ['failed','reverted'] or receipt.get('err') is not None
        kind='success' if outcome==1 or (native_confirmed and not native_failed) else 'reverted' if outcome==0 or native_failed else 'failed' if state=='failed' else 'pending' if state=='pending' else 'unverified'
        labels={'success':'Confirmed','reverted':'Reverted','failed':'Failed locally','pending':'Staged · inspect','unverified':'Confirmation unknown'}
        petal=str(status.get('petal_id','')).removeprefix('petal:')
        petal=petal if petal!='evm-wallet' else ''
        plan=data(get('read',path+'/plan.md'));plan=plan if isinstance(plan,str) else ''
        target=re.search(r'^To:\s+(\S+)',plan,re.M)
        target=transaction.get('to') or (target.group(1) if target else '')
        amount=re.search(r'^Value:\s+(.+?)\s*\(',plan,re.M)
        value=(integer(transaction.get('value')) or 0)/Decimal(10**18) if 'value' in transaction else None
        value_label=(f'{value:.6f}'.rstrip('0').rstrip('.')+' ETH') if value is not None and value>0 else amount.group(1) if amount else ''
        calldata=transaction.get('input','')
        # Decode only standard selectors and qualified known contracts. A Petal
        # identity by itself does not establish that a deposit or swap happened.
        selector=calldata[:10]
        token=TOKEN_ICONS.get((c,str(target).lower()))
        token_label={'usd-coin':'USDC','weth':'WETH'}.get(token,'token')
        action='Approve '+token_label if selector=='0x095ea7b3' and token else 'Transfer '+token_label if selector=='0xa9059cbb' and token else 'Send '+value_label if calldata in ['','0x'] and value and value>0 else (petal.title()+' interaction' if petal else 'Contract interaction')
        if token and len(calldata)>=138 and selector in ['0x095ea7b3','0xa9059cbb']:
            raw=integer('0x'+calldata[74:138])
            if raw is not None:
                qty=Decimal(raw)/Decimal(10**(6 if token=='usd-coin' else 18))
                amount_text='unlimited' if selector=='0x095ea7b3' and raw==2**256-1 else f'{qty:.6g}'
                action=('Approve ' if selector=='0x095ea7b3' else 'Transfer ')+amount_text+' '+token_label
        vaults=data(get('read',f'/petals/morpho/{c}/positions/{w}.json')).get('positions',[])
        vault=next((p for p in vaults if str(p.get('vault','')).lower()==str(target).lower()),None)
        if vault and selector=='0x6e553f65' and len(calldata)>=138:
            raw=integer('0x'+calldata[10:74]);underlying=TOKEN_ICONS.get((c,str(vault.get('asset','')).lower()))
            if raw is not None and underlying=='usd-coin':action='Deposit '+f'{Decimal(raw)/10**6:.6g}'+' USDC · '+str(vault.get('name','Morpho'))
        if not transaction:action=(petal.title()+' operation') if petal else ('Transfer '+value_label if value_label and value_label!='0 ETH' else 'Native SOL operation' if c.startswith('solana') else 'Wallet operation')
        if c.startswith('solana'):
            transfer=re.search(r'Solana native transfer: [1-9A-HJ-NP-Za-km-z]+ → ([1-9A-HJ-NP-Za-km-z]+) \((\d+) lamports\)',plan)
            if transfer:
                target=transfer.group(1)
                action='Send '+f'{Decimal(transfer.group(2))/10**9:.6g}'+' SOL'
        block=data(public.get('block'));block=block if isinstance(block,dict) else {}
        timestamp=integer(block.get('timestamp')) or integer(receipt.get('blockTimestamp'))
        if timestamp is None:
            timestamp=next((integer(log.get('blockTimestamp')) for log in receipt.get('logs',[]) if integer(log.get('blockTimestamp')) is not None),None)
        time_source='Block time' if timestamp is not None else 'Local record time'
        if timestamp is None:
            listing=data(get('list',path.rsplit('/',1)[0]))
            modified=next((e.get('modified_ms') for e in listing if e.get('name')==oid),None) if isinstance(listing,list) else None
            timestamp=(integer(modified) or 0)/1000 or None
        gas=integer(receipt.get('gasUsed'));price=integer(receipt.get('effectiveGasPrice'))
        fee=Decimal(gas)*Decimal(price)/Decimal(10**18) if gas is not None and price is not None else None
        reason={'success':'Execution succeeded on chain.','reverted':'Execution reverted on chain. A reverted transaction can still consume gas.','failed':'Bloom recorded a failure. No chain confirmation or failure reason was returned.','pending':'Review the operation in Bloom before approving.','unverified':'Broadcast was recorded, but no usable chain receipt was returned.'}[kind]
        items.append(dict(wallet=w,chain=c,id=oid,path=path,kind=kind,label=labels[kind],action=action,petal=petal,tx=tx,target=target,amount=value_label,timestamp=timestamp,time_source=time_source,fee=fee,reason=reason,receipt=receipt))
    return sorted(items,key=lambda item: (item['timestamp'] is None,-(item['timestamp'] or 0),item['id']))


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
    def mark(key, label):
        item=snapshot.get('icons',{}).get(key,{})
        file=item.get('file','')
        if re.fullmatch(r'icons/[a-zA-Z0-9_.-]+\.(png|jpg|webp)',file):
            return f'<img class="asset-mark" src="{text(file)}" alt="" width="28" height="28">'
        return f'<span class="asset-mark monogram" aria-hidden="true">{text(label[:2].upper())}</span>'
    def chain_name(c):return CHAIN_MARKETS.get(c,c)
    def quantity_label(quantity):
        parts=quantity.split(' ',1)
        value=number(parts[0])
        if value is None:return text(quantity)
        short=f'{value:.6g}'
        rounded='≈ ' if Decimal(short)!=value else ''
        return f'<span title="{text(quantity)}">{rounded}{text(short)}{(" "+text(parts[1])) if len(parts)>1 else ""}</span>'
    def chain_label(c):return f'<span class="asset-label">{mark("chain:"+c,chain_name(c))}<span>{text(chain_name(c))}</span></span>'
    def holding_label(h):
        identity=h['identity'].lower()
        token=('solana' if h['chain'].startswith('solana') else 'ethereum') if identity.startswith('native:') else TOKEN_ICONS.get((h['chain'],identity))
        key='token:'+token if token else 'chain:Hyperliquid' if h['chain']=='Hyperliquid' else ''
        return f'<span class="asset-label">{mark(key,h["name"])}<span><strong>{text(h["name"])}</strong><small>{quantity_label(h["quantity"])}</small></span></span>'
    def chart(points, label, unit, daily=True):
        points=sorted({int(stamp):number(value) for stamp,value in points if number(value) is not None and number(value)>=0}.items())
        if not points:return '<p class="empty-chart">No historical observations returned. Missing data is not drawn as zero.</p>'
        top=max(value for _,value in points)*Decimal('1.1') or Decimal(1)
        start,end=points[0][0],points[-1][0]
        span=max(end-start,1)
        fmt=lambda v:compact(v) if unit=='USD / day' else f'{v:.4f}'.rstrip('0').rstrip('.')+' gwei'
        dates=lambda ts:datetime.fromtimestamp(ts,timezone.utc).strftime('%d %b' if daily else '%d %b %H:%M')
        coords=[(round((ts-start)/span*600,2),round(160-float(v/top)*150,2)) for ts,v in points]
        path='';last=None
        for (ts,v),(x,y) in zip(points,coords):
            path+=('M' if last is None or ts-last>(86400 if daily else 5400) else 'L')+f'{x},{y} '
            last=ts
        marks=''.join(f'<circle cx="{x}" cy="{y}" r="2.5" />' for x,y in coords)
        interactive=[{'x':x,'y':y,'label':dates(ts)+' UTC · '+fmt(v)} for (ts,v),(x,y) in zip(points,coords)]
        rows=''.join(f'<tr><td>{dates(ts)} UTC</td><td>{fmt(v)}</td></tr>' for ts,v in points)
        last_x,last_y=coords[-1]
        return f'''<div class="history-chart"><div class="chart-scale"><span>{fmt(top)}</span><span>{text(unit)}</span></div><svg class="time-chart" viewBox="0 0 600 170" preserveAspectRatio="none" role="img" aria-label="{text(label)}" data-points="{text(json.dumps(interactive))}"><path class="chart-grid" d="M0 10H600 M0 85H600 M0 160H600"/><path class="chart-line" d="{path}"/><g class="chart-dots">{marks}</g><line class="chart-cursor" x1="{last_x}" x2="{last_x}" y1="0" y2="160"/><circle class="chart-selected" cx="{last_x}" cy="{last_y}" r="5"/></svg><span class="chart-zero">0</span><div class="chart-axis"><span>{dates(start)}</span><span>{dates(end)} UTC</span></div><output class="chart-readout" aria-live="polite">{text(interactive[-1]['label'])}</output>{details('Exact observations · '+str(len(points)), '<div class="table-wrap"><table><thead><tr><th scope="col">Date / time</th><th scope="col">'+text(unit)+'</th></tr></thead><tbody>'+rows+'</tbody></table></div>')}</div>'''
    def history_panel(mode):
        group='fees' if mode=='fees' else 'gas'
        histories=snapshot.get('fee_history' if mode=='fees' else 'gas_history',{})
        panels=[];controls=[]
        for c,record in sorted(histories.items(),key=lambda item:-sum((Decimal(h['value']) for h in priced if h['chain']==item[0]),Decimal(0))):
            controls.append(f'<button type="button" data-select="{text(c)}">{chain_label(c)}</button>')
            if mode=='fees':
                payload=data(record)
                cutoff=datetime.fromisoformat(record.get('fetched_at',snapshot['captured_at'])).replace(hour=0,minute=0,second=0,microsecond=0).timestamp()
                raw=payload.get('totalDataChart',[]) if payload.get('protocolType')=='chain' else []
                points=[(integer(p[0]),p[1]) for p in raw if isinstance(p,list) and len(p)==2 and integer(p[0]) is not None and cutoff-30*86400<=integer(p[0])<cutoff and number(p[1]) is not None and number(p[1])>=0]
                points=sorted(dict(points).items())
                label='Network fees paid per day';unit='USD / day';note='Total fees paid by everyone using this chain. This measures paid network usage, not your transaction price.'
                methodology=payload.get('methodology',{}).get('Fees','Provider methodology unavailable.')
                short=[p for p in points if p[0]>=cutoff-7*86400]
                content='<div class="range-switch" aria-label="History range"><button type="button" data-days="7" aria-pressed="false">7 days</button><button type="button" data-days="30" aria-pressed="true">30 days</button></div>'
                content+=f'<div data-range="30">{chart(points,chain_name(c)+" daily network fees",unit)}</div><div data-range="7">{chart(short,chain_name(c)+" daily network fees, seven days",unit)}</div>'
                end=points[-1][0] if points else None
                latest=compact(points[-1][1]) if points else 'Unavailable'
                when=datetime.fromtimestamp(end,timezone.utc).strftime('%d %b %Y') if end else 'No data'
                extra=details('How these fees are measured',f'<p>{text(methodology)}</p><p><a href="https://defillama.com/chain/{quote(chain_name(c))}">DefiLlama · {text(chain_name(c))}</a> · fetched {text(record.get("fetched_at","unknown"))}. Current UTC day excluded; gaps remain gaps.</p>')
            else:
                points=[]
                for p in record.get('points',[]):
                    b=data(p)
                    if isinstance(b,dict):
                        stamp=integer(b.get('timestamp'));fee=integer(b.get('baseFeePerGas'))
                        if stamp is not None and fee is not None:points.append((stamp,Decimal(fee)/10**9))
                points=sorted(dict(points).items())
                label='Base gas price';note='Gwei is one billionth of an ETH. One block sampled roughly each hour. Base fee only; priority fees and rollup data fees are additional. This is not a total transaction quote.';unit='gwei / gas'
                content=chart(points,chain_name(c)+' sampled base gas price',unit,False)
                latest=(f'{points[-1][1]:.4f}'.rstrip('0').rstrip('.')+' gwei') if points else 'Unavailable'
                when=datetime.fromtimestamp(points[-1][0],timezone.utc).strftime('%d %b · %H:%M UTC') if points else 'No data'
                extra=details('Source & sampling',f'<p>Read-only block headers from <code>{text(record.get("source","unavailable"))}</code>. Each point uses its block timestamp and baseFeePerGas. Unavailable samples are omitted; large gaps are not connected. Different chains are sampled independently.</p><p><a href="https://ethereum.org/developers/docs/gas/">How gas fees work</a></p>')
            panels.append(f'<article class="chart-panel" data-panel="{text(c)}"><div class="chart-heading"><div><p class="eyebrow">{text(label)}</p><h3>{chain_label(c)}</h3></div><div class="chart-latest"><strong>{latest}</strong><small>{text(when)}</small></div></div>{content}<p class="chart-note">{note}</p>{extra}</article>')
        if not panels:return '<p class="empty-chart">Fee history has not been captured yet.</p>'
        return f'<div class="history-explorer" data-switcher="{group}"><div class="chain-switch" role="group" aria-label="Choose network">{"".join(controls)}</div>{"".join(panels)}</div>'
    activities=activity_items(snapshot,get)
    def activity_row(item):
        glyph={'success':'✓','reverted':'×','failed':'!','pending':'◷','unverified':'?'}[item['kind']]
        time=datetime.fromtimestamp(item['timestamp'],timezone.utc).strftime('%d %b · %H:%M UTC') if item['timestamp'] else 'Time unavailable'
        fee=(f'{item["fee"]:.6g}'+' ETH') if item['fee'] is not None else 'Not available'
        expl={'ethereum':'https://etherscan.io/tx/','base':'https://basescan.org/tx/','arbitrum':'https://arbiscan.io/tx/','robinhood':'https://robinhoodchain.blockscout.com/tx/'}.get(item['chain'])
        tx=item['tx'];explorer=f'<a href="{expl}{text(tx)}" target="_blank" rel="noreferrer noopener">View on explorer ↗</a>' if expl and re.fullmatch('0x[0-9a-fA-F]{64}',tx) else ''
        facts=f'<p>{text(item["reason"])}</p><dl class="receipt-facts"><div><dt>Destination</dt><dd><code>{text(item["target"] or "Not returned")}</code></dd></div><div><dt>Transaction</dt><dd><code>{text(tx or "No transaction hash returned")}</code></dd></div><div><dt>Execution fee</dt><dd>{fee}<small>gasUsed × effectiveGasPrice; additional rollup fees may apply.</small></dd></div><div><dt>Time source</dt><dd>{text(item["time_source"])}, UTC</dd></div><div><dt>Bloom operation</dt><dd><code>{text(item["id"])}</code></dd></div></dl>{explorer}'
        reason='' if item['kind']=='success' else f'<p>{text(item["reason"])}</p>'
        return f'''<article class="activity-row status-{item['kind']}" data-outcome="{item['kind']}" data-wallet="{text(item['wallet'])}" data-search="{text((item['action']+' '+item['wallet']+' '+item['chain']+' '+item['tx']).lower())}"><div class="outcome-symbol" aria-hidden="true">{glyph}</div><div class="activity-description"><h3>{text(item['action'])}</h3><div class="activity-meta"><span>{text(item['wallet'])}</span>{chain_label(item['chain'])}<span title="{text(item['time_source'])}">{time}</span></div>{reason}{details('Receipt & operation details',facts)}</div><div class="activity-outcome"><span class="outcome-label">{glyph} {item['label']}</span><small>{'Execution fee' if item['fee'] is not None else 'Fee unverified'}</small><strong>{fee if item['fee'] is not None else '—'}</strong></div></article>'''
    def evidence(path):return details('Source & observation',f'<p><code>{text(path)}</code><br>Read during the capture ending {text(snapshot["captured_at"])}.</p>')
    def table(headers,rows):
        return '<div class="table-wrap"><table><thead><tr>'+''.join(f'<th scope="col">{text(h)}</th>' for h in headers)+'</tr></thead><tbody>'+''.join('<tr>'+''.join(f'<td>{cell}</td>' for cell in row)+'</tr>' for row in rows)+'</tbody></table></div>'
    def holding_rows(items):
        return [[holding_label(h),f'{text(h["wallet"])}<small>{chain_label(h["chain"])}</small>',money(h['value'])+('<small>Reference only</small>' if h['reference'] else ''),details('Details',f'<p>{text(h["note"])}</p><p><code>{text(h["identity"])}</code></p><p><code>{text(h["source"])}</code></p>')] for h in items]

    attention=f'{len(pending)} staged operations' if pending else ('No staged operations awaiting review' if pending_complete else 'Pending operations could not all be checked')
    captured_label = datetime.fromisoformat(snapshot['captured_at']).astimezone(timezone.utc).strftime('%d %b %Y · %H:%M UTC')
    movers_html=''.join(f'<article class="mover-tile"><div class="asset-label">{mark("token:"+t["id"],t["symbol"])}<h3>{text(t["symbol"].upper())}</h3></div><strong>{change(t["price_change_percentage_24h"])}</strong><small>{compact(t.get("total_volume"))} reported volume · 24h</small></article>' for t in movers[:3])
    market_pulse=f'<section class="market-pulse">{head("What is moving around you","Largest signed 24h changes · 20-token volume sample")}<div class="mover-grid">{movers_html or "<p>No usable market observations returned.</p>"}</div><div class="pulse-note"><p>A price move shows direction, not its cause. Volume adds context; neither creates a required trade.</p><a href="markets.html">Explore tokens →</a></div></section>'
    wallet_cards=[]; empty_wallets=[]
    for w in snapshot['wallets']:
        items=[h for h in holdings if h['wallet']==w]
        if not items:
            empty_wallets.append(f'<li><a href="portfolio.html#wallet-{text(w)}">{text(w)}</a> — no nonzero holdings returned by the sources that answered.</li>')
            continue
        values=[Decimal(h['value']) for h in priced if h['wallet']==w]
        value=money(sum(values,Decimal(0))) if values else 'No market valuation'
        owner=data(get('read',f'/wallets/{w}/addresses.json')).get('owner','')
        identity=(owner[:8]+'…'+owner[-6:]) if owner else 'Address unavailable'
        largest=sorted([h for h in items if h['value'] is not None and not h['reference']],key=lambda h:-Decimal(h['value']))[:3]
        assets=''.join(f'<li>{holding_label(h)}<strong>{money(h["value"])}</strong></li>' for h in largest)
        wallet_cards.append(f'<article class="card wallet-card"><div class="wallet-heading"><h3>{text(w)}</h3><code title="{text(owner)}">{text(identity)}</code></div><p class="wallet-value">{value}</p><small>Priced assets · {len(items)} holdings observed</small><ul class="holding-list">{assets}</ul><a class="link" href="portfolio.html#wallet-{text(w)}">All holdings & quantities →</a></article>')
    chains={}
    for h in priced:
        chains[h['chain']]=chains.get(h['chain'],Decimal(0))+Decimal(h['value'])
    allocations=[]
    for c,value in sorted(chains.items(),key=lambda item:-item[1]):
        share=value/total*100 if total and total>0 else Decimal(0)
        width=max(Decimal(0),min(Decimal(100),share))
        allocations.append(f'<li><div>{chain_label(c)}<strong>{money(value)}</strong><small>{share:.1f}%</small></div><div class="allocation-bar" aria-hidden="true"><span style="width:{width:.2f}%"></span></div></li>')
    failed=sum(a['kind'] in ['failed','reverted'] for a in activities)
    confirmed=sum(a['kind']=='success' for a in activities)
    unknown=sum(a['kind']=='unverified' for a in activities)
    actions=f'<div class="attention-strip"><div><p class="eyebrow">Your next step</p><h3>{text(attention)}</h3><p>{"Review the staged details in Bloom before approving." if pending else "No approval was waiting in the checked outboxes at capture time." if pending_complete else "Some outboxes did not answer; check Bloom for pending work."}</p></div><a class="button secondary" href="next-moves.html">Review next steps →</a></div>'
    recent=f'<section>{head("Your activity","Outcomes verified against available receipts")}<div class="outcome-overview"><a href="activity.html#success"><span class="mini-outcome success">✓</span><strong>{confirmed}</strong><span>Confirmed</span></a><a href="activity.html#failed"><span class="mini-outcome failed">!</span><strong>{failed}</strong><span>Failed / reverted</span></a><a href="activity.html#unverified"><span class="mini-outcome unverified">?</span><strong>{unknown}</strong><span>Unverified</span></a></div><div class="activity-ledger">'+''.join(activity_row(a) for a in activities[:3])+'</div><a class="section-link" href="activity.html">All activity & receipts →</a></section>'
    empty=details('Other wallets · '+str(len(empty_wallets)), '<ul>'+''.join(empty_wallets)+'</ul>') if empty_wallets else ''
    bodies['index']=('Your wallets, at a glance.','Your balances, where they live, and what needs a closer look. Captured from your Bloom daemon; this page does not refresh automatically.',f'''<section class="wallet-dashboard" aria-label="Wallet snapshot"><div class="balance-panel"><p class="eyebrow">Your observed priced assets</p><div class="metric">{money(total)}</div><p>Across {len(snapshot['wallets'])} wallets · {len(priced)} priced holdings</p><div class="capture-stamp">Captured {text(captured_label)}<br>Snapshot · not a live balance</div><a class="button" href="portfolio.html">Explore your holdings →</a><small>{len(unpriced)} unpriced holdings. Issuer reference values, test funds, and unchecked sources are excluded from this total.</small></div><div class="allocation-panel"><p class="eyebrow">Where your priced assets live</p><h2>Your network split</h2><ul class="allocation-list">{''.join(allocations) or '<li>No priced balances available.</li>'}</ul><a href="chains.html">Compare network activity →</a></div></section>{market_pulse}<section>{head('Your funded accounts','Largest priced holdings in each wallet')}<div class="grid">{''.join(wallet_cards) or '<p>No nonzero holdings returned by the checked sources.</p>'}</div>{empty}</section><section>{actions}</section>{recent}<section>{head('The cost of using a chain','Historical network fees · explore a network below')}{history_panel('fees')}<a class="section-link" href="fees.html">Compare fees & gas prices →</a></section>''')


    token_rows=[[f'<span class="asset-label">{mark("token:"+t["id"],t["symbol"])}<span><strong>{text(t["name"])}</strong><small>{text(t["symbol"].upper())}</small></span></span>',money(t.get('current_price')),change(t.get('price_change_percentage_24h')),compact(t.get('total_volume'))] for t in eligible]
    bodies['markets']=('What is moving?','Real provider observations. Volume, price movement, and your exposure answer different questions.',f'<section>{head("Most traded in the provider sample",str(len(eligible))+" fresh rows · CoinGecko · 24h reported volume")}{table(["Token","Price","24h change","24h volume"],token_rows) if token_rows else "<p>The market provider did not return usable current data.</p>"}</section><section class="callout"><strong>Price movement is not your personal return.</strong><p>Volume is aggregate trading reported by CoinGecko, not available liquidity. Stablecoins remain in this volume ranking. Quotes older than one hour are excluded.</p></section><section>{details("Source & timestamps", "<p><code>https://api.coingecko.com/api/v3/coins/markets</code></p>"+"".join(f"<p>{text(t['name'])}: {text(t.get('last_updated'))}</p>" for t in eligible))}</section>')
    title,lede,body=bodies['markets']
    bodies['markets']=(title,lede,market_pulse+body)
    chain_rows=[]
    for c in snapshot['chains']:
        dex=data(snapshot['markets'].get(c));vol=dex.get('total24h');pct=dex.get('change_1d')
        health=data(get('read',f'/status/chains/{c}/connected'))
        health='Connected' if str(health).strip().lower()=='true' else 'Connection unverified'
        owned=sum((Decimal(h['value']) for h in priced if h['chain']==c),Decimal(0))
        chain_rows.append((number(vol),[f'{chain_label(c)}<small>{health}</small>',compact(vol),change(pct),money(owned)]))
    chain_rows.sort(key=lambda x:-(x[0] if x[0] is not None else Decimal(-1)))
    bodies['chains']=('Where your assets live.','Trading activity comes from DefiLlama. Connection health comes from Bloom. Neither grants this wallet permission to transact.',f'<section>{head("Your configured networks","Provider-reported 24h spot DEX volume; not a global chain ranking")}{table(["Network","DEX volume","Vs previous period","Priced assets"],[r for _,r in chain_rows])}</section><section class="callout"><strong>Different sources have different clocks.</strong><p>DefiLlama’s total24h and change_1d are provider-reported rolling/daily aggregates, not a synchronized completed UTC-day comparison. Missing coverage is “Unavailable”, not zero. Test-network balances have no dollar valuation.</p></section>')
    wallet_sections=''.join(f'<section id="wallet-{text(w)}">{head(w)}{table(["Asset / quantity","Account / network","Observed value","Evidence"],holding_rows([h for h in holdings if h["wallet"]==w])) if any(h["wallet"]==w for h in holdings) else "<p>No nonzero balances in the sources that answered. Unavailable sources are listed below.</p>"}</section>' for w in snapshot['wallets'])
    bodies['portfolio']=('Your actual holdings.','Native balances, selected ERC-20s, and supported Petal positions read from your daemon. Missing quotes stay unpriced.',f'<section class="hero"><div><span class="label">Observed priced assets</span><div class="metric">{money(total)}</div></div><div class="hero-aside"><h3>Coverage stays visible.</h3><p>Known USDC, USDT, WETH and DAI plus up to 30 discovered tokens per wallet/network. Vault receipt shares count once. Robinhood issuer reference values are separate from market-valued assets.</p></div></section>'+wallet_sections)
    bodies['next-moves']=('What needs you.','Start with approvals awaiting your review. Historical failures are available to investigate, without turning them into automatic retries.',f'<section>{actions}</section><section><div class="activity-ledger">'+''.join(activity_row(a) for a in activities if a['kind']=='pending')+'</div></section><section class="attention-strip"><div><h3>Review unsuccessful operations</h3><p>'+str(failed)+' failed or reverted records in the captured history. Check the receipt before trying again.</p></div><a href="activity.html#failed">Inspect failures →</a></section>')
    status_groups=[('all','All activity','↗'),('success','Confirmed','✓'),('failed','Failed / reverted','!'),('unverified','Unverified','?'),('pending','Staged','◷')]
    controls=''.join(f'<button type="button" class="status-filter filter-{kind}" id="{kind}" data-filter="{kind}" aria-pressed="{str(kind=="all").lower()}"><span>{symbol} {label}</span><strong>{len(activities) if kind=="all" else sum(a["kind"] in ["failed","reverted"] for a in activities) if kind=="failed" else sum(a["kind"]==kind for a in activities)}</strong></button>' for kind,label,symbol in status_groups)
    wallets=''.join(f'<option value="{text(w)}">{text(w)}</option>' for w in snapshot['wallets'])
    ledger='<div class="activity-ledger">'+''.join(activity_row(a) for a in activities)+'</div>'
    bodies['activity']=('Your activity.','See what completed, what failed, and what still needs verification. Newest records first; this is the history captured by Bloom.',f'<section class="activity-browser"><div class="status-filters" role="group" aria-label="Filter activity by outcome">{controls}</div><div class="activity-toolbar"><label>Wallet<select id="activity-wallet"><option value="all">All wallets</option>{wallets}</select></label><label class="search-label">Find an operation<input id="activity-search" type="search" placeholder="Asset, network, wallet or transaction hash"></label><p id="activity-count" role="status">{len(activities)} operations</p></div><div class="activity-legend"><span><b>✓ Confirmed</b> — receipt reports success</span><span><b>! Failed locally</b> — Bloom recorded failure</span><span><b>× Reverted</b> — chain execution failed</span><span><b>? Unverified</b> — no usable receipt</span></div>{ledger}<p class="activity-empty" hidden>No operations match these filters.</p></section>')
    bodies['fees']=('Network fees, over time.','Two useful perspectives: what everyone pays to use a network, and the base gas price for an individual operation.',f'<section>{head("Network fees over time","Daily totals · USD · last 30 completed UTC days")}{history_panel("fees")}</section><section>{head("Gas prices through the day","Block samples · approximately 24 hours")}{history_panel("gas")}</section><section class="attention-strip"><div><h3>Your own execution fees</h3><p>Activity shows gas used × effective gas price for each available receipt, including reverted transactions. Missing receipts stay unverified; additional rollup charges may apply.</p></div><a href="activity.html">Inspect your transactions →</a></section>')
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
    coverage='<section class="coverage" id="coverage">'+details('Read coverage, unavailable sources & valuation limits',f'<p>{len(snapshot["records"])} VFS observations; {len(unavailable)} unavailable. Native balance and quote reads are not atomic across chains. Quotes without a usable timestamp, or older than one hour, are excluded from dollar totals. No SPL inventory, Pump.fun session balances, Hyperliquid spot valuation, or general allowance scan is claimed.</p>'+''.join(f'<p><code>{text(r["source"])}</code> · unavailable</p>' for r in unavailable))+'</section>'
    context_label=datetime.fromisoformat(snapshot.get('context_at',snapshot['captured_at'])).astimezone(timezone.utc).strftime('%d %b · %H:%M UTC')
    pages={}
    for name,(title,lede,body) in bodies.items():
        nav=''.join(f'<a href="{slug}.html"'+(' aria-current="page"' if slug==name else '')+f'>{label}</a>' for slug,label in NAV)
        pages[name+'.html']=f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'"><title>{text(title)} · Bloom</title><link rel="stylesheet" href="bloom.css"><link rel="icon" href="bloom-primary.svg"><script defer src="dashboard.js"></script></head><body class="personal-dashboard"><a class="skip" href="#main">Skip to content</a><div class="demo snapshot-banner"><strong>YOUR WALLET SNAPSHOT</strong><span>Wallet {text(captured_label)} · Public context {text(context_label)}</span><span>Snapshot · no automatic refresh</span></div><div class="shell"><header class="masthead"><a class="brand" href="index.html"><img src="bloom-primary.svg" alt="" width="32" height="32"><strong>/bloom</strong></a><span class="edition">Personal wallet overview<br>{len(snapshot['wallets'])} wallets · captured data</span></header><nav aria-label="Wallet views">{nav}</nav><main id="main"><div class="intro"><div><p class="eyebrow">Your place in the ecosystem</p><h1>{text(title)}</h1></div><p class="lede">{text(lede)}</p></div>{body}{coverage}</main><footer><span>Wallet captured {text(snapshot['captured_at'])}. Public context {text(context_label)}.</span><span>Token & network marks: CoinGecko / DefiLlama · cached locally</span><a href="observations.json">Local source observations</a></footer></div></body></html>'''
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
        snapshot=enrich(collect(str(args.socket)))
        cache_icons(snapshot,output)
        (output/'observations.json').write_text(json.dumps(snapshot,indent=2))
    pages,holdings=render(snapshot)
    for name,content in pages.items():(output/name).write_text(content)
    for name in ['bloom.css','bloom-primary.svg','dashboard.js']:(output/name).write_bytes((ROOT/name).read_bytes())
    (output/'holdings.json').write_text(json.dumps(holdings,indent=2))
    print(f'Rendered {len(pages)} real-data views at {output / "index.html"}',flush=True)


if __name__=='__main__':
    main()
