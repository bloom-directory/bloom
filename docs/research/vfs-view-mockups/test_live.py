"""Synthetic edge cases for classification and historical-chart integrity."""
import re
from decimal import Decimal
import unittest

from live import activity_items, render

TX='0x'+'a'*64
PATH='/outbox/sent/example'


def snapshot():
    return {'captured_at':'2026-09-05T12:00:00+00:00','wallets':['sample'],
            'evm_chains':['ethereum'],'chains':['ethereum'],'petals':[],
            'scopes':[],'token_scopes':[],'operations':[['sample','ethereum','sent','example',PATH]],
            'markets':{},'records':[{'method':'read','source':PATH+'/status.json','status':'ok','data':{'tx_hash':TX}}]}


def lookup(s):
    records={(r['method'],r['source']):r for r in s['records']}
    return lambda method,path:records.get((method,path),{})


def receipt(s, value):
    s['records'].append({'method':'read','source':f'/chains/ethereum/tx/{TX}/receipt.json','status':'ok','data':value})


class ActivityTests(unittest.TestCase):
    def test_sent_is_not_confirmation_or_zero_cost(self):
        s=snapshot();item=activity_items(s,lookup(s))[0]
        self.assertEqual(item['kind'],'unverified')
        self.assertIsNone(item['fee'])

    def test_revert_still_has_execution_cost(self):
        s=snapshot();receipt(s,{'transactionHash':TX,'status':'0x0','gasUsed':'0x5208','effectiveGasPrice':'0x3b9aca00'})
        item=activity_items(s,lookup(s))[0]
        self.assertEqual(item['kind'],'reverted')
        self.assertEqual(item['fee'],Decimal('0.000021'))

    def test_receipt_must_match_the_transaction(self):
        s=snapshot();receipt(s,{'transactionHash':'0x'+'b'*64,'status':'0x1'})
        self.assertEqual(activity_items(s,lookup(s))[0]['kind'],'unverified')

    def test_local_failure_is_distinct_from_revert(self):
        s=snapshot();s['operations'][0][2]='failed'
        item=activity_items(s,lookup(s))[0]
        self.assertEqual(item['kind'],'failed')
        self.assertIsNone(item['fee'])

    def test_successful_receipt_overrides_old_outbox_state(self):
        s=snapshot();s['operations'][0][2]='failed'
        receipt(s,{'transactionHash':TX,'status':'0x1'})
        self.assertEqual(activity_items(s,lookup(s))[0]['kind'],'success')

    def test_erc20_selector_requires_known_contract(self):
        s=snapshot();transaction={'hash':TX,'input':'0x095ea7b3'+'0'*128,'to':'0x'+'c'*40,'value':'0x0'}
        s['public_transactions']={'ethereum':{TX:{'transaction':{'status':'ok','data':transaction}}}}
        self.assertEqual(activity_items(s,lookup(s))[0]['action'],'Contract interaction')
        transaction['to']='0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'
        transaction['input']='0x095ea7b3'+'0'*64+format(1_000_000,'064x')
        self.assertEqual(activity_items(s,lookup(s))[0]['action'],'Approve 1 USDC')

    def test_native_receipt_requires_confirmed_success(self):
        s=snapshot();s['operations'][0][1]='solana-mainnet'
        r={'outcome':'success','confirmation_status':'processed'}
        s['records'].append({'method':'read','source':PATH+'/receipt.json','status':'ok','data':r})
        self.assertEqual(activity_items(s,lookup(s))[0]['kind'],'unverified')
        r['confirmation_status']='confirmed'
        self.assertEqual(activity_items(s,lookup(s))[0]['kind'],'success')
        r['err']={'InstructionError':[0,'Custom']}
        self.assertEqual(activity_items(s,lookup(s))[0]['kind'],'reverted')

    def test_unknown_time_does_not_sort_as_newest(self):
        s=snapshot();s['operations'].append(['sample','ethereum','sent','second','/outbox/sent/second'])
        s['records'].append({'method':'list','source':'/outbox/sent','status':'ok','data':[{'name':'second','modified_ms':1000}]})
        self.assertEqual(activity_items(s,lookup(s))[0]['id'],'second')


class ChartTests(unittest.TestCase):
    def test_chart_excludes_current_day_and_breaks_missing_days(self):
        s=snapshot()
        s['fee_history']={'ethereum':{'status':'ok','fetched_at':s['captured_at'],'data':{
            'protocolType':'chain','totalDataChart':[[1788220800,10],[1788393600,20],[1788566400,999999]],'methodology':{}}}}
        html=render(s)[0]['fees.html']
        self.assertNotIn('999999',html)
        self.assertIn('Exact observations · 2',html)
        # Two observations separated by a missing day must not be connected.
        path=re.search(r'class="chart-line" d="([^"]+)"',html).group(1)
        self.assertEqual(path.count('M'),2)
        self.assertNotIn('L',path)

    def test_unavailable_history_stays_empty(self):
        html=render(snapshot())[0]['fees.html']
        self.assertIn('Fee history has not been captured yet',html)
        self.assertNotIn('class="chart-line"',html)

    def test_source_text_is_escaped(self):
        s=snapshot();s['wallets']=['<script>alert(1)</script>']
        html=render(s)[0]['portfolio.html']
        self.assertNotIn('<script>alert(1)',html)
        self.assertIn('&lt;script&gt;',html)


if __name__=='__main__':
    unittest.main()
