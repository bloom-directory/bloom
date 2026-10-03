#!/usr/bin/env python3
"""Deterministic read/simulation-only JSON-RPC fixture for MA-05."""

import json
import pathlib
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


if len(sys.argv) != 3:
    raise SystemExit("usage: degraded-json-rpc.py PORT READY_FILE")
port = int(sys.argv[1])
ready_file = pathlib.Path(sys.argv[2])


def result_for(method):
    if method == "eth_chainId":
        return "0x7a69"
    if method in ("eth_blockNumber", "eth_getTransactionCount"):
        return "0x0"
    if method == "eth_getBalance":
        return "0x56bc75e2d63100000"
    if method in ("eth_getCode", "eth_call"):
        return "0x"
    if method == "eth_estimateGas":
        return "0x5208"
    if method == "eth_gasPrice":
        return "0x3b9aca00"
    if method == "eth_maxPriorityFeePerGas":
        return "0xf4240"
    if method == "eth_feeHistory":
        return {
            "oldestBlock": "0x0",
            "baseFeePerGas": ["0x3b9aca00", "0x3b9aca00"],
            "gasUsedRatio": [0.0],
            "reward": [["0xf4240"]],
        }
    if method == "eth_getBlockByNumber":
        return {
            "number": "0x0",
            "hash": "0x" + "11" * 32,
            "parentHash": "0x" + "00" * 32,
            "sha3Uncles": "0x" + "1d" * 32,
            "miner": "0x" + "00" * 20,
            "stateRoot": "0x" + "22" * 32,
            "transactionsRoot": "0x" + "33" * 32,
            "receiptsRoot": "0x" + "44" * 32,
            "logsBloom": "0x" + "00" * 256,
            "difficulty": "0x0",
            "totalDifficulty": "0x0",
            "extraData": "0x",
            "size": "0x0",
            "gasLimit": "0x1c9c380",
            "gasUsed": "0x0",
            "timestamp": "0x1",
            "transactions": [],
            "uncles": [],
            "mixHash": "0x" + "00" * 32,
            "nonce": "0x0000000000000000",
            "baseFeePerGas": "0x3b9aca00",
        }
    if method == "debug_traceCall":
        return {"gas": 21000, "failed": False, "returnValue": "", "structLogs": []}
    if method == "web3_clientVersion":
        return "bloom-ma05-fixture/1"
    if method == "net_version":
        return "31337"
    if method == "eth_sendRawTransaction":
        raise ValueError("broadcast is forbidden in the degraded fixture")
    raise ValueError(f"unsupported deterministic fixture method: {method}")


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        try:
            length = int(self.headers.get("content-length", "0"))
            payload = json.loads(self.rfile.read(length))
            requests = payload if isinstance(payload, list) else [payload]
            responses = []
            for request in requests:
                try:
                    result = result_for(request.get("method"))
                    response = {"jsonrpc": "2.0", "id": request.get("id"), "result": result}
                except ValueError as error:
                    response = {
                        "jsonrpc": "2.0",
                        "id": request.get("id"),
                        "error": {"code": -32000, "message": str(error)},
                    }
                responses.append(response)
            body = json.dumps(responses if isinstance(payload, list) else responses[0]).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as error:  # pragma: no cover - fixture diagnostics
            body = json.dumps({"error": str(error)}).encode()
            self.send_response(500)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, format_, *args):
        return


server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
ready_file.write_text(str(server.server_address[1]))
server.serve_forever()
