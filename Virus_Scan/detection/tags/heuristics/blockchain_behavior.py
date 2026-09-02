"""Blockchain and cryptocurrency abuse tag derivation."""

import re
from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.utils.tagging import ordered_unique_tags


@dataclass(frozen=True, slots=True)
class _BlockchainSignals:
    blockchain_api: bool
    blockchain_rpc: bool
    wallet_hit: bool
    polling_context: bool
    command_context: bool
    dynamic_exec: bool


def blockchain_behavior_text(value: object) -> object:
    text, reason = no_hook_text(
        value,
        missing_reason='blockchain_behavior_text_missing',
        unsupported_reason='blockchain_behavior_text_rejected',
    )
    if reason:
        return ''
    return text.lower()



def _blockchain_has_any(text: str, items: object) -> bool:
    return any(item in text for item in items)




def _append_blockchain_presence_tags(tags: list[object], signals: _BlockchainSignals) -> None:
    if signals.blockchain_api:
        tags.append("blockchain_api_access")
    if signals.blockchain_rpc:
        tags.append("blockchain_p2p_or_rpc")
    if signals.wallet_hit:
        tags.append("crypto_wallet_pattern")


def _append_blockchain_behavior_tags(tags: list[object], signals: _BlockchainSignals) -> None:
    blockchain_source = signals.blockchain_api or signals.blockchain_rpc
    if blockchain_source and signals.polling_context:
        tags.append("blockchain_c2_polling")
    if blockchain_source and signals.command_context:
        tags.append("blockchain_command_parse")
    if signals.dynamic_exec and (blockchain_source or signals.command_context):
        tags.append("dynamic_execution")


def _append_blockchain_base_tags(tags: list[object], signals: _BlockchainSignals) -> None:
    _append_blockchain_presence_tags(tags, signals)
    _append_blockchain_behavior_tags(tags, signals)


def _append_blockchain_tool_tags(text: str, tags: list[object]) -> None:
    if _blockchain_has_any(text, ("stratum+tcp://", "stratum+ssl://", "mining.subscribe", "mining.authorize")):
        tags.extend(("stratum_protocol", "mining_pool_connection"))
    if _blockchain_has_any(text, ("xmrig", "xmr-stak", "cpuminer", "nanominer", "t-rex miner", "teamredminer")):
        tags.append("miner_binary")


def _append_blockchain_clipboard_tags(text: str, wallet_hit: bool, tags: list[object]) -> None:
    clipboard_read = _blockchain_has_any(text, ("getclipboarddata", "openclipboard", "clipboard.gettext", "system.windows.forms.clipboard"))
    clipboard_write = _blockchain_has_any(text, ("setclipboarddata", "emptyclipboard", "clipboard.settext"))
    if wallet_hit and clipboard_read:
        tags.extend(("clipboard_access", "clipboard_crypto"))
    if wallet_hit and clipboard_read and clipboard_write:
        tags.append("crypto_wallet_clipboard_replace")


def _append_blockchain_ransom_tags(text: str, wallet_hit: bool, tags: list[object]) -> None:
    ransom_context = _blockchain_has_any(
        text,
        ("ransom", "decrypt", "payment", "pay ", "send bitcoin", "send monero", "recover your files", "encrypted files"),
    )
    if wallet_hit and ransom_context:
        tags.extend(("ransom_note_indicator", "crypto_address_display"))


def detect_blockchain_abuse_tags(blob: object) -> object:
    """Return behavior-gated blockchain and crypto-abuse tags."""
    tags: list[object] = []
    text = blockchain_behavior_text(blob)
    if not text:
        return tags
    wallet_regexes = (
        "\bbc1[ac-hj-np-z02-9]{20,90}\b",
        "\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        "\b0x[a-f0-9]{40}\b",
        "\b4[0-9ab][1-9a-hj-np-za-km-z]{93}\b",
    )
    wallet_hit = _blockchain_has_any(text, ("wallet address", "bitcoin address", "ethereum address", "monero address")) or any(
        re.search(pattern, text) for pattern in wallet_regexes
    )
    blockchain_api = _blockchain_has_any(text, (
        "etherscan.io", "api.etherscan.io", "blockstream.info", "blockchain.info", "blockchair.com",
        "mempool.space", "publicnode.com", "infura.io", "alchemy.com", "ankr.com",
        "eth_gettransaction", "eth_getlogs", "eth_getblock", "eth_blocknumber", "eth_call",
        "getrawtransaction", "getblockchaininfo", "bitcoin-cli", "monero daemon",
    ))
    blockchain_rpc = _blockchain_has_any(text, (
        "jsonrpc", "eth_sendrawtransaction", "eth_getbalance", "web3", "ethers.js",
        "ethereum-sepolia", "ethereum-mainnet",
    ))
    polling_context = _blockchain_has_any(text, ("poll", "setinterval", "while true", "sleep(", "time.sleep", "heartbeat", "checkin", "check-in"))
    command_context = _blockchain_has_any(text, ("op_return", "input data", "calldata", "decode command", "getcommand", "command", "cmd=", "tasking", "payload", "exec_payload"))
    dynamic_exec = _blockchain_has_any(text, ("eval(", "exec(", "subprocess", "os.system", "popen(", "createprocess", "shellexecute", "iex", "invoke-expression", "assembly.load"))
    signals = _BlockchainSignals(
        blockchain_api=blockchain_api,
        blockchain_rpc=blockchain_rpc,
        wallet_hit=wallet_hit,
        polling_context=polling_context,
        command_context=command_context,
        dynamic_exec=dynamic_exec,
    )
    _append_blockchain_base_tags(tags, signals)
    _append_blockchain_tool_tags(text, tags)
    _append_blockchain_clipboard_tags(text, wallet_hit, tags)
    _append_blockchain_ransom_tags(text, wallet_hit, tags)
    return ordered_unique_tags(tags)


__all__ = ('detect_blockchain_abuse_tags',)
