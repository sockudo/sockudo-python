# sockudo-python

Async Sockudo client SDK for Python.

## Features

- Protocol V2 by default, with V1 compatibility
- Public, private, presence, and encrypted channels
- Tag filter and per-subscription event filter helpers
- Connection recovery serial tracking
- Message deduplication
- JSON, MessagePack, and Protobuf wire formats
- Fossil and Xdelta3/VCDIFF delta compression support
- User sign-in and watchlist event handling

## Install

```bash
pip install -e client-sdks/sockudo-python
```

## Quick Start

```python
import asyncio

from sockudo_python import SockudoClient, SockudoOptions


async def main() -> None:
    client = SockudoClient(
        "app-key",
        SockudoOptions(
            cluster="local",
            force_tls=False,
            ws_host="127.0.0.1",
            ws_port=6001,
        ),
    )

    channel = client.subscribe("public-updates")
    channel.bind("message", lambda payload, meta: print(payload))

    await client.connect()
    await asyncio.sleep(5)
    await client.disconnect()


asyncio.run(main())
```
