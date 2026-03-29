import asyncio

from sockudo_python.client import (
    DeltaOptions,
    SockudoClient,
    SockudoOptions,
    SubscriptionOptions,
)


def test_subscribe_tracks_event_filters() -> None:
    client = SockudoClient("app-key", SockudoOptions(cluster="local", force_tls=False))

    channel = client.subscribe(
        "orders",
        SubscriptionOptions(events=["order.created", "order.cancelled"]),
    )

    assert channel.events_filter == ["order.created", "order.cancelled"]


def test_reset_delta_stats_and_clear_channel_state() -> None:
    client = SockudoClient(
        "app-key",
        SockudoOptions(
            cluster="local",
            force_tls=False,
            delta_compression=DeltaOptions(enabled=True),
        ),
    )

    assert client._delta_manager is not None
    client._delta_manager.handle_full_message("orders", '{"data":{"id":1}}', 1, None)
    assert client.get_delta_stats() is not None
    assert client.get_delta_stats().full_messages == 1

    client.reset_delta_stats()

    assert client.get_delta_stats().full_messages == 0

    client._delta_manager.clear_channel_state("orders")
    assert "orders" not in client._delta_manager._channel_states


def test_signin_forwards_to_user_facade() -> None:
    client = SockudoClient("app-key", SockudoOptions(cluster="local", force_tls=False))
    called = False

    async def fake_sign_in() -> None:
        nonlocal called
        called = True

    client.user.sign_in = fake_sign_in  # type: ignore[method-assign]
    asyncio.run(client.signin())

    assert called is True
