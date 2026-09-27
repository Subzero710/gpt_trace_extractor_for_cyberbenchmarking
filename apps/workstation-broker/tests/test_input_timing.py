from __future__ import annotations

from workstation_broker import computer


def test_click_settles_before_following_text(monkeypatch):
    calls = []

    def fake_qmp(_run, _domain, events):
        calls.append(("qmp", events))

    def fake_sleep(seconds):
        calls.append(("sleep", seconds))

    monkeypatch.setattr(computer, "qmp", fake_qmp)
    monkeypatch.setattr(computer.time, "sleep", fake_sleep)

    result = computer.input_events(
        lambda *args, **kwargs: b"",
        "vm",
        {
            "events": [
                {"type": "mouse_move", "x": 50, "y": 40},
                {"type": "click", "button": "left"},
                {"type": "text", "text": "AB"},
            ]
        },
        100,
        80,
    )

    assert result == {"ok": True, "events_processed": 3}

    sleeps = [item for item in calls if item[0] == "sleep"]
    assert sleeps == [
        ("sleep", computer.QMP_POINTER_SETTLE_SECONDS),
        ("sleep", computer.QMP_CLICK_SETTLE_SECONDS),
    ]

    click_release_index = next(
        index
        for index, item in enumerate(calls)
        if item[0] == "qmp"
        and item[1] == [{"type": "btn", "data": {"down": False, "button": "left"}}]
    )
    click_settle_index = calls.index(("sleep", computer.QMP_CLICK_SETTLE_SECONDS))
    first_key_index = next(
        index
        for index, item in enumerate(calls)
        if item[0] == "qmp" and item[1][0]["type"] == "key"
    )
    assert click_release_index < click_settle_index < first_key_index
