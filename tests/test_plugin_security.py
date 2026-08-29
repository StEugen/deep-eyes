"""Security boundaries for dynamic plugin loading and notifications."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from core.plugin_manager import PluginManager
from utils.notification_manager import NotificationManager


def _write_plugin(path: Path, marker_path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "from pathlib import Path",
                "from core.plugin_manager import PluginBase",
                f"Path({str(marker_path)!r}).write_text('imported', encoding='utf-8')",
                "class SafePlugin(PluginBase):",
                "    def scan(self, url, context):",
                "        return []",
            ]
        ),
        encoding="utf-8",
    )


def test_empty_allowlist_imports_nothing(tmp_path):
    marker = tmp_path / "marker"
    _write_plugin(tmp_path / "safe_plugin.py", marker)
    manager = PluginManager(
        None,
        {
            "plugin_manager": {
                "enabled": True,
                "plugin_directory": str(tmp_path),
                "allowed_plugins": [],
            },
            "plugins": {"safe": {"enabled": True}},
        },
    )

    assert manager.load_plugins() == 0
    assert not marker.exists()


def test_allowlisted_and_enabled_plugin_is_imported(tmp_path):
    marker = tmp_path / "marker"
    _write_plugin(tmp_path / "safe_plugin.py", marker)
    manager = PluginManager(
        None,
        {
            "plugin_manager": {
                "enabled": True,
                "plugin_directory": str(tmp_path),
                "allowed_plugins": ["safe_plugin.py"],
            },
            "plugins": {"safe": {"enabled": True}},
        },
    )

    assert manager.load_plugins() == 1
    assert marker.read_text(encoding="utf-8") == "imported"
    assert manager.get_plugin("safe") is not None


def test_path_traversal_allowlist_entry_is_rejected(tmp_path):
    outside = tmp_path.parent / "outside_plugin.py"
    marker = tmp_path / "marker"
    _write_plugin(outside, marker)
    manager = PluginManager(
        None,
        {
            "plugin_manager": {
                "enabled": True,
                "plugin_directory": str(tmp_path),
                "allowed_plugins": ["../outside_plugin.py"],
            }
        },
    )

    assert manager.load_plugins() == 0
    assert not marker.exists()


def test_discord_critical_does_not_mention_here_by_default():
    manager = NotificationManager(
        {
            "notifications": {
                "enabled": True,
                "discord": {
                    "enabled": True,
                    "webhook_url": "https://discord.invalid/api/webhooks/secret",
                },
            }
        }
    )
    response = MagicMock(status_code=204)
    response.raise_for_status.return_value = None
    data = {
        "vulnerability_type": "test",
        "target": "https://authorized.example",
        "severity": "critical",
        "url": "https://authorized.example/path",
        "evidence": "safe",
        "timestamp": "2026-01-01T00:00:00",
    }

    with patch("utils.notification_manager.requests.post", return_value=response) as post:
        assert manager._send_discord_critical(data)

    assert "@here" not in post.call_args.kwargs["json"]["content"]
