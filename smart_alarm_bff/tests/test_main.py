from __future__ import annotations

import unittest
from unittest.mock import patch

from smart_alarm_bff import main


class MainEntrypointTest(unittest.TestCase):
    def test_run_passes_factory_without_reimporting_metrics_module(self) -> None:
        settings = type("Settings", (), {"bind_host": "127.0.0.1"})()
        with patch.object(main, "load_settings", return_value=settings), patch.object(main.uvicorn, "run") as run:
            main.run()

        self.assertIs(run.call_args.args[0], main.create_app)
        self.assertTrue(run.call_args.kwargs["factory"])
        self.assertEqual(run.call_args.kwargs["host"], "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
