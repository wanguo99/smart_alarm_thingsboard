from __future__ import annotations

import asyncio
import json
import unittest

from smart_alarm_bff.infrastructure import Infrastructure


class Connection:
    def __init__(self) -> None:
        self.codecs: list[tuple[str, dict[str, object]]] = []

    async def set_type_codec(self, type_name: str, **options: object) -> None:
        self.codecs.append((type_name, options))


class InfrastructureTest(unittest.TestCase):
    def test_database_connections_decode_json_and_jsonb_as_structured_values(self) -> None:
        connection = Connection()

        asyncio.run(Infrastructure._initialize_database_connection(connection))  # type: ignore[arg-type]

        self.assertEqual([item[0] for item in connection.codecs], ["json", "jsonb"])
        for _, options in connection.codecs:
            self.assertEqual(options["schema"], "pg_catalog")
            self.assertEqual(options["format"], "text")
            self.assertEqual(options["decoder"]('["settings:read"]'), ["settings:read"])  # type: ignore[operator]
            self.assertEqual(options["encoder"]({"ready": True}), json.dumps({"ready": True}))  # type: ignore[operator]


if __name__ == "__main__":
    unittest.main()
