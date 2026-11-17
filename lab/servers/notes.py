"""Private notes server: the sensitive data store."""

from __future__ import annotations

import json

from ..tokens import AuthError, has_scope
from .base import Tool, ToolServer

_NO_ARGS = {"type": "object", "properties": {}, "required": []}


class NotesServer(ToolServer):
    name = "notes"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.register(
            Tool(
                name="list_notes",
                description="List the ids of the user's private notes.",
                input_schema=_NO_ARGS,
                required_scope="notes:read",
                data_class="private_meta",
                handler=self._list_notes,
            )
        )
        self.register(
            Tool(
                name="read_note",
                description="Read one of the user's private notes by id.",
                input_schema={
                    "type": "object",
                    "properties": {"note_id": {"type": "string"}},
                    "required": ["note_id"],
                },
                required_scope="notes:read",
                data_class="private_read",
                handler=self._read_note,
            )
        )
        self._trusted_call = False

    def call(self, tool_name: str, args: dict, token: str, via: str | None = None) -> str:
        # Remember whether this call arrived through a blindly trusted upstream,
        # so the handler knows whether to enforce the per-note admin check.
        self._trusted_call = via is not None and self.trust_upstream
        try:
            return super().call(tool_name, args, token, via)
        finally:
            self._trusted_call = False

    def _list_notes(self, args: dict, token: str, claims: dict) -> str:
        return json.dumps(
            [{"note_id": k, "restricted": v["restricted"]} for k, v in self.world.notes.items()]
        )

    def _read_note(self, args: dict, token: str, claims: dict) -> str:
        note_id = str(args["note_id"])
        note = self.world.notes.get(note_id)
        if note is None:
            raise ValueError(f"no note with id '{note_id}'")
        if note["restricted"] and not self._trusted_call and not has_scope(claims, "notes:admin"):
            raise AuthError("restricted note requires scope 'notes:admin'")
        return json.dumps({"note_id": note_id, "text": note["text"]})
