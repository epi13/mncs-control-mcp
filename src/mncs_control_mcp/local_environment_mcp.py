"""Stable one-tool local Codex bridge to Control's Environment owner socket."""

from __future__ import annotations

import json
import re
import secrets
import socket
import struct
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .config import load_config

MAX_FRAME = 256 * 1024
SESSION_RE = re.compile(r"ses_[A-Za-z0-9_-]{1,120}")
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{32,128}")
OPERATIONS = frozenset({
    "enter", "continuation", "inspect", "context", "health", "capabilities",
    "checkpoint", "handoff", "complete", "claims", "campaign_state",
    "artifact_read", "store_generation",
})
SESSION_OPERATIONS = frozenset({
    "inspect", "context", "health", "capabilities", "checkpoint", "handoff",
    "complete", "claims", "campaign_state", "artifact_read", "store_generation",
})


@dataclass
class _ProjectContext:
    grant: str
    sandbox_cwd: str
    selected_session_id: str | None = None


class _OwnerRPCError(Exception):
    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        super().__init__(str(response.get("error") or "Control Environment request failed"))


def _frame_read(connection: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("Control Environment socket closed before replying")
        chunks.extend(chunk)
    return bytes(chunks)


def _rpc(socket_path: Path, request: dict[str, Any]) -> dict[str, Any]:
    payload = json.dumps(request, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_FRAME:
        raise ValueError("Environment request exceeds the bounded local IPC frame")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(300.0)
        connection.connect(str(socket_path))
        connection.sendall(struct.pack("!I", len(payload)) + payload)
        size = struct.unpack("!I", _frame_read(connection, 4))[0]
        if size < 2 or size > 2 * 1024 * 1024:
            raise ValueError("Environment reply frame size is invalid")
        reply = json.loads(_frame_read(connection, size).decode("utf-8"))
    if not isinstance(reply, dict):
        raise ValueError("Environment reply must be an object")
    return reply


def _string(value: Any, name: str, *, max_length: int = 8192) -> str:
    if not isinstance(value, str) or len(value) > max_length or "\x00" in value:
        raise ValueError(f"{name} must be bounded text")
    return value


def _relative_path(value: Any, name: str) -> str:
    text = _string(value, name, max_length=1024)
    path = PurePosixPath(text)
    if (not text or path.is_absolute() or "\\" in text
            or any(part in {"..", ""} for part in text.split("/") if part != ".")):
        raise ValueError(f"{name} must stay inside the selected project")
    return text


def _string_list(value: Any, name: str, *, maximum: int = 64) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"{name} must be a list of at most {maximum} strings")
    return [_string(item, name, max_length=2048) for item in value]


def _fields(arguments: Any, allowed: set[str]) -> dict[str, Any]:
    if arguments is None:
        return {}
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be an object")
    unknown = sorted(set(arguments) - allowed)
    if unknown:
        raise ValueError(f"unsupported arguments for operation: {', '.join(unknown)}")
    return arguments


def _session_argument(arguments: dict[str, Any], context: _ProjectContext) -> str:
    supplied = arguments.get("session_id")
    if supplied is not None:
        supplied = _string(supplied, "session_id", max_length=128)
        if not SESSION_RE.fullmatch(supplied):
            raise ValueError("session_id is malformed")
        if context.selected_session_id != supplied:
            raise ValueError("session_id is not the session selected by this project context")
    selected = context.selected_session_id
    if selected is None or not SESSION_RE.fullmatch(selected):
        raise ValueError("no Environment session is selected; call enter or continuation first")
    return selected


def _build_argv(
    operation: str, arguments: Any, context: _ProjectContext, project: str,
) -> tuple[list[str], bool]:
    """Map one named operation to its fixed CLI grammar and return session use."""
    values_by_operation: dict[str, set[str]] = {
        "enter": {"definition", "workspace", "campaign_id", "task_identity", "new_session"},
        "continuation": {"campaign_id", "task_identity"},
        "inspect": {"session_id"}, "context": {"session_id"},
        "health": {"session_id", "live"}, "capabilities": {"session_id"},
        "checkpoint": {
            "session_id", "progress", "remaining", "campaign_base_checkpoint",
            "campaign_evidence", "campaign_evidence_delta", "campaign_delivery",
        },
        "handoff": {"session_id", "to", "notes", "blockers", "next"},
        "complete": {"session_id", "outcome", "retry_pending", "summary"},
        "claims": {
            "session_id", "mode", "repository", "claim_id", "offset", "limit",
            "reason", "ttl", "basis", "paths", "worktree", "branch",
            "expected_store_generation",
        },
        "campaign_state": {"session_id", "evidence_offset", "evidence_limit"},
        "artifact_read": {"session_id", "capability", "binding_id", "path"},
        "store_generation": {"session_id"},
    }
    values = _fields(arguments, values_by_operation[operation])
    claims_mode = values.get("mode", "list") if operation == "claims" else None
    if operation == "claims" and (
        not isinstance(claims_mode, str) or claims_mode not in {"list", "acquire", "release"}
    ):
        raise ValueError("claims mode must be list, acquire, or release")
    if operation == "claims" and claims_mode in {"list", "acquire"}:
        repository = values.get("repository", project)
        if repository != project:
            raise ValueError("project-scoped claims must target the selected project")
        values = {**values, "repository": project}
    argv: list[str]
    if operation == "enter":
        argv = ["enter"]
        for field, flag in (("definition", "--definition"), ("workspace", "--workspace")):
            if field in values:
                argv.extend([flag, _relative_path(values[field], field)])
        for field, flag in (("campaign_id", "--campaign-id"),
                            ("task_identity", "--task-identity")):
            if field in values:
                argv.extend([flag, _string(values[field], field, max_length=256)])
        if "new_session" in values:
            if type(values["new_session"]) is not bool:
                raise ValueError("new_session must be a boolean")
            if values["new_session"]:
                argv.append("--new-session")
        return argv, False
    if operation == "continuation":
        argv = ["continuation"]
        for field, flag in (("campaign_id", "--campaign-id"),
                            ("task_identity", "--task-identity")):
            if field in values:
                argv.extend([flag, _string(values[field], field, max_length=256)])
        return argv, False

    session_id = _session_argument(values, context)
    if operation in {"inspect", "context", "capabilities"}:
        return [operation, session_id], True
    if operation == "health":
        argv = ["health", session_id]
        if values.get("live") is True:
            argv.append("--live")
        elif "live" in values and type(values["live"]) is not bool:
            raise ValueError("live must be a boolean")
        return argv, True
    if operation == "checkpoint":
        argv = ["checkpoint", session_id]
        if "progress" in values:
            argv.extend(["--progress", _string(values["progress"], "progress")])
        if "remaining" in values:
            argv.extend(["--remaining", *_string_list(values["remaining"], "remaining")])
        if "campaign_base_checkpoint" in values:
            argv.extend(["--campaign-base-checkpoint", _string(
                values["campaign_base_checkpoint"], "campaign_base_checkpoint", max_length=128,
            )])
        for field, flag in (("campaign_evidence", "--campaign-evidence-json"),
                            ("campaign_evidence_delta", "--campaign-evidence-delta-json"),
                            ("campaign_delivery", "--campaign-delivery-json")):
            if field in values:
                if not isinstance(values[field], (dict, list)):
                    raise ValueError(f"{field} must be a JSON object or list")
                argv.extend([flag, json.dumps(values[field], ensure_ascii=False,
                                             sort_keys=True, separators=(",", ":"))])
        return argv, True
    if operation == "handoff":
        if "to" not in values:
            raise ValueError("handoff requires a 'to' consumer")
        argv = ["handoff", session_id, "--to", _string(values["to"], "to", max_length=128)]
        for field, flag in (("notes", "--notes"), ("blockers", "--blockers"),
                            ("next", "--next")):
            if field in values:
                argv.extend([flag, *_string_list(values[field], field)])
        return argv, True
    if operation == "complete":
        retry = values.get("retry_pending", False)
        outcome = values.get("outcome")
        if type(retry) is not bool:
            raise ValueError("retry_pending must be a boolean")
        if retry == (outcome is not None):
            raise ValueError("complete requires exactly one of outcome or retry_pending=true")
        argv = ["complete", session_id]
        if retry:
            argv.append("--retry-pending")
        else:
            argv.extend(["--outcome", _string(outcome, "outcome", max_length=128)])
        if "summary" in values:
            argv.extend(["--summary", _string(values["summary"], "summary")])
        return argv, True
    if operation == "claims":
        mode = claims_mode
        if mode not in {"list", "acquire", "release"}:
            raise ValueError("claims mode must be list, acquire, or release")
        repository = values.get("repository", project)
        repository = _string(repository, "repository", max_length=128)
        argv = ["claims", session_id]
        if mode == "list":
            if set(values) - {"session_id", "mode", "repository", "offset", "limit"}:
                raise ValueError("claims list accepts only repository, offset, and limit")
            argv.extend(["--repository", repository])
            for field, default, low, high in (("offset", 0, 0, 2**31 - 1),
                                              ("limit", 100, 1, 128)):
                number = values.get(field, default)
                if type(number) is not int or not low <= number <= high:
                    raise ValueError(f"{field} is outside its supported range")
                argv.extend([f"--{field}", str(number)])
        elif mode == "acquire":
            if set(values) - {"session_id", "mode", "repository", "reason",
                              "ttl", "basis", "paths", "worktree", "branch",
                              "expected_store_generation"}:
                raise ValueError("claims acquire received unsupported fields")
            if repository == "":
                raise ValueError("claims acquire requires repository")
            argv.extend(["--acquire", repository])
            if "reason" in values:
                argv.extend(["--reason", _string(values["reason"], "reason", max_length=1024)])
            if "ttl" in values:
                ttl = values["ttl"]
                if type(ttl) is not int or not 1 <= ttl <= 168:
                    raise ValueError("ttl must be an integer from 1 to 168 hours")
                argv.extend(["--ttl", str(ttl)])
            if "basis" in values:
                basis = values["basis"]
                if (not isinstance(basis, str)
                        or basis not in {"explicit-claim", "intent-scope", "recovery", "explicit-adoption"}):
                    raise ValueError("basis is unsupported")
                argv.extend(["--basis", basis])
            if "paths" in values:
                argv.extend(["--paths", *_string_list(values["paths"], "paths")])
            if "worktree" in values:
                argv.extend(["--worktree", _relative_path(values["worktree"], "worktree")])
            if "branch" in values:
                argv.extend(["--branch", _string(values["branch"], "branch", max_length=256)])
            if "expected_store_generation" in values:
                generation = values["expected_store_generation"]
                if type(generation) is not int or generation < 0:
                    raise ValueError("expected_store_generation must be a nonnegative integer")
                argv.extend(["--expected-store-generation", str(generation)])
        else:
            if set(values) - {"session_id", "mode", "claim_id",
                              "expected_store_generation"}:
                raise ValueError("claims release accepts only claim_id and expected generation")
            claim_id = _string(values.get("claim_id"), "claim_id", max_length=128)
            argv.extend(["--release", claim_id, "--claim-id", claim_id])
            if "expected_store_generation" in values:
                generation = values["expected_store_generation"]
                if type(generation) is not int or generation < 0:
                    raise ValueError("expected_store_generation must be a nonnegative integer")
                argv.extend(["--expected-store-generation", str(generation)])
        return argv, True
    if operation == "campaign_state":
        argv = ["campaign-state", session_id]
        for field, flag, default, low, high in (
            ("evidence_offset", "--evidence-offset", 0, 0, 2**31 - 1),
            ("evidence_limit", "--evidence-limit", 128, 1, 128),
        ):
            number = values.get(field, default)
            if type(number) is not int or not low <= number <= high:
                raise ValueError(f"{field} is outside its supported range")
            argv.extend([flag, str(number)])
        return argv, True
    if operation == "artifact_read":
        capability = _string(values.get("capability"), "capability", max_length=256)
        binding = _string(values.get("binding_id"), "binding_id", max_length=128)
        path = _relative_path(values.get("path"), "path")
        if any(part in {".", ".."} for part in path.split("/")):
            raise ValueError("path must be a safe artifact-relative path")
        return ["artifact-read", session_id, capability, binding, path], True
    if operation == "store_generation":
        return ["store", "--session", session_id, "--generation"], True
    raise ValueError(f"unsupported operation: {operation}")


class LocalEnvironmentMCP:
    def __init__(self) -> None:
        self.socket_path = load_config().environment_rpc_socket.expanduser().resolve()
        self._contexts: dict[tuple[str, str], _ProjectContext] = {}

    def _context(self, project: str, cwd: str) -> _ProjectContext:
        key = (project, cwd)
        context = self._contexts.get(key)
        if context is not None:
            return context
        request = {
            "action": "local-project-grant", "project": project,
            "cwd": cwd or None,
        }
        response = _rpc(self.socket_path, request)
        if response.get("ok") is not True or not isinstance(response.get("result"), dict):
            raise _OwnerRPCError(response)
        result = response["result"]
        token = result.get("grant")
        sandbox_cwd = result.get("sandbox_cwd")
        if (not isinstance(token, str) or not TOKEN_RE.fullmatch(token)
                or not isinstance(sandbox_cwd, str)):
            raise ValueError("Control returned an invalid local Environment capability")
        context = _ProjectContext(token, sandbox_cwd)
        self._contexts[key] = context
        return context

    def _response_error(self, response: dict[str, Any]) -> Any:
        error = response.get("error")
        if not isinstance(error, dict):
            return {"ok": False, "error": {"code": "ENVIRONMENT_RPC_FAILED",
                                             "message": "Control returned an invalid Environment response"}}
        return {"ok": False, "error": error}

    @staticmethod
    def _payload(response: dict[str, Any]) -> Any:
        result = response.get("result")
        if not isinstance(result, dict):
            return None
        stdout = result.get("stdout")
        if isinstance(stdout, str):
            try:
                return json.loads(stdout)
            except json.JSONDecodeError:
                return None
        return result

    @staticmethod
    def _selected_session(payload: Any) -> str | None:
        if not isinstance(payload, dict):
            return None
        for key in ("selected_session_id", "session_id"):
            value = payload.get(key)
            if isinstance(value, str) and SESSION_RE.fullmatch(value):
                return value
        if payload.get("status") != "ready":
            return None
        continuations = payload.get("continuations")
        if not isinstance(continuations, list) or len(continuations) != 1:
            return None
        session_ids = continuations[0].get("campaign_session_ids")
        if (isinstance(session_ids, list) and len(session_ids) == 1
                and isinstance(session_ids[0], str)
                and SESSION_RE.fullmatch(session_ids[0])):
            return session_ids[0]
        return None

    def _select_session(
        self, context: _ProjectContext, project: str, values: dict[str, Any],
    ) -> dict[str, Any] | None:
        if context.selected_session_id and SESSION_RE.fullmatch(context.selected_session_id):
            return None
        argv = ["continuation"]
        for field, flag in (("campaign_id", "--campaign-id"),
                            ("task_identity", "--task-identity")):
            if field in values:
                argv.extend([flag, _string(values[field], field, max_length=256)])
        response = _rpc(self.socket_path, {
            "grant": context.grant,
            "request_id": "req_" + secrets.token_hex(16),
            "cwd": context.sandbox_cwd,
            "argv": argv,
        })
        if response.get("ok") is not True:
            return response
        payload = self._payload(response)
        session_id = self._selected_session(payload)
        if session_id is not None:
            context.selected_session_id = session_id
            return None
        return {
            "ok": False,
            "error": {
                "code": "ENVIRONMENT_SESSION_SELECTION_REQUIRED",
                "message": "Environment continuation did not select one session for this project directory",
                "details": payload,
            },
        }

    def invoke(
        self, project: str, operation: str,
        arguments: dict[str, Any] | None = None, cwd: str = "",
    ) -> dict[str, Any]:
        if operation not in OPERATIONS:
            return {"ok": False, "error": {
                "code": "ENVIRONMENT_OPERATION_UNAVAILABLE",
                "message": "unknown stable Environment operation",
                "details": {"operation": operation, "supported": sorted(OPERATIONS)},
            }}
        if not isinstance(project, str) or len(project) > 128:
            return {"ok": False, "error": {"code": "ENVIRONMENT_RPC_INVALID_REQUEST",
                                             "message": "project must be a configured project name"}}
        try:
            if cwd:
                cwd = _relative_path(cwd, "cwd")
            context = self._context(project, cwd)
            if operation in SESSION_OPERATIONS:
                values = _fields(arguments, {
                    "session_id", "live", "progress", "remaining", "campaign_base_checkpoint",
                    "campaign_evidence", "campaign_evidence_delta", "campaign_delivery", "to",
                    "notes", "blockers", "next", "outcome", "retry_pending", "summary",
                    "mode", "repository", "claim_id", "offset", "limit", "reason", "ttl",
                    "basis", "paths", "worktree", "branch", "expected_store_generation",
                    "evidence_offset", "evidence_limit", "capability", "binding_id", "path",
                })
                selected_error = self._select_session(context, project, values)
                if selected_error is not None:
                    return self._response_error(selected_error)
            else:
                values = arguments or {}
            argv, uses_session = _build_argv(operation, values, context, project)
            if uses_session and not context.selected_session_id:
                raise ValueError("no authenticated session selected")
            request = {
                "grant": context.grant,
                "request_id": "req_" + secrets.token_hex(16),
                "cwd": context.sandbox_cwd,
                "argv": argv,
            }
            response = _rpc(self.socket_path, request)
            if response.get("ok") is True:
                payload = self._payload(response)
                if operation in {"enter", "continuation"} and isinstance(payload, dict):
                    candidate = self._selected_session(payload)
                    if candidate is not None:
                        context.selected_session_id = candidate
            else:
                error = response.get("error")
                if isinstance(error, dict) and error.get("code") == "ENVIRONMENT_AUTHORITY_DENIED":
                    # A Control restart or grant expiry is repaired by obtaining
                    # a new owner-issued grant. Rebind the continuation before
                    # any session-scoped operation is attempted again.
                    self._contexts.pop((project, cwd), None)
                    context = self._context(project, cwd)
                    if uses_session:
                        context.selected_session_id = None
                        selected_error = self._select_session(context, project, values)
                        if selected_error is not None:
                            return self._response_error(selected_error)
                    request["grant"] = context.grant
                    request["request_id"] = "req_" + secrets.token_hex(16)
                    argv, uses_session = _build_argv(operation, values, context, project)
                    request["argv"] = argv
                    response = _rpc(self.socket_path, request)
            return response
        except _OwnerRPCError as error:
            return self._response_error(error.response)
        except (ConnectionError, OSError, ValueError, TypeError) as error:
            return {"ok": False, "error": {
                "code": "ENVIRONMENT_LOCAL_BRIDGE_FAILED",
                "message": str(error)[:1200],
            }}


def main() -> None:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as error:  # pragma: no cover - packaging guard
        raise RuntimeError("MNCS Environment MCP requires the 'mcp' package") from error

    bridge = LocalEnvironmentMCP()
    server = FastMCP("MNCS Environment")

    @server.tool(
        name="mncs_environment",
        description=(
            "Enter or continue one configured MNCS project and perform a named, "
            "strictly validated Environment lifecycle operation. Supported operations "
            "include enter, continuation, inspect, context, health, capabilities, "
            "checkpoint, handoff, complete, claims, campaign_state, artifact_read, "
            "and store_generation. The project and optional cwd select one project "
            "directory; no shell or arbitrary CLI arguments are accepted."
        ),
    )
    def mncs_environment(
        project: str, operation: str, arguments: dict[str, Any] | None = None,
        cwd: str = "",
    ) -> dict[str, Any]:
        return bridge.invoke(project, operation, arguments, cwd)

    server.run(transport="stdio")


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    main()
