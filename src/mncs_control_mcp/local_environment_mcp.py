"""Stable one-tool local Codex bridge to Control's Environment owner socket."""

from __future__ import annotations

import json
import os
import re
import secrets
import socket
import struct
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .config import load_config
from .native_application_contract import canonical_native_application_call

MAX_FRAME = 256 * 1024
# The largest artifact-read result is a 1 MiB file encoded as base64 plus
# bounded provenance metadata. Keep enough response budget for that contract.
MAX_TOOL_RESULT_BYTES = 2 * 1024 * 1024
SESSION_RE = re.compile(r"ses_[A-Za-z0-9_-]{1,120}")
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{32,128}")
OPERATIONS = frozenset({
    "enter", "continuation", "inspect", "context", "health", "capabilities",
    "resume", "verify", "invoke", "checkpoint", "handoff", "complete", "claims",
    "campaign_state", "environmental_capability", "artifact_read",
    "store_generation", "scope_grant",
})
SESSION_OPERATIONS = frozenset({
    "inspect", "context", "health", "capabilities", "resume", "verify", "invoke",
    "checkpoint", "handoff", "complete", "claims", "campaign_state",
    "environmental_capability", "artifact_read", "store_generation", "scope_grant",
})
SESSION_SELECTOR_FIELDS = frozenset({"campaign_id", "task_identity", "session_id"})


@dataclass
class _ProjectContext:
    grant: str
    sandbox_cwd: str
    selected_session_id: str | None = None
    expires_at: float | None = None


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


def _worktree_path(value: Any, name: str, project: str) -> str:
    """Map a claim target through the authorized workspace sandbox.

    Relative targets retain the project-scoped grammar. Absolute targets may
    identify a registered checkout in another selected repository inside the
    same workspace, such as a Language worktree nested under a Compiler
    campaign checkout. The Environment owner still verifies repository
    identity, Git registration, common-directory provenance, and the selected
    session's workspace boundary before publishing the claim.
    """
    text = _string(value, name, max_length=4096)
    requested = Path(text).expanduser()
    if not requested.is_absolute():
        return _relative_path(text, name)
    if ".." in requested.parts:
        raise ValueError(f"{name} must not contain parent traversal")
    try:
        workspace_root = Path(load_config().workspace_root).expanduser().resolve(strict=True)
        project_root = workspace_root / project
        if project_root.is_symlink():
            raise ValueError(f"{name} project root must not be a symbolic link")
        project_root = project_root.resolve(strict=True)
        if project_root.parent != workspace_root:
            raise ValueError(f"{name} project root is outside the configured workspace")
        absolute = Path(os.path.abspath(requested))
        resolved = absolute.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"{name} must name an existing checkout inside the configured workspace") from error
    if absolute != resolved:
        raise ValueError(f"{name} must not traverse a symbolic link")
    try:
        relative = resolved.relative_to(workspace_root)
    except ValueError:
        raise ValueError(f"{name} must stay inside the authorized workspace") from None
    if not resolved.is_dir():
        raise ValueError(f"{name} must name a checkout directory")
    sandbox_path = Path("/workspace") / relative
    return sandbox_path.as_posix()


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
        "continuation": {"campaign_id", "task_identity", "session_id"},
        "inspect": {"session_id"}, "context": {"session_id"},
        "health": {"session_id", "live"}, "capabilities": {"session_id"},
        "resume": {"session_id"},
        "verify": {"session_id", "capability"},
        "invoke": {
            "session_id", "capability", "request_file", "input_artifact", "call",
            "worktree",
        },
        "checkpoint": {
            "session_id", "progress", "remaining", "campaign_base_checkpoint",
            "campaign_evidence", "campaign_evidence_delta", "campaign_delivery",
        },
        "scope_grant": {
            "session_id", "campaign_id", "repository",
            "expected_authority_revision", "approval_reference", "checkout_path",
            "workspace_checkout",
        },
        "handoff": {"session_id", "to", "notes", "blockers", "next"},
        "complete": {"session_id", "outcome", "retry_pending", "summary"},
        "claims": {
            "session_id", "mode", "repository", "claim_id", "offset", "limit",
            "reason", "ttl", "basis", "paths", "worktree", "branch",
            "expected_store_generation",
        },
        "campaign_state": {"session_id", "evidence_offset", "evidence_limit"},
        "environmental_capability": {
            "session_id", "history_pages", "evidence_offset", "evidence_limit",
        },
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
        if (not isinstance(repository, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", repository)):
            raise ValueError("repository must be a valid repository identifier")
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
                            ("task_identity", "--task-identity"),
                            ("session_id", "--session-id")):
            if field in values:
                max_length = 128 if field == "session_id" else 256
                argv.extend([flag, _string(values[field], field, max_length=max_length)])
        return argv, False

    session_id = _session_argument(values, context)
    if operation in {"inspect", "context", "capabilities"}:
        return [operation, session_id], True
    if operation == "resume":
        # Revalidate on every explicit resume so a fresh agent sees current
        # checkout/toolchain readiness through this stable gateway.
        return ["resume", session_id, "--revalidate"], True
    if operation == "verify":
        capability = _string(values.get("capability"), "capability", max_length=256)
        prefixes = (
            f"{project}:verification-executor/",
            f"{project}:test/",
        )
        name = next((capability[len(prefix):] for prefix in prefixes
                     if capability.startswith(prefix)), "")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}", name):
            raise ValueError(
                "verify accepts only a declared verification or test capability for the selected project"
            )
        # Control intentionally authorizes project verification only through
        # this exact fixed-argument CLI form; the Environment descriptor owns
        # the provider command and the selected session owns its authority.
        return ["invoke", session_id, capability], True
    if operation == "invoke":
        capability = _string(values.get("capability"), "capability", max_length=256)
        if capability == "mncs-compiler:native-application-build":
            if set(values) - {"session_id", "capability", "request_file"}:
                raise ValueError("Compiler application build accepts one request_file")
            request_file = _relative_path(values.get("request_file"), "request_file")
            if not request_file.endswith(".json"):
                raise ValueError("request_file must name a JSON build request")
            return [
                "invoke", session_id, capability, "--",
                "--request-file", request_file,
            ], True
        if capability == "mncs-forge:native-application-execution":
            artifact = values.get("input_artifact")
            if (not isinstance(artifact, dict)
                    or set(artifact) != {"name", "capability", "binding_id", "path"}
                    or artifact.get("name") != "native-application-build"
                    or artifact.get("capability") != "mncs-compiler:native-application-build"
                    or not isinstance(artifact.get("binding_id"), str)
                    or not re.fullmatch(r"cap_[0-9a-f]{16}", artifact["binding_id"])
                    or artifact.get("path") != "native-application-build.json"):
                raise ValueError("Forge execution requires the exact Compiler application-build Store artifact")
            try:
                encoded_call = canonical_native_application_call(values.get("call"))
            except ValueError as error:
                raise ValueError(f"Forge execution call is invalid: {error}") from error
            return [
                "invoke", session_id, capability,
                "--input-artifact", artifact["name"], artifact["capability"],
                artifact["binding_id"], artifact["path"],
                "--", "--call-json", encoded_call,
            ], True
        if capability == "mncs-control-mcp:workspace.worktree.prepare":
            if project != "mncs-control-mcp":
                raise ValueError(
                    "workspace.worktree.prepare is available only in the Control project context"
                )
            if set(values) - {"session_id", "capability", "worktree"}:
                raise ValueError(
                    "Control worktree preparation accepts one typed worktree request"
                )
            request = values.get("worktree")
            if (not isinstance(request, dict)
                    or set(request) - {"repository", "name", "branch", "source_ref"}
                    or not {"repository", "name", "branch"}.issubset(request)):
                raise ValueError(
                    "Control worktree preparation requires repository, name, and branch"
                )
            repository = _string(request["repository"], "repository", max_length=128)
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", repository):
                raise ValueError("repository is not a valid repository identifier")
            name = _string(request["name"], "name", max_length=128)
            branch = _string(request["branch"], "branch", max_length=256)
            source_ref = _string(
                request.get("source_ref", "origin/main"), "source_ref", max_length=256,
            )
            if not name or not branch or not source_ref:
                raise ValueError("worktree name, branch, and source_ref must be nonempty")
            workspace_root = Path(load_config().workspace_root).expanduser().resolve(strict=True)
            requests_json = json.dumps(
                [{
                    "repository": repository,
                    "name": name,
                    "branch": branch,
                    "source_ref": source_ref,
                }],
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            if len(requests_json.encode("utf-8")) > 2048:
                raise ValueError("worktree request exceeds the bounded provider input")
            return [
                "invoke", session_id, capability,
                "--effect-repository", repository,
                "--", "prepare", "--workspace-root", str(workspace_root),
                "--requests-json", requests_json,
            ], True
        raise ValueError(
            "invoke supports only native-application-build, native-application-execution, "
            "and the typed Control worktree-prepare contract"
        )
    if operation == "scope_grant":
        campaign_id = _string(values.get("campaign_id"), "campaign_id", max_length=160)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,159}", campaign_id):
            raise ValueError("campaign_id is not a valid campaign identity")
        repository = _string(values.get("repository"), "repository", max_length=128)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", repository):
            raise ValueError("repository is not a valid repository identity")
        revision = _string(
            values.get("expected_authority_revision"),
            "expected_authority_revision", max_length=64,
        )
        if not re.fullmatch(r"[0-9a-f]{64}", revision):
            raise ValueError("expected_authority_revision must be a full lowercase SHA-256 revision")
        approval_reference_value = values.get("approval_reference")
        approval_reference = (
            _string(
                approval_reference_value, "approval_reference", max_length=256,
            )
            if approval_reference_value is not None else None
        )
        if approval_reference is not None and not approval_reference.strip():
            raise ValueError("approval_reference must be nonempty text")
        if "checkout_path" in values and "workspace_checkout" in values:
            raise ValueError("supply only one of checkout_path or workspace_checkout")
        argv = [
            "scope-grant", session_id,
            "--campaign-id", campaign_id,
            "--repository", repository,
            "--expected-authority-revision", revision,
        ]
        if approval_reference is not None:
            argv.extend(["--approval-reference", approval_reference])
        if "checkout_path" in values:
            checkout_path = _string(
                values["checkout_path"], "checkout_path", max_length=1024,
            )
            if (not checkout_path or PurePosixPath(checkout_path).is_absolute()
                    or "\\" in checkout_path
                    or any(part in {"", ".", ".."}
                           for part in checkout_path.split("/"))):
                raise ValueError(
                    "checkout_path must stay inside the configured repository"
                )
            argv.extend(["--checkout", checkout_path])
        if "workspace_checkout" in values:
            workspace_checkout = _string(
                values["workspace_checkout"], "workspace_checkout", max_length=1024,
            )
            if (not workspace_checkout
                    or PurePosixPath(workspace_checkout).is_absolute()
                    or "\\" in workspace_checkout
                    or any(part in {"", ".", ".."}
                           for part in workspace_checkout.split("/"))):
                raise ValueError(
                    "workspace_checkout must stay inside the configured workspace"
                )
            argv.extend(["--workspace-checkout", workspace_checkout])
        return argv, True
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
                ("limit", 25, 1, 128)):
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
                argv.extend(["--worktree", _worktree_path(values["worktree"], "worktree", project)])
            if "branch" in values:
                argv.extend(["--branch", _string(values["branch"], "branch", max_length=256)])
            if "expected_store_generation" in values:
                generation = values["expected_store_generation"]
                if type(generation) is not int or generation < 0:
                    raise ValueError("expected_store_generation must be a nonnegative integer")
                argv.extend(["--expected-store-generation", str(generation)])
        else:
            if "expected_store_generation" in values:
                raise ValueError(
                    "expected_store_generation is supported only when acquiring a claim"
                )
            if set(values) - {"session_id", "mode", "claim_id", "repository"}:
                raise ValueError("claims release accepts only claim_id and repository")
            claim_id = _string(values.get("claim_id"), "claim_id", max_length=128)
            repository = values.get("repository")
            if repository is None:
                match = re.match(
                    r"^claim:([A-Za-z0-9][A-Za-z0-9._-]{0,127})(?::|$)",
                    claim_id,
                )
                repository = match.group(1) if match else project
            if (not isinstance(repository, str)
                    or not re.fullmatch(
                        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", repository
                    )):
                raise ValueError("repository must be a valid repository identifier")
            argv.extend(["--release", repository, "--claim-id", claim_id])
        return argv, True
    if operation == "campaign_state":
        argv = ["campaign-state", session_id]
        for field, flag, default, low, high in (
            ("evidence_offset", "--evidence-offset", 0, 0, 2**31 - 1),
            ("evidence_limit", "--evidence-limit", 20, 1, 128),
        ):
            number = values.get(field, default)
            if type(number) is not int or not low <= number <= high:
                raise ValueError(f"{field} is outside its supported range")
            argv.extend([flag, str(number)])
        return argv, True
    if operation == "environmental_capability":
        argv = [
            "projections", session_id,
            "--interpret", "environmental-capability",
        ]
        for field, flag, default, low, high in (
            ("history_pages", "--history-pages", 1, 1, 4),
            ("evidence_limit", "--evidence-limit", 32, 1, 32),
        ):
            number = values.get(field, default)
            if type(number) is not int or not low <= number <= high:
                raise ValueError(f"{field} is outside its supported range")
            argv.extend([flag, str(number)])
        if "evidence_offset" in values:
            number = values["evidence_offset"]
            if type(number) is not int or not 0 <= number <= 2**31 - 1:
                raise ValueError("evidence_offset is outside its supported range")
            argv.extend(["--evidence-offset", str(number)])
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
            if self._grant_needs_refresh(context):
                return self._refresh_context(project, cwd, context)
            return context
        if not cwd:
            existing = [
                (existing_cwd, existing_context)
                for (existing_project, existing_cwd), existing_context
                in self._contexts.items()
                if existing_project == project
            ]
            if len(existing) == 1:
                # Codex can omit the optional cwd field on a later call. Keep
                # the one project context already selected in this process so
                # that omission does not switch an isolated worktree to root.
                existing_cwd, context = existing[0]
                if self._grant_needs_refresh(context):
                    return self._refresh_context(project, existing_cwd, context)
                return context
            if len(existing) > 1:
                raise ValueError(
                    "cwd is required because this MCP process has multiple contexts for the project"
                )
        return self._issue_context(project, cwd)

    @staticmethod
    def _grant_needs_refresh(context: _ProjectContext) -> bool:
        # Leave a small margin for IPC and scheduling delay around the owner's
        # monotonic expiry. Contexts constructed by tests or older callers with
        # no expiry observation remain usable until the owner rejects them.
        return (context.expires_at is not None
                and time.monotonic() >= context.expires_at - 5.0)

    def _issue_context(
        self, project: str, cwd: str, context: _ProjectContext | None = None,
    ) -> _ProjectContext:
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
        expires_in_seconds = result.get("expires_in_seconds")
        if (not isinstance(token, str) or not TOKEN_RE.fullmatch(token)
                or not isinstance(sandbox_cwd, str)
                or type(expires_in_seconds) is not int
                or expires_in_seconds < 1 or expires_in_seconds > 86400):
            raise ValueError("Control returned an invalid local Environment capability")
        if context is None:
            context = _ProjectContext(token, sandbox_cwd)
        else:
            # Keep the already authenticated session selector in this object;
            # it is only a selector and every subsequent operation remains
            # authorized by the new Control-issued grant.
            context.grant = token
            context.sandbox_cwd = sandbox_cwd
        context.expires_at = time.monotonic() + expires_in_seconds
        self._contexts[(project, cwd)] = context
        return context

    def _refresh_context(
        self, project: str, cwd: str, context: _ProjectContext,
    ) -> _ProjectContext:
        # An omitted cwd may be reusing the sole selected worktree context.
        # Reissue for that original scope rather than silently widening to the
        # repository root.
        if not cwd:
            cached_key = next((key for key, value in self._contexts.items()
                               if key[0] == project and value is context), None)
            if cached_key is not None:
                cwd = cached_key[1]
        return self._issue_context(project, cwd, context)

    def _response_error(self, response: dict[str, Any]) -> Any:
        error = response.get("error")
        if not isinstance(error, dict):
            error = {
                "code": "ENVIRONMENT_RPC_FAILED",
                "message": "Control returned an invalid Environment response",
            }
        code = str(error.get("code", "ENVIRONMENT_RPC_FAILED"))[:128]
        message = str(error.get("message", "Environment operation failed"))[:1200]
        details = error.get("details")
        if code == "ENVIRONMENT_SESSION_SELECTION_REQUIRED" and isinstance(details, dict):
            details = self._compact_continuation(details)
        elif isinstance(details, dict):
            allowed = {
                "next", "status", "operation", "campaign_id", "claim_id",
                "repository", "expected_version", "version", "session_id",
                "selected_session_id", "required_project", "action", "target",
                "reason", "publication_completed", "conflict_kind", "stage",
            }
            compact_details: dict[str, Any] = {}
            for key in allowed:
                value = details.get(key)
                if isinstance(value, str):
                    compact_details[key] = value[:1024]
                elif key in details and (isinstance(value, (bool, int, float)) or value is None):
                    compact_details[key] = value
            if len(compact_details) < len(details):
                compact_details["details_truncated"] = True
            details = compact_details
        bounded_error: dict[str, Any] = {"code": code, "message": message}
        if details:
            bounded_error["details"] = details
        result = {"ok": False, "error": bounded_error}
        encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_TOOL_RESULT_BYTES:
            next_step = details.get("next") if isinstance(details, dict) else None
            bounded_error["message"] = message[:512]
            bounded_error["details"] = {
                "details_truncated": True,
                **({"next": next_step[:512]} if isinstance(next_step, str) else {}),
            }
            result = {"ok": False, "error": bounded_error}
            encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if len(encoded) > MAX_TOOL_RESULT_BYTES:
                bounded_error.pop("details", None)
                bounded_error["message"] = message[:512]
        return result

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
        return None

    @staticmethod
    def _compact_continuation(payload: dict[str, Any]) -> dict[str, Any]:
        rows = payload.get("continuations")
        if not isinstance(rows, list):
            rows = []
        campaigns = payload.get("campaigns")
        if not rows and isinstance(campaigns, list):
            for campaign in campaigns[:32]:
                if not isinstance(campaign, dict):
                    continue
                nested = campaign.get("continuations")
                campaign_id = campaign.get("campaign_id")
                if isinstance(nested, list):
                    for continuation in nested[:32 - len(rows)]:
                        if isinstance(continuation, dict):
                            rows.append({
                                **continuation,
                                "campaign_id": continuation.get("campaign_id", campaign_id),
                            })
                elif isinstance(campaign_id, str):
                    rows.append(campaign)
                if len(rows) >= 32:
                    break
        compact_rows: list[dict[str, Any]] = []
        for row in rows[:32]:
            if not isinstance(row, dict):
                continue
            item = {
                key: row[key]
                for key in (
                    "campaign_id", "campaign_session_ids", "current_campaign_consumer",
                    "authorized_consumers", "lifecycle", "latest_checkpoint",
                    "claim_ids", "work_intent", "evidence_count", "evidence_truncated",
                    "delivery", "repositories", "project_reference",
                )
                if key in row
            }
            if isinstance(item.get("delivery"), dict):
                delivery = item["delivery"]
                item["delivery"] = {
                    key: delivery[key]
                    for key in ("status", "reason", "repositories_count", "repositories_truncated")
                    if key in delivery
                }
            if isinstance(item.get("repositories"), list):
                item["repositories"] = [
                    {
                        key: repository[key]
                        for key in ("repository", "branch", "head", "status")
                        if key in repository
                    }
                    for repository in item["repositories"][:16]
                    if isinstance(repository, dict)
                ]
            compact_rows.append(item)
        selected = LocalEnvironmentMCP._selected_session(payload)
        compact = {
            key: payload[key]
            for key in ("schema_version", "status", "repository", "campaigns_count",
                        "continuations_count", "continuations_truncated", "next")
            if key in payload
        }
        campaign_statuses = payload.get("campaign_statuses")
        if isinstance(campaign_statuses, list):
            compact["campaign_statuses"] = [
                {
                    key: status[key]
                    for key in ("campaign_id", "status", "continuations_truncated")
                    if key in status
                }
                for status in campaign_statuses[:32]
                if isinstance(status, dict)
            ]
        elif isinstance(campaigns, list):
            compact["campaign_statuses"] = [
                {"campaign_id": campaign["campaign_id"]}
                for campaign in campaigns[:32]
                if isinstance(campaign, dict)
                and isinstance(campaign.get("campaign_id"), str)
            ]
        if selected is not None:
            compact["selected_session_id"] = selected
        compact["continuations"] = compact_rows
        return compact

    @staticmethod
    def _compact_context(payload: dict[str, Any]) -> dict[str, Any]:
        keys = (
            "schema_version", "session_id", "lifecycle", "environment_id",
            "work_intent", "workspace_root", "persistence", "toolchain",
            "writable_repositories", "protected_repositories",
        )
        compact = {key: payload[key] for key in keys if key in payload}
        # Environment already supplies a bounded, authoritative Rights
        # projection. Preserve that provider-owned summary at the admission
        # boundary instead of forcing each consumer to reconstruct it.
        rights_context = payload.get("rights_context")
        if isinstance(rights_context, dict):
            compact["rights_context"] = rights_context
        authority = payload.get("authority")
        if isinstance(authority, dict):
            compact["authority"] = {
                key: authority[key]
                for key in (
                    "readable", "writable", "protected_repositories",
                    "escalation_required", "revision",
                )
                if key in authority
            }
        readiness = payload.get("readiness")
        if isinstance(readiness, dict):
            compact["readiness"] = {
                key: readiness[key]
                for key in ("status", "blocking", "required_unavailable", "required_unknown",
                            "unavailable_count", "unknown_count")
                if key in readiness
            }
        doctor = payload.get("doctor")
        if isinstance(doctor, dict):
            compact["doctor"] = {
                key: doctor[key] for key in ("readiness", "summary", "remaining") if key in doctor
            }
        projects = payload.get("projects")
        if isinstance(projects, list):
            compact["projects"] = [
                {key: item[key] for key in ("repository", "path", "branch", "dirty") if key in item}
                for item in projects[:16] if isinstance(item, dict)
            ]
        revalidation = payload.get("revalidation")
        if isinstance(revalidation, dict):
            composition = revalidation.get("scope_composition")
            if isinstance(composition, dict):
                scope_summary: dict[str, Any] = {}
                status = composition.get("status")
                if isinstance(status, str):
                    scope_summary["status"] = status[:64]
                for field in ("composed", "retained", "removed"):
                    items = composition.get(field)
                    if isinstance(items, list):
                        scope_summary[field] = [
                            item[:128] for item in items[:16]
                            if isinstance(item, str)
                        ]
                for field in ("skipped", "base_intent_skipped"):
                    items = composition.get(field)
                    if isinstance(items, list):
                        scope_summary[field] = [
                            {
                                key: item[key][:160]
                                for key in ("repository", "reason")
                                if isinstance(item.get(key), str)
                            }
                            for item in items[:16]
                            if isinstance(item, dict)
                        ]
                compact["revalidation"] = {
                    "scope_composition": scope_summary,
                }
        capabilities = payload.get("capabilities")
        if isinstance(capabilities, dict):
            available = capabilities.get("available")
            if isinstance(available, list):
                compact["capabilities"] = {
                    "available": [
                        item.get("capability") for item in available[:64]
                        if isinstance(item, dict) and isinstance(item.get("capability"), str)
                    ],
                    "count": len(available),
                }
        return compact

    @staticmethod
    def _present(operation: str, response: dict[str, Any]) -> dict[str, Any]:
        if response.get("ok") is not True:
            error = response.get("error")
            return {"ok": False, "operation": operation,
                    "error": error if isinstance(error, dict) else {
                        "code": "ENVIRONMENT_RPC_FAILED",
                        "message": "Control Environment operation failed",
                    }}
        result = response.get("result")
        if not isinstance(result, dict):
            return {"ok": True, "operation": operation, "result": result}
        payload = LocalEnvironmentMCP._payload(response)
        if isinstance(payload, dict):
            if operation == "continuation":
                payload = LocalEnvironmentMCP._compact_continuation(payload)
            elif operation in {"enter", "context", "inspect", "resume"}:
                payload = LocalEnvironmentMCP._compact_context(payload)
            encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                 separators=(",", ":")).encode("utf-8")
            if len(encoded) > MAX_TOOL_RESULT_BYTES:
                payload = {
                    "status": "truncated",
                    "response_bytes": len(encoded),
                    "next": "request a smaller evidence or claim page",
                }
            return {
                "ok": True,
                "operation": operation,
                "exit_code": result.get("exit_code"),
                "result": payload,
                "stderr": str(result.get("stderr", ""))[:2048],
            }
        stdout = result.get("stdout")
        return {
            "ok": True,
            "operation": operation,
            "exit_code": result.get("exit_code"),
            "result": str(stdout)[:MAX_TOOL_RESULT_BYTES] if stdout is not None else result,
            "stderr": str(result.get("stderr", ""))[:2048],
        }

    def _select_session(
        self, context: _ProjectContext, project: str, values: dict[str, Any],
        cwd: str = "",
    ) -> dict[str, Any] | None:
        campaign_id = values.get("campaign_id")
        task_identity = values.get("task_identity")
        requested_session_id = values.get("session_id")
        if (context.selected_session_id
                and SESSION_RE.fullmatch(context.selected_session_id)
                and campaign_id is None and task_identity is None
                and requested_session_id in (None, context.selected_session_id)):
            return None
        # A fresh MCP process may not retain its in-memory session cache.
        # Rebind through Control's authenticated project continuation whenever
        # the caller supplies an exact session, campaign, or task selector.
        context.selected_session_id = None
        argv = ["continuation"]
        for field, flag in (("campaign_id", "--campaign-id"),
                            ("task_identity", "--task-identity"),
                            ("session_id", "--session-id")):
            if field in values:
                max_length = 128 if field == "session_id" else 256
                argv.extend([flag, _string(values[field], field, max_length=max_length)])
        request = {
            "grant": context.grant,
            "request_id": "req_" + secrets.token_hex(16),
            "cwd": context.sandbox_cwd,
            "argv": argv,
        }
        response = _rpc(self.socket_path, request)
        error = response.get("error")
        if (response.get("ok") is not True and isinstance(error, dict)
                and error.get("code") == "ENVIRONMENT_AUTHORITY_DENIED"):
            # Campaign/session selection is the first RPC on a fresh context.
            # Recover the grant here as well as after ordinary session calls,
            # then repeat the read-only continuation with the same selector.
            self._refresh_context(project, cwd, context)
            request["grant"] = context.grant
            request["request_id"] = "req_" + secrets.token_hex(16)
            request["cwd"] = context.sandbox_cwd
            response = _rpc(self.socket_path, request)
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
                                             "message": "project must be an immediate workspace Git checkout name"}}
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
                    "expected_authority_revision", "approval_reference",
                    "checkout_path", "workspace_checkout",
                    "evidence_offset", "evidence_limit", "capability", "binding_id", "path",
                    "request_file", "input_artifact", "call", "worktree",
                    *SESSION_SELECTOR_FIELDS,
                })
                selector_values = values
                if (operation == "scope_grant"
                        and context.selected_session_id is not None
                        and "session_id" not in values
                        and "task_identity" not in values):
                    # scope_grant's campaign_id is an authorization operand
                    # checked by Environment against the already selected
                    # session. Treating it as a fresh continuation selector
                    # discards a valid entry selection and can make a scoped
                    # checkout binding fail as not-found after entry succeeds.
                    selector_values = {
                        key: value for key, value in values.items()
                        if key != "campaign_id"
                    }
                selected_error = self._select_session(
                    context, project, selector_values, cwd,
                )
                if selected_error is not None:
                    return self._response_error(selected_error)
                operation_values = {
                    key: value for key, value in values.items()
                    if key not in SESSION_SELECTOR_FIELDS
                }
                if operation == "scope_grant" and "campaign_id" in values:
                    operation_values["campaign_id"] = values["campaign_id"]
            else:
                values = arguments or {}
                operation_values = values
            argv, uses_session = _build_argv(
                operation, operation_values, context, project,
            )
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
                    self._refresh_context(project, cwd, context)
                    if uses_session:
                        context.selected_session_id = None
                        selected_error = self._select_session(
                            context, project, values, cwd,
                        )
                        if selected_error is not None:
                            return self._response_error(selected_error)
                    request["grant"] = context.grant
                    request["request_id"] = "req_" + secrets.token_hex(16)
                    argv, uses_session = _build_argv(
                        operation, operation_values, context, project,
                    )
                    request["argv"] = argv
                    response = _rpc(self.socket_path, request)
            return self._present(operation, response)
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
            "resume, verify, checkpoint, handoff, complete, claims, campaign_state, "
            "environmental_capability, artifact_read, store_generation, and owner-approved "
            "or campaign-writable scope_grant. environmental_capability is a bounded, read-only interpretation "
            "of authenticated campaign evidence. "
            "Resume revalidates the selected "
            "session. Verify runs one already-bound project verification capability "
            "with its descriptor's fixed arguments and selected project authority. "
            "The project and optional project-relative cwd "
            "select one project directory. Continuation accepts an exact session_id, "
            "campaign_id, or task_identity. Session operations may include these selectors "
            "to reselect an authenticated context after an MCP process restart; Control "
            "checks principal, project, checkout, and claim ownership before binding. Invoke is "
                "limited to the typed Compiler application-build, Forge application-execution, "
                "and Control worktree-prepare contracts. Worktree preparation is routed only "
                "from the Control project context and records its repository as the Environment "
                "effect target; Environment checks the selected session's repository authority "
                "and Control verifies the requested ref and clean registered checkout. "
            "Scope_grant may use an exact configured owner grant to add repository scope, "
            "or bind a Control-verified checkout in a repository already writable in the "
            "campaign. A bridge that requires approval_reference may send the exact "
            "campaign-writable-checkout:<campaign_id>:<repository>:<session_id> binding; "
            "this selects a checkout without adding repository authority. Environment "
            "revalidates the selected checkout, write scope, and claims. "
            "No shell or arbitrary CLI arguments are accepted."
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
