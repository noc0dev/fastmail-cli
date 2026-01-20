#!/usr/bin/env python3
"""
jmapc-cli: Read-only JMAP CLI (JSON in/out)

Commands: session.get, email.query, email.get, mailbox.query, thread.get, pipeline.run
Exit codes: 0 ok, 2 validation, 3 auth, 4 http, 5 jmap method error, 6 runtime.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import requests

from jmapc.api import APIRequest
from jmapc.client import Client, ClientError
from jmapc import errors
from jmapc.methods import InvocationResponseOrError, Response
from jmapc.methods.email import (
    EmailGet,
    EmailQuery,
    EmailChanges,
    EmailQueryChanges,
)
from jmapc.methods.mailbox import MailboxQuery
from jmapc.methods.thread import ThreadGet
from jmapc.methods.search_snippet import SearchSnippetGet
from jmapc.models import Comparator


def utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def env_default(name: str, fallback: Optional[str]) -> Optional[str]:
    return os.environ.get(name) or fallback


def parse_json_arg(val: Optional[str]) -> Optional[Any]:
    if val is None:
        return None
    if val == "@-":
        return json.load(sys.stdin)
    if val.startswith("@"):
        with open(val[1:], "r", encoding="utf-8") as fh:
            return json.load(fh)
    return json.loads(val)


def comparators_from_json(val: Optional[str]) -> Optional[List[Comparator]]:
    if not val:
        return None
    data = parse_json_arg(val)
    if not isinstance(data, list):
        raise ValueError("sort must be a JSON array")
    comps: List[Comparator] = []
    for item in data:
        if not isinstance(item, dict) or "property" not in item:
            raise ValueError("each sort comparator must be an object with 'property'")
        comps.append(
            Comparator(
                property=item["property"],
                is_ascending=bool(item.get("isAscending", True)),
                collation=item.get("collation"),
            )
        )
    return comps


def json_dump(data: Any, style: str) -> None:
    if style == "pretty":
        json.dump(data, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    elif style == "compact":
        json.dump(data, sys.stdout, separators=(",", ":"), ensure_ascii=False)
        sys.stdout.write("\n")
    elif style == "jsonl":
        json.dump(data, sys.stdout, separators=(",", ":"), ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        raise ValueError(f"Unknown json style: {style}")


def http_exit_code(status: int) -> int:
    return 3 if status in (401, 403) else 4


def envelope(
    ok: bool,
    command: str,
    args: Dict[str, Any],
    meta: Dict[str, Any],
    data: Optional[Any] = None,
    error: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "ok": ok,
        "command": command,
        "args": args,
        "meta": meta,
    }
    if ok:
        out["data"] = data
    else:
        out["error"] = error or {}
    return out


def meta_block(host: str, account_id: str, capabilities: Sequence[str], capabilities_server: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "accountId": account_id,
        "capabilitiesUsed": sorted(capabilities),
        **({"capabilitiesServer": sorted(capabilities_server)} if capabilities_server is not None else {}),
    }


def discover_session(host: str, timeout: float, verify: bool, token: Optional[str] = None) -> Dict[str, Any]:
    url = f"https://{host}/.well-known/jmap"
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = requests.get(url, timeout=timeout, verify=verify, headers=headers)
    resp.raise_for_status()
    return resp.json()


def build_client(host: str, token: str, timeout: float, verify: bool) -> Tuple[Client, Dict[str, Any]]:
    session_json = discover_session(host, timeout, verify, token=token)
    client = Client.create_with_api_token(host, token)
    return client, session_json


def resolve_account_id(session_json: Dict[str, Any], requested: Optional[str]) -> str:
    if requested and requested != "primary":
        return requested
    primary = session_json.get("primaryAccounts") or {}
    return primary.get("urn:ietf:params:jmap:mail") or primary.get("urn:ietf:params:jmap:core")


def jmap_request(
    client: Client,
    account_id: str,
    calls: Union[Sequence[Any], Any],
    raise_errors: bool = True,
) -> Tuple[set[str], List[InvocationResponseOrError]]:
    api_request = APIRequest.from_calls(account_id, calls)
    result = list(client._api_request(api_request))
    if raise_errors and any(isinstance(r.response, errors.Error) for r in result):
        raise ClientError("Errors found in method responses", result=result)
    return api_request.using, result


def client_error_details(exc: ClientError) -> List[Dict[str, Any]]:
    details: List[Dict[str, Any]] = []
    for r in exc.result:
        try:
            payload = r.response.to_dict()  # type: ignore[attr-defined]
        except Exception:
            payload = str(r.response)
        details.append({"id": getattr(r, "id", None), "response": payload})
    return details


def handle_session_get(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    try:
        session_json = discover_session(args.host, args.timeout, not args.insecure, token=args.api_token)
        account_id = resolve_account_id(session_json, args.account)
        capabilities_server = session_json.get("capabilities", {}).keys()
        meta = meta_block(args.host, account_id, [], capabilities_server)
        return 0, envelope(True, "session.get", vars(args), meta, data=session_json)
    except ValueError as exc:
        err = {"type": "validationError", "message": str(exc), "details": {}}
        return 2, envelope(False, "session.get", vars(args), meta_block(args.host, "unknown", []), error=err)
    except requests.HTTPError as exc:
        code = http_exit_code(exc.response.status_code)
        err = {"type": "httpError", "message": str(exc), "details": {"status": exc.response.status_code}}
        return code, envelope(False, "session.get", vars(args), meta_block(args.host, "unknown", []), error=err)
    except Exception as exc:
        err = {"type": "runtimeError", "message": str(exc), "details": {}}
        return 6, envelope(False, "session.get", vars(args), meta_block(args.host, "unknown", []), error=err)


def handle_email_query(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    try:
        client, session_json = build_client(args.host, args.api_token, args.timeout, not args.insecure)
        account_id = resolve_account_id(session_json, args.account)
        filt = parse_json_arg(args.filter)
        sort = comparators_from_json(args.sort)
        query = EmailQuery(
            filter=filt,
            limit=args.limit,
            position=args.position,
            collapse_threads=args.collapse_threads,
            calculate_total=args.calculate_total,
            sort=sort,
        )
        using, mrs = jmap_request(client, account_id, query, raise_errors=True)
        resp = mrs[0].response  # EmailQueryResponse
        capabilities_server = session_json.get("capabilities", {}).keys()
        meta = meta_block(args.host, account_id, using, capabilities_server)
        return 0, envelope(True, "email.query", vars(args), meta, data=resp.to_dict())
    except ValueError as exc:
        err = {"type": "validationError", "message": str(exc), "details": {}}
        return 2, envelope(False, "email.query", vars(args), meta_block(args.host, "unknown", []), error=err)
    except ClientError as exc:
        err = {
            "type": "jmapError",
            "message": str(exc),
            "details": {"responses": client_error_details(exc)},
        }
        return 5, envelope(False, "email.query", vars(args), meta_block(args.host, "unknown", []), error=err)
    except requests.HTTPError as exc:
        code = http_exit_code(exc.response.status_code)
        err = {"type": "httpError", "message": str(exc), "details": {"status": exc.response.status_code}}
        return code, envelope(False, "email.query", vars(args), meta_block(args.host, "unknown", []), error=err)
    except Exception as exc:
        err = {"type": "runtimeError", "message": str(exc), "details": {}}
        return 6, envelope(False, "email.query", vars(args), meta_block(args.host, "unknown", []), error=err)


def handle_email_get(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    try:
        client, session_json = build_client(args.host, args.api_token, args.timeout, not args.insecure)
        account_id = resolve_account_id(session_json, args.account)
        ids = parse_json_arg(args.ids)
        props = parse_json_arg(args.properties) if args.properties else None
        call = EmailGet(ids=ids, properties=props)
        using, mrs = jmap_request(client, account_id, call, raise_errors=True)
        resp = mrs[0].response  # EmailGetResponse
        capabilities_server = session_json.get("capabilities", {}).keys()
        meta = meta_block(args.host, account_id, using, capabilities_server)
        return 0, envelope(True, "email.get", vars(args), meta, data=resp.to_dict())
    except ValueError as exc:
        err = {"type": "validationError", "message": str(exc), "details": {}}
        return 2, envelope(False, "email.get", vars(args), meta_block(args.host, "unknown", []), error=err)
    except ClientError as exc:
        err = {
            "type": "jmapError",
            "message": str(exc),
            "details": {"responses": client_error_details(exc)},
        }
        return 5, envelope(False, "email.get", vars(args), meta_block(args.host, "unknown", []), error=err)
    except requests.HTTPError as exc:
        code = http_exit_code(exc.response.status_code)
        err = {"type": "httpError", "message": str(exc), "details": {"status": exc.response.status_code}}
        return code, envelope(False, "email.get", vars(args), meta_block(args.host, "unknown", []), error=err)
    except Exception as exc:
        err = {"type": "runtimeError", "message": str(exc), "details": {}}
        return 6, envelope(False, "email.get", vars(args), meta_block(args.host, "unknown", []), error=err)


def handle_mailbox_query(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    try:
        client, session_json = build_client(args.host, args.api_token, args.timeout, not args.insecure)
        account_id = resolve_account_id(session_json, args.account)
        filt = parse_json_arg(args.filter)
        sort = comparators_from_json(args.sort)
        call = MailboxQuery(filter=filt, limit=args.limit, position=args.position, sort=sort)
        using, mrs = jmap_request(client, account_id, call, raise_errors=True)
        resp = mrs[0].response  # MailboxQueryResponse
        capabilities_server = session_json.get("capabilities", {}).keys()
        meta = meta_block(args.host, account_id, using, capabilities_server)
        return 0, envelope(True, "mailbox.query", vars(args), meta, data=resp.to_dict())
    except ValueError as exc:
        err = {"type": "validationError", "message": str(exc), "details": {}}
        return 2, envelope(False, "mailbox.query", vars(args), meta_block(args.host, "unknown", []), error=err)
    except ClientError as exc:
        err = {
            "type": "jmapError",
            "message": str(exc),
            "details": {"responses": client_error_details(exc)},
        }
        return 5, envelope(False, "mailbox.query", vars(args), meta_block(args.host, "unknown", []), error=err)
    except requests.HTTPError as exc:
        code = http_exit_code(exc.response.status_code)
        err = {"type": "httpError", "message": str(exc), "details": {"status": exc.response.status_code}}
        return code, envelope(False, "mailbox.query", vars(args), meta_block(args.host, "unknown", []), error=err)
    except Exception as exc:
        err = {"type": "runtimeError", "message": str(exc), "details": {}}
        return 6, envelope(False, "mailbox.query", vars(args), meta_block(args.host, "unknown", []), error=err)


def handle_thread_get(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    try:
        client, session_json = build_client(args.host, args.api_token, args.timeout, not args.insecure)
        account_id = resolve_account_id(session_json, args.account)
        ids = parse_json_arg(args.ids)
        call = ThreadGet(ids=ids)
        using, mrs = jmap_request(client, account_id, call, raise_errors=True)
        resp = mrs[0].response  # ThreadGetResponse
        capabilities_server = session_json.get("capabilities", {}).keys()
        meta = meta_block(args.host, account_id, using, capabilities_server)
        return 0, envelope(True, "thread.get", vars(args), meta, data=resp.to_dict())
    except ValueError as exc:
        err = {"type": "validationError", "message": str(exc), "details": {}}
        return 2, envelope(False, "thread.get", vars(args), meta_block(args.host, "unknown", []), error=err)
    except ClientError as exc:
        err = {
            "type": "jmapError",
            "message": str(exc),
            "details": {"responses": client_error_details(exc)},
        }
        return 5, envelope(False, "thread.get", vars(args), meta_block(args.host, "unknown", []), error=err)
    except requests.HTTPError as exc:
        code = http_exit_code(exc.response.status_code)
        err = {"type": "httpError", "message": str(exc), "details": {"status": exc.response.status_code}}
        return code, envelope(False, "thread.get", vars(args), meta_block(args.host, "unknown", []), error=err)
    except Exception as exc:
        err = {"type": "runtimeError", "message": str(exc), "details": {}}
        return 6, envelope(False, "thread.get", vars(args), meta_block(args.host, "unknown", []), error=err)


def handle_pipeline_run(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    try:
        client, session_json = build_client(args.host, args.api_token, args.timeout, not args.insecure)
        account_id = resolve_account_id(session_json, args.account)
        payload = parse_json_arg(args.input)
        if not isinstance(payload, dict) or "calls" not in payload:
            raise ValueError("pipeline input must be an object with 'calls'")
        api_url = client.jmap_session.api_url
        headers = {
            "Authorization": f"Bearer {args.api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        using = payload.get("using") or [
            "urn:ietf:params:jmap:core",
            "urn:ietf:params:jmap:mail",
        ]
        # Allowlist read-only methods unless explicitly bypassed
        if not args.allow_unsafe:
            allowed_suffixes = ("/get", "/query", "/changes", "/queryChanges")
            allowed_exact = {"Core/echo", "SearchSnippet/get"}
            for call in payload["calls"]:
                if not isinstance(call, list) or len(call) != 3:
                    raise ValueError("each call must be [name, args, id]")
                name = call[0]
                if name in allowed_exact:
                    continue
                if not any(name.endswith(suf) for suf in allowed_suffixes):
                    raise ValueError(f"method {name} not allowed in read-only pipeline (use --allow-unsafe to bypass)")
        method_calls = []
        for call in payload["calls"]:
            if not isinstance(call, list) or len(call) != 3:
                raise ValueError("each call must be [name, args, id]")
            name, call_args, call_id = call
            if isinstance(call_args, dict) and "accountId" not in call_args:
                call_args = dict(call_args)
                call_args["accountId"] = account_id
            method_calls.append([name, call_args, call_id])
        req = {"using": using, "methodCalls": method_calls}
        resp = requests.post(api_url, headers=headers, json=req, timeout=args.timeout, verify=not args.insecure)
        resp.raise_for_status()
        data = resp.json()
        method_responses = data.get("methodResponses", [])
        has_error = any(mr and mr[0] == "error" for mr in method_responses)
        capabilities_server = session_json.get("capabilities", {}).keys()
        meta = meta_block(args.host, account_id, using, capabilities_server)
        if has_error:
            err = {
                "type": "jmapError",
                "message": "JMAP method error(s) returned",
                "details": {"methodResponses": method_responses},
            }
            return 5, envelope(False, "pipeline.run", vars(args), meta, error=err)
        return 0, envelope(True, "pipeline.run", vars(args), meta, data=data)
    except ValueError as exc:
        err = {"type": "validationError", "message": str(exc), "details": {}}
        return 2, envelope(False, "pipeline.run", vars(args), meta_block(args.host, "unknown", []), error=err)
    except requests.HTTPError as exc:
        code = http_exit_code(exc.response.status_code)
        err = {"type": "httpError", "message": str(exc), "details": {"status": exc.response.status_code}}
        return code, envelope(False, "pipeline.run", vars(args), meta_block(args.host, "unknown", []), error=err)
    except Exception as exc:
        err = {"type": "runtimeError", "message": str(exc), "details": {}}
        return 6, envelope(False, "pipeline.run", vars(args), meta_block(args.host, "unknown", []), error=err)


def handle_searchsnippet_get(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    try:
        client, session_json = build_client(args.host, args.api_token, args.timeout, not args.insecure)
        account_id = resolve_account_id(session_json, args.account)
        ids = parse_json_arg(args.email_ids)
        filt = parse_json_arg(args.filter)
        call = SearchSnippetGet(ids=ids, filter=filt)
        using, mrs = jmap_request(client, account_id, call, raise_errors=True)
        resp = mrs[0].response
        capabilities_server = session_json.get("capabilities", {}).keys()
        meta = meta_block(args.host, account_id, using, capabilities_server)
        return 0, envelope(True, "searchsnippet.get", vars(args), meta, data=resp.to_dict())
    except ValueError as exc:
        err = {"type": "validationError", "message": str(exc), "details": {}}
        return 2, envelope(False, "searchsnippet.get", vars(args), meta_block(args.host, "unknown", []), error=err)
    except ClientError as exc:
        err = {"type": "jmapError", "message": str(exc), "details": {"responses": client_error_details(exc)}}
        return 5, envelope(False, "searchsnippet.get", vars(args), meta_block(args.host, "unknown", []), error=err)
    except requests.HTTPError as exc:
        code = http_exit_code(exc.response.status_code)
        err = {"type": "httpError", "message": str(exc), "details": {"status": exc.response.status_code}}
        return code, envelope(False, "searchsnippet.get", vars(args), meta_block(args.host, "unknown", []), error=err)
    except Exception as exc:
        err = {"type": "runtimeError", "message": str(exc), "details": {}}
        return 6, envelope(False, "searchsnippet.get", vars(args), meta_block(args.host, "unknown", []), error=err)


def handle_email_changes(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    try:
        client, session_json = build_client(args.host, args.api_token, args.timeout, not args.insecure)
        account_id = resolve_account_id(session_json, args.account)
        call = EmailChanges(since_state=args.since_state, max_changes=args.max_changes)
        using, mrs = jmap_request(client, account_id, call, raise_errors=True)
        resp = mrs[0].response
        capabilities_server = session_json.get("capabilities", {}).keys()
        meta = meta_block(args.host, account_id, using, capabilities_server)
        return 0, envelope(True, "email.changes", vars(args), meta, data=resp.to_dict())
    except ValueError as exc:
        err = {"type": "validationError", "message": str(exc), "details": {}}
        return 2, envelope(False, "email.changes", vars(args), meta_block(args.host, "unknown", []), error=err)
    except ClientError as exc:
        err = {"type": "jmapError", "message": str(exc), "details": {"responses": client_error_details(exc)}}
        return 5, envelope(False, "email.changes", vars(args), meta_block(args.host, "unknown", []), error=err)
    except requests.HTTPError as exc:
        code = http_exit_code(exc.response.status_code)
        err = {"type": "httpError", "message": str(exc), "details": {"status": exc.response.status_code}}
        return code, envelope(False, "email.changes", vars(args), meta_block(args.host, "unknown", []), error=err)
    except Exception as exc:
        err = {"type": "runtimeError", "message": str(exc), "details": {}}
        return 6, envelope(False, "email.changes", vars(args), meta_block(args.host, "unknown", []), error=err)


def handle_email_query_changes(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    try:
        client, session_json = build_client(args.host, args.api_token, args.timeout, not args.insecure)
        account_id = resolve_account_id(session_json, args.account)
        filt = parse_json_arg(args.filter)
        sort = comparators_from_json(args.sort)
        call = EmailQueryChanges(
            filter=filt,
            since_query_state=args.since_query_state,
            sort=sort,
            max_changes=args.max_changes,
            collapse_threads=args.collapse_threads,
            calculate_total=args.calculate_total,
            up_to_id=args.up_to_id,
        )
        using, mrs = jmap_request(client, account_id, call, raise_errors=True)
        resp = mrs[0].response
        capabilities_server = session_json.get("capabilities", {}).keys()
        meta = meta_block(args.host, account_id, using, capabilities_server)
        return 0, envelope(True, "email.query-changes", vars(args), meta, data=resp.to_dict())
    except ValueError as exc:
        err = {"type": "validationError", "message": str(exc), "details": {}}
        return 2, envelope(False, "email.query-changes", vars(args), meta_block(args.host, "unknown", []), error=err)
    except ClientError as exc:
        err = {"type": "jmapError", "message": str(exc), "details": {"responses": client_error_details(exc)}}
        return 5, envelope(False, "email.query-changes", vars(args), meta_block(args.host, "unknown", []), error=err)
    except requests.HTTPError as exc:
        code = http_exit_code(exc.response.status_code)
        err = {"type": "httpError", "message": str(exc), "details": {"status": exc.response.status_code}}
        return code, envelope(False, "email.query-changes", vars(args), meta_block(args.host, "unknown", []), error=err)
    except Exception as exc:
        err = {"type": "runtimeError", "message": str(exc), "details": {}}
        return 6, envelope(False, "email.query-changes", vars(args), meta_block(args.host, "unknown", []), error=err)


def handle_events_listen(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    try:
        client, session_json = build_client(args.host, args.api_token, args.timeout, not args.insecure)
        account_id = resolve_account_id(session_json, args.account)
        from jmapc.client import EventSourceConfig
        esc = EventSourceConfig(
            types=args.types or "*",
            closeafter=args.closeafter,
            ping=args.ping,
        )
        client = Client.create_with_api_token(args.host, args.api_token, last_event_id=args.since, event_source_config=esc)
        meta_base = meta_block(
            args.host,
            account_id,
            ["urn:ietf:params:jmap:core"],
            session_json.get("capabilities", {}).keys(),
        )
        emitted = 0
        for event in client.events:
            payload = envelope(
                True,
                "events.listen",
                vars(args),
                meta_base | {"eventId": getattr(event, "id", None)},
                data=event.to_dict(),
            )
            json_dump(payload, "jsonl")
            emitted += 1
            if args.max_events and emitted >= args.max_events:
                break
        return 0, None  # already streamed
    except ValueError as exc:
        err = {"type": "validationError", "message": str(exc), "details": {}}
        return 2, envelope(False, "events.listen", vars(args), meta_block(args.host, "unknown", []), error=err)
    except requests.HTTPError as exc:
        code = http_exit_code(exc.response.status_code)
        err = {"type": "httpError", "message": str(exc), "details": {"status": exc.response.status_code}}
        return code, envelope(False, "events.listen", vars(args), meta_block(args.host, "unknown", []), error=err)
    except Exception as exc:
        err = {"type": "runtimeError", "message": str(exc), "details": {}}
        return 6, envelope(False, "events.listen", vars(args), meta_block(args.host, "unknown", []), error=err)


def handle_help(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    data = {"commands": [{"name": k, "summary": v["summary"]} for k, v in COMMAND_SPECS().items()]}
    meta = {"timestamp": utc_now_iso(), "host": "n/a", "accountId": "n/a", "capabilitiesUsed": []}
    return 0, envelope(True, "help", vars(args), meta, data=data)


def handle_describe(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    specs = COMMAND_SPECS()
    if args.command_name not in specs:
        err = {"type": "validationError", "message": f"Unknown command {args.command_name}", "details": {}}
        return 2, envelope(False, "describe", vars(args), meta_block(args.host, "unknown", []), error=err)
    data = {"command": args.command_name, **specs[args.command_name]}
    meta = {"timestamp": utc_now_iso(), "host": "n/a", "accountId": "n/a", "capabilitiesUsed": []}
    return 0, envelope(True, "describe", vars(args), meta, data=data)


def COMMAND_SPECS() -> Dict[str, Dict[str, Any]]:
    return {
        "help": {"summary": "List commands", "options": []},
        "describe": {
            "summary": "Describe a command",
            "options": [{"name": "command_name", "type": "string", "required": True}],
        },
        "session.get": {
            "summary": "Return JMAP session object",
            "options": [],
        },
        "email.query": {
            "summary": "Email/query",
            "options": [
                {"name": "filter", "type": "json", "required": False},
                {"name": "sort", "type": "json", "required": False},
                {"name": "limit", "type": "int", "required": False, "default": 10},
                {"name": "position", "type": "int", "required": False, "default": 0},
                {"name": "calculate_total", "type": "flag", "required": False},
                {"name": "collapse_threads", "type": "flag", "required": False},
            ],
        },
        "email.get": {
            "summary": "Email/get",
            "options": [
                {"name": "ids", "type": "json", "required": True},
                {"name": "properties", "type": "json", "required": False},
            ],
        },
        "email.changes": {
            "summary": "Email/changes",
            "options": [
                {"name": "since_state", "type": "string", "required": True},
                {"name": "max_changes", "type": "int", "required": False},
            ],
        },
        "email.query-changes": {
            "summary": "Email/queryChanges",
            "options": [
                {"name": "since_query_state", "type": "string", "required": True},
                {"name": "filter", "type": "json", "required": False},
                {"name": "sort", "type": "json", "required": False},
                {"name": "max_changes", "type": "int", "required": False},
                {"name": "up_to_id", "type": "string", "required": False},
                {"name": "calculate_total", "type": "flag", "required": False},
                {"name": "collapse_threads", "type": "flag", "required": False},
            ],
        },
        "mailbox.query": {
            "summary": "Mailbox/query",
            "options": [
                {"name": "filter", "type": "json", "required": False},
                {"name": "sort", "type": "json", "required": False},
                {"name": "limit", "type": "int", "required": False, "default": 10},
                {"name": "position", "type": "int", "required": False, "default": 0},
            ],
        },
        "thread.get": {
            "summary": "Thread/get",
            "options": [{"name": "ids", "type": "json", "required": True}],
        },
        "searchsnippet.get": {
            "summary": "SearchSnippet/get",
            "options": [
                {"name": "email_ids", "type": "json", "required": True},
                {"name": "filter", "type": "json", "required": False},
                {"name": "properties", "type": "json", "required": False},
            ],
        },
        "events.listen": {
            "summary": "Stream events (read-only)",
            "options": [
                {"name": "since", "type": "string", "required": False},
                {"name": "max_events", "type": "int", "required": False},
            ],
        },
        "pipeline.run": {
            "summary": "Run raw multi-call pipeline",
            "options": [
                {"name": "input", "type": "json", "required": True},
                {"name": "allow_unsafe", "type": "flag", "required": False},
            ],
        },
    }


def add_connection_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--host", default=env_default("JMAP_HOST", "api.fastmail.com"), help="JMAP host")
    p.add_argument("--api-token", default=env_default("JMAP_API_TOKEN", env_default("FASTMAIL_READONLY_API_TOKEN", None)), help="JMAP API token (read-only)")
    p.add_argument("--account", default=env_default("JMAP_ACCOUNT", "primary"), help="Account id or 'primary'")
    p.add_argument("--timeout", type=float, default=float(env_default("JMAP_TIMEOUT", "30")), help="HTTP timeout seconds")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    p.add_argument("--json", choices=["compact", "pretty", "jsonl"], help="JSON output style")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="jmapc-cli", description="Read-only JMAP CLI (JSON in/out)")
    sub = parser.add_subparsers(dest="command", required=True)

    h = sub.add_parser("help", help="List commands")
    h.add_argument("--json", choices=["compact", "pretty"], default="compact", help="JSON output style")

    d = sub.add_parser("describe", help="Describe a command")
    d.add_argument("command_name")
    d.add_argument("--json", choices=["compact", "pretty"], default="compact", help="JSON output style")

    s = sub.add_parser("session.get", help="Return JMAP session object")
    add_connection_opts(s)
    s.set_defaults(json="compact")

    eq = sub.add_parser("email.query", help="Email/query")
    add_connection_opts(eq)
    eq.set_defaults(json="compact")
    eq.add_argument("--filter", help="EmailQueryFilter JSON (inline, @file, @-)")
    eq.add_argument("--sort", help="JSON array of Comparator objects")
    eq.add_argument("--limit", type=int, default=10)
    eq.add_argument("--position", type=int, default=0)
    eq.add_argument("--calculate-total", action="store_true")
    eq.add_argument("--collapse-threads", action="store_true")

    eg = sub.add_parser("email.get", help="Email/get")
    add_connection_opts(eg)
    eg.set_defaults(json="compact")
    eg.add_argument("--ids", required=True, help="JSON array of ids or @file/@-")
    eg.add_argument("--properties", help="JSON array of properties")

    ech = sub.add_parser("email.changes", help="Email/changes")
    add_connection_opts(ech)
    ech.set_defaults(json="compact")
    ech.add_argument("--since-state", required=True, help="sinceState string")
    ech.add_argument("--max-changes", type=int, help="Maximum changes")

    eqc = sub.add_parser("email.query-changes", help="Email/queryChanges")
    add_connection_opts(eqc)
    eqc.set_defaults(json="compact")
    eqc.add_argument("--since-query-state", required=True, help="sinceQueryState string")
    eqc.add_argument("--filter", help="EmailQueryFilter JSON (inline/@file/@-)")
    eqc.add_argument("--sort", help="JSON array of Comparator objects")
    eqc.add_argument("--max-changes", type=int, help="Maximum changes")
    eqc.add_argument("--up-to-id", help="upToId")
    eqc.add_argument("--calculate-total", action="store_true")
    eqc.add_argument("--collapse-threads", action="store_true")

    mq = sub.add_parser("mailbox.query", help="Mailbox/query")
    add_connection_opts(mq)
    mq.set_defaults(json="compact")
    mq.add_argument("--filter", help="MailboxQueryFilter JSON (inline/@file/@-)")
    mq.add_argument("--sort", help="JSON array of Comparator objects")
    mq.add_argument("--limit", type=int, default=10)
    mq.add_argument("--position", type=int, default=0)

    tg = sub.add_parser("thread.get", help="Thread/get")
    add_connection_opts(tg)
    tg.set_defaults(json="compact")
    tg.add_argument("--ids", required=True, help="JSON array of thread ids or @file/@-")

    ss = sub.add_parser("searchsnippet.get", help="SearchSnippet/get")
    add_connection_opts(ss)
    ss.set_defaults(json="compact")
    ss.add_argument("--email-ids", required=True, help="JSON array of email ids")
    ss.add_argument("--filter", help="EmailQueryFilter JSON")
    ss.add_argument("--properties", nargs="+", help="Snippet properties")

    ev = sub.add_parser("events.listen", help="Listen to JMAP event stream")
    add_connection_opts(ev)
    ev.set_defaults(json="jsonl")
    ev.add_argument("--since", help="lastEventId")
    ev.add_argument("--max-events", type=int, help="Max events before exit")
    ev.add_argument("--types", help="Comma-separated event types (default *)")
    ev.add_argument("--closeafter", default="no", help="closeafter param (no|state|push)")
    ev.add_argument("--ping", type=int, default=0, help="ping interval seconds (0=default)")

    pl = sub.add_parser("pipeline.run", help="Run raw multi-call pipeline")
    add_connection_opts(pl)
    pl.add_argument("--input", required=True, help="Pipeline JSON (inline/@file/@-)")
    pl.add_argument("--allow-unsafe", action="store_true", help="Bypass read-only allowlist")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    command_map = {
        "help": handle_help,
        "describe": handle_describe,
        "session.get": handle_session_get,
        "email.query": handle_email_query,
        "email.get": handle_email_get,
        "email.changes": handle_email_changes,
        "email.query-changes": handle_email_query_changes,
        "mailbox.query": handle_mailbox_query,
        "thread.get": handle_thread_get,
        "searchsnippet.get": handle_searchsnippet_get,
        "events.listen": handle_events_listen,
        "pipeline.run": handle_pipeline_run,
    }

    # Enforce json mode compatibility before doing any work
    streaming_commands = {"events.listen"}
    if args.command in streaming_commands and args.json != "jsonl":
        err = envelope(
            False,
            args.command,
            vars(args),
            meta_block(getattr(args, "host", "n/a"), "unknown", []),
            error={"type": "validationError", "message": "--json must be jsonl for streaming commands", "details": {}},
        )
        json_dump(err, "compact")
        return 2
    if args.command not in streaming_commands and args.json == "jsonl":
        err = envelope(
            False,
            args.command,
            vars(args),
            meta_block(getattr(args, "host", "unknown"), "unknown", []),
            error={"type": "validationError", "message": "jsonl is only supported for streaming commands", "details": {}},
        )
        json_dump(err, "compact")
        return 2

    if args.command in {"help", "describe"}:
        # No auth needed for introspection
        args_dict = vars(args)
        code, payload = command_map[args.command](args)
        json_dump(payload, args.json)
        return code

    if not args.api_token:
        err = envelope(
            False,
            args.command,
            vars(args),
            meta_block(args.host, "unknown", []),
            error={"type": "validationError", "message": "Missing API token", "details": {}},
        )
        json_dump(err, args.json)
        return 2

    handler = command_map.get(args.command)
    if handler is None:
        parser.error(f"Unknown command {args.command}")

    code, payload = handler(args)
    if payload is not None:
        if args.json == "jsonl" and args.command != "events.listen":
            err = envelope(
                False,
                args.command,
                vars(args),
                meta_block(args.host, "unknown", []),
                error={"type": "validationError", "message": "jsonl is only supported for events.listen", "details": {}},
            )
            json_dump(err, "compact")
            return 2
        json_dump(payload, args.json)
    return code


if __name__ == "__main__":
    sys.exit(main())
