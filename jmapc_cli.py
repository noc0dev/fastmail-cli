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
from jmapc.methods.email import EmailGet, EmailQuery
from jmapc.methods.mailbox import MailboxQuery
from jmapc.methods.thread import ThreadGet
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


def meta_block(host: str, account_id: str, capabilities: Sequence[str]) -> Dict[str, Any]:
    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "accountId": account_id,
        "capabilitiesUsed": sorted(capabilities),
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
) -> Tuple[set[str], Union[InvocationResponseOrError, Sequence[InvocationResponseOrError], Response, Sequence[Response]]]:
    api_request = APIRequest.from_calls(account_id, calls)
    result = client._api_request(api_request)
    if raise_errors:
        if any(isinstance(r.response, errors.Error) for r in result):
            raise ClientError("Errors found in method responses", result=result)
        responses: List[Response] = [r.response for r in result]  # type: ignore[attr-defined]
        return api_request.using, responses if len(responses) > 1 else responses[0]
    return api_request.using, result


def handle_session_get(args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    try:
        session_json = discover_session(args.host, args.timeout, not args.insecure, token=args.api_token)
        account_id = resolve_account_id(session_json, args.account)
        meta = meta_block(args.host, account_id, [])
        meta["capabilitiesServer"] = sorted(session_json.get("capabilities", {}).keys())
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
        using, resp = jmap_request(client, account_id, query, raise_errors=True)
        meta = meta_block(args.host, account_id, using)
        return 0, envelope(True, "email.query", vars(args), meta, data=resp.to_dict())
    except ValueError as exc:
        err = {"type": "validationError", "message": str(exc), "details": {}}
        return 2, envelope(False, "email.query", vars(args), meta_block(args.host, "unknown", []), error=err)
    except ClientError as exc:
        err = {
            "type": "jmapError",
            "message": str(exc),
            "details": {"responses": [r.response.to_dict() for r in exc.result]},  # type: ignore[attr-defined]
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
        using, resp = jmap_request(client, account_id, call, raise_errors=True)
        meta = meta_block(args.host, account_id, using)
        return 0, envelope(True, "email.get", vars(args), meta, data=resp.to_dict())
    except ValueError as exc:
        err = {"type": "validationError", "message": str(exc), "details": {}}
        return 2, envelope(False, "email.get", vars(args), meta_block(args.host, "unknown", []), error=err)
    except ClientError as exc:
        err = {
            "type": "jmapError",
            "message": str(exc),
            "details": {"responses": [r.response.to_dict() for r in exc.result]},  # type: ignore[attr-defined]
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
        using, resp = jmap_request(client, account_id, call, raise_errors=True)
        meta = meta_block(args.host, account_id, using)
        return 0, envelope(True, "mailbox.query", vars(args), meta, data=resp.to_dict())
    except ValueError as exc:
        err = {"type": "validationError", "message": str(exc), "details": {}}
        return 2, envelope(False, "mailbox.query", vars(args), meta_block(args.host, "unknown", []), error=err)
    except ClientError as exc:
        err = {
            "type": "jmapError",
            "message": str(exc),
            "details": {"responses": [r.response.to_dict() for r in exc.result]},  # type: ignore[attr-defined]
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
        using, resp = jmap_request(client, account_id, call, raise_errors=True)
        meta = meta_block(args.host, account_id, using)
        return 0, envelope(True, "thread.get", vars(args), meta, data=resp.to_dict())
    except ValueError as exc:
        err = {"type": "validationError", "message": str(exc), "details": {}}
        return 2, envelope(False, "thread.get", vars(args), meta_block(args.host, "unknown", []), error=err)
    except ClientError as exc:
        err = {
            "type": "jmapError",
            "message": str(exc),
            "details": {"responses": [r.response.to_dict() for r in exc.result]},  # type: ignore[attr-defined]
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
        meta = meta_block(args.host, account_id, using)
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


def add_connection_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--host", default=env_default("JMAP_HOST", "api.fastmail.com"), help="JMAP host")
    p.add_argument("--api-token", default=env_default("JMAP_API_TOKEN", env_default("FASTMAIL_READONLY_API_TOKEN", None)), help="JMAP API token (read-only)")
    p.add_argument("--account", default=env_default("JMAP_ACCOUNT", "primary"), help="Account id or 'primary'")
    p.add_argument("--timeout", type=float, default=float(env_default("JMAP_TIMEOUT", "30")), help="HTTP timeout seconds")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    p.add_argument("--json", choices=["compact", "pretty"], default="compact", help="JSON output style")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="jmapc-cli", description="Read-only JMAP CLI (JSON in/out)")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("session.get", help="Return JMAP session object")
    add_connection_opts(s)

    eq = sub.add_parser("email.query", help="Email/query")
    add_connection_opts(eq)
    eq.add_argument("--filter", help="EmailQueryFilter JSON (inline, @file, @-)")
    eq.add_argument("--sort", help="JSON array of Comparator objects")
    eq.add_argument("--limit", type=int, default=10)
    eq.add_argument("--position", type=int, default=0)
    eq.add_argument("--calculate-total", action="store_true")
    eq.add_argument("--collapse-threads", action="store_true")

    eg = sub.add_parser("email.get", help="Email/get")
    add_connection_opts(eg)
    eg.add_argument("--ids", required=True, help="JSON array of ids or @file/@-")
    eg.add_argument("--properties", help="JSON array of properties")

    mq = sub.add_parser("mailbox.query", help="Mailbox/query")
    add_connection_opts(mq)
    mq.add_argument("--filter", help="MailboxQueryFilter JSON (inline/@file/@-)")
    mq.add_argument("--sort", help="JSON array of Comparator objects")
    mq.add_argument("--limit", type=int, default=10)
    mq.add_argument("--position", type=int, default=0)

    tg = sub.add_parser("thread.get", help="Thread/get")
    add_connection_opts(tg)
    tg.add_argument("--ids", required=True, help="JSON array of thread ids or @file/@-")

    pl = sub.add_parser("pipeline.run", help="Run raw multi-call pipeline")
    add_connection_opts(pl)
    pl.add_argument("--input", required=True, help="Pipeline JSON (inline/@file/@-)")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

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

    command_map = {
        "session.get": handle_session_get,
        "email.query": handle_email_query,
        "email.get": handle_email_get,
        "mailbox.query": handle_mailbox_query,
        "thread.get": handle_thread_get,
        "pipeline.run": handle_pipeline_run,
    }

    handler = command_map.get(args.command)
    if handler is None:
        parser.error(f"Unknown command {args.command}")

    code, payload = handler(args)
    json_dump(payload, args.json)
    return code


if __name__ == "__main__":
    sys.exit(main())
