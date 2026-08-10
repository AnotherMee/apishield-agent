from pathlib import Path
import json
import yaml

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}

def load_spec(path: str) -> dict:
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
        parsed = yaml.safe_load(raw) if p.suffix.lower() in {".yaml", ".yml"} else json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Could not parse the OpenAPI document: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ValueError("The OpenAPI document must be a JSON or YAML object.")
    if not isinstance(parsed.get("openapi"), str) and not isinstance(parsed.get("swagger"), str):
        raise ValueError("The document does not declare an OpenAPI or Swagger version.")
    if not isinstance(parsed.get("paths"), dict):
        raise ValueError("The OpenAPI document must contain a paths object.")
    return parsed

def inventory(spec: dict) -> list[dict]:
    rows = []
    global_security = bool(spec.get("security"))

    for path, node in spec.get("paths", {}).items():
        if not isinstance(node, dict):
            continue

        for method, op in node.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue

            params = []
            path_params = node.get("parameters", []) if isinstance(node.get("parameters", []), list) else []
            operation_params = op.get("parameters", []) if isinstance(op.get("parameters", []), list) else []
            for param in path_params + operation_params:
                if isinstance(param, dict) and param.get("name"):
                    params.append(param["name"])

            rows.append({
                "method": method.upper(),
                "path": path,
                "operation_id": op.get("operationId"),
                "auth_required": bool(op["security"]) if "security" in op else global_security,
                "parameters": sorted(set(params)),
            })

    return rows
