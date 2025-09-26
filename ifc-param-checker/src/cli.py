import argparse, csv, hashlib, json, os, re, sys, time
from typing import Any, Dict, List, Optional
from pathlib import Path

import yaml
from jsonschema import validate, ValidationError
from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich.console import Console
from rich.progress import track

try:
    import ifcopenshell
    from ifcopenshell.util.element import get_psets
except Exception as e:
    print("Error: ifcopenshell not available:", e, file=sys.stderr)
    sys.exit(2)

console = Console()

def load_rules(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def load_schema(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def hash_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()[:12]

def collect_ifc_files(paths: List[str]) -> List[str]:
    ifc_files: List[str] = []
    for p in paths:
        path = Path(p)
        if path.is_file() and path.suffix.lower() == ".ifc":
            ifc_files.append(str(path))
        elif path.is_dir():
            for file in path.rglob("*.ifc"):
                ifc_files.append(str(file))
        else:
            console.print(f"[yellow]Warning: path '{p}' is not an .ifc file or directory; skipping.[/yellow]")
    return sorted(ifc_files)

def normalize_value(val: Any) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, bool):
        return str(val)
    if isinstance(val, (int, float)):
        return str(val)
    return str(val).strip()

def resolve_property(elem, prop_path: str, case_sensitive: bool) -> Optional[str]:
    if prop_path.startswith("#attr:"):
        attr = prop_path.split(":", 1)[1]
        val = getattr(elem, attr, None)
        return normalize_value(val)
    if "." not in prop_path:
        return None
    pset_name, prop_name = prop_path.split(".", 1)
    psets = get_psets(elem, psets_only=False) or {}
    if not case_sensitive:
        pset_key = next((k for k in psets if k.lower() == pset_name.lower()), None)
        if pset_key is None:
            return None
        props = psets.get(pset_key, {}) or {}
        prop_key = next((k for k in props if k.lower() == prop_name.lower()), None)
        return normalize_value(props.get(prop_key)) if prop_key else None
    return normalize_value(psets.get(pset_name, {}).get(prop_name))

def matches_entity_filters(elem, filters: List[Dict[str, List[str]]], case_sensitive: bool) -> bool:
    if not filters:
        return True
    for filter_group in filters:
        match = True
        for key, allowed_vals in filter_group.items():
            actual_val = resolve_property(elem, key, case_sensitive)
            if actual_val is None:
                match = False
                break
            if not case_sensitive:
                actual_val = actual_val.lower()
                allowed_vals = [v.lower() for v in allowed_vals]
            if actual_val not in allowed_vals:
                match = False
                break
        if match:
            return True
    return False

def check_value(val: Optional[str], chk: Dict[str, Any], missing_policy: str) -> Optional[str]:
    if chk.get("required") and (val is None or val == ""):
        return "warn" if missing_policy == "warn" else "fail" if missing_policy == "fail" else None
    if "allowedValues" in chk and (val is None or val not in chk["allowedValues"]):
        return "fail"
    if "pattern" in chk:
        try:
            if val is None or re.fullmatch(chk["pattern"], val) is None:
                return "fail"
        except re.error:
            return "fail"
    return None

def run(ifc_files: List[str], rules: Dict[str, Any], html_out: Optional[str], csv_out: Optional[str], csv_all: bool) -> int:
    case_sensitive = rules.get("defaults", {}).get("case_sensitive", False)
    missing_policy = rules.get("defaults", {}).get("when_missing_property", "fail")
    ignored_entities = set(e.lower() for e in rules.get("defaults", {}).get("ignoredEntities", []))

    violations: List[Dict[str, Any]] = []
    passes_count = 0
    by_rule: Dict[str, Dict[str, Any]] = {}
    prop_values: Dict[str, Dict[str, set]] = {}

    for rule in rules.get("rules", []):
        rid, title = rule["id"], rule["title"]
        by_rule[rid] = {"title": title, "checked": 0, "pass": 0, "warn": 0, "fail": 0}

    total_objects = 0

    for fpath in ifc_files:
        console.print(f"[blue]Processing file:[/blue] {fpath}")
        try:
            model = ifcopenshell.open(fpath)
        except Exception as e:
            console.print(f"[red]Failed to open {fpath}: {e}[/red]")
            continue

        for rule in rules.get("rules", []):
            rid = rule["id"]
            title = rule["title"]
            targets = rule.get("targetEntities", [])
            filters = rule.get("targetEntityProperties", [])
            checks = rule.get("checks", [])

            elems = []
            for ent in targets:
                try:
                    elems.extend(model.by_type(ent) or [])
                except Exception:
                    continue

            for elem in track(elems, description=f"{Path(fpath).name} • {rid}"):
                if elem.is_a().lower() in ignored_entities:
                    continue
                if not matches_entity_filters(elem, filters, case_sensitive):
                    continue
                total_objects += 1
                for chk in checks:
                    prop = chk["property"]
                    actual_val = resolve_property(elem, prop, case_sensitive)
                    severity = check_value(actual_val, chk, missing_policy)

                    by_rule[rid]["checked"] += 1
                    prop_key = f"{rid} {prop}"
                    prop_values.setdefault(prop_key, {"pass": set(), "fail": set()})

                    if severity is None:
                        by_rule[rid]["pass"] += 1
                        passes_count += 1
                        if csv_out and csv_all:
                            violations.append({
                                "file": fpath, "rule": rid, "ruleTitle": title, "entity": elem.is_a(),
                                "globalId": getattr(elem, "GlobalId", ""), "name": getattr(elem, "Name", ""),
                                "path": "", "property": prop,
                                "expected": json.dumps({k: chk[k] for k in ("allowedValues", "pattern") if k in chk}, ensure_ascii=False),
                                "actual": actual_val, "severity": "pass"
                            })
                        prop_values[prop_key]["pass"].add(actual_val or "")
                    else:
                        by_rule[rid][severity] += 1
                        violations.append({
                            "file": fpath, "rule": rid, "ruleTitle": title, "entity": elem.is_a(),
                            "globalId": getattr(elem, "GlobalId", ""), "name": getattr(elem, "Name", ""),
                            "path": "", "property": prop,
                            "expected": json.dumps({k: chk[k] for k in ("allowedValues", "pattern") if k in chk}, ensure_ascii=False),
                            "actual": actual_val, "severity": severity
                        })
                        prop_values[prop_key]["fail"].add(actual_val or "")

    summary = {
        "files": len(ifc_files),
        "objects_checked": total_objects,
        "violations": sum(1 for v in violations if v["severity"] == "fail"),
        "warnings": sum(1 for v in violations if v["severity"] == "warn"),
        "passes": passes_count,
    }

    if csv_out:
        fieldnames = ["file", "rule", "ruleTitle", "entity", "globalId", "name", "path", "property", "expected", "actual", "severity"]
        os.makedirs(os.path.dirname(csv_out) or ".", exist_ok=True)
        with open(csv_out, "w", encoding="utf-8", newline="") as fcsv:
            writer = csv.DictWriter(fcsv, fieldnames=fieldnames)
            writer.writeheader()
            for row in violations:
                if csv_all or row["severity"] != "pass":
                    writer.writerow(row)

    if html_out:
        env = Environment(
            loader=FileSystemLoader(os.path.dirname(__file__)),
            autoescape=select_autoescape(["html", "xml"]), enable_async=False,
        )
        tpl = env.get_template("report.html.j2")
        meta = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tool_version": "0.3.0",
            "rules_hash": rules.get("_hash", ""),
        }
        html = tpl.render(summary=summary, by_rule=by_rule, violations=[v for v in violations if v["severity"] != "pass"], meta=meta, prop_values=prop_values)
        os.makedirs(os.path.dirname(html_out) or ".", exist_ok=True)
        with open(html_out, "w", encoding="utf-8") as fh:
            fh.write(html)

    return 1 if summary["violations"] > 0 else 0

def main():
    ap = argparse.ArgumentParser(description="IFC rule checker (properties only)")
    ap.add_argument("paths", nargs="+", help="IFC files and/or directories to scan")
    ap.add_argument("--rules", required=True, help="YAML rules file")
    ap.add_argument("--schema", default="rules.schema.json", help="JSON schema for rules validation")
    ap.add_argument("--out-html", dest="out_html", required=False, help="Path to HTML report")
    ap.add_argument("--out-csv", dest="out_csv", required=False, help="Path to CSV output")
    ap.add_argument("--csv-all", action="store_true", help="Include passing rows in CSV")
    args = ap.parse_args()

    ifc_files = collect_ifc_files(args.paths)
    if not ifc_files:
        console.print("[red]Error: No .ifc files found in the specified paths.[/red]")
        sys.exit(1)

    rules = load_rules(args.rules)
    try:
        schema = load_schema(args.schema)
        validate(instance=rules, schema=schema)
    except FileNotFoundError:
        console.print(f"[yellow]Schema file '{args.schema}' not found; skipping validation.[/yellow]")
    except ValidationError as e:
        console.print("[red]Rules file does not conform to schema:[/red]")
        console.print(e)
        sys.exit(3)

    try:
        rules["_hash"] = hash_file(args.rules)
    except Exception:
        rules["_hash"] = ""

    exit_code = run(ifc_files, rules, args.out_html, args.out_csv, args.csv_all)
    sys.exit(exit_code)

if __name__ == "__main__":
    main()