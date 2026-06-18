import threading
from modules import get_modules_for
import db

_running = {}


def run_scan(scan_id, target, target_types):
    """Run modules for one or more selected target types."""

    if isinstance(target_types, str):
        target_types = [target_types]

    modules = []
    seen = set()

    for target_type in target_types:
        for mod in get_modules_for(target_type):
            key = f"{target_type}:{mod.name}"
            if key not in seen:
                modules.append((mod, target_type))
                seen.add(key)

    _running[scan_id] = {
        "total": len(modules),
        "done": 0,
        "current": "",
        "stopped": False
    }

    try:
        for mod, target_type in modules:
            if _running.get(scan_id, {}).get("stopped"):
                db.finish_scan(scan_id, "stopped")
                return

            _running[scan_id]["current"] = f"{mod.name} ({target_type})"

            try:
                results = mod.run(target, target_type)
                db.save_results(scan_id, results)

            except Exception as e:
                db.save_results(scan_id, [{
                    "module": mod.name,
                    "data_type": "error",
                    "value": str(e),
                    "source": mod.name,
                    "raw": {}
                }])

            _running[scan_id]["done"] += 1

        db.finish_scan(scan_id, "done")

    except Exception:
        db.finish_scan(scan_id, "error")

    finally:
        _running.pop(scan_id, None)


def start_scan(target, target_type, target_types=None):
    """Create scan record and run selected scan types."""

    selected_types = target_types or [target_type]

    if isinstance(selected_types, str):
        selected_types = [selected_types]

    display_type = "+".join(selected_types)

    scan_id = db.create_scan(target, display_type)

    t = threading.Thread(
        target=run_scan,
        args=(scan_id, target, selected_types),
        daemon=True
    )
    t.start()

    return scan_id


def get_progress(scan_id):
    if scan_id in _running:
        info = _running[scan_id]
        total = info["total"] or 1
        pct = int((info["done"] / total) * 100)

        return {
            "status": "running",
            "pct": pct,
            "current": info["current"],
            "done": info["done"],
            "total": total
        }

    scan = db.get_scan(scan_id)

    if scan:
        return {
            "status": scan["status"],
            "pct": 100,
            "current": "",
            "done": 0,
            "total": 0
        }

    return {
        "status": "unknown",
        "pct": 0,
        "current": "",
        "done": 0,
        "total": 0
    }


def stop_scan(scan_id):
    if scan_id in _running:
        _running[scan_id]["stopped"] = True
        db.finish_scan(scan_id, "stopped")