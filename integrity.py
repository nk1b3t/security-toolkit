import os
import hashlib
import json

BASELINE_FILE = "baseline.json"

def hash_file(filepath, algorithm="sha256"):
    """Compute hash of a file using the chosen algorithm."""
    try:
        h = hashlib.new(algorithm)
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def create_baseline(directory=".", algorithm="sha256"):
    """Create a baseline of file hashes for a directory."""
    baseline = {}
    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            # Skip baseline file itself
            if os.path.basename(filepath) == BASELINE_FILE:
                continue
            file_hash = hash_file(filepath, algorithm)
            if file_hash:
                baseline[filepath] = file_hash

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=4)

    return baseline  # Return dict, not int

def scan_for_changes(directory=".", algorithm="sha256"):
    """Compare current directory files against the baseline."""
    if not os.path.exists(BASELINE_FILE):
        return {"error": "No baseline found. Please create one first."}

    with open(BASELINE_FILE, "r") as f:
        baseline = json.load(f)

    current = {}
    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            if os.path.basename(filepath) == BASELINE_FILE:
                continue
            file_hash = hash_file(filepath, algorithm)
            if file_hash:
                current[filepath] = file_hash

    added = [f for f in current if f not in baseline]
    removed = [f for f in baseline if f not in current]
    modified = [f for f in current if f in baseline and current[f] != baseline[f]]

    return {
        "added": added,
        "removed": removed,
        "modified": modified,
        "summary": f"Added: {len(added)}, Removed: {len(removed)}, Modified: {len(modified)}"
    }
