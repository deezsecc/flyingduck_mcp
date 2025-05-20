import json

def to_json(data):
    """Convert a dict to a pretty JSON string."""
    return json.dumps(data, indent=2) 