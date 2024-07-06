from os import path

def validate_path(given_path: str):
    """make sure this path is abs and exists"""
    assert path.isabs(given_path), (f"Invalid path. {given_path} must be "
                                 f"absolute. Stopping.")
    assert path.exists(given_path), f"Path '{given_path}' doesn't exist"
    return True