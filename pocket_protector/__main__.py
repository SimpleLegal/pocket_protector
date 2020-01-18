import os
import sys

from .cli import main

if __name__ == '__main__':  # pragma: no cover
    try:
        sys.exit(main() or 0)
    except Exception:
        if os.getenv('PPROTECT_ENABLE_DEBUG'):
            import pdb;pdb.post_mortem()
        raise
