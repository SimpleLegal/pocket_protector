import os
import sys

from .cli import main

if __name__ == '__main__':
    if sys.argv[0] == '__main__.py':
        args = 'python -m pocket_protector' + sys.argv[1:]
    else:
        args = sys.argv
    try:
        sys.exit(main(args) or 0)
    except Exception:
        if os.getenv('PPROTECT_ENABLE_DEBUG'):
            import pdb;pdb.post_mortem()
        raise
