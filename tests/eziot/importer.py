import sys
from pathlib import Path

root = Path(__file__).parent.parent.parent
tests = root / 'tests'

sys.path.append(str(root))

