#!/usr/bin/env python3
"""Fail closed instead of returning a false green product check."""
import json,sys
print(json.dumps({'status':'blocked','gate':sys.argv[1] if len(sys.argv)>1 else 'unknown','reason':'Implementation, qualified local capacity and acceptance evidence are not yet available.'},sort_keys=True))
sys.exit(78)
