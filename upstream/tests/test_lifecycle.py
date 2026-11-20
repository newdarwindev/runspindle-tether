"""Original store APIs in fresh synthetic child processes; no live application."""

import importlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class LifecycleTests(unittest.TestCase):
    def child(self, protected: bool) -> None:
        original = importlib.import_module("tether.db")
        if original.__file__ is None:
            self.fail("original upstream source path required")
        paths = [str(Path(original.__file__).parents[2]), *sys.path]
        code = r"""
import sys,json,asyncio,sqlite3
sys.path[:0]=json.loads(sys.argv[1])
from tether.store import store,SessionStore
from tether.db import get_session
from sqlmodel import select
from tether.models import BridgeDelivery
from runspindle_tether.authority import VerifiedAction,digest,Denied
from runspindle_tether.upstream_outbox import Outbox
from runspindle_tether.upstream_lifecycle import protect_session_history
session=store.create_session('synthetic-repo',None)
payload={'text':'synthetic final','platform':'slack','turn_id':'turn'}
action=VerifiedAction('event','actor','workspace','channel','thread','message',session.id,'host',1,'output',digest(payload))
async def observe(*args): return 'unknown'
async def effect(): return None
asyncio.run(Outbox(lambda _:True,observe)(action,payload,effect))
def snapshot():
 with get_session() as db:
  return [(x.id,x.status,x.payload) for x in db.exec(select(BridgeDelivery)).all()]
before=snapshot()
if sys.argv[2]=='protected':
 protect_session_history();protect_session_history()
 for owner in (store,SessionStore()):
  for call in (lambda:owner.delete_session(session.id),lambda:owner.clear_all_data()):
   try:
    try: raise ValueError('PRIVATE_CANARY')
    except ValueError: call()
   except Denied as e:
    if str(e)!='upstream session retirement is not qualified' or e.__context__ is not None: raise AssertionError('unsafe denial')
   else: raise AssertionError('destructive lifecycle admitted')
   if snapshot()!=before or owner.get_session(session.id) is None: raise AssertionError('history removed')
else:
 store.clear_all_data()
 if snapshot(): raise AssertionError('original negative control did not erase')
"""
        with tempfile.TemporaryDirectory(prefix="upstream-lifecycle-") as directory:
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    *(["-O"] if sys.flags.optimize else []),
                    "-c",
                    code,
                    json.dumps(paths),
                    "protected" if protected else "original",
                ],
                env={"PATH": os.defpath, "TETHER_AGENT_DATA_DIR": directory},
                capture_output=True,
                text=True,
                timeout=10,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("PRIVATE_CANARY", result.stdout + result.stderr)

    def test_actual_original_destructive_lifecycle_negative_control(self) -> None:
        self.child(False)

    def test_guard_preserves_history_for_existing_and_new_original_instances(
        self,
    ) -> None:
        self.child(True)
