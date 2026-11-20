"""Actual original store status APIs, fresh processes and synthetic SQLite only."""

import importlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class DeliveryStatusTests(unittest.TestCase):
    def child(self, protected: bool) -> None:
        original = importlib.import_module("tether.db")
        if original.__file__ is None:
            self.fail("original upstream source required")
        paths = [str(Path(original.__file__).parents[2]), *sys.path]
        code = r"""
import sys,json,asyncio
sys.path[:0]=json.loads(sys.argv[1])
from tether.store import store,SessionStore
from tether.db import get_session
from sqlmodel import select
from tether.models import BridgeDelivery
from runspindle_tether.authority import VerifiedAction,digest,Denied
from runspindle_tether.upstream_outbox import Outbox
from runspindle_tether.upstream_lifecycle import protect_session_history,protect_delivery_status
session=store.create_session('synthetic-repo',None)
payload={'text':'synthetic final','platform':'slack','turn_id':'turn'}
action=VerifiedAction('event','actor','workspace','channel','thread','message',session.id,'host',1,'output',digest(payload))
async def observe(*args): return 'unknown'
async def effect(): return None
asyncio.run(Outbox(lambda _:True,observe)(action,payload,effect))
with get_session() as db:
 row=db.exec(select(BridgeDelivery)).one(); key=row.id
def reset(status):
 with get_session() as db:
  row=db.get(BridgeDelivery,key);row.status=status;row.last_error=None;row.sent_at=None;row.next_attempt_at=None;row.attempts=0;db.add(row);db.commit()
def snapshot():
 with get_session() as db:
  row=db.get(BridgeDelivery,key)
  return (row.id,row.status,row.payload,row.last_error,row.sent_at,row.next_attempt_at,row.attempts)
protected=sys.argv[2]=='protected'
if protected:
 protect_delivery_status();protect_delivery_status();protect_session_history()
for status in ('runspindle_unknown','runspindle_confirmed','runspindle_rejected','runspindle_conflict'):
 for owner in (store,SessionStore()):
  for name in ('mark_bridge_delivery_sent','mark_bridge_delivery_failed','cancel_bridge_delivery'):
   reset(status);before=snapshot()
   call=getattr(owner,name)
   args=(key,ValueError('PRIVATE_CANARY')) if name=='mark_bridge_delivery_failed' else (key,)
   if protected:
    try:
     try: raise ValueError('PRIVATE_CANARY')
     except ValueError: call(*args)
    except Denied as e:
     if str(e)!='upstream session retirement is not qualified' or e.__context__ is not None: raise AssertionError('unsafe denial')
    else: raise AssertionError('legacy status mutation admitted')
    if snapshot()!=before: raise AssertionError('protected evidence changed')
   else:
    call(*args)
    if snapshot()[1]==status: raise AssertionError('negative control did not mutate')
    if name=='mark_bridge_delivery_failed' and snapshot()[3]!='PRIVATE_CANARY': raise AssertionError('original raw error control absent')
"""
        with tempfile.TemporaryDirectory(prefix="upstream-status-") as directory:
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
                timeout=15,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("PRIVATE_CANARY", result.stdout + result.stderr)

    def test_original_status_mutators_overwrite_all_protected_states(self) -> None:
        self.child(False)

    def test_guard_denies_existing_new_and_repeated_status_mutation(self) -> None:
        self.child(True)
