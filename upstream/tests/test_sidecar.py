import asyncio
import dataclasses
import unittest
from agent_tether import BridgeCallbacks, BridgeManager
from tether.bridges.turn_accumulator import BridgeTurnAccumulator
from runspindle_tether.authority import AuthorityGate, Denied, VerifiedAction, digest
from runspindle_tether.upstream_runtime import Sidecar


class SidecarTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.effects = []
        self.allowed = True
        self.action = VerifiedAction('event1','actor','workspace','channel','thread','message','session','host',7,'send_input',digest({'text':'approved'}))
        def authenticate(raw, headers):
            if raw != b'original-signed-event' or headers != (('signature','verified-fixture'),):
                raise Denied('signature mismatch')
            return self.action
        async def execute(action, payload):
            self.effects.append((action, payload)); return True
        self.gate = AuthorityGate(authenticate, lambda _: self.allowed, execute)
        self.sidecar = Sidecar(self.gate)

    async def invoke(self, callback):
        return await self.gate.dispatch(b'original-signed-event', (('signature','verified-fixture'),), callback)

    async def test_actual_upstream_types_and_one_native_owner(self):
        self.assertIsInstance(self.sidecar.manager, BridgeManager)
        self.assertIsInstance(self.sidecar.callbacks, BridgeCallbacks)
        self.assertIsInstance(self.sidecar.turns, BridgeTurnAccumulator)
        await self.invoke(lambda: self.sidecar.callbacks.send_input('session','approved'))
        self.assertEqual(len(self.effects), 1)
        self.assertEqual(self.effects[0][0].host_id, 'host')
        self.assertEqual(self.effects[0][0].lease_epoch, 7)
        with self.assertRaises(Denied): await self.sidecar.callbacks.create_session(directory='/tmp')
        with self.assertRaises(Denied): await self.sidecar.callbacks.attach_external('other')

    async def test_missing_actor_context_and_autoapproval_denied(self):
        with self.assertRaises(Denied): await self.sidecar.callbacks.send_input('session','approved')
        with self.assertRaises(Denied): await self.sidecar.callbacks.respond_to_permission('session','request',True)
        self.assertEqual(self.effects, [])

    async def test_exact_action_content_and_session(self):
        for session,text in [('other','approved'),('session','changed')]:
            with self.assertRaises(Denied): await self.invoke(lambda: self.sidecar.send_input(session,text))
        self.allowed = False
        with self.assertRaises(Denied): await self.invoke(lambda: self.sidecar.send_input('session','approved'))
        self.assertEqual(self.effects, [])

    async def test_original_event_verified_before_callback(self):
        with self.assertRaises(Denied):
            await self.gate.dispatch(b'copied-json', (), lambda: self.sidecar.send_input('session','approved'))
        self.assertEqual(self.effects, [])

    async def test_context_cannot_escape_into_child_task(self):
        async def callback():
            await asyncio.create_task(self.sidecar.send_input('session','approved'))
        with self.assertRaises(Denied): await self.invoke(callback)
        self.assertEqual(self.effects, [])

    async def test_one_effect_per_callback_and_unknown_not_retried(self):
        async def uncertain(action, payload):
            self.effects.append((action,payload)); raise TimeoutError('ambiguous')
        self.gate.execute = uncertain
        async def callback():
            with self.assertRaises(TimeoutError): await self.sidecar.send_input('session','approved')
            with self.assertRaises(Denied): await self.sidecar.send_input('session','approved')
        await self.invoke(callback)
        self.assertEqual(len(self.effects),1)

    async def test_actual_upstream_output_accumulation_and_route(self):
        observed=[]
        class Boundary:
            async def on_output(self, session, text, metadata):
                observed.append((session,text,metadata))
        self.sidecar.manager.register_bridge('synthetic',Boundary())
        payload={'text':'approved final','turn_id':'turn1','platform':'synthetic'}
        self.action=dataclasses.replace(self.action, action='output',payload_sha256=digest(payload))
        await self.invoke(lambda: self.sidecar.final_output('session','approved final','turn1','synthetic'))
        self.assertEqual(observed,[('session','approved final',{'turn_id':'turn1'})])
        self.assertEqual(self.effects,[])  # No second Core/Host execution owner.

    async def test_output_exception_is_unknown_not_delivered_or_retried(self):
        observed=[]
        class Boundary:
            async def on_output(self,*args):
                observed.append(args); raise TimeoutError('lost acknowledgement')
        self.sidecar.manager.register_bridge('synthetic',Boundary())
        payload={'text':'approved final','turn_id':'turn1','platform':'synthetic'}
        self.action=dataclasses.replace(self.action, action='output',payload_sha256=digest(payload))
        with self.assertRaises(TimeoutError):
            await self.invoke(lambda: self.sidecar.final_output('session','approved final','turn1','synthetic'))
        self.assertEqual(len(observed),1)

    async def test_queries_and_discovery_default_deny(self):
        for callback in (self.sidecar.callbacks.list_sessions,self.sidecar.callbacks.get_usage,self.sidecar.callbacks.check_directory,self.sidecar.callbacks.list_external_sessions,self.sidecar.callbacks.get_external_history,self.sidecar.callbacks.sync_session):
            with self.assertRaises(Denied): await callback()

    async def test_incomplete_actor_or_invalid_lease_is_rejected(self):
        original=self.action
        for change in ({'actor_id':''},{'workspace_id':''},{'lease_epoch':True},{'payload_sha256':'not-a-hash'},{'action':'start_new_agent'}):
            self.action=dataclasses.replace(original,**change)
            with self.assertRaises(Denied): await self.invoke(lambda: self.sidecar.send_input('session','approved'))
        self.assertEqual(self.effects,[])

    async def test_scope_is_gone_after_original_callback_returns(self):
        async def no_effect(): return None
        await self.invoke(no_effect)
        with self.assertRaises(Denied): await self.sidecar.send_input('session','approved')
        self.assertEqual(self.effects,[])
