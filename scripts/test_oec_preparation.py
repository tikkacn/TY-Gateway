import importlib.util
import pathlib
import unittest

path = pathlib.Path(__file__).resolve().parents[1] / "firmware/oec/rootfs/usr/local/libexec/ty-gateway-prepare"
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader("prepare", str(path))
spec = importlib.util.spec_from_loader(loader.name, loader)
prepare = importlib.util.module_from_spec(spec)
loader.exec_module(prepare)


class PreparationTests(unittest.TestCase):
    def run_wait(self, states, timeout=10):
        clock = [0]
        calls = []
        messages = []
        def call(action):
            calls.append(action)
            state = states[min(len(calls)-1, len(states)-1)]
            if isinstance(state, Exception): raise state
            return state
        result = prepare.wait(timeout, call=call, clock=lambda:clock[0], pause=lambda delta:clock.__setitem__(0,clock[0]+delta), report=lambda *args,**kwargs:messages.append(str(args[0])))
        return result, calls, messages

    def test_success_never_requires_proxy_on(self):
        result,calls,messages = self.run_wait([{"prepared":False,"blocker":"configuration_pending"},{"prepared":True,"enrolled":True,"rules_cached":True,"nodes_validated":True,"node_count":17,"proxy_enabled":False,"frp_state":"configured:hash"}])
        self.assertEqual(result,0)
        self.assertEqual(calls,["prepare","onboarding"])
        self.assertIn("17 nodes",messages[-2])
        self.assertIn("must still be checked",messages[-1])

    def test_missing_subscription_is_not_installation_ready(self):
        result,_,messages = self.run_wait([{"prepared":False,"blocker":"subscription_missing","sync_running":False}])
        self.assertEqual(result,3)
        self.assertIn("bind a valid subscription",messages[-1])

    def test_timeout_and_false_ready_are_not_success(self):
        for states in ([OSError("no agent")],[{"prepared":True,"enrolled":True,"rules_cached":True,"nodes_validated":False,"node_count":0}]):
            result,_,messages = self.run_wait(states)
            self.assertEqual(result,3)
            self.assertIn("NOT complete",messages[-1])


if __name__ == "__main__": unittest.main()
