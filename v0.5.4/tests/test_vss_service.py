import json
import os
import unittest
import uuid
from unittest.mock import Mock, patch

from ransomguard import recovery, snapshot_retention, snapshots, vss_broker


class State:
    def __init__(self, volume):
        self.volume = volume
        self.records = {}

    def get(self, group, name):
        return self.records.get((group, name))

    def put(self, group, name, value):
        self.records[group, name] = value


class VssProviderTests(unittest.TestCase):
    def setUp(self):
        self.volume = "\\\\?\\Volume{" + str(uuid.uuid4()) + "}\\"
        self.state = State(self.volume)
        self.snap = recovery.Snapshot(str(uuid.uuid4()), self.volume,
                                      "2026-11-25T12:00:00Z", r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3")

    def call(self, op, *, key=None, **kwargs):
        message = {"volume": self.volume, "op": op}
        if op == "delete":
            message["snapshot"] = self.snap.to_dict()
        return vss_broker.perform(key or uuid.uuid4().hex, json.dumps(message), self.state, **kwargs)

    def test_only_verified_scope_and_fixed_verbs(self):
        create = Mock()
        for body in ({"op":"create","volume":self.volume,"command":"x"},
                     {"op":"create","volume":"C:\\"}, {"op":"exec","volume":self.volume},
                     {"op":"create","volume":"\\\\?\\Volume{"+str(uuid.uuid4())+"}\\"}):
            with self.assertRaises((ValueError,PermissionError)):
                vss_broker.perform(uuid.uuid4().hex,json.dumps(body),self.state,create=create)
        create.assert_not_called()
        self.assertFalse(self.state.records)

    def test_inventory_and_space_have_no_mutations(self):
        self.assertEqual(self.call("list",inventory=lambda _: [self.snap])["value"],[self.snap.to_dict()])
        self.assertEqual(self.call("space",space=lambda _: {"free_bytes":50})["value"]["free_bytes"],50)
        self.assertFalse(self.state.records)

    def test_created_receipt_replayed_without_provider_call(self):
        key = uuid.uuid4().hex
        create = Mock(return_value=self.snap)
        reply = self.call("create", key=key, create=create)
        self.assertEqual(reply["value"], self.snap.to_dict())
        self.assertEqual(self.call("create", key=key, create=create), reply)
        create.assert_called_once_with(self.volume)
        self.assertEqual(self.state.get("Owned",self.snap.snapshot_id), self.snap.to_dict())

    def test_interrupted_and_unknown_creates_are_not_retried(self):
        key = uuid.uuid4().hex
        def crash(_volume):
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.call("create",key=key,create=crash)
        never = Mock()
        self.assertEqual(self.call("create",key=key,create=never)["status"],"unknown")
        never.assert_not_called()
        uncertain = Mock(side_effect=snapshots.SnapshotOutcomeUnknown("transport",snapshot_id=self.snap.snapshot_id))
        self.assertEqual(self.call("create",create=uncertain)["snapshot_id"],self.snap.snapshot_id)
        rejected = Mock(side_effect=snapshots.SnapshotCreationFailed("no_space",return_value=6))
        self.assertEqual(self.call("create",create=rejected)["status"], "known_failure")

    def test_only_broker_owned_exact_copy_can_be_deleted(self):
        delete = Mock()
        with self.assertRaises(PermissionError):
            self.call("delete",delete=delete)
        self.call("create",create=lambda _:self.snap)
        original = self.snap
        self.snap = recovery.Snapshot(original.snapshot_id,self.volume,"2026-11-26T12:00:00Z",original.device_path)
        with self.assertRaises(PermissionError):
            self.call("delete",delete=delete)
        self.snap = original
        self.assertTrue(self.call("delete",delete=delete)["value"]["absent"])
        with self.assertRaises(PermissionError):
            self.call("delete",delete=delete)
        delete.assert_called_once_with(original)

    def test_storage_uses_broker_and_preserves_authorization_errors(self):
        with patch.dict(os.environ,RANSOM0_SERVICE_STORAGE="1"), patch("ransomguard.vss_service.request") as request:
            request.return_value = self.snap.to_dict()
            self.assertEqual(snapshots._create_vss_snapshot(self.volume),self.snap)
            request.return_value = [self.snap.to_dict()]
            self.assertEqual(recovery.enumerate_snapshots(self.volume),[self.snap])
            request.return_value = {"used_bytes":0}
            self.assertEqual(snapshot_retention.read_storage(self.volume),{"used_bytes":0})
            request.return_value = {"snapshot_id":self.snap.snapshot_id,"absent":True}
            snapshot_retention.delete_exact(self.snap)
            self.assertEqual([c.args[0] for c in request.call_args_list],["create","list","space","delete"])
            with patch("ransomguard.service_identity.require_service_account",side_effect=PermissionError):
                with self.assertRaises(PermissionError):
                    snapshots.require_storage_operator()
