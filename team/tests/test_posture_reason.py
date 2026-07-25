"""Named Team resource and namespace posture failures."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from container_policy import network as net


class PostureReasonTests(unittest.TestCase):
    def test_first_failing_posture_reason_is_named(self):
        valid = {
            "Memory": net.BRAIN_MEMORY_BYTES,
            "MemoryReservation": net.BRAIN_MEMORY_RESERVATION_BYTES,
            "NanoCpus": net.BRAIN_NANO_CPUS,
            "PidsLimit": net.BRAIN_PIDS_LIMIT,
            "MemorySwap": net.BRAIN_MEMORY_BYTES,
            "Tmpfs": {net.TMPFS_MOUNT_PATH: "size=16m"},
            "Ulimits": [{"Name": "nofile", "Soft": 256, "Hard": 256}],
            "RestartPolicy": {"Name": "no"},
            "LogConfig": {
                "Type": "json-file",
                "Config": {
                    "labels": "team.id",
                    "max-size": net.TEAM_LOG_MAX_SIZE,
                    "max-file": net.TEAM_LOG_MAX_FILE,
                },
            },
            "PortBindings": None,
            "PublishAllPorts": False,
            "Devices": None,
            "DeviceRequests": None,
            "Binds": None,
            "PidMode": "",
            "IpcMode": "private",
            "UTSMode": "",
            "CgroupnsMode": "private",
            "UsernsMode": "",
        }
        flipped = {**valid, "PidMode": "host"}

        self.assertIsNone(net._resource_and_namespace_posture_reason(valid, "brain"))
        self.assertEqual(net._resource_and_namespace_posture_reason(flipped, "brain"), "pid-mode")
        self.assertTrue(net._resource_and_namespace_posture_valid(valid, "brain"))
        self.assertFalse(net._resource_and_namespace_posture_valid(flipped, "brain"))
