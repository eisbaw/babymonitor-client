#!/usr/bin/env python3
"""Unit tests for regions_decrypt.py (TASK-0048 host-enumeration fix).

Run: python3 re/scripts/test_regions_decrypt.py
(plain stdlib unittest; no pip deps -- matches the project's no-pip gate.)

ROOT-CAUSE under test: the script previously emitted only 2 host fields
(mobileApiUrl/gwApiUrl), which produced a host false-exhaustion (the iotbing/px
gateways were never even enumerated). `region_host_fields` must now surface
EVERY scalar regionConfig host/port field. The primary assertion is ">2 host
fields" per the task.

The decrypted `regions` asset is gitignored (lives only in the regenerable
`decompiled/` tree), so the core tests run on a SYNTHETIC regionConfig and need
no asset. A final, OPT-IN cross-check runs against the real asset only if it is
present locally (skipped in a clean checkout / CI).
"""
import os
import unittest

import regions_decrypt as M

# A synthetic regionConfig mirroring the real EU shape (public-host names only;
# no secret). It carries >2 host fields plus a couple of ports and one non-host
# scalar (regionCode) so the test also proves ports/codes are included as scalar
# config and bools/objects are excluded.
SYNTHETIC_REGION_CONFIG = {
    "mobileApiUrl": "https://a1.example.com",
    "gwApiUrl": "http://a.gw.example.com/gw.json",
    "fusionUrl": "https://apigw-eu.example.com",
    "pxApiUrl": "http://px.example.com",
    "deviceHttpsPskUrl": "https://a3.example.com",
    "mobileMqttsUrl": "m1.example.com",
    "httpsPort": 443,
    "mqttPort": 1883,
    "regionCode": "EU",
    # Non-scalar / bool fields that MUST be excluded by region_host_fields:
    "someNestedObject": {"k": "v"},
    "someBoolFlag": True,
}


class TestRegionHostFields(unittest.TestCase):
    def test_emits_more_than_two_host_fields(self):
        """The task's headline assertion: >2 host fields are emitted."""
        fields = M.region_host_fields(SYNTHETIC_REGION_CONFIG)
        self.assertGreater(
            len(fields),
            2,
            "region_host_fields must emit MORE than 2 fields (the old "
            "mobileApiUrl/gwApiUrl-only behaviour was the host false-exhaustion bug)",
        )

    def test_includes_the_previously_unprobed_hosts(self):
        """fusionUrl / pxApiUrl / deviceHttpsPskUrl were invisible before; assert
        they are now surfaced (these are the TASK-0048 probe targets)."""
        keys = {k for k, _ in M.region_host_fields(SYNTHETIC_REGION_CONFIG)}
        for required in ("fusionUrl", "pxApiUrl", "deviceHttpsPskUrl"):
            self.assertIn(required, keys, f"{required} must be enumerated")

    def test_excludes_objects_and_bools(self):
        keys = {k for k, _ in M.region_host_fields(SYNTHETIC_REGION_CONFIG)}
        self.assertNotIn("someNestedObject", keys, "object fields must be skipped")
        self.assertNotIn("someBoolFlag", keys, "bool fields must be skipped")

    def test_negative_two_field_config_does_not_pass_the_gt2_assertion(self):
        """Prove the check bites: a 2-field config (the OLD behaviour) must NOT
        satisfy the >2 assertion."""
        old_shape = {"mobileApiUrl": "x", "gwApiUrl": "y"}
        self.assertEqual(len(M.region_host_fields(old_shape)), 2)
        self.assertFalse(
            len(M.region_host_fields(old_shape)) > 2,
            "a 2-field config must fail the >2 gate (so the gate is real)",
        )

    def test_real_asset_emits_many_host_fields_if_present(self):
        """OPT-IN: if the gitignored decrypted asset is present locally, confirm
        the REAL EU region carries far more than 2 host fields. Skipped in a
        clean checkout (the asset lives only under decompiled/)."""
        regions_path = os.path.join(M.ASSETS_DEFAULT, "regions")
        if not os.path.exists(regions_path):
            self.skipTest("regions asset absent (gitignored decompiled/ tree)")
        pt = M.decrypt_asset(regions_path)
        data = M._unescape_regions_json(pt)
        eu = next((r for r in data if r.get("region") == "EU"), None)
        self.assertIsNotNone(eu, "EU region must be present in the real asset")
        fields = M.region_host_fields(eu["regionConfig"])
        # The real EU regionConfig has ~24 scalar host/port fields.
        self.assertGreater(
            len(fields), 10, "real EU regionConfig must enumerate many host fields"
        )
        keys = {k for k, _ in fields}
        # The four TASK-0048 probe-target hosts must be enumerable from the asset.
        for required in ("fusionUrl", "pxApiUrl", "deviceHttpsPskUrl"):
            self.assertIn(required, keys)


if __name__ == "__main__":
    unittest.main()
