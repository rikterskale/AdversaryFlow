from __future__ import annotations

import email.message
import hashlib
import io
import json
import os
import tempfile
import unittest
import urllib.error
from typing import Any
from unittest.mock import patch

from backend import attack_data


def bundle(domain: str) -> dict:
    return {
        "id": f"bundle--{domain}",
        "objects": [
            {
                "id": f"intrusion-set--{domain}",
                "type": "intrusion-set",
                "name": domain.title(),
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": f"G-{domain}"}
                ],
            }
        ],
    }


class DomainIndexTests(unittest.TestCase):
    def setUp(self):
        attack_data.clear_memory_cache()
        attack_data.configure_offline(False)

    def tearDown(self):
        attack_data.configure_offline(False)

    @patch("backend.attack_data.load_bundle", side_effect=lambda domain: bundle(domain))
    def test_domain_sets_have_independent_indexes(self, _load):
        enterprise = attack_data.get_index(["enterprise"])
        ics = attack_data.get_index(["ics"])

        self.assertIsNot(enterprise, ics)
        self.assertEqual(enterprise.domains, ["enterprise"])
        self.assertEqual(ics.domains, ["ics"])
        self.assertEqual(enterprise.data_version, "enterprise:bundle--enterprise")
        self.assertEqual(ics.data_version, "ics:bundle--ics")

    @patch("backend.attack_data.load_bundle", side_effect=lambda domain: bundle(domain))
    def test_domain_order_is_normalized_and_duplicates_are_removed(self, _load):
        first = attack_data.get_index(["enterprise", "enterprise", "ics"])
        second = attack_data.get_index(["enterprise", "ics"])

        self.assertIs(first, second)
        self.assertEqual(first.domains, ["enterprise", "ics"])

    @patch("backend.attack_data.load_bundle", side_effect=lambda domain: bundle(domain))
    def test_rebuild_replaces_only_requested_domain_set(self, _load):
        enterprise = attack_data.get_index(["enterprise"])
        ics = attack_data.get_index(["ics"])

        rebuilt = attack_data.get_index(["ics"], rebuild=True)

        self.assertIsNot(ics, rebuilt)
        self.assertIs(enterprise, attack_data.get_index(["enterprise"]))

    @patch("backend.attack_data.os.path.exists", return_value=False)
    def test_offline_mode_reports_missing_cache(self, _exists):
        attack_data.configure_offline(True)
        with self.assertRaisesRegex(RuntimeError, "offline mode requires a cached enterprise"):
            attack_data.load_bundle("enterprise")

    def test_bundle_validation_rejects_unstructured_json(self):
        with self.assertRaisesRegex(ValueError, "not a STIX bundle"):
            attack_data._validate_bundle({"objects": []}, "enterprise")

    def test_cache_status_reports_known_domains(self):
        original = attack_data.CACHE_DIR
        with tempfile.TemporaryDirectory() as directory:
            attack_data.configure_cache_dir(directory)
            status = attack_data.cache_status()
            self.assertEqual(set(status["domains"]), set(attack_data.STIX_SOURCES))
            self.assertFalse(status["domains"]["enterprise"]["exists"])
        attack_data.configure_cache_dir(original)

    def test_download_validates_and_records_provenance(self):
        original = attack_data.CACHE_DIR
        payload = json.dumps({
            "type": "bundle", "id": "bundle--test",
            "objects": [{"type": "x-mitre-matrix", "id": "x-mitre-matrix--test", "tactic_refs": []}],
        }).encode()
        response = FakeResponse(payload, {"Content-Length": str(len(payload)), "ETag": '"fixture"'})
        with tempfile.TemporaryDirectory() as directory:
            attack_data.configure_cache_dir(directory)
            destination = attack_data._cache_path("enterprise")
            with patch("backend.attack_data.urllib.request.urlopen", return_value=response):
                metadata = attack_data._download("https://example.test/bundle.json", destination, "enterprise")
            self.assertEqual(metadata["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(attack_data._load_validated(destination, "enterprise")["id"], "bundle--test")
            self.assertEqual(attack_data._read_metadata("enterprise")["etag"], '"fixture"')
        attack_data.configure_cache_dir(original)

    @patch("backend.attack_data.load_bundle", side_effect=lambda domain, force_refresh=False: bundle(domain))
    def test_refresh_invalidates_derived_domain_combinations(self, _load):
        combined = attack_data.get_index(["enterprise", "ics"])
        refreshed = attack_data.refresh_index(["enterprise"])
        self.assertIsNot(combined, refreshed)
        self.assertIsNot(combined, attack_data.get_index(["enterprise", "ics"]))

    def test_unknown_domain_is_rejected_before_any_io(self):
        with self.assertRaisesRegex(ValueError, "Unknown ATT&CK domain: bogus"):
            attack_data.load_bundle("bogus")

    def test_loaded_index_status_reports_built_domain_sets(self):
        with patch("backend.attack_data.load_bundle", side_effect=lambda domain: bundle(domain)):
            attack_data.get_index(["enterprise"])
        status = attack_data.loaded_index_status()
        self.assertTrue(status["ready"])
        self.assertEqual(status["domain_sets"], [["enterprise"]])
        self.assertEqual(status["data_versions"], ["enterprise:bundle--enterprise"])

    def test_loaded_index_status_is_not_ready_before_any_build(self):
        status = attack_data.loaded_index_status()
        self.assertFalse(status["ready"])
        self.assertEqual(status["domain_sets"], [])


class DefaultCacheLocationTests(unittest.TestCase):
    """The per-user cache must land outside the installation on every platform."""

    def resolve(self, platform: str, environ: dict[str, str]) -> str:
        with patch.object(attack_data.sys, "platform", platform), \
                patch.dict(attack_data.os.environ, environ, clear=True):
            return attack_data._default_cache_dir()

    def test_an_explicit_override_wins_on_every_platform(self):
        for platform in ("win32", "darwin", "linux"):
            with self.subTest(platform=platform):
                resolved = self.resolve(platform, {"ADVERSARYFLOW_CACHE_DIR": "~/af-cache"})
                self.assertEqual(resolved, os.path.abspath(os.path.expanduser("~/af-cache")))

    def test_windows_uses_local_appdata(self):
        self.assertEqual(self.resolve("win32", {"LOCALAPPDATA": r"C:\Users\af\AppData\Local"}),
                         os.path.join(r"C:\Users\af\AppData\Local", "AdversaryFlow", "Cache"))

    def test_windows_falls_back_to_the_home_directory(self):
        resolved = self.resolve("win32", {})
        self.assertEqual(resolved, os.path.join(os.path.expanduser("~"), "AdversaryFlow", "Cache"))

    def test_macos_uses_the_caches_directory(self):
        self.assertEqual(self.resolve("darwin", {}),
                         os.path.expanduser("~/Library/Caches/AdversaryFlow"))

    def test_linux_honours_xdg_cache_home(self):
        self.assertEqual(self.resolve("linux", {"XDG_CACHE_HOME": "/var/tmp/xdg"}),
                         os.path.join("/var/tmp/xdg", "adversaryflow"))

    def test_linux_falls_back_to_dot_cache(self):
        self.assertEqual(self.resolve("linux", {}),
                         os.path.join(os.path.expanduser("~/.cache"), "adversaryflow"))


class DomainKeyTests(unittest.TestCase):
    def test_none_defaults_to_enterprise(self):
        self.assertEqual(attack_data._domain_key(None), ("enterprise",))

    def test_an_empty_list_defaults_to_enterprise(self):
        self.assertEqual(attack_data._domain_key([]), ("enterprise",))

    def test_duplicates_collapse_while_order_is_preserved(self):
        self.assertEqual(attack_data._domain_key(["ics", "enterprise", "ics"]),
                         ("ics", "enterprise"))


# ---------------------------------------------------------------------------
# Real STIX parsing
# ---------------------------------------------------------------------------

def present(value: dict[str, Any] | None) -> dict[str, Any]:
    """Assert a fixture lookup resolved, and narrow it for the type checker."""
    assert value is not None, "expected the fixture object to be present"
    return value


def stix_bundle() -> dict:
    """A bundle shaped like the published ATT&CK data, small enough to assert on."""
    return {
        "type": "bundle",
        "id": "bundle--fixture",
        "objects": [
            {"type": "x-mitre-matrix", "id": "x-mitre-matrix--f",
             "tactic_refs": ["x-mitre-tactic--exec", "x-mitre-tactic--disc"]},
            {"type": "x-mitre-tactic", "id": "x-mitre-tactic--exec",
             "x_mitre_shortname": "execution", "name": "Execution"},
            {"type": "x-mitre-tactic", "id": "x-mitre-tactic--disc",
             "x_mitre_shortname": "discovery", "name": "Discovery"},
            {"type": "intrusion-set", "id": "intrusion-set--zeta", "name": "Zeta Group",
             "aliases": ["Zeta Group", "Zed"], "description": "First line.\nSecond line.",
             "external_references": [
                 {"source_name": "mitre-attack", "external_id": "G0002",
                  "url": "https://attack.mitre.org/groups/G0002/"}]},
            {"type": "campaign", "id": "campaign--alpha", "name": "Alpha Campaign",
             "aliases": ["Alpha Campaign"], "description": "Campaign fixture.",
             "external_references": [
                 {"source_name": "mitre-attack", "external_id": "C0001"}]},
            {"type": "intrusion-set", "id": "intrusion-set--gone", "name": "Retired Group",
             "x_mitre_deprecated": True,
             "external_references": [{"source_name": "mitre-attack", "external_id": "G0003"}]},
            {"type": "intrusion-set", "id": "intrusion-set--idle", "name": "Idle Group",
             "external_references": [{"source_name": "mitre-attack", "external_id": "G0004"}]},
            {"type": "intrusion-set", "id": "intrusion-set--nameless", "name": "Unreferenced Group"},
            {"type": "attack-pattern", "id": "attack-pattern--ps", "name": "PowerShell",
             "description": "Adversaries may abuse PowerShell.\n\nMore detail.",
             "kill_chain_phases": [
                 {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
                 {"kill_chain_name": "lockheed", "phase_name": "ignored"}],
             "x_mitre_platforms": ["Windows"], "x_mitre_is_subtechnique": True,
             "x_mitre_data_sources": ["Command: Command Execution"],
             "x_mitre_detection": "  Watch script block logs.  ",
             "external_references": [
                 {"source_name": "mitre-attack", "external_id": "T1059.001",
                  "url": "https://attack.mitre.org/techniques/T1059/001/"}]},
            {"type": "attack-pattern", "id": "attack-pattern--sysinfo", "name": "System Information Discovery",
             "description": "Discovery fixture.",
             "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "discovery"}],
             "external_references": [{"source_name": "mitre-attack", "external_id": "T1082"}]},
            {"type": "attack-pattern", "id": "attack-pattern--revoked", "name": "Revoked Technique",
             "revoked": True,
             "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
             "external_references": [{"source_name": "mitre-attack", "external_id": "T1000"}]},
            {"type": "relationship", "relationship_type": "uses",
             "id": "relationship--1", "source_ref": "intrusion-set--zeta",
             "target_ref": "attack-pattern--ps"},
            {"type": "relationship", "relationship_type": "uses",
             "id": "relationship--2", "source_ref": "intrusion-set--zeta",
             "target_ref": "attack-pattern--ps"},
            {"type": "relationship", "relationship_type": "uses",
             "id": "relationship--3", "source_ref": "intrusion-set--zeta",
             "target_ref": "attack-pattern--sysinfo"},
            {"type": "relationship", "relationship_type": "uses",
             "id": "relationship--4", "source_ref": "intrusion-set--zeta",
             "target_ref": "attack-pattern--revoked"},
            {"type": "relationship", "relationship_type": "uses",
             "id": "relationship--5", "source_ref": "campaign--alpha",
             "target_ref": "attack-pattern--sysinfo"},
            {"type": "relationship", "relationship_type": "mitigates",
             "id": "relationship--6", "source_ref": "intrusion-set--idle",
             "target_ref": "attack-pattern--ps"},
        ],
    }


class AttackIndexTests(unittest.TestCase):
    def setUp(self):
        attack_data.clear_memory_cache()
        patcher = patch("backend.attack_data.load_bundle", side_effect=lambda domain: stix_bundle())
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(attack_data.clear_memory_cache)
        self.index = attack_data.AttackIndex(["enterprise"])

    def test_kill_chain_order_is_derived_from_the_matrix(self):
        self.assertEqual(self.index.tactic_order, ["execution", "discovery"])
        self.assertEqual(self.index.tactic_titles,
                         {"execution": "Execution", "discovery": "Discovery"})

    def test_list_actors_returns_only_mapped_non_deprecated_actors(self):
        actors = self.index.list_actors()
        self.assertEqual([a["attack_id"] for a in actors], ["C0001", "G0002"])
        self.assertEqual([a["type"] for a in actors], ["campaign", "group"])

    def test_list_actors_strips_the_self_alias_and_first_description_line(self):
        zeta = next(a for a in self.index.list_actors() if a["attack_id"] == "G0002")
        self.assertEqual(zeta["aliases"], ["Zed"])
        self.assertEqual(zeta["description"], "First line.")
        self.assertEqual(zeta["technique_count"], 3)

    def test_list_actors_excludes_actors_without_an_attack_id(self):
        self.assertNotIn("Unreferenced Group", [a["name"] for a in self.index.list_actors()])

    def test_get_actor_rejects_non_actor_objects(self):
        self.assertIsNone(self.index.get_actor("attack-pattern--ps"))
        self.assertIsNone(self.index.get_actor("does-not-exist"))
        self.assertEqual(present(self.index.get_actor("campaign--alpha"))["name"], "Alpha Campaign")

    def test_technique_parses_the_published_fields(self):
        technique = present(self.index.technique("attack-pattern--ps"))
        self.assertEqual(technique["attack_id"], "T1059.001")
        self.assertEqual(technique["tactics"], ["execution"])
        self.assertEqual(technique["platforms"], ["Windows"])
        self.assertTrue(technique["is_subtechnique"])
        self.assertEqual(technique["data_sources"], ["Command: Command Execution"])
        self.assertEqual(technique["detection"], "Watch script block logs.")
        self.assertEqual(technique["description"], "Adversaries may abuse PowerShell.")
        self.assertEqual(technique["url"], "https://attack.mitre.org/techniques/T1059/001/")

    def test_technique_rejects_revoked_and_non_technique_objects(self):
        self.assertIsNone(self.index.technique("attack-pattern--revoked"))
        self.assertIsNone(self.index.technique("intrusion-set--zeta"))
        self.assertIsNone(self.index.technique("missing"))

    def test_actor_techniques_deduplicates_and_drops_revoked(self):
        techniques = self.index.actor_techniques("intrusion-set--zeta")
        self.assertEqual(sorted(t["attack_id"] for t in techniques), ["T1059.001", "T1082"])

    def test_actor_techniques_is_empty_for_an_unmapped_actor(self):
        self.assertEqual(self.index.actor_techniques("intrusion-set--idle"), [])

    def test_only_uses_relationships_build_the_actor_map(self):
        self.assertNotIn("intrusion-set--idle", self.index.actor_uses)

    def test_attack_id_and_url_helpers_tolerate_missing_references(self):
        self.assertIsNone(attack_data.AttackIndex._attack_id({"external_references": []}))
        self.assertIsNone(attack_data.AttackIndex._url({"external_references": [
            {"source_name": "other", "url": "https://example.test"}]}))
        self.assertEqual(attack_data.AttackIndex._attack_id({"external_references": [
            {"source_name": "mitre-ics-attack", "external_id": "T0836"}]}), "T0836")

    def test_deprecation_covers_both_markers(self):
        self.assertTrue(self.index._is_deprecated({"revoked": True}))
        self.assertTrue(self.index._is_deprecated({"x_mitre_deprecated": True}))
        self.assertFalse(self.index._is_deprecated({"name": "live"}))

    def test_data_version_names_every_requested_domain(self):
        self.assertEqual(self.index.data_version, "enterprise:bundle--fixture")

    def test_first_domain_wins_on_an_object_id_collision(self):
        combined = attack_data.AttackIndex(["enterprise", "ics"])
        self.assertEqual(combined.domains, ["enterprise", "ics"])
        self.assertEqual(combined.data_version,
                         "enterprise:bundle--fixture|ics:bundle--fixture")
        self.assertEqual(combined.objects_by_id["intrusion-set--zeta"]["name"], "Zeta Group")

    def test_tactic_order_falls_back_when_the_bundle_has_no_matrix(self):
        matrixless = stix_bundle()
        matrixless["objects"] = [o for o in matrixless["objects"] if o["type"] != "x-mitre-matrix"]
        with patch("backend.attack_data.load_bundle", return_value=matrixless):
            index = attack_data.AttackIndex(["enterprise"])
        self.assertEqual(index.tactic_order, attack_data.TACTIC_ORDER)
        self.assertEqual(index.tactic_titles, attack_data.TACTIC_TITLES)


# ---------------------------------------------------------------------------
# Download, cache and provenance paths
# ---------------------------------------------------------------------------

class FakeResponse(io.BytesIO):
    headers: dict[str, str]

    def __init__(self, payload: bytes, headers: dict[str, str] | None = None):
        super().__init__(payload)
        self.headers = headers or {}


def valid_payload(bundle_id: str = "bundle--test") -> bytes:
    return json.dumps({
        "type": "bundle", "id": bundle_id,
        "objects": [{"type": "x-mitre-matrix", "id": "x-mitre-matrix--t", "tactic_refs": []}],
    }).encode()


class CacheLifecycleTests(unittest.TestCase):
    def setUp(self):
        attack_data.clear_memory_cache()
        attack_data.configure_offline(False)
        self.original = attack_data.CACHE_DIR
        self.directory = tempfile.TemporaryDirectory()
        attack_data.configure_cache_dir(self.directory.name)
        self.path = attack_data._cache_path("enterprise")
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(attack_data.configure_cache_dir, self.original)
        self.addCleanup(attack_data.configure_offline, False)
        self.addCleanup(attack_data.clear_memory_cache)

    def seed_cache(self, payload: bytes | None = None) -> bytes:
        payload = payload if payload is not None else valid_payload()
        os.makedirs(self.directory.name, exist_ok=True)
        with open(self.path, "wb") as handle:
            handle.write(payload)
        attack_data._write_metadata("enterprise", {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "etag": '"seeded"', "source_url": "https://example.test/bundle.json",
        })
        return payload

    def test_not_modified_reuses_the_cached_bundle(self):
        self.seed_cache()
        error = urllib.error.HTTPError("https://example.test", 304, "Not Modified", email.message.Message(), None)
        with patch("backend.attack_data.urllib.request.urlopen", side_effect=error):
            metadata = attack_data._download("https://example.test/b.json", self.path, "enterprise")
        self.assertFalse(metadata["stale"])
        self.assertIn("checked_at", metadata)
        self.assertEqual(attack_data._read_metadata("enterprise")["etag"], '"seeded"')

    def test_a_non_304_http_error_propagates(self):
        error = urllib.error.HTTPError("https://example.test", 500, "Server Error", email.message.Message(), None)
        with patch("backend.attack_data.urllib.request.urlopen", side_effect=error), self.assertRaises(urllib.error.HTTPError):
            attack_data._download("https://example.test/b.json", self.path, "enterprise")

    def test_a_declared_length_over_the_limit_is_refused(self):
        payload = valid_payload()
        response = FakeResponse(payload, {"Content-Length": str(attack_data.MAX_BUNDLE_BYTES + 1)})
        with patch("backend.attack_data.urllib.request.urlopen", return_value=response), \
                self.assertRaisesRegex(ValueError, "exceeds the"):
            attack_data._download("https://example.test/b.json", self.path, "enterprise")
        self.assertFalse(os.path.exists(self.path))

    def test_a_stream_over_the_limit_is_refused_mid_download(self):
        payload = valid_payload()
        response = FakeResponse(payload, {})
        with patch.object(attack_data, "MAX_BUNDLE_BYTES", 4), \
                patch("backend.attack_data.urllib.request.urlopen", return_value=response), \
                self.assertRaisesRegex(ValueError, "exceeds the"):
            attack_data._download("https://example.test/b.json", self.path, "enterprise")
        self.assertFalse(os.path.exists(self.path))

    def test_a_downloaded_non_bundle_never_replaces_the_cache(self):
        response = FakeResponse(b'{"type": "not-a-bundle"}', {})
        with patch("backend.attack_data.urllib.request.urlopen", return_value=response), \
                self.assertRaisesRegex(ValueError, "not a STIX bundle"):
            attack_data._download("https://example.test/b.json", self.path, "enterprise")
        self.assertFalse(os.path.exists(self.path))

    def test_a_bundle_without_a_matrix_is_refused(self):
        with self.assertRaisesRegex(ValueError, "contains no matrix"):
            attack_data._validate_bundle(
                {"type": "bundle", "objects": [{"type": "intrusion-set"}]}, "enterprise")

    def test_an_empty_object_list_is_refused(self):
        with self.assertRaisesRegex(ValueError, "contains no objects"):
            attack_data._validate_bundle({"type": "bundle", "objects": []}, "enterprise")

    def test_a_checksum_mismatch_is_detected_on_load(self):
        self.seed_cache()
        with open(self.path, "wb") as handle:
            handle.write(valid_payload("bundle--tampered"))
        with self.assertRaisesRegex(ValueError, "does not match its recorded SHA-256"):
            attack_data._load_validated(self.path, "enterprise")

    def test_a_failed_refresh_serves_the_stale_cache_and_records_the_error(self):
        self.seed_cache()
        os.utime(self.path, (0, 0))  # force the freshness check to want a download
        with patch("backend.attack_data._download", side_effect=OSError("network down")):
            bundle_data = attack_data.load_bundle("enterprise")
        self.assertEqual(bundle_data["id"], "bundle--test")
        status = attack_data.cache_status()["domains"]["enterprise"]["metadata"]
        self.assertTrue(status["stale"])
        self.assertIn("network down", status["refresh_error"])

    def test_a_failed_first_download_with_no_cache_propagates(self):
        with patch("backend.attack_data._download", side_effect=OSError("network down")), self.assertRaises(OSError):
            attack_data.load_bundle("enterprise")

    def test_a_corrupt_cache_triggers_an_unconditional_redownload(self):
        with open(self.path, "wb") as handle:
            handle.write(b"not json at all")
        replacement = valid_payload("bundle--repaired")

        def repair(url, dest, domain, conditional=True):
            self.assertFalse(conditional)
            with open(dest, "wb") as handle:
                handle.write(replacement)
            return {}

        with patch("backend.attack_data._download", side_effect=repair):
            bundle_data = attack_data.load_bundle("enterprise")
        self.assertEqual(bundle_data["id"], "bundle--repaired")

    def test_offline_refresh_is_refused(self):
        self.seed_cache()
        attack_data.configure_offline(True)
        with self.assertRaisesRegex(RuntimeError, "cannot refresh .* while offline"):
            attack_data.load_bundle("enterprise", force_refresh=True)

    def test_offline_load_of_a_corrupt_cache_is_actionable(self):
        with open(self.path, "wb") as handle:
            handle.write(b"not json at all")
        attack_data.configure_offline(True)
        with self.assertRaisesRegex(RuntimeError, "is invalid; reconnect and refresh"):
            attack_data.load_bundle("enterprise")

    def test_offline_serves_a_valid_cache_without_network_access(self):
        self.seed_cache()
        attack_data.configure_offline(True)
        with patch("backend.attack_data.urllib.request.urlopen",
                   side_effect=AssertionError("offline mode must not reach the network")):
            self.assertEqual(attack_data.load_bundle("enterprise")["id"], "bundle--test")

    def test_a_fresh_cache_is_reused_without_downloading(self):
        self.seed_cache()
        with patch("backend.attack_data._download",
                   side_effect=AssertionError("a fresh cache must not be re-downloaded")):
            self.assertEqual(attack_data.load_bundle("enterprise")["id"], "bundle--test")

    def test_memory_cache_short_circuits_a_second_load(self):
        self.seed_cache()
        first = attack_data.load_bundle("enterprise")
        with patch("backend.attack_data._load_validated",
                   side_effect=AssertionError("the memory cache must serve the second load")):
            self.assertIs(attack_data.load_bundle("enterprise"), first)

    def test_cache_status_reports_freshness_and_provenance(self):
        self.seed_cache()
        status = attack_data.cache_status()
        self.assertEqual(status["cache_dir"], self.directory.name)
        enterprise = status["domains"]["enterprise"]
        self.assertTrue(enterprise["exists"])
        self.assertTrue(enterprise["fresh"])
        self.assertLess(enterprise["age_seconds"], attack_data.CACHE_TTL_SECONDS)
        self.assertEqual(enterprise["metadata"]["etag"], '"seeded"')
        self.assertFalse(status["domains"]["ics"]["exists"])

    def test_unreadable_metadata_degrades_to_an_empty_record(self):
        with open(attack_data._metadata_path("enterprise"), "w", encoding="utf-8") as handle:
            handle.write("[not, a, dict")
        self.assertEqual(attack_data._read_metadata("enterprise"), {})

    def test_non_dict_metadata_degrades_to_an_empty_record(self):
        with open(attack_data._metadata_path("enterprise"), "w", encoding="utf-8") as handle:
            handle.write("[1, 2, 3]")
        self.assertEqual(attack_data._read_metadata("enterprise"), {})

    def test_clear_disk_cache_removes_only_known_files(self):
        self.seed_cache()
        unrelated = os.path.join(self.directory.name, "unrelated.json")
        with open(unrelated, "w", encoding="utf-8") as handle:
            handle.write("{}")
        removed = attack_data.clear_disk_cache()
        self.assertEqual(sorted(removed),
                         sorted([self.path, attack_data._metadata_path("enterprise")]))
        self.assertFalse(os.path.exists(self.path))
        self.assertTrue(os.path.exists(unrelated))

    def test_clear_disk_cache_is_a_no_op_when_nothing_is_cached(self):
        self.assertEqual(attack_data.clear_disk_cache(), [])

    def test_clear_disk_cache_also_drops_the_in_memory_bundle(self):
        self.seed_cache()
        attack_data.load_bundle("enterprise")
        self.assertIn("enterprise", attack_data._MEM_CACHE)
        attack_data.clear_disk_cache()
        self.assertNotIn("enterprise", attack_data._MEM_CACHE)

    def test_cache_freshness_uses_the_configured_ttl(self):
        self.seed_cache()
        self.assertTrue(attack_data._cache_is_fresh(self.path))
        os.utime(self.path, (0, 0))
        self.assertFalse(attack_data._cache_is_fresh(self.path))
        self.assertFalse(attack_data._cache_is_fresh(os.path.join(self.directory.name, "nope.json")))

    def test_metadata_is_written_atomically_without_leftovers(self):
        attack_data._write_metadata("enterprise", {"sha256": "abc"})
        self.assertEqual(attack_data._read_metadata("enterprise"), {"sha256": "abc"})
        leftovers = [name for name in os.listdir(self.directory.name) if name.endswith(".tmp")]
        self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
