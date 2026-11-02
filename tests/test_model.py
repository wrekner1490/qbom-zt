from qbom.model import Component, Finding, QBOM


def test_finding_location_id():
    f = Finding("MD5", "HASH", "a/b.py", 10, "hashlib.md5(x)", "test")
    assert f.location_id == "a/b.py:10"


def test_finding_salt_excluded_from_public_dict():
    f = Finding("MD5", "HASH", "a/b.py", 10, "snippet", "test")
    d = f.to_public_dict()
    assert "salt" not in d
    assert d["catalog_id"] == "MD5"


def test_finding_salts_are_random_per_instance():
    f1 = Finding("MD5", "HASH", "a.py", 1, "x", "t")
    f2 = Finding("MD5", "HASH", "a.py", 1, "x", "t")
    assert f1.salt != f2.salt


def test_qbom_counts_and_by_catalog_id():
    q = QBOM(org="test")
    q.add_finding(Finding("MD5", "HASH", "a.py", 1, "x", "t"))
    q.add_finding(Finding("MD5", "HASH", "b.py", 2, "x", "t"))
    q.add_finding(Finding("SHA1", "HASH", "c.py", 3, "x", "t"))
    counts = q.counts()
    assert counts["MD5"] == 2
    assert counts["SHA1"] == 1
    assert len(q.by_catalog_id()["MD5"]) == 2


def test_qbom_to_dict_json_serializable():
    q = QBOM(org="test")
    q.add_component(Component("svc", exposure="internet_facing"))
    q.add_finding(Finding("MD5", "HASH", "a.py", 1, "x", "t", component="svc"))
    d = q.to_dict()
    assert d["org"] == "test"
    assert "svc" in d["components"]
    js = q.to_json()
    assert '"MD5"' in js
    assert "salt" not in js  # never serialize secrets into the QBOM export either
