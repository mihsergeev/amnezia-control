import json
import shutil
import sys
from pathlib import Path

import pytest

pytest.importorskip("fcntl")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import acontrol_updater as worker


class PanelFixture:
    services = ("db", "backend", "frontend")
    source_files = ("compose.yml",)
    previous = "0.84.84"
    target = "0.84.85"

    def __init__(self, root):
        self.root = root
        self.store = root / worker.STORE
        self.store.mkdir()
        self.data = root / "data"
        self.data.mkdir()
        self.fixture = self.data / "fixture"
        self.fixture.write_text("original")
        self.old_images = {"backend": "original"}
        self.old_ids = {"backend": "original-id"}
        self.new_images = {"backend": "candidate", "frontend": "frontend"}
        self.pins(self.old_images)
        for filename in (".env", *self.source_files, worker.OVERLAY):
            (root / filename).touch()
        self.stops = 0
        self.fail_shadow = False
        self.fail_promotion = False
        self.fail_rollback = False
        self.head = "0043"
        self.installed = self.previous

    def version(self):
        return self.installed

    def check_inputs(self):
        pass

    def check_space(self):
        pass

    def validate(self, previous, target, commit):
        assert previous == self.previous and target == self.target and commit == "source"
        return self.old_images, self.old_ids

    def revision(self):
        return self.head

    def docker(self, operation, image, *, timeout):
        assert operation == "pull" and image in self.new_images.values()

    def candidate_revision(self, image, target):
        assert target == self.target and image == self.new_images["backend"]
        return self.head

    def configured_images(self):
        return json.loads((self.root / worker.PINS).read_text())

    def check_active_images(self, images):
        assert self.configured_images() == images
        return self.local_image_ids(images)

    def local_image_ids(self, images):
        return {service: f"{image}-id" for service, image in images.items()}

    def pins(self, images, *, preview=False):
        (self.root / worker.PINS).write_text(json.dumps(images))

    def stop(self):
        self.stops += 1

    def copy_data(self, destination):
        shutil.copytree(self.data, destination)

    def remove_shadow(self, _job):
        pass

    def start_data_services(self):
        self.start("db")

    def start(self, *services):
        candidate = self.configured_images() == self.new_images
        if not candidate and self.fail_rollback:
            raise RuntimeError("previous stack unavailable")
        self.installed = self.target if candidate else self.previous
        if candidate and services == ("frontend",) and self.fail_promotion:
            self.fixture.write_text("accepted post-update write")
            raise RuntimeError("proxy failed")

    def check_candidate_frontend(self, _job, image):
        assert image == self.new_images["frontend"]
        if self.fail_shadow:
            self.fixture.write_text("candidate-only write")
            raise worker.Refused("health_failed")

    def check_frontend(self):
        pass


@pytest.fixture
def updater(tmp_path, monkeypatch):
    panel = PanelFixture(tmp_path)
    monkeypatch.setattr(worker, "trusted", lambda path, **_options: path)
    monkeypatch.setattr(worker, "verify_release", lambda target: (panel.new_images, "source"))
    return worker.Updater(panel)


JOB = "0" * 32


def install(updater):
    updater.journal(phase="queued", job=JOB, version=updater.panel.target, stopped=False, promoted=False)
    updater.update(JOB, updater.panel.target)


def test_success_keeps_the_original_database_and_config(updater):
    panel = updater.panel
    install(updater)
    assert updater.status() == {"phase": "succeeded", "version": panel.target, "error": None}
    assert panel.configured_images() == panel.new_images
    assert panel.fixture.read_text() == "original"
    assert (panel.store / JOB / "data.previous" / "fixture").read_text() == "original"
    assert (panel.store / JOB / "config" / worker.PINS).exists()
    assert panel.stops == 1


def test_cannot_change_the_running_panel_with_unverified_images(updater, monkeypatch):
    def reject(_version):
        raise ValueError("invalid signature")

    monkeypatch.setattr(worker, "verify_release", reject)
    panel = updater.panel
    install(updater)
    assert updater.status()["error"] == "verification_failed"
    assert updater.status()["phase"] == "failed"
    assert panel.stops == 0
    assert panel.configured_images() == panel.old_images
    assert not (panel.store / JOB).exists()


def test_early_failure_restores_original_files_and_images(updater):
    panel = updater.panel
    panel.fail_shadow = True
    install(updater)
    assert updater.status()["phase"] == "rolled_back"
    assert updater.status()["error"] == "health_failed"
    assert panel.installed == panel.previous
    assert panel.fixture.read_text() == "original"
    assert (panel.store / JOB / "data.failed" / "fixture").read_text() == "candidate-only write"


def test_late_failure_preserves_accepted_writes_during_rollback(updater):
    panel = updater.panel
    panel.fail_promotion = True
    install(updater)
    assert updater.status()["phase"] == "rolled_back"
    assert panel.installed == panel.previous
    assert panel.fixture.read_text() == "accepted post-update write"
    assert (panel.store / JOB / "data.previous" / "fixture").read_text() == "original"


def test_recovery_restarts_after_interrupted_data_swap(updater):
    panel = updater.panel
    job = panel.store / JOB
    (job / "config").mkdir(parents=True)
    shutil.copy2(panel.root / worker.PINS, job / "config" / worker.PINS)
    panel.data.rename(job / "data.previous")
    updater.journal(phase="backing_up", job=JOB, version=panel.target, stopped=True, promoted=False,
                    images=panel.old_images, image_ids=panel.old_ids, previous=panel.previous)
    new_worker = worker.Updater(panel)
    new_worker.restore("interrupted")
    assert new_worker.status()["phase"] == "rolled_back"
    assert panel.fixture.read_text() == "original"
    assert panel.configured_images() == panel.old_images


def test_recovery_can_be_retried_after_docker_error(updater):
    panel = updater.panel
    panel.fail_shadow = True
    panel.fail_rollback = True
    install(updater)
    assert updater.status()["phase"] == "recovery_required"
    assert updater.install(panel.target)["accepted"] is False
    panel.fail_rollback = False
    updater.restore("interrupted")
    assert updater.status()["phase"] == "rolled_back"
    assert panel.fixture.read_text() == "original"
