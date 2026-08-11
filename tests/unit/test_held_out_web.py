# SPDX-License-Identifier: Apache-2.0
"""Representative owned website fixture and capsule tests."""

from __future__ import annotations

import http.cookiejar
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING

import pytest

from sova.formats import PackageReader, strict_json_loads
from sova.formats.errors import FormatError
from sova.live import (
    OwnedWebMatrixFixture,
    WebApplicationClass,
    build_web_matrix_capsule,
)

if TYPE_CHECKING:
    from pathlib import Path


def _read(url: str, *, opener: urllib.request.OpenerDirector | None = None) -> str:
    selected = opener or urllib.request.build_opener()
    with selected.open(url, timeout=5) as response:
        value: str = response.read().decode()
        return value


def test_owned_web_matrix_serves_static_spa_popup_and_cookie_bound_authentication() -> None:
    with OwnedWebMatrixFixture() as fixture:
        assert "SOVA owned static fixture" in _read(fixture.url(WebApplicationClass.STATIC))
        assert "SPA_READY" in _read(fixture.url(WebApplicationClass.SPA))
        assert "Fixture consent" in _read(fixture.url(WebApplicationClass.POPUP))

        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        assert "Sign in to fixture" in _read(
            fixture.url(WebApplicationClass.AUTHENTICATED),
            opener=opener,
        )
        request = urllib.request.Request(  # noqa: S310 - exact self-owned loopback fixture
            fixture.origin + "/auth/login",
            data=urllib.parse.urlencode(
                {"username": "fixture-user", "password": "fixture-password"}
            ).encode(),
            method="POST",
        )
        with opener.open(request, timeout=5) as response:
            authenticated = response.read().decode()
        assert "SOVA owned authenticated app" in authenticated
        assert any(cookie.name == "sova_matrix_session" for cookie in jar)


@pytest.mark.parametrize("application_class", tuple(WebApplicationClass))
def test_web_matrix_capsules_are_portable_and_class_specific(
    tmp_path: Path,
    application_class: WebApplicationClass,
) -> None:
    with OwnedWebMatrixFixture() as fixture:
        capsule = tmp_path / f"{application_class.value}.sova"
        build_web_matrix_capsule(application_class, fixture.url(application_class), capsule)
    reader = PackageReader(capsule)
    descriptors = reader.verify("sova.capsule")
    scenario_descriptor = next(item for item in descriptors if item.role == "scenario")
    scenario = strict_json_loads(reader.read_object(scenario_descriptor))
    assert scenario["extensions"]["x-sova-web-matrix"]["applicationClass"] == (
        application_class.value
    )
    assert scenario["oracles"][0]["contains"] == "SOVA_MATRIX_TRIGGERED"
    assert scenario["limitations"][0].endswith("not universal website compatibility.")


def test_web_matrix_capsule_refuses_non_loopback_targets(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="loopback"):
        build_web_matrix_capsule(
            WebApplicationClass.STATIC,
            "https://example.com/",
            tmp_path / "external.sova",
        )
