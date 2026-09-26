"""The documentation screenshot helper: one call outlines the control the
text talks about, saves a padded crop around it, and cleans up."""

import pytest
from PIL import Image

from .docs_shots import shoot

_BOX = ('<div id="box" style="margin:100px;width:200px;height:50px">'
        '<button id="go">Go</button></div>')


@pytest.mark.browser
def test_shoot_saves_a_padded_crop_of_the_region(page, tmp_path):
    page.set_viewport_size({"width": 800, "height": 600})
    page.set_content(_BOX)

    out = shoot(page, tmp_path / "a" / "b.png", page.locator("#go"),
                region=page.locator("#box"), pad=10)

    assert out == tmp_path / "a" / "b.png" and out.exists()
    assert Image.open(out).size == (220, 70)


@pytest.mark.browser
def test_shoot_removes_the_outline_afterwards(page, tmp_path):
    page.set_content(_BOX)

    shoot(page, tmp_path / "c.png", page.locator("#go"))

    assert page.locator("#go").evaluate("el => el.style.outline") == ""


@pytest.mark.browser
def test_shoot_fails_and_writes_nothing_when_the_target_is_missing(page, tmp_path):
    page.set_content("<p>nothing here</p>")

    with pytest.raises(AssertionError):
        shoot(page, tmp_path / "x.png", page.locator("#missing"))

    assert not (tmp_path / "x.png").exists()
