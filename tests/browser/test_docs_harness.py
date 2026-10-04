"""The documentation screenshot helper: one call outlines the control the
text talks about, saves a padded crop around it, and cleans up."""

import pytest
from PIL import Image

from .docs_shots import replace_text, shoot

_BOX = ('<div id="box" style="margin:100px;width:200px;height:50px">'
        '<button id="go">Go</button></div>')
_FADE = ('<div id="fade" style="margin:50px;width:100px;height:40px;'
         'background-color:rgb(255, 255, 255);transition:background-color 30s linear"></div>')
_TIMES = '<div id="times"><p>made 2026-10-04 13:56</p><p>seen <b>2026-10-04 13:57</b></p></div>'


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


@pytest.mark.browser
def test_shoot_finishes_a_colour_fade_first(page, tmp_path):
    """A control just clicked or typed in is often still fading to its new
    colour; a picture taken mid-fade differs from run to run."""
    page.set_content(_FADE)
    page.locator("#fade").evaluate(
        "el => { getComputedStyle(el).backgroundColor;"
        " el.style.backgroundColor = 'rgb(0, 0, 255)'; }"
    )

    out = shoot(page, tmp_path / "fade.png", page.locator("#fade"), pad=0)

    assert Image.open(out).convert("RGB").getpixel((50, 20)) == (0, 0, 255)


@pytest.mark.browser
def test_replace_text_swaps_each_match_in_page_order(page):
    page.set_content(_TIMES)

    replace_text(page.locator("#times"), r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}",
                 ["2026-03-10 10:12", "2026-03-10 10:13"])

    assert page.locator("#times p").all_text_contents() == [
        "made 2026-03-10 10:12", "seen 2026-03-10 10:13"]


@pytest.mark.browser
def test_replace_text_fails_and_changes_nothing_when_the_count_differs(page):
    page.set_content(_TIMES)

    with pytest.raises(AssertionError, match="matched 2 times, not 1"):
        replace_text(page.locator("#times"), r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}",
                     ["2026-03-10 10:12"])

    assert page.locator("#times p").all_text_contents() == [
        "made 2026-10-04 13:56", "seen 2026-10-04 13:57"]
