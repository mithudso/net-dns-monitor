"""Journal archive boundaries preserve quoted prompt examples."""

import pytest

from scripts.rotate_workflow_logs import split_sections


@pytest.mark.parametrize("fence", ["```", "~~~~", "    ```"])
def test_fenced_version_examples_stay_with_their_entry(fence):
    text = (
        f"# Journal\n\n## v1 - old\n\n{fence}markdown\n## v999 - sample\n{fence}\n\n## v2 - new\n"
    )
    header, sections = split_sections(text)
    # Four-space indented backticks are not a Markdown fence.
    assert len(sections) == (3 if fence.startswith("    ") else 2)
    assert header == "# Journal\n\n"
    assert header + "".join(sections) == text
    if not fence.startswith("    "):
        assert "## v999 - sample" in sections[0]


def test_shorter_or_other_fence_does_not_end_a_quoted_entry():
    text = "## v1\n````markdown\n```\n~~~\n## v999\n````\n## v2\n"
    _, sections = split_sections(text)
    assert len(sections) == 2
    assert "## v999" in sections[0]


def test_unclosed_fence_keeps_remaining_text_in_its_entry():
    text = "## v1\n```markdown\n## v999\n"
    _, sections = split_sections(text)
    assert sections == [text]


@pytest.mark.parametrize("keep", [0, -1])
def test_rotation_rejects_invalid_keep_before_writing(tmp_path, keep):
    from scripts.rotate_workflow_logs import rotate

    journal = tmp_path / "journal.md"
    original = "# Journal\n## v1\nold\n## v2\nnew\n"
    journal.write_text(original)
    archive = tmp_path / "archive"
    with pytest.raises(ValueError, match="keep"):
        rotate(journal, archive, max_bytes=0, keep=keep)
    assert journal.read_text() == original
    assert not archive.exists()
