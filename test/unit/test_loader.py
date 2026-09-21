import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "speakeasy_service", "vendor", "speakeasy-src"))

from speakeasy.windows.winemu import coalesce_page_perms  # noqa: E402

PAGE = 0x1000


def test_adjacent_pages_with_equal_permissions_become_one_call():
    pages = {0x1000 + i * PAGE: 3 for i in range(8000)}  # a ~32 MB section
    assert coalesce_page_perms(pages, PAGE) == [(0x1000, 8000 * PAGE, 3)]


def test_permission_changes_and_gaps_start_a_new_run():
    pages = {0x1000: 1, 0x2000: 1, 0x3000: 5, 0x5000: 5, 0x6000: 5}
    assert coalesce_page_perms(pages, PAGE) == [(0x1000, 2 * PAGE, 1), (0x3000, PAGE, 5), (0x5000, 2 * PAGE, 5)]


def test_input_order_does_not_matter():
    assert coalesce_page_perms({0x3000: 1, 0x1000: 1, 0x2000: 1}, PAGE) == [(0x1000, 3 * PAGE, 1)]


def test_empty():
    assert coalesce_page_perms({}, PAGE) == []
