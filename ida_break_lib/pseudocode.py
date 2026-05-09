import logging
from collections import Counter

from PySide6 import QtCore, QtGui, QtWidgets
try:
    import numpy as np
except Exception:  # pragma: no cover - IDA bundles numpy, but keep a safe fallback.
    np = None

from ida_break_lib.game import Brick


logger = logging.getLogger(__name__)


def sample_viewport_bg_colors(viewport, max_colors=4, min_count_pct=0.02, dedupe_dist=60, grab=None):
    """Return up to `max_colors` distinct dominant colors in the viewport image,
    sorted by frequency. The first one is the primary background; subsequent
    ones are typically the current-line highlight, selection background,
    indent-guide color, etc.

    Treating ALL of these as "not ink" prevents the brick detector from picking
    up empty highlighted regions as fake bricks.

    - Coarse 4x grid sampling for speed.
    - 5-bit-per-channel quantization to merge anti-aliasing variants.
    - `dedupe_dist` Manhattan distance threshold prevents near-identical colors.
    - `grab` lets the caller share an already-captured viewport buffer; saves
      a re-grab when the brick detector is going to run right after.
    """
    if grab is None:
        if viewport is None:
            return []
        grab = grab_viewport_buffer(viewport)
        if grab is None:
            return []
    buf, w, h, _dpr = grab

    counter = Counter()
    step = 4
    for y in range(0, h, step):
        row_off = y * w * 4
        for x in range(0, w, step):
            off = row_off + x * 4
            key = (buf[off + 2] & 0xF8, buf[off + 1] & 0xF8, buf[off] & 0xF8)
            counter[key] += 1

    if not counter:
        return []

    total = sum(counter.values())
    threshold = max(1, int(total * min_count_pct))

    result = []
    for (r, g, b), count in counter.most_common(max_colors * 8):
        if count < threshold:
            break
        if any(
            abs(r - rc.red()) + abs(g - rc.green()) + abs(b - rc.blue()) <= dedupe_dist
            for rc in result
        ):
            continue
        c = QtGui.QColor(r, g, b)
        if not c.isValid():
            continue
        result.append(c)
        if len(result) >= max_colors:
            break
    return result


_KNOWN_OUTER_VIEWERS = (
    "TEAViewer",
    "TGraphViewer",
)


_KNOWN_CUSTOM_CONTROLS = (
    "TCustomControl",
    "IDACustomViewer",
    "IDACustomControl",
    "PyCustomViewer",
)


_VIEWER_CLASS_HINTS = ("Viewer", "Editor", "TEA")


def _dump_widget_tree(qwidget, depth=0, max_depth=4):
    """Log the widget hierarchy under qwidget so we can identify the render surface."""
    if qwidget is None or depth > max_depth:
        return
    indent = "  " * depth
    try:
        cls = qwidget.metaObject().className()
        geom = (qwidget.x(), qwidget.y(), qwidget.width(), qwidget.height())
        font = qwidget.font().family()
        logger.info("ida-break: %s%s geom=%s font=%s", indent, cls, geom, font)
    except Exception:
        logger.exception("dump_widget_tree failed at depth %d", depth)
        return
    for child in qwidget.findChildren(
        QtWidgets.QWidget, options=QtCore.Qt.FindDirectChildrenOnly
    ):
        _dump_widget_tree(child, depth + 1, max_depth)


def find_pseudocode_viewport(qwidget):
    """Return the QWidget that actually paints the pseudocode text plus the
    enclosing scroll-bar host if there is one.

    Strategy:
      1. QAbstractScrollArea + viewport() — works for QPlainTextEdit-style hosts.
      2. Match a known IDA custom-viewer class by name (TCustomControl, etc.).
      3. Pick the largest descendant QWidget that has a real geometry.
      4. Fall back to the outer qwidget itself.

    Always emits diagnostic logs so we can adapt to unknown IDA builds.
    """
    if qwidget is None:
        return None, None

    logger.info(
        "ida-break: find_pseudocode_viewport: outer class=%s size=%dx%d font=%s",
        qwidget.metaObject().className(),
        qwidget.width(),
        qwidget.height(),
        qwidget.font().family(),
    )
    logger.info("ida-break: widget tree:")
    _dump_widget_tree(qwidget)

    cls_name = qwidget.metaObject().className()
    if cls_name in _KNOWN_OUTER_VIEWERS or any(h in cls_name for h in _VIEWER_CLASS_HINTS):
        outer_area = max(1, qwidget.width() * qwidget.height())
        biggest = None
        biggest_area = 0
        for child in qwidget.findChildren(
            QtWidgets.QWidget, options=QtCore.Qt.FindDirectChildrenOnly
        ):
            if not child.isVisible():
                continue
            r = child.geometry()
            a = r.width() * r.height()
            if a > biggest_area:
                biggest_area = a
                biggest = child
        if biggest is not None and biggest_area >= outer_area * 0.5:
            logger.info(
                "ida-break: using main-content child of %s as viewport: %s geom=%s",
                cls_name,
                biggest.metaObject().className(),
                (biggest.x(), biggest.y(), biggest.width(), biggest.height()),
            )
            return biggest, None
        logger.info(
            "ida-break: using outer widget directly as viewport: %s", cls_name
        )
        return qwidget, None

    scroll_areas = qwidget.findChildren(QtWidgets.QAbstractScrollArea)
    if scroll_areas:
        sa = scroll_areas[0]
        vp = sa.viewport()
        if vp is not None:
            logger.info(
                "ida-break: picked viewport via QAbstractScrollArea: %s (sa=%s)",
                vp.metaObject().className(), sa.metaObject().className(),
            )
            return vp, sa

    all_widgets = qwidget.findChildren(QtWidgets.QWidget)
    for w in all_widgets:
        try:
            cls = w.metaObject().className()
        except Exception:
            continue
        if cls in _KNOWN_CUSTOM_CONTROLS or "CustomViewer" in cls or "CustomControl" in cls:
            logger.info("ida-break: picked viewport via known-class match: %s", cls)
            return w, None

    candidate = None
    best_area = qwidget.width() * qwidget.height() // 4
    for w in all_widgets:
        try:
            area = w.width() * w.height()
        except Exception:
            continue
        if area > best_area and w.isVisible():
            candidate = w
            best_area = area
    if candidate is not None:
        logger.info(
            "ida-break: picked viewport via largest-visible-child: %s area=%d",
            candidate.metaObject().className(), best_area,
        )
        return candidate, None

    logger.warning(
        "ida-break: no good child found; falling back to outer widget %s",
        qwidget.metaObject().className(),
    )
    return qwidget, None


def compute_playfield_height(viewport):
    """Return the y-coordinate of the topmost bottom-anchored child widget,
    or the full viewport height if none. Lets the game floor sit just above
    a status bar / footer.
    """
    if viewport is None:
        return 0
    h = viewport.height()
    eff = h
    try:
        for child in viewport.findChildren(
            QtWidgets.QWidget, options=QtCore.Qt.FindDirectChildrenOnly
        ):
            if not child.isVisible():
                continue
            r = child.geometry()
            if r.y() + r.height() >= h - 5 and r.y() > h // 2:
                eff = min(eff, r.y())
    except Exception:
        logger.exception("compute_playfield_height failed")
    return eff


def grab_viewport_buffer(viewport):
    """Return (rgba_bytes, width, height, dpr) for fast pixel access, or None.

    On HiDPI / Retina, viewport.grab() returns a pixmap sized in *device*
    pixels (2x logical on macOS Retina). The QImage we get from .toImage()
    is the same device-pixel size. The dpr lets the caller convert back
    to logical (Qt overlay) coordinates.

    Qt binding builds vary: constBits() returns sip.voidptr in older PyQt5
    (needs setsize) and memoryview in PySide6 / newer PyQt5 (already sized).
    Handle both for safety.
    """
    if viewport is None:
        return None
    try:
        pixmap = viewport.grab()
        if pixmap.isNull():
            return None
        img = pixmap.toImage().convertToFormat(QtGui.QImage.Format_RGB32)
        if img.isNull() or img.width() < 4 or img.height() < 4:
            return None
        w, h = img.width(), img.height()
        try:
            logical_w = max(1, viewport.width())
            dpr = w / float(logical_w)
        except Exception:
            dpr = 1.0
        if dpr <= 0:
            dpr = 1.0
        ptr = img.constBits()
        if hasattr(ptr, "setsize"):
            n = img.sizeInBytes() if hasattr(img, "sizeInBytes") else img.byteCount()
            ptr.setsize(n)
        return bytes(ptr), w, h, dpr
    except Exception:
        logger.exception("grab_viewport_buffer failed")
        return None


def detect_bricks_from_pixels(
    viewport,
    bg_colors,
    color_threshold=40,
    column_gap_tolerance=4,
    line_gap_tolerance=1,
    min_run_w=2,
    min_run_h=2,
    padding=1,
    max_run_w_ratio=0.6,
    grab=None,
):
    """Build bricks by scanning the viewport image for ink (non-background) pixels.

    `bg_colors` is a list of QColor; a pixel is "ink" only if it differs from
    *all* of them by more than `color_threshold`. This keeps the
    current-line-highlight, selection, etc. from being mistaken for text.

    `max_run_w_ratio` drops bricks wider than that fraction of the viewport,
    which would otherwise be a full-line highlight rather than a real token.

    `grab` lets the caller share an already-captured viewport buffer with the
    bg-color sampler (avoids a second viewport.grab() round-trip on cold start).
    """
    if not bg_colors:
        return []
    if isinstance(bg_colors, QtGui.QColor):
        bg_colors = [bg_colors]
    if grab is None:
        grab = grab_viewport_buffer(viewport)
        if grab is None:
            return []
    buf, w, h, dpr = grab
    logger.info(
        "ida-break: grab: %dx%d dpr=%.2f bg_colors=%s",
        w, h, dpr,
        [(c.red(), c.green(), c.blue()) for c in bg_colors],
    )

    masked_rects = []
    for child in viewport.findChildren(
        QtWidgets.QWidget, options=QtCore.Qt.FindDirectChildrenOnly
    ):
        if not child.isVisible():
            continue
        r = child.geometry()
        if r.width() > 0 and r.height() > 0:
            masked_rects.append(r)
    if masked_rects:
        logger.info(
            "ida-break: masking child rects: %s",
            [(r.x(), r.y(), r.width(), r.height()) for r in masked_rects],
        )

    bg_channels = tuple((c.blue(), c.green(), c.red()) for c in bg_colors)

    ink_mask = None
    if np is not None:
        pixels = np.frombuffer(buf, dtype=np.uint8).reshape(h, w, 4)[..., :3].astype(
            np.int16, copy=False
        )
        bg = np.asarray(bg_channels, dtype=np.int16)
        diff = np.abs(pixels[:, :, None, :] - bg[None, None, :, :]).sum(axis=3)
        ink_mask = ~np.any(diff <= color_threshold, axis=2)
        row_has_ink = ink_mask[:, ::2].any(axis=1)
    else:
        def is_ink(off):
            b = buf[off]
            g = buf[off + 1]
            r = buf[off + 2]
            for bg_b, bg_g, bg_r in bg_channels:
                if (abs(r - bg_r) + abs(g - bg_g) + abs(b - bg_b)) <= color_threshold:
                    return False
            return True

        row_has_ink = bytearray(h)
        for y in range(h):
            base = y * w * 4
            for x in range(0, w, 2):
                if is_ink(base + x * 4):
                    row_has_ink[y] = 1
                    break

    line_ranges = []
    y = 0
    while y < h:
        if row_has_ink[y]:
            start = y
            while y < h and row_has_ink[y]:
                y += 1
            end = y
            while line_ranges and start - line_ranges[-1][1] <= line_gap_tolerance:
                start = line_ranges[-1][0]
                line_ranges.pop()
            if end - start >= min_run_h:
                line_ranges.append((start, end))
        else:
            y += 1

    def _to_logical(v):
        return int(v / dpr) if dpr > 1.001 else int(v)

    max_run_w_dp = int(w * max_run_w_ratio)

    def _emit_brick(run_start_dp, last_ink_dp, y_start_dp, y_end_dp):
        width_dp = last_ink_dp - run_start_dp + 1
        if width_dp < min_run_w:
            return
        if width_dp > max_run_w_dp:
            return
        x_log = max(0, _to_logical(run_start_dp - padding))
        y_log = max(0, _to_logical(y_start_dp - padding))
        w_log = max(1, _to_logical(width_dp + 2 * padding))
        h_log = max(1, _to_logical((y_end_dp - y_start_dp) + 2 * padding))
        bricks.append(
            Brick(x=x_log, y=y_log, w=w_log, h=h_log, text="")
        )

    bricks = []
    for y_start, y_end in line_ranges:
        if ink_mask is not None:
            col_has_ink = ink_mask[y_start:y_end, :].any(axis=0)
        else:
            col_has_ink = bytearray(w)
            for x in range(w):
                for yy in range(y_start, y_end):
                    if is_ink((yy * w + x) * 4):
                        col_has_ink[x] = 1
                        break

        in_run = False
        run_start = 0
        last_ink = 0
        x = 0
        while x < w:
            if col_has_ink[x]:
                if not in_run:
                    in_run = True
                    run_start = x
                last_ink = x
                x += 1
            else:
                if in_run and (x - last_ink) > column_gap_tolerance:
                    _emit_brick(run_start, last_ink, y_start, y_end)
                    in_run = False
                x += 1
        if in_run:
            _emit_brick(run_start, last_ink, y_start, y_end)

    if masked_rects and bricks:
        before = len(bricks)
        bricks = [
            b for b in bricks
            if not any(mr.intersects(QtCore.QRect(b.x, b.y, b.w, b.h)) for mr in masked_rects)
        ]
        if before != len(bricks):
            logger.info(
                "ida-break: dropped %d bricks overlapping masked child widgets",
                before - len(bricks),
            )

    logger.info(
        "ida-break: detect_bricks_from_pixels: viewport=%dx%d lines=%d bricks=%d",
        w, h, len(line_ranges), len(bricks),
    )
    return bricks
