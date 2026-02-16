# -*- coding: utf-8 -*-
import re
import sys

import ida_idaapi
import ida_kernwin
import ida_funcs
import ida_lines
import idautils

try:
    import ida_hexrays
except Exception:
    ida_hexrays = None

QT_BINDING = None

try:
    from PySide6 import QtCore, QtGui, QtWidgets

    QT_BINDING = "PySide6"
except Exception:
    try:
        from PyQt5 import QtCore, QtGui, QtWidgets

        QT_BINDING = "PyQt5"
    except Exception:
        from PySide2 import QtCore, QtGui, QtWidgets

        QT_BINDING = "PySide2"

import __main__ as _ida_main
if not hasattr(_ida_main, "QtGui"):
    _ida_main.QtGui = QtGui
if not hasattr(_ida_main, "QtCore"):
    _ida_main.QtCore = QtCore
if not hasattr(_ida_main, "QtWidgets"):
    _ida_main.QtWidgets = QtWidgets


MAX_BRICK_LINES = 56
LINE_SPLIT_RE = re.compile(r"\S+|\s+")


def _clean_ida_line(line):
    return ida_lines.tag_remove(line or "").strip()


def _rotate_items_from_anchor(items, anchor_idx, limit):
    if not items:
        return []
    if anchor_idx < 0 or anchor_idx >= len(items):
        anchor_idx = 0

    out = []
    n = len(items)
    for i in range(min(limit, n)):
        out.append(items[(anchor_idx + i) % n])
    return out


def _get_hexrays_anchor_raw_idx():
    if ida_hexrays is None:
        return 0

    twidget = ida_kernwin.get_current_widget()
    if twidget is None:
        return 0

    try:
        get_vdui = getattr(ida_hexrays, "get_widget_vdui", None)
        if not callable(get_vdui):
            return 0
        vdui = get_vdui(twidget)
        cpos = getattr(vdui, "cpos", None) if vdui is not None else None
        lnnum = getattr(cpos, "lnnum", None) if cpos is not None else None
        if isinstance(lnnum, int) and lnnum >= 0:
            return lnnum
    except Exception:
        pass
    return 0


def _collect_decompiler_lines(ea):
    if ida_hexrays is None:
        return [], 0

    lines = []
    anchor_raw = _get_hexrays_anchor_raw_idx()
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return [], 0
        cfunc = ida_hexrays.decompile(ea)
        if cfunc is None:
            return [], 0

        for raw_idx, sline in enumerate(cfunc.get_pseudocode()):
            line = _clean_ida_line(sline.line)
            if not line:
                continue
            lines.append((raw_idx + 1, line, raw_idx))
    except Exception:
        return [], 0

    if not lines:
        return [], 0

    anchor_idx = 0
    for idx, (_, _, raw_idx) in enumerate(lines):
        if raw_idx >= anchor_raw:
            anchor_idx = idx
            break

    return [(line_no, text) for line_no, text, _ in lines], anchor_idx


def _collect_disasm_lines(ea):
    fn = ida_funcs.get_func(ea)
    if fn is None:
        return [], 0

    items = list(idautils.FuncItems(fn.start_ea))
    if not items:
        return [], 0

    anchor_raw = 0
    for idx, iea in enumerate(items):
        if iea >= ea:
            anchor_raw = idx
            break

    lines = []
    for raw_idx, iea in enumerate(items):
        line = _clean_ida_line(ida_lines.generate_disasm_line(iea, 0))
        if not line:
            continue
        lines.append((raw_idx + 1, line, raw_idx))

    if not lines:
        return [], 0

    anchor_idx = 0
    for idx, (_, _, raw_idx) in enumerate(lines):
        if raw_idx >= anchor_raw:
            anchor_idx = idx
            break

    return [(line_no, text) for line_no, text, _ in lines], anchor_idx


def _extract_line_blocks_from_current_context(max_tokens=56, source_ea=None):
    ea = source_ea if source_ea is not None else ida_kernwin.get_screen_ea()
    ordered_lines, anchor_idx = _collect_decompiler_lines(ea)

    if not ordered_lines:
        ordered_lines, anchor_idx = _collect_disasm_lines(ea)

    if not ordered_lines:
        ordered_lines = [
            (1, "mov eax, ebx"),
            (2, "cmp eax, 0"),
            (3, "jne loc_next"),
            (4, "call sub_handler"),
            (5, "ret"),
        ]

    ordered_lines = _rotate_items_from_anchor(ordered_lines, anchor_idx, max_tokens)

    return [
        {
            "line_no": line_no,
            "full_text": line,
            "label": line,
        }
        for line_no, line in ordered_lines
    ]


def _extract_tokens_from_current_context(max_tokens=56, source_ea=None):
    return _extract_line_blocks_from_current_context(max_tokens=max_tokens, source_ea=source_ea)


class CodeBreakWidget(QtWidgets.QWidget):
    def __init__(self, parent=None, source_ea=None):
        super(CodeBreakWidget, self).__init__(parent)
        self.source_ea = source_ea
        self.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.setMouseTracking(True)
        self.setMinimumSize(800, 520)

        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(16)

        self._init_state()

    def _init_state(self):
        self.paddle_w = 130.0
        self.paddle_h = 12.0
        self.paddle_speed = 9.0
        self.paddle_x = 300.0

        self.ball_r = 7.0
        self.ball_x = 350.0
        self.ball_y = 350.0
        self.ball_vx = 3.8
        self.ball_vy = -4.6

        self.left_pressed = False
        self.right_pressed = False
        self.launched = False
        self.game_over = False

        self.score = 0
        self.lives = 3
        self._hover_text = ""
        self.render_lines = []

        self.brick_labels = []
        self.bricks = []
        self.reload_bricks()

    def reload_bricks(self):
        self.brick_labels = _extract_line_blocks_from_current_context(max_tokens=MAX_BRICK_LINES, source_ea=self.source_ea)
        self._build_bricks()
        self._reset_ball_on_paddle()
        self.update()

    def _build_bricks(self):
        self.bricks = []
        self.render_lines = []

        w = max(640, self.width())
        h = max(360, self.height())
        code_left = 70
        code_right = w - 18
        code_top = 64

        code_font = QtGui.QFont("Menlo", 10)
        fm = QtGui.QFontMetrics(code_font)
        line_h = max(16, fm.height() + 2)
        max_visible_lines = max(1, int((h - code_top - 70) / line_h))

        for i, line_info in enumerate(self.brick_labels[:max_visible_lines]):
            full_line = line_info["full_text"]
            y_base = code_top + i * line_h + fm.ascent()
            self.render_lines.append({"line_no": line_info["line_no"], "y_base": y_base})

            x = code_left
            for part in LINE_SPLIT_RE.findall(full_line):
                part_w = max(1, fm.horizontalAdvance(part))
                if x + part_w > code_right:
                    break
                if part.strip():
                    self.bricks.append(
                        {
                            "rect": QtCore.QRectF(x, y_base - fm.ascent(), max(6, part_w), line_h),
                            "label": part,
                            "full_text": full_line,
                            "line_no": line_info["line_no"],
                            "draw_x": x,
                            "draw_y": y_base,
                            "alive": True,
                        }
                    )
                x += part_w

    def _find_hover_brick(self, pos):
        point = QtCore.QPointF(pos)
        for b in self.bricks:
            if b["alive"] and b["rect"].contains(point):
                return b
        return None

    def mouseMoveEvent(self, e):
        brick = self._find_hover_brick(e.pos())
        tooltip = ""
        if brick is not None:
            if brick["full_text"] != brick["label"]:
                tooltip = brick["full_text"]
        if tooltip:
            if tooltip != self._hover_text:
                self._hover_text = tooltip
                QtWidgets.QToolTip.showText(e.globalPos(), tooltip, self)
        else:
            if self._hover_text:
                self._hover_text = ""
                QtWidgets.QToolTip.hideText()
        super(CodeBreakWidget, self).mouseMoveEvent(e)

    def leaveEvent(self, e):
        if self._hover_text:
            self._hover_text = ""
            QtWidgets.QToolTip.hideText()
        super(CodeBreakWidget, self).leaveEvent(e)

    def _reset_ball_on_paddle(self):
        h = max(300, self.height())
        self.paddle_x = max(10, min(self.paddle_x, self.width() - self.paddle_w - 10))
        self.ball_x = self.paddle_x + self.paddle_w / 2.0
        self.ball_y = h - 42.0
        self.ball_vx = 3.8
        self.ball_vy = -4.6
        self.launched = False

    def _ball_rect(self):
        return QtCore.QRectF(
            self.ball_x - self.ball_r,
            self.ball_y - self.ball_r,
            self.ball_r * 2.0,
            self.ball_r * 2.0,
        )

    def resizeEvent(self, e):
        super(CodeBreakWidget, self).resizeEvent(e)
        self._build_bricks()

    def keyPressEvent(self, e):
        k = e.key()
        if k in (QtCore.Qt.Key_Left, QtCore.Qt.Key_A):
            self.left_pressed = True
        elif k in (QtCore.Qt.Key_Right, QtCore.Qt.Key_D):
            self.right_pressed = True
        elif k == QtCore.Qt.Key_Space and not self.game_over:
            self.launched = True
        elif k == QtCore.Qt.Key_R:
            self.score = 0
            self.lives = 3
            self.game_over = False
            self.reload_bricks()
        elif k == QtCore.Qt.Key_N:
            self.source_ea = ida_kernwin.get_screen_ea()
            self.reload_bricks()

    def keyReleaseEvent(self, e):
        k = e.key()
        if k in (QtCore.Qt.Key_Left, QtCore.Qt.Key_A):
            self.left_pressed = False
        elif k in (QtCore.Qt.Key_Right, QtCore.Qt.Key_D):
            self.right_pressed = False

    def _tick(self):
        w = max(640, self.width())
        h = max(360, self.height())

        if self.left_pressed:
            self.paddle_x -= self.paddle_speed
        if self.right_pressed:
            self.paddle_x += self.paddle_speed
        self.paddle_x = max(10, min(self.paddle_x, w - self.paddle_w - 10))

        if not self.launched and not self.game_over:
            self.ball_x = self.paddle_x + self.paddle_w / 2.0
            self.ball_y = h - 42.0
            self.update()
            return

        if self.game_over:
            self.update()
            return

        self.ball_x += self.ball_vx
        self.ball_y += self.ball_vy

        if self.ball_x - self.ball_r <= 0:
            self.ball_x = self.ball_r
            self.ball_vx *= -1
        if self.ball_x + self.ball_r >= w:
            self.ball_x = w - self.ball_r
            self.ball_vx *= -1
        if self.ball_y - self.ball_r <= 0:
            self.ball_y = self.ball_r
            self.ball_vy *= -1

        paddle_rect = QtCore.QRectF(self.paddle_x, h - 30, self.paddle_w, self.paddle_h)
        if self._ball_rect().intersects(paddle_rect) and self.ball_vy > 0:
            self.ball_y = h - 30 - self.ball_r
            self.ball_vy = -abs(self.ball_vy)
            hit = (self.ball_x - self.paddle_x) / self.paddle_w
            self.ball_vx = (hit - 0.5) * 10.0

        brect = self._ball_rect()
        for b in self.bricks:
            if b["alive"] and brect.intersects(b["rect"]):
                b["alive"] = False
                self.score += 10
                self.ball_vy *= -1
                break

        if self.bricks and not any(b["alive"] for b in self.bricks):
            self.reload_bricks()

        if self.ball_y - self.ball_r > h:
            self.lives -= 1
            if self.lives <= 0:
                self.game_over = True
                self.launched = False
            else:
                self._reset_ball_on_paddle()

        self.update()

    def paintEvent(self, e):
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing, True)

        w = self.width()
        h = self.height()

        base_bg = self.palette().base().color()
        text_fg = self.palette().text().color()
        gutter_fg = QtGui.QColor(130, 130, 130)
        p.fillRect(self.rect(), base_bg)

        code_rect = QtCore.QRectF(12, 52, max(100, w - 24), max(100, h - 92))
        p.setPen(QtGui.QPen(QtGui.QColor(180, 180, 180), 1))
        p.setBrush(QtCore.Qt.NoBrush)
        p.drawRect(code_rect)

        p.setPen(text_fg)
        p.setFont(QtGui.QFont("Menlo", 10))
        p.drawText(14, 24, "Score: %d   Lives: %d" % (self.score, self.lives))

        p.setFont(QtGui.QFont("Menlo", 10))
        p.setPen(gutter_fg)
        for line in self.render_lines:
            p.drawText(18, int(line["y_base"]), "%4d" % line["line_no"])

        p.setPen(text_fg)
        for b in self.bricks:
            if not b["alive"]:
                continue
            p.drawText(QtCore.QPointF(b["draw_x"], b["draw_y"]), b["label"])

        paddle_rect = QtCore.QRectF(self.paddle_x, h - 30, self.paddle_w, self.paddle_h)
        p.setPen(QtCore.Qt.NoPen)
        p.setBrush(QtGui.QColor(255, 170, 60))
        p.drawRoundedRect(paddle_rect, 5, 5)

        p.setBrush(QtGui.QColor(220, 80, 80))
        p.drawEllipse(QtCore.QPointF(self.ball_x, self.ball_y), self.ball_r, self.ball_r)

        if self.game_over:
            p.setPen(QtGui.QColor(255, 110, 110))
            p.setFont(QtGui.QFont("Menlo", 20, QtGui.QFont.Bold))
            p.drawText(self.rect(), QtCore.Qt.AlignCenter, "GAME OVER\nPress R to restart")

        p.end()

    def closeEvent(self, e):
        if hasattr(self, "timer") and self.timer is not None:
            self.timer.stop()
        super(CodeBreakWidget, self).closeEvent(e)


class CodeBreakForm(ida_kernwin.PluginForm):
    def __init__(self, on_close_cb=None, source_ea=None):
        super(CodeBreakForm, self).__init__()
        self._on_close_cb = on_close_cb
        self.game = None
        self.source_ea = source_ea

    def set_source_ea(self, ea, reload_game=False):
        self.source_ea = ea
        if self.game is not None:
            self.game.source_ea = ea
            if reload_game:
                self.game.reload_bricks()

    def OnCreate(self, form):
        ctx = sys.modules[__name__]
        if hasattr(self, "FormToPyQtWidget"):
            try:
                self.parent = self.FormToPyQtWidget(form, ctx)
            except TypeError:
                self.parent = self.FormToPyQtWidget(form)
        else:
            if hasattr(self, "FormToPySideWidget"):
                try:
                    self.parent = self.FormToPySideWidget(form, ctx)
                except TypeError:
                    self.parent = self.FormToPySideWidget(form)
            else:
                self.parent = self.FormToQtPythonWidget(form)
        layout = QtWidgets.QVBoxLayout(self.parent)
        layout.setContentsMargins(0, 0, 0, 0)
        self.game = CodeBreakWidget(self.parent, source_ea=self.source_ea)
        layout.addWidget(self.game)
        self.game.setFocus()

    def OnClose(self, form):
        if self.game is not None and hasattr(self.game, "timer"):
            self.game.timer.stop()
            self.game.deleteLater()
            self.game = None
        if callable(self._on_close_cb):
            self._on_close_cb()


class CodeBreakPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Breakout game from decompiled code"
    help = "Turn pseudocode into bricks"
    wanted_name = "Code Break"
    wanted_hotkey = "Ctrl-Alt-B"

    def init(self):
        self._form = None
        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        source_ea = ida_kernwin.get_screen_ea()
        if self._form is None:
            self._form = CodeBreakForm(on_close_cb=self._on_form_close, source_ea=source_ea)
        else:
            self._form.set_source_ea(source_ea, reload_game=True)
        self._form.Show("Code Break", options=ida_kernwin.PluginForm.WOPN_DP_TAB)

    def term(self):
        game = getattr(self._form, "game", None) if self._form is not None else None
        timer = getattr(game, "timer", None)
        if timer is not None:
            timer.stop()
        self._form = None

    def _on_form_close(self):
        self._form = None


def PLUGIN_ENTRY():
    return CodeBreakPlugin()
