import logging
import os
import sys

import ida_kernwin


logger = logging.getLogger(__name__)


_PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)


def should_load() -> bool:
    if not ida_kernwin.is_idaq():
        return False
    raw_version = ida_kernwin.get_kernel_version()
    parts = tuple(int(p) for p in raw_version.split(".") if p.isdigit())
    if parts and parts < (9, 0):
        logger.warning("ida-break requires IDA 9.0+ (got %s)", raw_version)
        return False
    try:
        from PySide6 import QtCore, QtGui, QtWidgets  # noqa: F401
    except Exception:
        logger.warning("ida-break requires PySide6 (normally bundled with IDA 9.x)")
        return False
    try:
        import ida_hexrays  # noqa: F401
    except Exception:
        logger.warning("ida-break requires the Hex-Rays decompiler")
        return False
    return True


if should_load():
    from ida_break import break_plugin_t

    def PLUGIN_ENTRY():
        return break_plugin_t()

else:
    import ida_idaapi

    class _BreakNopPlugin(ida_idaapi.plugin_t):
        flags = ida_idaapi.PLUGIN_HIDE | ida_idaapi.PLUGIN_UNL
        wanted_name = "ida-break (disabled)"
        comment = "ida-break is disabled in this environment"
        help = ""
        wanted_hotkey = ""

        def init(self):
            return ida_idaapi.PLUGIN_SKIP

        def run(self, arg):
            pass

        def term(self):
            pass

    def PLUGIN_ENTRY():
        return _BreakNopPlugin()
