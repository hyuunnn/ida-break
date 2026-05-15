# ida-breakout

[README_ko.md](README_ko.md)

Turn the IDA Pro Pseudocode view into a Breakout game. Variable names,
keywords, and numbers in the decompiled C source become bricks you smash
with the ball; the listing stays visible underneath while you play.

One hotkey turns the function in front of you into a playfield. Press it
again and you're back to your decompile.

![ida-breakout in action](images/image.png)

## Requirements

- IDA Pro 9.0 or later
- Hex-Rays Decompiler license
- PySide6 (bundled with IDA 9.x)

## Installation

Clone the repo and symlink it into IDA's plugin directory:

```sh
git clone https://github.com/hyuunnn/ida-breakout.git
ln -s "$(pwd)/ida-breakout" ~/.idapro/plugins/ida-breakout
```

Restart IDA. The plugin auto-loads via `ida_breakout_entry.py`.

## Usage

In any Pseudocode view (the `F5` decompile output):

| Action            | Key                                                                 |
| ----------------- | ------------------------------------------------------------------- |
| Start / stop game | `Ctrl-Alt-K` *or* right-click → "ida-breakout: Start brick break"      |
| Move paddle       | `←` / `→` (or `h`/`l`, `a`/`d`)                                     |
| Launch ball       | `Space`                                                             |
| Restart           | `R` (after WIN / LOSE)                                              |
| Quit              | `Esc`                                                               |

The game runs as a transparent overlay on the decompiled function.
Bricks are extracted from the actually-rendered text pixels — what you
see is what you smash.

Mechanics at a glance:

- Standard Breakout paddle physics: ball speed magnitude is preserved
  across bounces; the paddle controls direction (angle), not speed.
- Multiball: every 15 points spawns an extra ball (max 5).
- Speed ramps up gradually as bricks break (capped at 2.0x).
- WIN / LOSE shows a banner with `[R] restart   [Esc] exit` — no
  auto-close.

