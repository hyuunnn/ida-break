# ida-break

[README_ko.md](README_ko.md)

Turn the IDA Pro Pseudocode view into a Breakout game. Variable names,
keywords, and numbers in the decompiled C source become bricks you smash
with the ball; the listing stays visible underneath while you play.

One hotkey turns the function in front of you into a playfield. Press it
again and you're back to your decompile.

![ida-break in action](images/image.png)

## Requirements

- IDA Pro 9.0 or later
- Hex-Rays Decompiler license
- PySide6 (bundled with IDA 9.x)

## Installation

Clone the repo and symlink it into IDA's plugin directory:

```sh
git clone https://github.com/hyuunnn/ida-break.git
ln -s "$(pwd)/ida-break" ~/.idapro/plugins/ida-break
```

Restart IDA. The plugin auto-loads via `ida_break_entry.py`.

## Usage

In any Pseudocode view (the `F5` decompile output):

| Action            | Key                                                                 |
| ----------------- | ------------------------------------------------------------------- |
| Start / stop game | `Ctrl-Alt-K` *or* right-click → "ida-break: Start brick break"      |
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
- Speed ramps up gradually as bricks break (capped at 2.5x).
- WIN / LOSE shows a banner with `[R] restart   [Esc] exit` — no
  auto-close.

## How it works (briefly)

The plugin grabs the pseudocode viewport's pixels, samples the background
color(s), and detects ink runs — those are your bricks. An overlay
`QWidget` sits on top of the viewport and runs the game loop in a Qt
timer; the underlying decompile text remains visible through transparency,
and dead brick areas are erased to fake the "broken" look.

For the deeper architectural notes — viewport identification across IDA
builds, why pixel-based detection over `QFontMetrics`, the magnitude-
preserving paddle math, lifecycle quirks under PySide6 — see
[CLAUDE.md](CLAUDE.md).

## Development

`game.py` has no Qt dependency, so the physics is unit-testable without
IDA:

```sh
python3 -m py_compile ida_break_lib/*.py ida_break*.py
python3 -c "
from ida_break_lib.game import GameState, Paddle, Brick, Phase
g = GameState(width=400, height=300, paddle=Paddle(x=160, y=280))
g.bricks = [Brick(x=10, y=10, w=20, h=8, text='a')]
g.spawn_ball_on_paddle()
g.reset()
assert g.phase is Phase.READY
print('ok')
"
```

`pseudocode.py` and `overlay.py` need real Qt widgets and only run inside
IDA.
