# ida-break

IDA Pro의 Pseudocode 뷰를 그대로 Breakout(벽돌깨기) 게임으로 만드는
플러그인. 디컴파일된 C 소스의 변수명, 키워드, 숫자가 그대로 벽돌이 되고,
밑에 깔린 디컴파일 결과는 게임 중에도 비쳐 보임.

핫키 한 번이면 지금 보고 있는 함수가 게임판이 되고, 다시 누르면 원래
디컴파일 결과로 돌아옴.

![ida-break 실행 화면](images/image.png)

## 요구사항

- IDA Pro 9.0+
- Hex-Rays Decompiler 라이선스
- PySide6 (IDA 9.x 번들)

## 설치

레포를 IDA 플러그인 폴더에 심링크:

```sh
git clone https://github.com/hyuunnn/ida-break.git
ln -s "$(pwd)/ida-break" ~/.idapro/plugins/ida-break
```

IDA를 재시작하면 `ida_break_entry.py`가 자동 로드됨.

## 사용법

Pseudocode 뷰 (`F5` 디컴파일 창)에서:

| 동작              | 키                                                              |
| ----------------- | --------------------------------------------------------------- |
| 시작 / 종료       | `Ctrl-Alt-K` *또는* 우클릭 → "ida-break: Start brick break"     |
| 패들 이동         | `←` / `→` (또는 `h`/`l`, `a`/`d`)                                |
| 공 발사           | `Space`                                                         |
| 재시작            | `R` (WIN / LOSE 후)                                              |
| 종료              | `Esc`                                                            |

게임은 디컴파일된 함수 위에 투명 오버레이로 깔리고, 벽돌은 실제 렌더된
텍스트 픽셀에서 추출됨 — 화면에 보이는 글자가 그대로 부서지는 대상.

메커니즘 요약:

- 표준 Breakout 패들 물리: 반사 시 magnitude(속력) 보존, 패들 위치는
  각도만 결정 (속도는 변하지 않음).
- 멀티볼: 점수 15점마다 추가 공 분기 (최대 5개).
- 부순 벽돌 수에 비례한 점진적 가속 (최대 2.5x).
- WIN / LOSE 시 `[R] restart   [Esc] exit` 배너 표시 — 자동 종료 없음.

## 동작 원리 (간단히)

Pseudocode viewport의 픽셀을 캡처하고 배경색을 샘플링한 뒤 잉크 영역을
연속된 벽돌로 묶음. 오버레이 `QWidget`이 viewport 위에 얹히고 Qt
타이머에서 게임 루프를 돌림. 하단 디컴파일 텍스트는 투명도로 그대로
보이고, 부서진 벽돌 영역만 배경색으로 덮어 "사라진" 효과를 냄.

자세한 아키텍처 — IDA 빌드별 viewport 식별, `QFontMetrics` 대신 픽셀
기반을 쓴 이유, magnitude 보존 패들 수식, PySide6 라이프사이클 이슈
등 — 은 [CLAUDE.md](CLAUDE.md) 참고.

## 개발

`game.py`는 Qt 의존이 없는 순수 Python이라 IDA 없이 단위 테스트 가능:

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

`pseudocode.py`, `overlay.py`는 실제 Qt 위젯이 필요해서 IDA 내부에서만
동작.
