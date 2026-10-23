#!/usr/bin/env python3
"""Frame a phone screenshot for the README and the store listing: 420x860, the screen inside a
plain dark bezel on the page background. Every image in docs/images (except hero.png) is made
this way, so they line up side by side.

    python3 tools/frame_screenshot.py shot.png docs/images/approval.png
    adb exec-out screencap -p > shot.png                      # 1080x2400 from the emulator

Needs Pillow. Dev tool only; nothing in the app or the installer uses it.
"""
import sys

from PIL import Image, ImageDraw

W, H = 420, 860
BG = (9, 11, 15)
EDGE = (52, 58, 72)
BEZEL = (30, 34, 44)
SCREEN = (30, 30, 390, 830)          # where the screenshot goes: 360 x 800 (the 9:20 of 1080x2400)


def rounded(size, box, radius, fill):
    m = Image.new("L", size, 0)
    ImageDraw.Draw(m).rounded_rectangle(box, radius=radius, fill=255)
    return Image.new("RGB", size, fill), m


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    shot = Image.open(sys.argv[1]).convert("RGB")
    out = Image.new("RGB", (W, H), BG)
    for box, radius, color in (((20, 20, 400, 840), 46, EDGE), ((22, 22, 398, 838), 44, BEZEL)):
        layer, mask = rounded((W, H), box, radius, color)
        out.paste(layer, (0, 0), mask)
    x0, y0, x1, y1 = SCREEN
    screen = shot.resize((x1 - x0, y1 - y0), Image.LANCZOS)
    mask = Image.new("L", screen.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, screen.size[0] - 1, screen.size[1] - 1), radius=34, fill=255)
    out.paste(screen, (x0, y0), mask)
    out.save(sys.argv[2], optimize=True)


if __name__ == "__main__":
    main()
