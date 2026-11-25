/**
 * VERDICT v2 brand masthead for the terminal.
 *
 * Renders the cobalt/lilac V-mark + Paper Cream "VERDICT" wordmark as ANSI art,
 * matching the brand palette in dev-verdict-github/docs/brand.md. Uses 24-bit
 * truecolor when the terminal advertises it, falls back to xterm-256 otherwise,
 * and drops all color when NO_COLOR is set or the stream is not a TTY.
 *
 * Note: the opencode TUI runs in the alternate screen buffer, so a banner
 * printed *before* launch is typically cleared once the TUI paints. The exit
 * banner (printed after the TUI restores the main buffer) is the one that
 * reliably persists.
 */

type Rgb = readonly [number, number, number]

/** Brand palette — 24-bit and nearest xterm-256 index. */
const PALETTE = {
  cobalt: { rgb: [77, 93, 255] as Rgb, x256: 63 },
  lilac: { rgb: [184, 168, 255] as Rgb, x256: 147 },
  cream: { rgb: [245, 241, 232] as Rgb, x256: 230 },
  muted: { rgb: [139, 134, 168] as Rgb, x256: 103 },
} as const

type ColorName = keyof typeof PALETTE

export interface MastheadOptions {
  /** Force color on/off. Default: auto (TTY on the target stream && !NO_COLOR). */
  color?: boolean
  /** Force truecolor. Default: auto from COLORTERM (truecolor/24bit). */
  truecolor?: boolean
  /** Terminal width used to pick full vs compact. Default: stream columns or 80. */
  width?: number
  /** Stream the banner targets (for TTY/width detection). Default: process.stderr. */
  stream?: NodeJS.WriteStream
}

const RESET = "\x1b[0m"

/** Minimum columns the full masthead needs before falling back to compact. */
const FULL_MIN_WIDTH = 44

// The block wordmark "VERDICT" (5 rows). Kept as data so coloring is one pass.
const WORDMARK: readonly string[] = [
  "█   █ █████ ████  ████  █████  ████ █████",
  "█   █ █     █   █ █   █   █   █       █  ",
  "█   █ ████  ████  █   █   █   █       █  ",
  " █ █  █     █  █  █   █   █   █       █  ",
  "  █    █████ █   █ ████  █████  ████   █  ",
]

/** Render the masthead as a string (no trailing newline). */
export function renderMasthead(opts: MastheadOptions = {}): string {
  const stream = opts.stream ?? process.stderr
  const enabled = opts.color ?? (stream.isTTY === true && !process.env.NO_COLOR)
  const truecolor =
    opts.truecolor ?? /truecolor|24bit/i.test(process.env.COLORTERM ?? "")
  const width = opts.width ?? stream.columns ?? 80

  const paint = (name: ColorName, text: string): string => {
    if (!enabled) return text
    const c = PALETTE[name]
    const open = truecolor
      ? `\x1b[38;2;${c.rgb[0]};${c.rgb[1]};${c.rgb[2]}m`
      : `\x1b[38;5;${c.x256}m`
    return `${open}${text}${RESET}`
  }

  return width < FULL_MIN_WIDTH ? compact(paint) : full(paint)
}

/** Write the masthead to the target stream, followed by a newline. */
export function printMasthead(opts: MastheadOptions = {}): void {
  const stream = opts.stream ?? process.stderr
  stream.write(renderMasthead(opts) + "\n")
}

type Paint = (name: ColorName, text: string) => string

function full(paint: Paint): string {
  // Symmetric V-mark: one ╲ (cobalt) and one ╱ (lilac) per row, cream node.
  const strokeRows = [
    "╲           ╱",
    " ╲         ╱ ",
    "  ╲       ╱  ",
    "   ╲     ╱   ",
    "    ╲   ╱    ",
    "     ╲ ╱     ",
  ]
  const mark = strokeRows.map((row) =>
    row.replace("╲", paint("cobalt", "╲")).replace("╱", paint("lilac", "╱")),
  )
  mark.push("      " + paint("cream", "◯") + "      ")

  const wordmark = WORDMARK.map((row) => paint("cream", row))

  const kicker =
    paint("lilac", "DFIR") +
    paint("muted", " · TRACE IT. TEST IT. TRUST IT.")

  return ["", ...mark, "", ...wordmark, "", "  " + kicker, ""].join("\n")
}

function compact(paint: Paint): string {
  const l1 =
    paint("cobalt", "╲") +
    " " +
    paint("lilac", "╱") +
    "  " +
    paint("cream", "V E R D I C T") +
    "   " +
    paint("muted", "DFIR")
  const l2 = " " + paint("cream", "◯") + "   " + paint("lilac", "Show Me the Evidence")
  return ["", l1, l2, ""].join("\n")
}
