import { chatGptOAuthLogin, chatGptOAuthLogout, chatGptOAuthStatus } from "../chatgpt-auth.js"
import { xaiOAuthLogin, xaiOAuthLogout, xaiOAuthStatus } from "../xai-auth.js"

type Flags = Record<string, string | boolean>

function usage(): void {
  console.log(`caseforge auth — subscription OAuth for the VERDICT runtime

  auth status [--provider openai|xai]
      show whether ChatGPT and/or SuperGrok OAuth is configured
  auth login [--provider openai|xai] [--method M]
      openai: ChatGPT Pro/Plus OAuth (M: headless|browser)  [default provider]
      xai:    SuperGrok subscription OAuth (M: headless|browser)
  auth logout [--provider openai|xai]
      remove the provider credential through verdict auth

This does not configure OPENAI_API_KEY or XAI_API_KEY platform API billing.`)
}

function providerId(flags: Flags, args: string[]): "openai" | "xai" {
  const fromFlag = typeof flags.provider === "string" ? flags.provider : undefined
  // allow: auth login xai
  const fromArg = args[1] === "xai" || args[1] === "openai" ? args[1] : undefined
  const p = (fromFlag ?? fromArg ?? "openai").toLowerCase()
  if (p === "xai" || p === "grok") return "xai"
  return "openai"
}

export function auth(args: string[], flags: Flags): number {
  const subcommand = args[0] ?? "status"
  const provider = providerId(flags, args)
  switch (subcommand) {
    case "status": {
      let code = 0
      if (provider === "openai" || flags.provider === undefined) {
        const status = chatGptOAuthStatus()
        if (status.ok) {
          console.log(`  [ok]   ChatGPT OAuth credential present for provider 'openai' (${status.source})`)
        } else {
          console.log(`  [MISS] ChatGPT OAuth credential missing: ${status.reason}`)
          console.log(`         checked: ${status.authPath}`)
          if (provider === "openai") code = 1
        }
        if (process.env.OPENAI_API_KEY) {
          console.log("  [info] OPENAI_API_KEY is set, but route 'chatgpt-oauth' ignores API keys.")
        }
      }
      if (provider === "xai" || flags.provider === undefined) {
        const status = xaiOAuthStatus()
        if (status.ok) {
          console.log(`  [ok]   SuperGrok OAuth credential present for provider 'xai' (${status.source})`)
        } else {
          console.log(`  [MISS] SuperGrok OAuth credential missing: ${status.reason}`)
          console.log(`         checked: ${status.authPath}`)
          if (provider === "xai") code = 1
        }
        if (process.env.XAI_API_KEY) {
          console.log("  [info] XAI_API_KEY is set, but route 'xai-grok-oauth' ignores API keys.")
        }
      }
      // status with no --provider: exit 0 if either is ok, else 1
      if (flags.provider === undefined) {
        const anyOk = chatGptOAuthStatus().ok || xaiOAuthStatus().ok
        return anyOk ? 0 : 1
      }
      return code
    }
    case "login":
      return provider === "xai" ? xaiOAuthLogin(flags.method) : chatGptOAuthLogin(flags.method)
    case "logout":
      return provider === "xai" ? xaiOAuthLogout() : chatGptOAuthLogout()
    case "help":
    case "--help":
    case "-h":
      usage()
      return 0
    default:
      console.error(`unknown auth command: ${subcommand}`)
      usage()
      return 2
  }
}
