#!/usr/bin/env node
import { launchTui } from "./index.js"
process.exit(await launchTui(process.argv[2]))
