// Editorial type system, loaded via @remotion/google-fonts so the render is
// deterministic (no reliance on a system-installed font). Three-way pairing:
//   SERIF   — Fraunces: headlines, pull-quotes, the VERDICT logotype
//   GROTESK — Archivo: kickers, labels, captions, evidence tags, furniture
//   MONO    — JetBrains Mono: data / code / hashes / exhibits only
import { loadFont as loadFraunces } from "@remotion/google-fonts/Fraunces";
import { loadFont as loadArchivo } from "@remotion/google-fonts/Archivo";
import { loadFont as loadJetBrainsMono } from "@remotion/google-fonts/JetBrainsMono";

const fraunces = loadFraunces("normal", { weights: ["400", "600", "900"], subsets: ["latin"] });
loadFraunces("italic", { weights: ["400", "600"], subsets: ["latin"] });
const archivo = loadArchivo("normal", { weights: ["400", "500", "600", "700"], subsets: ["latin"] });
const jetbrains = loadJetBrainsMono("normal", { weights: ["400", "700"], subsets: ["latin"] });

export const SERIF = fraunces.fontFamily;
export const GROTESK = archivo.fontFamily;
export const MONO = jetbrains.fontFamily;
