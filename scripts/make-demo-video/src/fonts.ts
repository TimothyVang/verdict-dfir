// VERDICT v2 type system, loaded via @remotion/google-fonts so the render is
// deterministic (no reliance on a system-installed font). Keep SERIF as a legacy
// export name for existing scenes; in v2 it resolves to Archivo's heavy editorial
// sans instead of a separate serif face.
import { loadFont as loadArchivo } from "@remotion/google-fonts/Archivo";
import { loadFont as loadJetBrainsMono } from "@remotion/google-fonts/JetBrainsMono";

const archivo = loadArchivo("normal", { weights: ["400", "500", "600", "700", "800", "900"], subsets: ["latin"] });
const jetbrains = loadJetBrainsMono("normal", { weights: ["400", "700"], subsets: ["latin"] });

export const SERIF = archivo.fontFamily;
export const GROTESK = archivo.fontFamily;
export const MONO = jetbrains.fontFamily;
