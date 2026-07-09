import { continueRender, delayRender, staticFile } from "remotion";

// Self-hosted fonts (public/fonts/*.woff2, pulled from @fontsource) loaded via
// the FontFace API instead of @remotion/google-fonts — so a render never depends
// on fonts.gstatic.com and works fully offline (matches the project's contained/
// self-sufficient ethos). Each face holds the render via delayRender until its
// (local) woff2 decodes; .catch(continueRender) keeps the render alive if a face
// is ever missing rather than failing the whole frame.
//
// v2 brand-board type roles (VERDICT_DFIR_SVG_Assets_v2 panel 7):
//   CONDENSED — heavy CONDENSED editorial headlines (Archivo Narrow)
//   SERIF/GROTESK — editorial furniture / labels (Archivo)
//   BODY — clean-sans body/lead copy (Inter)
//   HAND — restrained handwritten annotations (Caveat)
//   MONO — evidence/data only (JetBrains Mono)

interface Face {
  weight: string;
  file: string;
}

function loadFamily(family: string, faces: Face[]): string {
  for (const { weight, file } of faces) {
    const handle = delayRender(`font ${family} ${weight}`);
    const face = new FontFace(family, `url(${staticFile(`fonts/${file}`)}) format("woff2")`, {
      weight,
      style: "normal",
    });
    face
      .load()
      .then((loaded) => {
        document.fonts.add(loaded);
        continueRender(handle);
      })
      .catch(() => continueRender(handle));
  }
  return family;
}

const inter = loadFamily("Inter", [
  { weight: "400", file: "inter-400.woff2" },
  { weight: "500", file: "inter-500.woff2" },
  { weight: "600", file: "inter-600.woff2" },
  { weight: "700", file: "inter-700.woff2" },
  { weight: "800", file: "inter-800.woff2" },
]);
const archivo = loadFamily("Archivo", [
  { weight: "400", file: "archivo-400.woff2" },
  { weight: "500", file: "archivo-500.woff2" },
  { weight: "600", file: "archivo-600.woff2" },
  { weight: "700", file: "archivo-700.woff2" },
  { weight: "800", file: "archivo-800.woff2" },
  { weight: "900", file: "archivo-900.woff2" },
]);
const archivoNarrow = loadFamily("Archivo Narrow", [
  { weight: "600", file: "archivonarrow-600.woff2" },
  { weight: "700", file: "archivonarrow-700.woff2" },
]);
const jetbrains = loadFamily("JetBrains Mono", [
  { weight: "400", file: "jbm-400.woff2" },
  { weight: "700", file: "jbm-700.woff2" },
  { weight: "800", file: "jbm-800.woff2" },
]);
const caveat = loadFamily("Caveat", [
  { weight: "400", file: "caveat-400.woff2" },
  { weight: "700", file: "caveat-700.woff2" },
]);

export const CONDENSED = `'${archivoNarrow}', 'Arial Narrow', system-ui, sans-serif`;
export const SERIF = `'${archivo}', system-ui, sans-serif`;
export const GROTESK = `'${archivo}', system-ui, -apple-system, sans-serif`;
export const BODY = `'${inter}', system-ui, -apple-system, sans-serif`;
export const HAND = `'${caveat}', cursive`;
export const MONO = `'${jetbrains}', 'Courier New', monospace`;
