import type { Plugin } from "vite";

// Minimal stub plugin - not used in pure frontend project
export function metaImagesPlugin(): Plugin {
  return {
    name: "meta-images-plugin",
    apply: "build",
    generateBundle() {
      // No-op
    },
  };
}
