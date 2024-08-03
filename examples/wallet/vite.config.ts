import process from 'process';

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const host = process.env.TAURI_DEV_HOST;

// https://vitejs.dev/config/
export default defineConfig({
    plugins: [react()],
    clearScreen: false,
    server: {
        host: host || false,
        port: 1420,
        hmr: host
            ? {
                protocol: "ws",
                host: host,
                port: 1430,
            }
            : undefined,
        // strictPort: true,
        watch: {
            ignored: ["**/src-tauri/**"],
        },
    },
    // to make use of `TAURI_DEBUG` and other env variables
    // https://tauri.studio/v1/api/config#buildconfig.beforedevcommand
    envPrefix: ["VITE_", "TAURI_"],
    build: {
        // Tauri supports es2021
        target: process.env.TAURI_PLATFORM === "windows" ? "chrome105" : "safari13",
        minify: !process.env.TAURI_DEBUG ? "esbuild" : false,
        sourcemap: !!process.env.TAURI_DEBUG,
    },
    resolve: {
        alias: { '@': '/src' },
    }
});
