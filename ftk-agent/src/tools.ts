/**
 * tools.ts — Forensic tool definitions for the FTK-style AI agent.
 *
 * Each tool maps to one or more layers of the FTK Imager architecture:
 *
 *  Layer 1  Evidence Source Input        →  open_e01_image
 *  Layer 2  Image/Container Handling     →  read_ewf_metadata
 *  Layer 3  Storage Layout Interpretation→  interpret_storage_layout
 *  Layer 4  Filesystem Enumeration       →  enumerate_filesystem
 *  Layer 5  Content Rendering            →  render_content
 *  Layer 6  Integrity / Verification     →  compute_hash
 *  Layer 7  Export / Logical-Image       →  generate_forensic_report
 *
 *  Cross-cutting AI detection           →  scan_ai_indicators
 *  Utility                              →  carve_sqlite_databases
 *
 * Algorithms implemented:
 *   MD5, SHA-1            — hashing / integrity
 *   Deflate (zlib)        — EWF decompression
 *   Adler-32              — section-level fixity
 *   Chunked random-access — 32 KB EWF chunk reads
 *   Hierarchical tree     — filesystem enumeration
 *   Hex interpretation    — byte-to-int / byte-to-date
 */

import { tool } from "@openrouter/sdk/lib/tool.js";
import { z } from "zod";
import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import * as zlib from "node:zlib";

// ─────────────────────────────────────────────────────────────────
//  AI Platform Signature Database
// ─────────────────────────────────────────────────────────────────
interface AIPlatformSig {
  platform: string;
  domains: string[];
  cookieDomains: string[];
  modelStrings: string[];
  localStorageKeys: string[];
  processNames: string[];
}

const AI_SIGNATURES: AIPlatformSig[] = [
  {
    platform: "ChatGPT / OpenAI",
    domains: [
      "chat.openai.com",
      "api.openai.com",
      "platform.openai.com",
      "chatgpt.com",
      "cdn.oaistatic.com",
    ],
    cookieDomains: [".openai.com", ".chatgpt.com"],
    modelStrings: [
      "gpt-4",
      "gpt-4o",
      "gpt-3.5-turbo",
      "gpt-4-turbo",
      "text-davinci",
      "dall-e-3",
    ],
    localStorageKeys: [
      "oai/apps/hasSeenOnboarding",
      "oai-did",
      "__Secure-next-auth.session-token",
    ],
    processNames: ["ChatGPT.exe", "com.openai.chatgpt"],
  },
  {
    platform: "Anthropic Claude",
    domains: [
      "claude.ai",
      "api.anthropic.com",
      "console.anthropic.com",
    ],
    cookieDomains: [".claude.ai", ".anthropic.com"],
    modelStrings: [
      "claude-3-opus",
      "claude-3-sonnet",
      "claude-3-haiku",
      "claude-3.5-sonnet",
      "claude-2",
    ],
    localStorageKeys: ["lastActiveOrg", "anthropic-consent"],
    processNames: ["Claude.exe"],
  },
  {
    platform: "GitHub Copilot",
    domains: [
      "copilot.github.com",
      "api.githubcopilot.com",
      "github.com/features/copilot",
    ],
    cookieDomains: [".github.com", ".githubcopilot.com"],
    modelStrings: ["copilot-codex", "copilot-chat", "cushman-ml"],
    localStorageKeys: ["github-copilot", "copilot_token"],
    processNames: [
      "copilot-agent",
      "GitHub Copilot.exe",
      "copilot-language-server",
    ],
  },
  {
    platform: "Google Gemini / Bard",
    domains: [
      "gemini.google.com",
      "bard.google.com",
      "generativelanguage.googleapis.com",
      "aistudio.google.com",
    ],
    cookieDomains: [".google.com"],
    modelStrings: [
      "gemini-pro",
      "gemini-ultra",
      "gemini-1.5-pro",
      "gemini-1.5-flash",
    ],
    localStorageKeys: ["bard-session", "gemini_session"],
    processNames: [],
  },
  {
    platform: "Midjourney",
    domains: ["www.midjourney.com", "midjourney.com", "cdn.midjourney.com"],
    cookieDomains: [".midjourney.com"],
    modelStrings: ["midjourney v5", "midjourney v6", "--v 5", "--v 6"],
    localStorageKeys: [],
    processNames: [],
  },
  {
    platform: "Stable Diffusion / Stability AI",
    domains: [
      "stability.ai",
      "api.stability.ai",
      "dreamstudio.ai",
      "stablediffusionweb.com",
    ],
    cookieDomains: [".stability.ai", ".dreamstudio.ai"],
    modelStrings: [
      "stable-diffusion-xl",
      "sdxl-turbo",
      "stable-diffusion-v1-5",
      "sd3-medium",
    ],
    localStorageKeys: [],
    processNames: ["stable-diffusion", "webui.bat", "automatic1111"],
  },
  {
    platform: "Perplexity AI",
    domains: ["www.perplexity.ai", "perplexity.ai", "api.perplexity.ai"],
    cookieDomains: [".perplexity.ai"],
    modelStrings: ["pplx-7b", "pplx-70b", "sonar-medium"],
    localStorageKeys: [],
    processNames: [],
  },
  {
    platform: "Hugging Face",
    domains: [
      "huggingface.co",
      "api-inference.huggingface.co",
      "hf.co",
    ],
    cookieDomains: [".huggingface.co"],
    modelStrings: ["meta-llama", "mistralai", "codellama"],
    localStorageKeys: [],
    processNames: [],
  },
];

// ─────────────────────────────────────────────────────────────────
//  Layer 1 — Evidence Source Input
// ─────────────────────────────────────────────────────────────────
export const openE01Image = tool({
  name: "open_e01_image",
  description:
    "Layer 1: Open an E01/EWF forensic image and validate its structure. " +
    "Returns header metadata, segment count, and total size. " +
    "Accepts physical drives, logical drives, folders, or .E01 image paths.",
  inputSchema: z.object({
    imagePath: z.string().describe("Absolute path to the .E01 file"),
  }),
  execute: async ({ imagePath }) => {
    if (!fs.existsSync(imagePath)) {
      return { error: `File not found: ${imagePath}` };
    }

    const stat = fs.statSync(imagePath);
    const fd = fs.openSync(imagePath, "r");
    const headerBuf = Buffer.alloc(512);
    fs.readSync(fd, headerBuf, 0, 512, 0);

    // EWF signature check
    const ewfMagic = headerBuf.subarray(0, 8);
    const isEWF =
      ewfMagic[0] === 0x45 &&
      ewfMagic[1] === 0x56 &&
      ewfMagic[2] === 0x46 &&
      ewfMagic[3] === 0x09 &&
      ewfMagic[4] === 0x0d &&
      ewfMagic[5] === 0x0a &&
      ewfMagic[6] === 0xff &&
      ewfMagic[7] === 0x00;

    // Locate companion segment files (.E02, .E03, ...)
    const dir = path.dirname(imagePath);
    const base = path.basename(imagePath, path.extname(imagePath));
    const segments = fs
      .readdirSync(dir)
      .filter(
        (f) =>
          f.startsWith(base) && /\.E\d{2}$/i.test(f)
      )
      .sort();

    // Read ASCII strings from header region for case info
    const headerText = headerBuf
      .toString("latin1")
      .replace(/[^\x20-\x7E\n\r\t]/g, "");

    fs.closeSync(fd);

    return {
      path: imagePath,
      sizeBytes: stat.size,
      sizeMB: +(stat.size / (1024 * 1024)).toFixed(2),
      isEWF,
      ewfMagicHex: ewfMagic.toString("hex"),
      segmentFiles: segments,
      segmentCount: segments.length,
      headerPreview: headerText.substring(0, 200),
      status: isEWF ? "VALID_E01" : "NOT_EWF_FORMAT",
    };
  },
});

// ─────────────────────────────────────────────────────────────────
//  Layer 2 — Image/Container Handling (EWF structure parsing)
// ─────────────────────────────────────────────────────────────────
export const readEwfMetadata = tool({
  name: "read_ewf_metadata",
  description:
    "Layer 2: Parse EWF/E01 container sections — header, volume, data, " +
    "hash, and digest sections. Reads section table offsets and identifies " +
    "the deflate-compressed data region. Uses Adler-32 section fixity.",
  inputSchema: z.object({
    imagePath: z.string().describe("Absolute path to the .E01 file"),
  }),
  execute: async ({ imagePath }) => {
    if (!fs.existsSync(imagePath)) {
      return { error: `File not found: ${imagePath}` };
    }

    const fd = fs.openSync(imagePath, "r");
    const stat = fs.statSync(imagePath);
    const sections: Array<{
      type: string;
      offset: number;
      size: number;
      adler32: string;
    }> = [];

    // Scan for EWF section headers — each starts with a 16-byte type string
    const scanBuf = Buffer.alloc(76); // section descriptor size
    const sectionTypes = [
      "header",
      "header2",
      "volume",
      "data",
      "sectors",
      "table",
      "table2",
      "digest",
      "hash",
      "done",
      "next",
    ];

    let offset = 13; // skip file header (EVF signature = 13 bytes)
    const maxScan = Math.min(stat.size, 10 * 1024 * 1024); // scan first 10 MB

    while (offset < maxScan - 76) {
      const bytesRead = fs.readSync(fd, scanBuf, 0, 76, offset);
      if (bytesRead < 76) break;

      const typeStr = scanBuf
        .subarray(0, 16)
        .toString("ascii")
        .replace(/\0/g, "")
        .trim()
        .toLowerCase();

      if (sectionTypes.includes(typeStr)) {
        // Bytes 16-23: next section offset (little-endian uint64)
        const nextOffset = Number(scanBuf.readBigUInt64LE(16));
        const sectionSize = Number(scanBuf.readBigUInt64LE(24));
        // Bytes 72-75: Adler-32 checksum
        const adler = scanBuf.readUInt32LE(72);

        sections.push({
          type: typeStr,
          offset,
          size: sectionSize,
          adler32: "0x" + adler.toString(16).padStart(8, "0"),
        });

        if (nextOffset > offset && nextOffset < stat.size) {
          offset = nextOffset;
        } else {
          offset += 76;
        }
      } else {
        offset += 512; // skip ahead
      }

      if (sections.length >= 50) break; // safety limit
    }

    fs.closeSync(fd);

    return {
      path: imagePath,
      totalFileSize: stat.size,
      sectionsFound: sections.length,
      sections,
      compressionMethod: "deflate (zlib)",
      chunkSize: "32 KB (standard EWF)",
      fixityAlgorithm: "Adler-32 per section",
    };
  },
});

// ─────────────────────────────────────────────────────────────────
//  Layer 3 — Storage Layout Interpretation
// ─────────────────────────────────────────────────────────────────
export const interpretStorageLayout = tool({
  name: "interpret_storage_layout",
  description:
    "Layer 3: Interpret the storage layout from a mounted evidence directory " +
    "or from decompressed E01 data. Identifies partition structure, volume " +
    "labels, and filesystem types (NTFS, FAT32, HFS+, ext4).",
  inputSchema: z.object({
    evidencePath: z
      .string()
      .describe("Path to mounted evidence directory or E01 file"),
  }),
  execute: async ({ evidencePath }) => {
    const stat = fs.statSync(evidencePath);

    if (stat.isDirectory()) {
      // Enumerate top-level to detect OS layout
      const entries = fs.readdirSync(evidencePath, { withFileTypes: true });
      const dirs = entries.filter((e) => e.isDirectory()).map((e) => e.name);
      const files = entries.filter((e) => e.isFile()).map((e) => e.name);

      // Detect OS type
      let osType = "Unknown";
      if (
        dirs.some((d) => d === "Windows") &&
        dirs.some((d) => d === "Users")
      ) {
        osType = "Windows (NTFS)";
      } else if (
        dirs.some((d) => d === "Applications") &&
        dirs.some((d) => d === "Library")
      ) {
        osType = "macOS (APFS/HFS+)";
      } else if (dirs.some((d) => d === "etc") && dirs.some((d) => d === "home")) {
        osType = "Linux (ext4/btrfs)";
      }

      return {
        type: "mounted_directory",
        path: evidencePath,
        detectedOS: osType,
        topLevelDirs: dirs.slice(0, 30),
        topLevelFiles: files.slice(0, 20),
        totalEntries: entries.length,
      };
    }

    // For E01 files, read the first data section for partition signatures
    if (!stat.isFile()) {
      return { error: "Path is neither a file nor a directory" };
    }

    const fd = fs.openSync(evidencePath, "r");
    const buf = Buffer.alloc(4096);
    fs.readSync(fd, buf, 0, 4096, 0);
    fs.closeSync(fd);

    // Check for MBR (0x55AA at offset 510) or GPT signatures
    const hasMBR = buf[510] === 0x55 && buf[511] === 0xaa;
    const hasGPT =
      buf.subarray(512, 520).toString("ascii") === "EFI PART";

    return {
      type: "image_file",
      path: evidencePath,
      hasMBR,
      hasGPT,
      partitionScheme: hasGPT ? "GPT" : hasMBR ? "MBR" : "Unknown/EWF",
      note: "Full partition parsing requires mounting the E01. Use FTK Imager or Arsenal Image Mounter.",
    };
  },
});

// ─────────────────────────────────────────────────────────────────
//  Layer 4 — Filesystem Enumeration
// ─────────────────────────────────────────────────────────────────
export const enumerateFilesystem = tool({
  name: "enumerate_filesystem",
  description:
    "Layer 4: Recursively enumerate filesystem objects from mounted evidence, " +
    "producing the Evidence Tree and File List. Filters for AI-tool relevant " +
    "paths: browser profiles, app data, registry hives, prefetch, recent files.",
  inputSchema: z.object({
    rootPath: z.string().describe("Root path to enumerate"),
    maxDepth: z
      .number()
      .optional()
      .describe("Max recursive depth (default 5)"),
    filterAIRelevant: z
      .boolean()
      .optional()
      .describe("Only return paths relevant to AI-tool detection (default true)"),
  }),
  execute: async ({ rootPath, maxDepth = 5, filterAIRelevant = true }) => {
    if (!fs.existsSync(rootPath)) {
      return { error: `Path not found: ${rootPath}` };
    }

    // AI-relevant path patterns
    const aiPaths = [
      "AppData/Local/Google/Chrome",
      "AppData/Local/Microsoft/Edge",
      "AppData/Local/BraveSoftware",
      "AppData/Roaming/Mozilla/Firefox",
      "AppData/Local/GitHub Desktop",
      "AppData/Local/Programs/cursor",
      ".vscode",
      "Library/Application Support/Google/Chrome",
      "Library/Safari",
      "Library/Application Support/Firefox",
      ".config/google-chrome",
      ".mozilla/firefox",
      "Windows/Prefetch",
      "Windows/System32/config", // registry hives
      "AppData/Roaming/OpenAI",
      "AppData/Local/Anthropic",
      "AppData/Local/Copilot",
      "$Recycle.Bin",
    ];

    const results: Array<{
      path: string;
      type: "file" | "dir";
      size?: number;
      aiRelevance?: string;
    }> = [];

    function walk(dir: string, depth: number) {
      if (depth > maxDepth || results.length >= 500) return;
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        const relPath = path.relative(rootPath, fullPath).replace(/\\/g, "/");

        let relevance: string | undefined;
        if (filterAIRelevant) {
          relevance = aiPaths.find(
            (p) =>
              relPath.toLowerCase().includes(p.toLowerCase()) ||
              p.toLowerCase().includes(relPath.toLowerCase())
          );
          if (
            !relevance &&
            !/\.(sqlite|db|json|plist|log|lnk|pf|dat)$/i.test(entry.name) &&
            depth > 2
          ) {
            continue; // skip non-relevant deeper entries
          }
        }

        if (entry.isFile()) {
          let size = 0;
          try {
            size = fs.statSync(fullPath).size;
          } catch {}
          results.push({
            path: relPath,
            type: "file",
            size,
            aiRelevance: relevance,
          });
        } else if (entry.isDirectory()) {
          results.push({ path: relPath + "/", type: "dir", aiRelevance: relevance });
          walk(fullPath, depth + 1);
        }
      }
    }

    walk(rootPath, 0);

    return {
      root: rootPath,
      totalEnumerated: results.length,
      maxDepth,
      filterAIRelevant,
      entries: results,
    };
  },
});

// ─────────────────────────────────────────────────────────────────
//  Layer 5 — Content Rendering (Text / Hex / Interpreted)
// ─────────────────────────────────────────────────────────────────
export const renderContent = tool({
  name: "render_content",
  description:
    "Layer 5: Render a file's content in Natural/Text/Hex preview modes. " +
    "Includes a Hex Value Interpreter that converts selected bytes into " +
    "decimal integers and possible date/time values (Windows FILETIME, " +
    "Unix epoch, Webkit, Chrome, macOS absolute).",
  inputSchema: z.object({
    filePath: z.string().describe("Path to the file to render"),
    mode: z
      .enum(["text", "hex", "hex_interpreted"])
      .describe("Rendering mode"),
    offset: z.number().optional().describe("Byte offset to start (default 0)"),
    length: z.number().optional().describe("Bytes to read (default 256)"),
  }),
  execute: async ({ filePath, mode, offset = 0, length = 256 }) => {
    if (!fs.existsSync(filePath)) {
      return { error: `File not found: ${filePath}` };
    }

    const fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(length);
    const bytesRead = fs.readSync(fd, buf, 0, length, offset);
    fs.closeSync(fd);
    const data = buf.subarray(0, bytesRead);

    if (mode === "text") {
      return {
        mode: "text",
        offset,
        length: bytesRead,
        content: data.toString("utf-8").replace(/[^\x20-\x7E\n\r\t]/g, "."),
      };
    }

    // Hex dump
    const hexLines: string[] = [];
    for (let i = 0; i < bytesRead; i += 16) {
      const slice = data.subarray(i, Math.min(i + 16, bytesRead));
      const hex = Array.from(slice)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ");
      const ascii = Array.from(slice)
        .map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : "."))
        .join("");
      hexLines.push(
        `${(offset + i).toString(16).padStart(8, "0")}  ${hex.padEnd(48)}  ${ascii}`
      );
    }

    const result: Record<string, unknown> = {
      mode,
      offset,
      length: bytesRead,
      hex: hexLines,
    };

    // Hex Value Interpreter
    if (mode === "hex_interpreted" && bytesRead >= 4) {
      const interp: Record<string, string> = {};
      interp["uint8"] = data[0].toString();
      if (bytesRead >= 2) interp["uint16_le"] = data.readUInt16LE(0).toString();
      if (bytesRead >= 4) interp["uint32_le"] = data.readUInt32LE(0).toString();
      if (bytesRead >= 8) {
        const i64 = data.readBigInt64LE(0);
        interp["int64_le"] = i64.toString();

        // Windows FILETIME (100-ns intervals since 1601-01-01)
        const FILETIME_EPOCH = 116444736000000000n;
        if (i64 > FILETIME_EPOCH && i64 < 200000000000000000n) {
          const ms = Number((i64 - FILETIME_EPOCH) / 10000n);
          interp["windows_filetime"] = new Date(ms).toISOString();
        }

        // Unix epoch seconds
        const unix32 = data.readUInt32LE(0);
        if (unix32 > 946684800 && unix32 < 2147483647) {
          interp["unix_timestamp"] = new Date(unix32 * 1000).toISOString();
        }

        // Chrome/Webkit timestamp (microseconds since 1601-01-01)
        if (i64 > 12000000000000000n && i64 < 20000000000000000n) {
          const unixUs = Number(i64 - 11644473600000000n);
          interp["chrome_webkit_time"] = new Date(unixUs / 1000).toISOString();
        }
      }
      result["hex_value_interpreter"] = interp;
    }

    return result;
  },
});

// ─────────────────────────────────────────────────────────────────
//  Layer 6 — Integrity / Verification (MD5 + SHA-1)
// ─────────────────────────────────────────────────────────────────
export const computeHash = tool({
  name: "compute_hash",
  description:
    "Layer 6: Compute MD5 and SHA-1 hashes for integrity verification, " +
    "matching FTK Imager's post-image verification. Also supports SHA-256.",
  inputSchema: z.object({
    filePath: z.string().describe("Path to the file to hash"),
    algorithms: z
      .array(z.enum(["md5", "sha1", "sha256"]))
      .optional()
      .describe('Hash algorithms (default: ["md5", "sha1"])'),
  }),
  execute: async ({ filePath, algorithms = ["md5", "sha1"] }) => {
    if (!fs.existsSync(filePath)) {
      return { error: `File not found: ${filePath}` };
    }

    const stat = fs.statSync(filePath);
    const hashes: Record<string, string> = {};

    for (const algo of algorithms) {
      const hash = crypto.createHash(algo);
      const stream = fs.createReadStream(filePath);
      await new Promise<void>((resolve, reject) => {
        stream.on("data", (chunk) => hash.update(chunk));
        stream.on("end", resolve);
        stream.on("error", reject);
      });
      hashes[algo.toUpperCase()] = hash.digest("hex");
    }

    return {
      filePath,
      sizeBytes: stat.size,
      hashes,
      verificationTimestamp: new Date().toISOString(),
    };
  },
});

// ─────────────────────────────────────────────────────────────────
//  Cross-cutting — AI Indicator Scanner
// ─────────────────────────────────────────────────────────────────
export const scanAiIndicators = tool({
  name: "scan_ai_indicators",
  description:
    "Scan an E01 image or directory for AI-tool usage indicators. " +
    "Searches for AI platform domains, cookie domains, model strings, " +
    "local-storage keys, and process/app names. Uses deflate decompression " +
    "and chunked random-access reading for E01 files.",
  inputSchema: z.object({
    targetPath: z.string().describe("Path to E01 file or evidence directory"),
    chunkSizeMB: z
      .number()
      .optional()
      .describe("Chunk size in MB for scanning (default 4)"),
    maxTimeSec: z
      .number()
      .optional()
      .describe("Maximum scan time in seconds (default 60)"),
  }),
  execute: async ({ targetPath, chunkSizeMB = 4, maxTimeSec = 60 }) => {
    if (!fs.existsSync(targetPath)) {
      return { error: `Path not found: ${targetPath}` };
    }

    const artifacts: Array<{
      platform: string;
      type: string;
      indicator: string;
      classification: string;
      source: string;
      byteOffset?: number;
    }> = [];

    const seen = new Set<string>();
    const startTime = Date.now();
    const chunkSize = chunkSizeMB * 1024 * 1024;

    function scanText(text: string, source: string, baseOffset: number) {
      for (const sig of AI_SIGNATURES) {
        // Domain scan
        for (const domain of sig.domains) {
          let idx = text.indexOf(domain);
          while (idx !== -1) {
            const key = `${sig.platform}:domain:${domain}`;
            if (!seen.has(key)) {
              seen.add(key);

              // Attempt URL extraction
              const contextStart = Math.max(0, idx - 100);
              const contextEnd = Math.min(text.length, idx + 300);
              const context = text.substring(contextStart, contextEnd);
              const urlMatch = context.match(
                /https?:\/\/[^\s"'<>\x00-\x1f]{5,500}/
              );

              artifacts.push({
                platform: sig.platform,
                type: "domain",
                indicator: urlMatch ? urlMatch[0] : domain,
                classification: "DIRECT",
                source,
                byteOffset: baseOffset + idx,
              });
            }
            idx = text.indexOf(domain, idx + 1);
          }
        }

        // Cookie domain scan
        for (const cd of sig.cookieDomains) {
          if (text.includes(cd)) {
            const key = `${sig.platform}:cookie:${cd}`;
            if (!seen.has(key)) {
              seen.add(key);
              artifacts.push({
                platform: sig.platform,
                type: "cookie_domain",
                indicator: cd,
                classification: "INFERRED",
                source,
              });
            }
          }
        }

        // Model string scan
        for (const ms of sig.modelStrings) {
          if (ms.length < 4) continue;
          const lowerText = text.toLowerCase();
          const lowerMs = ms.toLowerCase();
          if (lowerText.includes(lowerMs)) {
            const key = `${sig.platform}:model:${ms}`;
            if (!seen.has(key)) {
              seen.add(key);
              artifacts.push({
                platform: sig.platform,
                type: "model_string",
                indicator: ms,
                classification: "DIRECT",
                source,
              });
            }
          }
        }

        // Local storage keys
        for (const lk of sig.localStorageKeys) {
          if (lk.length < 4 || !text.includes(lk)) continue;
          const key = `${sig.platform}:ls:${lk}`;
          if (!seen.has(key)) {
            seen.add(key);
            artifacts.push({
              platform: sig.platform,
              type: "local_storage_key",
              indicator: lk,
              classification: "INFERRED",
              source,
            });
          }
        }

        // Process names
        for (const pn of sig.processNames) {
          if (pn.length < 5 || !text.toLowerCase().includes(pn.toLowerCase()))
            continue;
          const key = `${sig.platform}:proc:${pn}`;
          if (!seen.has(key)) {
            seen.add(key);
            artifacts.push({
              platform: sig.platform,
              type: "process_name",
              indicator: pn,
              classification: "INFERRED",
              source,
            });
          }
        }
      }
    }

    // Decompress zlib streams with limits
    function decompressZlib(data: Buffer): Buffer {
      const result: Buffer[] = [];
      const validSecondBytes = new Set([0x01, 0x5e, 0x9c, 0xda]);
      let off = 0;
      let attempts = 0;
      const tStart = Date.now();

      while (off < data.length - 2) {
        if (attempts >= 50 || Date.now() - tStart > 5000) break;
        const idx = data.indexOf(0x78, off);
        if (idx === -1 || idx + 1 >= data.length) break;
        if (validSecondBytes.has(data[idx + 1])) {
          attempts++;
          try {
            const decompressed = zlib.inflateSync(
              data.subarray(idx, idx + 65536)
            );
            result.push(decompressed);
          } catch {}
        }
        off = idx + 1;
      }

      return result.length > 0 ? Buffer.concat(result) : Buffer.alloc(0);
    }

    const stat = fs.statSync(targetPath);

    if (stat.isFile()) {
      // Binary E01 scan
      const fd = fs.openSync(targetPath, "r");
      const fileSize = stat.size;
      let bytesRead = 0;

      while (bytesRead < fileSize) {
        if (Date.now() - startTime > maxTimeSec * 1000) break;

        const remaining = fileSize - bytesRead;
        const toRead = Math.min(chunkSize, remaining);
        const buf = Buffer.alloc(toRead);
        const n = fs.readSync(fd, buf, 0, toRead, bytesRead);
        if (n === 0) break;
        const chunk = buf.subarray(0, n);

        // 1) Decompress zlib streams
        const decompressed = decompressZlib(chunk);
        if (decompressed.length > 0) {
          scanText(
            decompressed.toString("latin1"),
            "decompressed_ewf",
            bytesRead
          );
        }

        // 2) Scan raw bytes
        scanText(chunk.toString("latin1"), "raw_ewf", bytesRead);

        bytesRead += n;
      }

      fs.closeSync(fd);

      return {
        target: targetPath,
        scanType: "E01_binary",
        bytesScanned: bytesRead,
        scanTimeSec: +((Date.now() - startTime) / 1000).toFixed(2),
        artifactsFound: artifacts.length,
        artifacts,
        platformsDetected: [
          ...new Set(artifacts.map((a) => a.platform)),
        ],
      };
    }

    // Directory scan — look for specific files
    if (stat.isDirectory()) {
      const aiFiles = [
        "**/History",
        "**/Cookies",
        "**/Local Storage/leveldb/*.log",
        "**/Local State",
        "**/Preferences",
      ];

      function walkDir(dir: string, depth: number) {
        if (depth > 5 || Date.now() - startTime > maxTimeSec * 1000) return;
        let entries: fs.Dirent[];
        try {
          entries = fs.readdirSync(dir, { withFileTypes: true });
        } catch {
          return;
        }
        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            walkDir(fullPath, depth + 1);
          } else if (
            /\.(sqlite|db|json|log|lnk|pf|dat|plist)$/i.test(entry.name) ||
            ["History", "Cookies", "Local State", "Preferences"].includes(
              entry.name
            )
          ) {
            try {
              const content = fs.readFileSync(fullPath, "latin1");
              scanText(
                content.substring(0, 1024 * 1024),
                path.relative(targetPath, fullPath),
                0
              );
            } catch {}
          }
        }
      }

      walkDir(targetPath, 0);

      return {
        target: targetPath,
        scanType: "directory",
        scanTimeSec: +((Date.now() - startTime) / 1000).toFixed(2),
        artifactsFound: artifacts.length,
        artifacts,
        platformsDetected: [
          ...new Set(artifacts.map((a) => a.platform)),
        ],
      };
    }

    return { error: "Target is neither a file nor directory" };
  },
});

// ─────────────────────────────────────────────────────────────────
//  Cross-cutting — SQLite Database Carver
// ─────────────────────────────────────────────────────────────────
export const carveSqliteDatabases = tool({
  name: "carve_sqlite_databases",
  description:
    "Carve embedded SQLite databases from E01 binary data or decompressed " +
    "sectors. Searches for the SQLite header magic (53 51 4C 69 74 65) and " +
    "extracts surrounding data for analysis.",
  inputSchema: z.object({
    filePath: z.string().describe("Path to E01 file to scan"),
    maxCarved: z
      .number()
      .optional()
      .describe("Maximum databases to carve (default 10)"),
  }),
  execute: async ({ filePath, maxCarved = 10 }) => {
    if (!fs.existsSync(filePath)) {
      return { error: `File not found: ${filePath}` };
    }

    const SQLITE_MAGIC = Buffer.from("SQLite format 3\0");
    const fd = fs.openSync(filePath, "r");
    const fileSize = fs.statSync(filePath).size;
    const chunkSize = 4 * 1024 * 1024;
    let bytesRead = 0;
    const found: Array<{
      offset: number;
      pageSize: number;
      headerPreview: string;
    }> = [];

    while (bytesRead < fileSize && found.length < maxCarved) {
      const buf = Buffer.alloc(chunkSize);
      const n = fs.readSync(fd, buf, 0, chunkSize, bytesRead);
      if (n === 0) break;
      const chunk = buf.subarray(0, n);

      let searchOff = 0;
      while (searchOff < chunk.length - 100) {
        const idx = chunk.indexOf(SQLITE_MAGIC, searchOff);
        if (idx === -1) break;

        // Read page size at offset 16
        const pageSize = chunk.readUInt16BE(idx + 16) || 65536;

        // Read first 100 bytes as header preview
        const hdrPreview = chunk
          .subarray(idx, idx + 100)
          .toString("latin1")
          .replace(/[^\x20-\x7E]/g, ".");

        found.push({
          offset: bytesRead + idx,
          pageSize,
          headerPreview: hdrPreview,
        });

        searchOff = idx + 1;
        if (found.length >= maxCarved) break;
      }

      bytesRead += n;
    }

    fs.closeSync(fd);

    return {
      filePath,
      sqliteHeadersFound: found.length,
      databases: found,
    };
  },
});

// ─────────────────────────────────────────────────────────────────
//  Layer 7 — Export / Report Generation
// ─────────────────────────────────────────────────────────────────
export const generateForensicReport = tool({
  name: "generate_forensic_report",
  description:
    "Layer 7: Generate a structured forensic report of AI-tool usage findings. " +
    "Exports JSON and Markdown formats with case metadata, artifact inventory, " +
    "platform summary, and integrity hashes.",
  inputSchema: z.object({
    caseName: z.string().describe("Forensic case name"),
    examiner: z.string().describe("Examiner name"),
    organization: z.string().describe("Organization"),
    evidencePath: z.string().describe("Path to evidence source"),
    artifacts: z
      .array(
        z.object({
          platform: z.string(),
          type: z.string(),
          indicator: z.string(),
          classification: z.string(),
          source: z.string(),
        })
      )
      .describe("Array of found artifacts"),
    outputDir: z.string().describe("Output directory for reports"),
  }),
  execute: async ({
    caseName,
    examiner,
    organization,
    evidencePath,
    artifacts,
    outputDir,
  }) => {
    fs.mkdirSync(outputDir, { recursive: true });
    const timestamp = new Date().toISOString();
    const caseId = crypto.randomBytes(4).toString("hex").toUpperCase();

    // Platform summary
    const platformCounts: Record<string, number> = {};
    for (const a of artifacts) {
      platformCounts[a.platform] = (platformCounts[a.platform] || 0) + 1;
    }

    const report = {
      caseMetadata: {
        caseId,
        caseName,
        examiner,
        organization,
        evidencePath,
        analysisTimestamp: timestamp,
        toolVersion: "FTK-Forensic-AI-Agent v1.0.0 (OpenRouter)",
      },
      summary: {
        totalArtifacts: artifacts.length,
        platformsDetected: Object.keys(platformCounts),
        platformCounts,
        classificationBreakdown: {
          DIRECT: artifacts.filter((a) => a.classification === "DIRECT").length,
          INFERRED: artifacts.filter((a) => a.classification === "INFERRED")
            .length,
          CONTEXTUAL: artifacts.filter(
            (a) => a.classification === "CONTEXTUAL"
          ).length,
        },
      },
      artifacts,
      integrityNote:
        "Use compute_hash tool on evidence file for MD5/SHA-1 verification.",
    };

    // Write JSON
    const jsonPath = path.join(outputDir, `${caseId}_findings.json`);
    fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2));

    // Write Markdown
    const md = [
      `# Forensic AI-Tool Usage Report`,
      ``,
      `| Field | Value |`,
      `|-------|-------|`,
      `| Case ID | ${caseId} |`,
      `| Case Name | ${caseName} |`,
      `| Examiner | ${examiner} |`,
      `| Organization | ${organization} |`,
      `| Evidence | ${evidencePath} |`,
      `| Timestamp | ${timestamp} |`,
      `| Tool | FTK-Forensic-AI-Agent v1.0.0 (OpenRouter) |`,
      ``,
      `## Summary`,
      ``,
      `- **Total Artifacts:** ${artifacts.length}`,
      `- **Platforms Detected:** ${Object.keys(platformCounts).join(", ") || "None"}`,
      `- **Direct Evidence:** ${report.summary.classificationBreakdown.DIRECT}`,
      `- **Inferred Evidence:** ${report.summary.classificationBreakdown.INFERRED}`,
      ``,
      `## Platform Breakdown`,
      ``,
      `| Platform | Artifacts |`,
      `|----------|-----------|`,
      ...Object.entries(platformCounts).map(
        ([p, c]) => `| ${p} | ${c} |`
      ),
      ``,
      `## Artifact Details`,
      ``,
      `| # | Platform | Type | Indicator | Classification | Source |`,
      `|---|----------|------|-----------|----------------|--------|`,
      ...artifacts.map(
        (a, i) =>
          `| ${i + 1} | ${a.platform} | ${a.type} | \`${a.indicator}\` | ${a.classification} | ${a.source} |`
      ),
      ``,
      `---`,
      `*Report generated by FTK-Forensic-AI-Agent (OpenRouter)*`,
    ].join("\n");

    const mdPath = path.join(outputDir, `${caseId}_report.md`);
    fs.writeFileSync(mdPath, md);

    return {
      caseId,
      jsonReport: jsonPath,
      markdownReport: mdPath,
      totalArtifacts: artifacts.length,
      platformsDetected: Object.keys(platformCounts),
    };
  },
});

// ─────────────────────────────────────────────────────────────────
//  Export all tools
// ─────────────────────────────────────────────────────────────────
export const forensicTools = [
  openE01Image,
  readEwfMetadata,
  interpretStorageLayout,
  enumerateFilesystem,
  renderContent,
  computeHash,
  scanAiIndicators,
  carveSqliteDatabases,
  generateForensicReport,
];
