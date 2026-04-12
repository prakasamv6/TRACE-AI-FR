/**
 * headless.ts — Use the forensic agent programmatically (no UI).
 *
 * Run:  OPENROUTER_API_KEY=sk-or-... npm run start:headless
 */

import { createAgent } from "./agent.js";
import { forensicTools } from "./tools.js";

async function main() {
  const apiKey = process.env.OPENROUTER_API_KEY;
  if (!apiKey) {
    console.error(
      "ERROR: Set OPENROUTER_API_KEY environment variable.\n" +
        "  Get one at https://openrouter.ai/settings/keys"
    );
    process.exit(1);
  }

  const agent = createAgent({
    apiKey,
    model: "openrouter/auto",
    tools: forensicTools,
    maxSteps: 10,
  });

  // ── Hook into agent events ──────────────────────────────────
  agent.on("thinking:start", () => console.log("\n[*] Thinking..."));
  agent.on("thinking:end", () => {});
  agent.on("tool:call", (name, args) =>
    console.log(`[TOOL] ${name}:`, JSON.stringify(args, null, 2).substring(0, 300))
  );
  agent.on("tool:result", (name, result) =>
    console.log(
      `[RESULT] ${name}:`,
      typeof result === "string"
        ? result.substring(0, 200)
        : JSON.stringify(result).substring(0, 200)
    )
  );
  agent.on("stream:delta", (delta) => process.stdout.write(delta));
  agent.on("stream:end", () => console.log("\n"));
  agent.on("reasoning:update", (text) =>
    console.log("[REASONING]", text.substring(0, 200))
  );
  agent.on("error", (err) => console.error("[ERROR]", err.message));

  // ── Interactive REPL ────────────────────────────────────────
  const readline = await import("readline");
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  console.log("╔══════════════════════════════════════════════════════════╗");
  console.log("║  FTK Forensic AI Agent (OpenRouter)                     ║");
  console.log("║  AI-Tool Usage Detection in E01/EWF Forensic Images     ║");
  console.log("║                                                         ║");
  console.log("║  Architecture: 7-layer FTK Imager pipeline              ║");
  console.log("║  Algorithms:  MD5, SHA-1, Deflate, Adler-32, Chunked   ║");
  console.log("║               random-access, Hex interpretation         ║");
  console.log("║                                                         ║");
  console.log("║  Type your forensic query.  Ctrl+C to exit.             ║");
  console.log("╚══════════════════════════════════════════════════════════╝\n");
  console.log("Example prompts:");
  console.log('  > Analyze E01 image at C:\\Evidence\\ItemA.E01 for AI tool usage');
  console.log('  > Scan the mounted evidence at D:\\MountedImage for ChatGPT artifacts');
  console.log('  > Compute MD5 and SHA-1 of C:\\Evidence\\ItemA.E01');
  console.log('  > Show hex dump of C:\\Evidence\\History at offset 0x1000\n');

  const prompt = () => {
    rl.question("forensic> ", async (input: string) => {
      if (!input.trim()) {
        prompt();
        return;
      }
      try {
        await agent.send(input);
      } catch (err) {
        console.error(
          "[ERROR]",
          err instanceof Error ? err.message : String(err)
        );
      }
      prompt();
    });
  };

  prompt();
}

main().catch(console.error);
