/**
 * agent.ts — Standalone forensic agent core with hooks.
 *
 * Architecture mirrors FTK Imager's seven-layer pipeline
 * but specialised for AI-tool-usage detection inside E01/EWF
 * forensic images.  Runs independently of any UI; any frontend
 * (Ink TUI, HTTP, Discord, AionUi) subscribes via EventEmitter hooks.
 */

import { OpenRouter } from "@openrouter/sdk";
import type { Tool } from "@openrouter/sdk/lib/tool-types.js";
import { stepCountIs } from "@openrouter/sdk/lib/stop-conditions.js";
import type { StreamableOutputItem } from "@openrouter/sdk/lib/stream-transformers.js";
import { EventEmitter } from "eventemitter3";

// ─── Message Types ──────────────────────────────────────────────
export interface Message {
  role: "user" | "assistant" | "system";
  content: string;
}

// ─── Agent Events (items-based streaming model) ─────────────────
export interface AgentEvents {
  "message:user": (message: Message) => void;
  "message:assistant": (message: Message) => void;
  "item:update": (item: StreamableOutputItem) => void;
  "stream:start": () => void;
  "stream:delta": (delta: string, accumulated: string) => void;
  "stream:end": (fullText: string) => void;
  "tool:call": (name: string, args: unknown) => void;
  "tool:result": (name: string, result: unknown) => void;
  "reasoning:update": (text: string) => void;
  error: (error: Error) => void;
  "thinking:start": () => void;
  "thinking:end": () => void;
}

// ─── Agent Configuration ────────────────────────────────────────
export interface AgentConfig {
  apiKey: string;
  model?: string;
  instructions?: string;
  tools?: Tool[];
  maxSteps?: number;
}

// ─── FTK Forensic AI Agent ──────────────────────────────────────
export class Agent extends EventEmitter<AgentEvents> {
  private client: OpenRouter;
  private messages: Message[] = [];
  private config: Required<Omit<AgentConfig, "apiKey">> & { apiKey: string };
  [key: string]: unknown; // allow index access

  constructor(config: AgentConfig) {
    super();
    this.client = new OpenRouter({ apiKey: config.apiKey });
    this.config = {
      apiKey: config.apiKey,
      model: config.model ?? "openrouter/auto",
      instructions:
        config.instructions ??
        `You are an expert digital-forensics AI agent specialising in detecting
AI-tool usage evidence inside E01/EWF forensic disk images.

You follow the FTK Imager seven-layer architecture:
1. Evidence Source Input — accept .E01 paths or mounted directories
2. Image/Container Handling — read EWF headers, chunk tables, deflate-compressed data sections
3. Storage Layout Interpretation — interpret partition tables and volume structures
4. Filesystem Enumeration — enumerate NTFS/FAT/HFS+/ext4 filesystem objects
5. Content Rendering — render files in text/hex and interpret timestamps
6. Integrity/Verification — compute and verify MD5 + SHA-1 hashes
7. Export/Logical-Image — export findings, generate forensic reports

Your goal: find evidence of AI platform usage (ChatGPT, Claude, GitHub Copilot,
Gemini, Midjourney, Stable Diffusion, etc.) by scanning browser history, cookies,
local storage, registry hives, prefetch files, app data, and process execution
artifacts.

When asked to analyse an E01 image, use your tools to:
- Open and validate the E01 container
- Scan for AI-platform domains, cookie domains, model strings, and app identifiers
- Carve embedded SQLite databases for browser history
- Compute integrity hashes
- Generate a structured forensic report

Always cite the artifact source, byte offset, and classification
(DIRECT / INFERRED / CONTEXTUAL).`,
      tools: config.tools ?? [],
      maxSteps: config.maxSteps ?? 10,
    };
  }

  /** Get conversation history */
  getMessages(): Message[] {
    return [...this.messages];
  }

  /** Clear conversation */
  clearHistory(): void {
    this.messages = [];
  }

  /** Update system prompt at runtime */
  setInstructions(instructions: string): void {
    this.config.instructions = instructions;
  }

  /** Register an additional tool at runtime */
  addTool(newTool: Tool): void {
    this.config.tools.push(newTool);
  }

  /**
   * Send a message with items-based streaming.
   * Items are emitted multiple times with the same ID but progressively
   * updated content — replace by ID, don't accumulate.
   */
  async send(content: string): Promise<string> {
    const userMessage: Message = { role: "user", content };
    this.messages.push(userMessage);
    this.emit("message:user", userMessage);
    this.emit("thinking:start");

    try {
      const result = this.client.callModel({
        model: this.config.model,
        instructions: this.config.instructions,
        input: this.messages.map((m) => ({ role: m.role, content: m.content })),
        tools: this.config.tools.length > 0 ? this.config.tools : undefined,
        stopWhen: [stepCountIs(this.config.maxSteps)],
      });

      this.emit("stream:start");
      let fullText = "";

      for await (const item of result.getItemsStream()) {
        this.emit("item:update", item);

        switch (item.type) {
          case "message": {
            const textContent = item.content?.find(
              (c: { type: string }) => c.type === "output_text"
            );
            if (textContent && "text" in textContent) {
              const newText = textContent.text;
              if (newText !== fullText) {
                const delta = newText.slice(fullText.length);
                fullText = newText;
                this.emit("stream:delta", delta, fullText);
              }
            }
            break;
          }
          case "function_call":
            if (item.status === "completed") {
              this.emit(
                "tool:call",
                item.name,
                JSON.parse(item.arguments || "{}")
              );
            }
            break;
          case "function_call_output":
            this.emit("tool:result", item.callId, item.output);
            break;
          case "reasoning": {
            const reasoningText = item.content?.find(
              (c: { type: string }) => c.type === "reasoning_text"
            );
            if (reasoningText && "text" in reasoningText) {
              this.emit("reasoning:update", reasoningText.text);
            }
            break;
          }
        }
      }

      if (!fullText) {
        fullText = await result.getText();
      }

      this.emit("stream:end", fullText);

      const assistantMessage: Message = {
        role: "assistant",
        content: fullText,
      };
      this.messages.push(assistantMessage);
      this.emit("message:assistant", assistantMessage);

      return fullText;
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      this.emit("error", error);
      throw error;
    } finally {
      this.emit("thinking:end");
    }
  }

  /** Send without streaming (simpler for programmatic use) */
  async sendSync(content: string): Promise<string> {
    const userMessage: Message = { role: "user", content };
    this.messages.push(userMessage);
    this.emit("message:user", userMessage);

    try {
      const result = this.client.callModel({
        model: this.config.model,
        instructions: this.config.instructions,
        input: this.messages.map((m) => ({ role: m.role, content: m.content })),
        tools: this.config.tools.length > 0 ? this.config.tools : undefined,
        stopWhen: [stepCountIs(this.config.maxSteps)],
      });

      const fullText = await result.getText();
      const assistantMessage: Message = {
        role: "assistant",
        content: fullText,
      };
      this.messages.push(assistantMessage);
      this.emit("message:assistant", assistantMessage);

      return fullText;
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      this.emit("error", error);
      throw error;
    }
  }
}

/** Factory helper */
export function createAgent(config: AgentConfig): Agent {
  return new Agent(config);
}
