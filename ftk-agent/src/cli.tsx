/**
 * cli.tsx — Ink TUI for the FTK Forensic AI Agent.
 *
 * A terminal interface styled after AionUi's Cowork paradigm —
 * the agent works alongside the user, showing tool calls, streaming
 * responses, and reasoning in real time.
 *
 * Run:  OPENROUTER_API_KEY=sk-or-... npm start
 */

import React, { useState, useEffect, useCallback } from "react";
import { render, Box, Text, useInput, useApp } from "ink";
import type { StreamableOutputItem } from "@openrouter/sdk/lib/stream-transformers.js";
import { createAgent, type Agent, type Message } from "./agent.js";
import { forensicTools } from "./tools.js";

// ── Initialise agent (independent of UI) ────────────────────────
const apiKey = process.env.OPENROUTER_API_KEY;
if (!apiKey) {
  console.error(
    "ERROR: Set OPENROUTER_API_KEY environment variable.\n" +
      "  Get one at https://openrouter.ai/settings/keys"
  );
  process.exit(1);
}

const agent: Agent = createAgent({
  apiKey,
  model: "openrouter/auto",
  tools: forensicTools,
  maxSteps: 10,
});

// ── Components ──────────────────────────────────────────────────

function ChatMessage({ message }: { message: Message }) {
  const isUser = message.role === "user";
  return (
    <Box flexDirection="column" marginBottom={1}>
      <Text bold color={isUser ? "cyan" : "green"}>
        {isUser ? "▶ You" : "◀ Agent"}
      </Text>
      <Text wrap="wrap">{message.content}</Text>
    </Box>
  );
}

function ItemRenderer({ item }: { item: StreamableOutputItem }) {
  switch (item.type) {
    case "message": {
      const textContent = item.content?.find(
        (c: { type: string }) => c.type === "output_text"
      );
      const text =
        textContent && "text" in textContent ? textContent.text : "";
      return (
        <Box flexDirection="column" marginBottom={1}>
          <Text bold color="green">
            ◀ Agent
          </Text>
          <Text wrap="wrap">{text}</Text>
          {item.status !== "completed" && <Text color="gray">▌</Text>}
        </Box>
      );
    }
    case "function_call":
      return (
        <Text color="yellow">
          {item.status === "completed" ? "  [done]" : "  [tool]"}{" "}
          {item.name}
          {item.status === "in_progress" && "..."}
        </Text>
      );
    case "reasoning": {
      const reasoningText = item.content?.find(
        (c: { type: string }) => c.type === "reasoning_text"
      );
      const text =
        reasoningText && "text" in reasoningText ? reasoningText.text : "";
      return (
        <Box flexDirection="column" marginBottom={1}>
          <Text bold color="magenta">
            Thinking
          </Text>
          <Text wrap="wrap" color="gray">
            {text}
          </Text>
        </Box>
      );
    }
    default:
      return null;
  }
}

function InputField({
  value,
  onChange,
  onSubmit,
  disabled,
}: {
  value: string;
  onChange: (v: string) => void;
  onSubmit: () => void;
  disabled: boolean;
}) {
  useInput((input, key) => {
    if (disabled) return;
    if (key.return) onSubmit();
    else if (key.backspace || key.delete) onChange(value.slice(0, -1));
    else if (input && !key.ctrl && !key.meta) onChange(value + input);
  });

  return (
    <Box>
      <Text color="yellow">{"forensic> "}</Text>
      <Text>{value}</Text>
      <Text color="gray">{disabled ? " ..." : "█"}</Text>
    </Box>
  );
}

// ── Main App ────────────────────────────────────────────────────

function App() {
  const { exit } = useApp();
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [items, setItems] = useState<Map<string, StreamableOutputItem>>(
    new Map()
  );

  useInput((_, key) => {
    if (key.escape) exit();
  });

  useEffect(() => {
    const onThinkingStart = () => {
      setIsLoading(true);
      setItems(new Map());
    };

    const onItemUpdate = (item: StreamableOutputItem) => {
      const id = "id" in item ? (item as { id: string }).id : String(Math.random());
      setItems((prev) => new Map(prev).set(id, item));
    };

    const onMessageAssistant = () => {
      setMessages(agent.getMessages());
      setItems(new Map());
      setIsLoading(false);
    };

    const onError = () => {
      setIsLoading(false);
    };

    agent.on("thinking:start", onThinkingStart);
    agent.on("item:update", onItemUpdate);
    agent.on("message:assistant", onMessageAssistant);
    agent.on("error", onError);

    return () => {
      agent.off("thinking:start", onThinkingStart);
      agent.off("item:update", onItemUpdate);
      agent.off("message:assistant", onMessageAssistant);
      agent.off("error", onError);
    };
  }, []);

  const sendMessage = useCallback(async () => {
    if (!input.trim() || isLoading) return;
    const text = input.trim();
    setInput("");
    setMessages((prev) => [...prev, { role: "user", content: text }]);
    await agent.send(text);
  }, [input, isLoading]);

  return (
    <Box flexDirection="column" padding={1}>
      {/* Header */}
      <Box marginBottom={1} flexDirection="column">
        <Text bold color="magenta">
          FTK Forensic AI Agent — AI Tool Usage Detector
        </Text>
        <Text color="gray">
          7-Layer FTK Architecture | MD5/SHA-1 | Deflate | Adler-32 | OpenRouter
        </Text>
        <Text color="gray">Esc to exit</Text>
      </Box>

      {/* Message history */}
      <Box flexDirection="column" marginBottom={1}>
        {messages.map((msg, i) => (
          <ChatMessage key={i} message={msg} />
        ))}
        {Array.from(items.values()).map((item) => (
          <ItemRenderer key={item.id} item={item} />
        ))}
      </Box>

      {/* Input */}
      <Box borderStyle="single" borderColor="gray" paddingX={1}>
        <InputField
          value={input}
          onChange={setInput}
          onSubmit={sendMessage}
          disabled={isLoading}
        />
      </Box>
    </Box>
  );
}

render(<App />);
