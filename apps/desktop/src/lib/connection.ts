import type { Tone } from "../components/ui";
import type { ConnectionState, Feature } from "./types";

export function stateTone(s?: ConnectionState): Tone {
  switch (s?.state) {
    case "connected":
      return s.peer === "confirmed" ? "ok" : s.peer === "no_response" ? "bad" : "pending";
    case "preparing":
    case "connecting":
    case "reconnecting":
    case "disconnecting":
      return "pending";
    case "failed":
      return "bad";
    default:
      return "none";
  }
}

/** Plain-language headline. Never says "protected" or "secure". */
export function stateHeadline(s: ConnectionState, name?: string): string {
  const to = name ? ` ${name}` : "";
  switch (s.state) {
    case "disconnected":
      return "Not connected";
    case "preparing":
      return `Preparing${to}`;
    case "connecting":
      return `Connecting to${to}`;
    case "connected":
      if (s.peer === "confirmed") return `Connected to${to}`;
      if (s.peer === "no_response") return `No response from${to}`;
      return `Tunnel up, waiting for${to}`;
    case "reconnecting":
      return `Reconnecting to${to}`;
    case "disconnecting":
      return "Disconnecting";
    case "failed":
      return "Connection failed";
  }
}

export function isBusy(s: ConnectionState): boolean {
  return ["preparing", "connecting", "disconnecting"].includes(s.state);
}

export function isActive(s: ConnectionState): boolean {
  return !["disconnected", "failed"].includes(s.state);
}

export function featureTone(f: Feature): Tone {
  return f.status === "verified"
    ? "ok"
    : f.status === "failed"
      ? "bad"
      : f.status === "configured"
        ? "pending"
        : "none";
}

export function featureText(f: Feature): string {
  switch (f.status) {
    case "off":
      return "Off";
    case "unsupported":
      return "Not available";
    case "configured":
      return "Configured, not verified";
    case "verified":
      return "Verified";
    case "failed":
      return "Failed";
  }
}
