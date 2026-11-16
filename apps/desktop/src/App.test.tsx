import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Capabilities, ProfileView, Settings, Snapshot } from "./lib/types";

vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));

const caps = (simulated: boolean, killSwitch = false): Capabilities => ({
  backend: simulated ? "mock" : "network_manager",
  simulated,
  backend_version: null,
  available: { status: "supported" },
  kill_switch: killSwitch ? { status: "supported" } : { status: "unsupported", detail: "helper not installed" },
  dns_protection: { status: "supported" },
  ipv6_protection: { status: "supported" },
  exact_handshake_time: { status: "unsupported", detail: "needs helper" },
  notes: [],
});

const profile: ProfileView = {
  id: "p1",
  name: "Office",
  created_ms: 0,
  updated_ms: 0,
  preferred: true,
  active: false,
  summary: {
    interface_public_key: "pub",
    addresses: ["10.0.0.2/32"],
    dns: ["10.0.0.1"],
    endpoints: ["vpn.example.com:51820"],
    allowed_ips: ["0.0.0.0/0", "::/0"],
    route_kind: "full",
    peer_count: 1,
    mtu: null,
    has_preshared_key: false,
    warnings: [],
  },
};

const settings: Settings = {
  theme: "system",
  close_to_tray: true,
  launch_on_login: false,
  connect_on_launch: false,
  preferred_profile: "p1",
  auto_reconnect: true,
  reconnect_max_attempts: 8,
  kill_switch: false,
  notifications: true,
  check_updates: false,
};

const off = { status: "off" } as const;
const snap = (state: Snapshot["state"], p: ProfileView | null = null): Snapshot => ({
  state,
  protection: { kill_switch: off, dns: off, ipv6: off },
  stats: null,
  profile: p,
  simulated: false,
});

const mockApi = vi.hoisted(() => ({
  appInfo: vi.fn(),
  capabilities: vi.fn(),
  snapshot: vi.fn(),
  events: vi.fn(),
  profiles: vi.fn(),
  settings: vi.fn(),
  setSettings: vi.fn(),
  connect: vi.fn(),
  disconnect: vi.fn(),
  cancel: vi.fn(),
  importDialog: vi.fn(),
  newDraft: vi.fn(),
  draft: vi.fn(),
  createProfile: vi.fn(),
  updateProfile: vi.fn(),
  duplicateProfile: vi.fn(),
  deleteProfile: vi.fn(),
  exportProfile: vi.fn(),
  diagnostics: vi.fn(),
  exportDiagnostics: vi.fn(),
}));

vi.mock("./lib/api", async (orig) => {
  const real = await orig<typeof import("./lib/api")>();
  return {
    ...real,
    api: mockApi,
    onEngineEvent: vi.fn(async () => () => {}),
    onImportResult: vi.fn(async () => () => {}),
  };
});

import { App } from "./App";

function setup(opts: { simulated?: boolean; profiles?: ProfileView[]; snapshot?: Snapshot } = {}) {
  mockApi.appInfo.mockResolvedValue({ version: "0.1.0", os: "linux", arch: "x86_64", tray_available: true });
  mockApi.capabilities.mockResolvedValue(caps(opts.simulated ?? false));
  mockApi.snapshot.mockResolvedValue(opts.snapshot ?? snap({ state: "disconnected" }));
  mockApi.profiles.mockResolvedValue(opts.profiles ?? [profile]);
  mockApi.settings.mockResolvedValue(settings);
  mockApi.events.mockResolvedValue([]);
  mockApi.diagnostics.mockResolvedValue([]);
  mockApi.connect.mockResolvedValue(undefined);
  return render(<App />);
}

describe("App", () => {
  beforeEach(() => vi.clearAllMocks());

  it("labels the simulated backend so mock connections never look real", async () => {
    setup({ simulated: true });
    expect(await screen.findByRole("alert")).toHaveTextContent(/not protected/i);
  });

  it("shows no simulated banner for a real backend", async () => {
    setup();
    await screen.findByRole("heading", { name: "Not connected" });
    expect(screen.queryByText(/Simulated backend/)).not.toBeInTheDocument();
  });

  it("does not claim Connected before the server has responded", async () => {
    setup({
      snapshot: snap({ state: "connected", profile: "p1", since_ms: Date.now(), peer: "pending" }, profile),
    });
    const h = await screen.findByRole("heading", { level: 1 });
    expect(h).toHaveTextContent("Tunnel up, waiting for Office");
    expect(h).not.toHaveTextContent(/^Connected/);
    expect(screen.getByText("Waiting for data from the server")).toBeInTheDocument();
  });

  it("reports unavailable values explicitly instead of blanks", async () => {
    setup();
    await screen.findByRole("heading", { name: "Not connected" });
    expect(screen.getByText("Lookup not enabled")).toBeInTheDocument();
    expect(screen.getByText("Not tested")).toBeInTheDocument();
  });

  it("connects the selected profile", async () => {
    setup();
    await userEvent.click(await screen.findByRole("button", { name: "Connect" }));
    expect(mockApi.connect).toHaveBeenCalledWith("p1");
  });

  it("invites import when there are no profiles", async () => {
    setup({ profiles: [] });
    expect(await screen.findByRole("button", { name: "Import profile" })).toBeInTheDocument();
  });

  it("navigates by keyboard and explains an unsupported kill switch", async () => {
    setup();
    await screen.findByRole("heading", { name: "Not connected" });
    const nav = screen.getByRole("navigation", { name: "Main" });
    const settingsBtn = within(nav).getByRole("button", { name: "Settings" });
    settingsBtn.focus();
    await userEvent.keyboard("{Enter}");
    expect(settingsBtn).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("switch", { name: "Kill switch" })).toHaveAccessibleDescription(
      /not available on this system.*refuses to connect/i,
    );
  });

  it("requires confirmation before deleting a profile", async () => {
    setup();
    await screen.findByRole("heading", { name: "Not connected" });
    await userEvent.click(within(screen.getByRole("navigation")).getByRole("button", { name: "Profiles" }));
    await userEvent.click(screen.getByRole("button", { name: "Delete Office" }));
    expect(mockApi.deleteProfile).not.toHaveBeenCalled();
    await userEvent.click(await screen.findByRole("button", { name: "Delete profile", hidden: true }));
    await act(async () => {});
    expect(mockApi.deleteProfile).toHaveBeenCalledWith("p1");
  });

  it("warns that export contains the private key", async () => {
    setup();
    await screen.findByRole("heading", { name: "Not connected" });
    await userEvent.click(within(screen.getByRole("navigation")).getByRole("button", { name: "Profiles" }));
    await userEvent.click(screen.getByRole("button", { name: "Export Office" }));
    expect(await screen.findByText(/contains the private key/i)).toBeInTheDocument();
    expect(mockApi.exportProfile).not.toHaveBeenCalled();
  });
});
