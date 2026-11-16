import { listen } from "@tauri-apps/api/event";
import { Activity, Info, KeyRound, LayoutDashboard, Settings as SettingsIcon, X } from "lucide-react";
import { useEffect, useState } from "react";
import { Dot } from "./components/ui";
import { stateTone } from "./lib/connection";
import { StoreContext, useAppStore, useStore } from "./lib/store";
import { About } from "./screens/About";
import { ActivityScreen } from "./screens/Activity";
import { Dashboard } from "./screens/Dashboard";
import { Profiles } from "./screens/Profiles";
import { SettingsScreen } from "./screens/Settings";

const screens = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "profiles", label: "Profiles", icon: KeyRound },
  { id: "activity", label: "Activity", icon: Activity },
  { id: "settings", label: "Settings", icon: SettingsIcon },
  { id: "about", label: "About", icon: Info },
] as const;
export type ScreenId = (typeof screens)[number]["id"];

export function App() {
  const store = useAppStore();
  return (
    <StoreContext.Provider value={store}>
      <Shell />
    </StoreContext.Provider>
  );
}

function Shell() {
  const store = useStore();
  const [screen, setScreen] = useState<ScreenId>("dashboard");
  useEffect(() => {
    const p = listen<ScreenId>("navigate", (e) => setScreen(e.payload));
    return () => void p.then((u) => u());
  }, []);

  if (!store.ready) {
    return (
      <div className="grid h-full place-items-center text-muted" role="status">
        Starting…
        <Notices />
      </div>
    );
  }
  const tone = stateTone(store.snapshot?.state);

  return (
    <div className="flex h-full flex-col">
      {store.caps?.simulated && (
        <div
          role="alert"
          className="border-b border-pending/40 bg-pending-soft px-4 py-1.5 text-[13px] text-pending"
        >
          Simulated backend. No real tunnel is created and your traffic is not protected.
        </div>
      )}
      <div className="flex min-h-0 flex-1">
        <nav
          aria-label="Main"
          className="flex w-48 shrink-0 flex-col border-r border-line bg-surface max-[720px]:w-14"
        >
          <div className="flex items-center gap-2 px-4 py-4 max-[720px]:justify-center max-[720px]:px-0">
            <Shield />
            <span className="font-semibold tracking-tight max-[720px]:hidden">Aegis VPN</span>
          </div>
          <ul className="flex flex-col gap-0.5 px-2">
            {screens.map((s) => (
              <li key={s.id}>
                <button
                  type="button"
                  onClick={() => setScreen(s.id)}
                  aria-current={screen === s.id ? "page" : undefined}
                  title={s.label}
                  className={`flex w-full items-center gap-2.5 rounded-md px-2.5 py-1.5 text-left text-[13px] max-[720px]:justify-center ${
                    screen === s.id
                      ? "bg-raised font-medium text-fg"
                      : "text-muted hover:bg-raised hover:text-fg"
                  }`}
                >
                  <s.icon size={16} aria-hidden />
                  <span className="max-[720px]:sr-only">{s.label}</span>
                  {s.id === "dashboard" && (
                    <span className="ml-auto max-[720px]:hidden">
                      <Dot tone={tone} />
                    </span>
                  )}
                </button>
              </li>
            ))}
          </ul>
        </nav>
        <main className="min-w-0 flex-1 overflow-y-auto">
          <div className="mx-auto max-w-5xl px-6 py-6 max-[720px]:px-4">
            {screen === "dashboard" && <Dashboard goTo={setScreen} />}
            {screen === "profiles" && <Profiles />}
            {screen === "activity" && <ActivityScreen />}
            {screen === "settings" && <SettingsScreen />}
            {screen === "about" && <About />}
          </div>
        </main>
      </div>
      <Notices />
    </div>
  );
}

function Notices() {
  const { notices, dismiss } = useStore();
  return (
    <div
      aria-live="polite"
      className="pointer-events-none fixed right-4 bottom-4 flex w-[min(420px,calc(100%-32px))] flex-col gap-2"
    >
      {notices.map((n) => (
        <div
          key={n.id}
          role={n.tone === "error" ? "alert" : "status"}
          className={`pointer-events-auto flex items-start gap-3 rounded-md border px-3 py-2 text-[13px] shadow-lg ${
            n.tone === "error" ? "border-danger/50 bg-danger-soft text-fg" : "border-line bg-surface text-fg"
          }`}
        >
          <div className="min-w-0 flex-1">
            <p>{n.text}</p>
            {n.error && n.error.issues.length > 1 && (
              <ul className="mt-1 list-disc pl-4 text-[12px] text-muted">
                {n.error.issues.slice(0, 6).map((i, k) => (
                  <li key={`${k}-${i.message}`}>
                    {i.line ? `Line ${i.line}: ` : ""}
                    {i.field ? `${i.field} ` : ""}
                    {i.message}
                  </li>
                ))}
              </ul>
            )}
          </div>
          <button
            type="button"
            onClick={() => dismiss(n.id)}
            aria-label="Dismiss"
            className="text-muted hover:text-fg"
          >
            <X size={14} />
          </button>
        </div>
      ))}
    </div>
  );
}

function Shield() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" aria-hidden className="text-accent">
      <path
        d="M12 2.5 4 5.5v6.2c0 4.9 3.4 8.6 8 9.8 4.6-1.2 8-4.9 8-9.8V5.5l-8-3Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <path
        d="M8.5 12.2 11 14.6l4.6-5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
      />
    </svg>
  );
}
