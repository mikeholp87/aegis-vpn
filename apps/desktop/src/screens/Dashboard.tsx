import { useEffect, useId, useState } from "react";
import type { ScreenId } from "../App";
import { Button, Dot, Panel, Row, type Tone } from "../components/ui";
import { api } from "../lib/api";
import { featureText, featureTone, isActive, isBusy, stateHeadline, stateTone } from "../lib/connection";
import { ago, bytes, clock, duration, rate, routeLabel } from "../lib/format";
import { useStore } from "../lib/store";
import type { Feature, ProfileView } from "../lib/types";

function useNow(active: boolean) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [active]);
  return now;
}

export function Dashboard({ goTo }: { goTo: (s: ScreenId) => void }) {
  const { snapshot, profiles, settings, events, run, caps } = useStore();
  const selectId = useId();
  const state = snapshot?.state ?? { state: "disconnected" as const };
  const active = isActive(state);
  const now = useNow(state.state === "connected");
  const fallback = profiles.find((p) => p.preferred) ?? profiles[0];
  const [chosen, setChosen] = useState<string | undefined>(undefined);
  const selected: ProfileView | undefined =
    snapshot?.profile ?? profiles.find((p) => p.id === chosen) ?? fallback;

  if (profiles.length === 0) {
    return (
      <div className="mx-auto max-w-md py-16 text-center">
        <h1 className="text-xl font-semibold">Add a WireGuard profile to get started</h1>
        <p className="mt-2 text-muted">
          Import a <span className="font-mono">.conf</span> file from your VPN provider or server, or drop it
          onto this window.
        </p>
        <div className="mt-6 flex justify-center gap-2">
          <Button variant="primary" onClick={() => run(api.importDialog)}>
            Import profile
          </Button>
          <Button onClick={() => goTo("profiles")}>Create manually</Button>
        </div>
      </div>
    );
  }

  const stats = snapshot?.stats;
  const connected = state.state === "connected";
  const s = selected?.summary;

  return (
    <div className="flex flex-col gap-5">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-[13px] text-muted">
            <Dot tone={stateTone(state)} />
            <span>
              {state.state === "reconnecting" ? `Attempt ${state.attempt}` : statusSub(state.state)}
            </span>
          </div>
          <h1
            className="mt-1 truncate text-[26px] leading-tight font-semibold tracking-tight"
            aria-live="polite"
          >
            {stateHeadline(state, selected?.name)}
          </h1>
          {state.state === "failed" && (
            <p className="mt-1 max-w-[70ch] text-[13px] text-danger">{state.reason}</p>
          )}
        </div>
        <div className="flex items-center gap-2">
          <label htmlFor={selectId} className="sr-only">
            Profile
          </label>
          <select
            id={selectId}
            value={selected?.id}
            disabled={active}
            onChange={(e) => setChosen(e.target.value)}
            className="max-w-56 rounded-md border border-line bg-surface px-2.5 py-1.5 text-[13px] disabled:opacity-60"
          >
            {profiles.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
                {p.id === settings?.preferred_profile ? " (preferred)" : ""}
              </option>
            ))}
          </select>
          <PrimaryAction selected={selected} />
        </div>
      </header>

      <div className="grid gap-5 md:grid-cols-[minmax(260px,1fr)_2fr]">
        <Panel title="What is confirmed">
          <ol className="py-2">
            <Step
              tone={connected ? "ok" : active ? "pending" : "none"}
              title="Tunnel interface"
              detail={connected ? (stats?.interface ?? "Up") : active ? "Starting" : "Not started"}
            />
            <Step
              tone={connected ? stateTone(state) : "none"}
              title="Server response"
              detail={
                !connected
                  ? "Not started"
                  : state.peer === "confirmed"
                    ? "Server answered"
                    : state.peer === "no_response"
                      ? "Nothing received. Check endpoint, keys and firewall."
                      : "Waiting for data from the server"
              }
            />
            <FeatureStep title="Kill switch" f={snapshot?.protection.kill_switch} />
            <FeatureStep title="DNS leak protection" f={snapshot?.protection.dns} />
            <FeatureStep title="IPv6 protection" f={snapshot?.protection.ipv6} />
            <Step tone="none" title="Internet reachability" detail="Not tested" last />
          </ol>
        </Panel>

        <Panel title="Connection">
          <dl className="grid gap-x-8 sm:grid-cols-2">
            <div>
              <Row label="Endpoint">{s?.endpoints[0] ?? "None"}</Row>
              <Row label="Tunnel address">
                <span className="font-mono text-[12.5px]">{s?.addresses.join(", ")}</span>
              </Row>
              <Row label="Routing">{s ? routeLabel[s.route_kind] : ""}</Row>
              <Row label="Duration" state={connected ? "confirmed" : "unavailable"}>
                {connected ? duration(now - state.since_ms) : "Not connected"}
              </Row>
              <Row
                label="Last handshake"
                state={stats?.last_handshake_ms ? "confirmed" : connected ? "pending" : "unavailable"}
              >
                {stats?.last_handshake_ms
                  ? `${ago(stats.last_handshake_ms, now)}`
                  : connected
                    ? caps?.exact_handshake_time.status === "supported"
                      ? "None yet"
                      : "Not readable on this system"
                    : undefined}
              </Row>
            </div>
            <div>
              <Row label="Received" state={stats ? "confirmed" : "unavailable"}>
                {stats ? bytes(stats.rx_bytes) : undefined}
              </Row>
              <Row label="Sent" state={stats ? "confirmed" : "unavailable"}>
                {stats ? bytes(stats.tx_bytes) : undefined}
              </Row>
              <Row label="Download" state={stats ? "confirmed" : "unavailable"}>
                {stats ? rate(stats.rx_rate_bps) : undefined}
              </Row>
              <Row label="Upload" state={stats ? "confirmed" : "unavailable"}>
                {stats ? rate(stats.tx_rate_bps) : undefined}
              </Row>
              <Row label="Public IP" state="unavailable">
                Lookup not enabled
              </Row>
            </div>
          </dl>
          {s && s.warnings.length > 0 && (
            <ul className="my-2 rounded-md bg-pending-soft px-3 py-2 text-[12.5px] text-pending">
              {s.warnings.map((w) => (
                <li key={w}>{w}</li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <Panel
        title="Recent events"
        actions={
          <Button variant="ghost" className="py-0.5 text-[12px]" onClick={() => goTo("activity")}>
            View all
          </Button>
        }
      >
        {events.length === 0 ? (
          <p className="py-3 text-muted">Nothing yet.</p>
        ) : (
          <ul>
            {events
              .slice(-5)
              .reverse()
              .map((e, i) => (
                <li
                  key={`${e.at_ms}-${i}`}
                  className="flex gap-3 border-b border-line py-1.5 last:border-b-0"
                >
                  <span className="w-20 shrink-0 text-muted">{clock(e.at_ms)}</span>
                  <span
                    className={e.level === "error" ? "text-danger" : e.level === "warn" ? "text-pending" : ""}
                  >
                    {e.message}
                  </span>
                </li>
              ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}

function statusSub(s: string) {
  return {
    disconnected: "Idle",
    preparing: "Checking profile",
    connecting: "Bringing the tunnel up",
    connected: "Active",
    disconnecting: "Removing the tunnel",
    failed: "Stopped",
    reconnecting: "Retrying",
  }[s];
}

function PrimaryAction({ selected }: { selected?: ProfileView }) {
  const { snapshot, run } = useStore();
  const state = snapshot?.state ?? { state: "disconnected" as const };
  if (state.state === "connecting" || state.state === "preparing" || state.state === "reconnecting") {
    return <Button onClick={() => run(api.cancel)}>Cancel</Button>;
  }
  if (isActive(state)) {
    return (
      <Button variant="secondary" disabled={isBusy(state)} onClick={() => run(api.disconnect)}>
        Disconnect
      </Button>
    );
  }
  return (
    <Button
      variant="primary"
      disabled={!selected}
      onClick={() => selected && run(() => api.connect(selected.id))}
    >
      Connect
    </Button>
  );
}

function Step({ tone, title, detail, last }: { tone: Tone; title: string; detail: string; last?: boolean }) {
  return (
    <li className="relative flex gap-3 pb-3 last:pb-1">
      <div className="flex flex-col items-center pt-1.5">
        <Dot tone={tone} />
        {!last && <span aria-hidden className="mt-1 w-px flex-1 bg-line" />}
      </div>
      <div className="min-w-0">
        <div className="font-medium">{title}</div>
        <div className={`text-[12.5px] ${tone === "bad" ? "text-danger" : "text-muted"}`}>{detail}</div>
      </div>
    </li>
  );
}

function FeatureStep({ title, f }: { title: string; f?: Feature }) {
  const feature = f ?? { status: "off" as const };
  const detail = "detail" in feature ? `${featureText(feature)}: ${feature.detail}` : featureText(feature);
  return <Step tone={featureTone(feature)} title={title} detail={detail} />;
}
