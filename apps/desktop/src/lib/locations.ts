import type { Country, ProfileView, ServerHealth, Settings } from "./types";

export type LocationFilter = "all" | "favorites" | "recent" | "available";
export type LocationSort = "country" | "recent" | "favorites";
export const HEALTH_MAX_AGE_MS = 300_000;

export function hasRecentResponse(health: ServerHealth | undefined, now: number) {
  return (
    health?.reachability === "responded" &&
    health.observed_ms !== null &&
    health.observed_ms <= now &&
    now - health.observed_ms <= HEALTH_MAX_AGE_MS
  );
}

export function countryName(code: string | undefined, countries: Country[]) {
  return countries.find((c) => c.code === code)?.name ?? code ?? "Unassigned location";
}

export function locationLabel(p: ProfileView, countries: Country[]) {
  const l = p.server.location;
  return l
    ? [l.city, l.region, countryName(l.country_code, countries)].filter(Boolean).join(", ")
    : "Unassigned location";
}

export function locationGroups(
  profiles: ProfileView[],
  countries: Country[],
  settings: Settings,
  health: ServerHealth[],
  query: string,
  filter: LocationFilter,
  sort: LocationSort,
  now: number,
) {
  const needle = query.trim().toLocaleLowerCase();
  const samples = new Map(health.map((h) => [h.id, h]));
  const groups = new Map<string, ProfileView[]>();
  for (const p of profiles) {
    const code = p.server.location?.country_code ?? "";
    const favorite = p.server.favorite || settings.favorite_countries.includes(code);
    if (filter === "favorites" && !favorite) continue;
    if (filter === "recent" && p.server.last_connected_ms === null) continue;
    if (
      filter === "available" &&
      (!p.server.enabled || p.server.registration_pending || !hasRecentResponse(samples.get(p.id), now))
    )
      continue;
    if (
      needle &&
      ![p.name, locationLabel(p, countries), code, ...p.summary.endpoints]
        .join(" ")
        .toLocaleLowerCase()
        .includes(needle)
    )
      continue;
    const group = groups.get(code) ?? [];
    group.push(p);
    groups.set(code, group);
  }
  const recent = (p: ProfileView) => p.server.last_connected_ms ?? 0;
  const result = [...groups].map(([code, servers]) => ({
    code,
    name: countryName(code || undefined, countries),
    favorite: settings.favorite_countries.includes(code),
    servers: servers.sort(
      (a, b) =>
        (sort === "recent"
          ? recent(b) - recent(a)
          : sort === "favorites"
            ? Number(b.server.favorite) - Number(a.server.favorite)
            : 0) ||
        a.name.localeCompare(b.name) ||
        a.id.localeCompare(b.id),
    ),
    responded: servers.filter((p) => hasRecentResponse(samples.get(p.id), now)).length,
    last: Math.max(0, ...servers.map(recent)),
  }));
  return result.sort(
    (a, b) =>
      (sort === "recent"
        ? b.last - a.last
        : sort === "favorites"
          ? Number(b.favorite) - Number(a.favorite)
          : 0) || a.name.localeCompare(b.name),
  );
}
