import { describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import { computeActorActivity, summariseActorActivity } from "../server/actorActivity";

/** Minimal in-memory stand-in for the two tables the join reads. */
function db() {
  const d = new Database(":memory:");
  d.exec(`
    CREATE TABLE threat_actors (
      id TEXT PRIMARY KEY, tenant_id TEXT, primary_name TEXT,
      aliases TEXT, vendor_names TEXT, updated_at TEXT
    );
    CREATE TABLE osint_findings (
      id TEXT PRIMARY KEY, tenant_id TEXT, threat_actors TEXT, published_at TEXT
    );
  `);
  return d;
}

const NOW = Date.parse("2026-09-14T00:00:00.000Z");
const daysAgo = (n: number) => new Date(NOW - n * 86_400_000).toISOString();

describe("actor activity derived from intel", () => {
  it("separates actors seen now, gone quiet, and never seen", () => {
    const d = db();
    const actor = d.prepare("INSERT INTO threat_actors VALUES (?,?,?,?,?,?)");
    actor.run("a1", "t", "LockBit", JSON.stringify(["LockBit 3.0"]), null, daysAgo(100));
    actor.run("a2", "t", "Conti", "[]", null, daysAgo(100));
    actor.run("a3", "t", "Ghostly", "[]", null, daysAgo(100));

    const finding = d.prepare("INSERT INTO osint_findings VALUES (?,?,?,?)");
    finding.run("f1", "t", JSON.stringify(["LockBit"]), daysAgo(0));
    finding.run("f2", "t", JSON.stringify(["LockBit 3.0"]), daysAgo(2));
    finding.run("f3", "t", JSON.stringify(["Conti"]), daysAgo(90));

    const act = computeActorActivity(d as any, "t", { windowDays: 30, nowMs: NOW });

    const lockbit = act.get("a1")!;
    expect(lockbit.signal).toBe("active");
    expect(lockbit.daysSinceLastSeen).toBe(0);
    // An alias hit counts toward the same dossier.
    expect(lockbit.intelMentions).toBe(2);
    expect(lockbit.recentMentions).toBe(2);
    expect(lockbit.intelNewerThanDossier).toBe(true);

    const conti = act.get("a2")!;
    expect(conti.signal).toBe("quiet");
    expect(conti.recentMentions).toBe(0);
    expect(conti.intelMentions).toBe(1);

    const ghostly = act.get("a3")!;
    expect(ghostly.signal).toBe("unseen");
    expect(ghostly.lastSeenInIntel).toBeNull();
    expect(ghostly.intelNewerThanDossier).toBe(false);

    const sum = summariseActorActivity(act);
    expect(sum).toMatchObject({ total: 3, active: 1, quiet: 1, unseen: 1, staleDossiers: 2 });
    d.close();
  });

  it("scopes to the tenant and ignores names too short to be distinctive", () => {
    const d = db();
    d.prepare("INSERT INTO threat_actors VALUES (?,?,?,?,?,?)").run("a1", "t1", "APT41", "[]", null, daysAgo(10));
    d.prepare("INSERT INTO threat_actors VALUES (?,?,?,?,?,?)").run("a2", "t1", "X1", "[]", null, daysAgo(10));
    // Same actor named in another tenant's intel must not leak across.
    d.prepare("INSERT INTO osint_findings VALUES (?,?,?,?)").run("f1", "t2", JSON.stringify(["APT41"]), daysAgo(1));
    d.prepare("INSERT INTO osint_findings VALUES (?,?,?,?)").run("f2", "t1", JSON.stringify(["X1"]), daysAgo(1));

    const act = computeActorActivity(d as any, "t1", { windowDays: 30, nowMs: NOW });
    expect(act.get("a1")!.signal).toBe("unseen");
    // "X1" is two characters — below the length floor that stops a short token
    // from matching a large slice of the corpus.
    expect(act.get("a2")!.signal).toBe("unseen");
    d.close();
  });

  it("matches vendor synonyms as well as aliases", () => {
    const d = db();
    d.prepare("INSERT INTO threat_actors VALUES (?,?,?,?,?,?)").run(
      "a1",
      "t",
      "Cl0p",
      "[]",
      JSON.stringify({ threatlens: ["Lace Tempest"], mitre: [] }),
      daysAgo(50),
    );
    d.prepare("INSERT INTO osint_findings VALUES (?,?,?,?)").run(
      "f1",
      "t",
      JSON.stringify(["Lace Tempest"]),
      daysAgo(3),
    );

    const act = computeActorActivity(d as any, "t", { windowDays: 30, nowMs: NOW });
    const a = act.get("a1")!;
    expect(a.signal).toBe("active");
    expect(a.matchedNames).toContain("lace tempest");
    d.close();
  });
});

describe("ATT&CK tactic normalisation", () => {
  it("collapses every stored tactic shape onto one slug", async () => {
    const { tacticSlug, TACTIC_ORDER } = await import("../server/attackTactics");

    // Hand-authored dossiers, enrichment output, and the AI extractor on
    // findings each write the tactic differently. All three must agree, or the
    // matrix grows a duplicate column per tactic.
    expect(tacticSlug("Initial Access")).toBe("initial-access");
    expect(tacticSlug("TA0001 Initial Access")).toBe("initial-access");
    expect(tacticSlug("TA0001")).toBe("initial-access");

    expect(tacticSlug("Command and Control")).toBe("command-and-control");
    expect(tacticSlug("TA0011 Command and Control")).toBe("command-and-control");
    expect(tacticSlug("TA0011")).toBe("command-and-control");

    // Tolerate casing and separator noise.
    expect(tacticSlug("  defense_evasion ")).toBe("defense-evasion");
    expect(tacticSlug("ta0005")).toBe("defense-evasion");

    expect(tacticSlug(null)).toBeUndefined();
    expect(tacticSlug("")).toBeUndefined();

    // Every tactic the matrix can render must round-trip from its own id.
    for (const tac of TACTIC_ORDER) {
      expect(tacticSlug(tac.id)).toBe(tac.slug);
      expect(tacticSlug(tac.label)).toBe(tac.slug);
      expect(tacticSlug(`${tac.id} ${tac.label}`)).toBe(tac.slug);
    }
  });
});
