import assert from "node:assert/strict";
import { it } from "vitest";
import { LEGACY_SOURCE_NAME_ALIASES, OSINT_SOURCES, REMOVED_OSINT_SOURCE_IDS } from "../server/osintSeed";
import { buildDeepParsers } from "../server/osintFetcher";

it("keeps the OSINT source catalog well formed", () => {
  const byId = new Map(OSINT_SOURCES.map((source) => [source.id, source]));

  assert.equal(byId.size, OSINT_SOURCES.length, "OSINT source ids must be unique");

  for (const source of OSINT_SOURCES) {
    assert.match(source.id, /^osrc-[0-9a-z]+$/i, `${source.name} has an invalid source id`);
    assert.ok(source.name.trim(), `${source.id} is missing a source name`);
    // HTTPS only: server/httpClient.ts refuses plaintext outbound requests, so
    // an http:// row in the catalog is a source that can never be fetched.
    assert.ok(source.url.startsWith("https://"), `${source.name} must use an https:// feed URL`);
    assert.match(source.reliability, /^[ABCD]$/, `${source.name} has an invalid reliability rating`);
  }

  for (const id of REMOVED_OSINT_SOURCE_IDS) {
    assert.equal(byId.has(id), false, `${id} is a known zero-parse or non-public source and must stay pruned`);
  }

  const expectedFeeds = new Map([
    ["osrc-0261", "https://feeds.feedburner.com/OfficeOfInadequateSecurity"],
    ["osrc-0282", "https://feeds.feedburner.com/eset/blog"],
    ["osrc-0334", "https://grahamcluley.com/feed/"],
    ["osrc-0348", "https://labs.infoguard.ch/rss.xml"],
  ]);

  for (const [id, url] of expectedFeeds) {
    assert.equal(byId.get(id)?.url, url, `${id} should use the reviewed canonical feed URL`);
  }

  // Every deep parser must target a catalog row, otherwise its findings land on
  // an ad-hoc source the Sources tab cannot explain.
  for (const parser of buildDeepParsers()) {
    assert.ok(
      byId.has(parser.sourceId),
      `deep parser ${parser.id} targets ${parser.sourceId}, which is not in the catalog`,
    );
  }
  for (const [alias, id] of Object.entries(LEGACY_SOURCE_NAME_ALIASES)) {
    assert.ok(byId.has(id), `legacy alias "${alias}" points at ${id}, which is not in the catalog`);
  }
});
