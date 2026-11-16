// Esegui con: npm test
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.DEV_LOGIN = "1";
process.env.DATA_DIR = mkdtempSync(join(tmpdir(), "approvazione-"));

const enc = (claims: object[]) => Buffer.from(JSON.stringify({ claims })).toString("base64");

async function main() {
  const { app, parsePrincipal } = await import("./app"); // dopo aver impostato l'ambiente

  // principal Easy Auth
  assert.deepEqual(
    parsePrincipal(enc([
      { typ: "http://schemas.microsoft.com/identity/claims/tenantid", val: "T" },
      { typ: "http://schemas.microsoft.com/identity/claims/objectidentifier", val: "O" },
      { typ: "name", val: "Mario" },
      { typ: "roles", val: "Approvatore" },
    ])),
    { tid: "T", oid: "O", nome: "Mario", approvatore: true });
  assert.equal(parsePrincipal(enc([{ typ: "name", val: "N" }])), null); // senza tid/oid
  assert.equal(parsePrincipal("non-base64!"), null);

  const server = app.listen(0, "127.0.0.1");
  await new Promise((ok) => server.once("listening", ok));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const chiama = (cookie: string, path: string, init: RequestInit = {}) =>
    fetch(base + path, { redirect: "manual", ...init, headers: { Cookie: cookie, ...init.headers } });

  async function login(nome: string, tenant: string, approvatore = true) {
    const r = await chiama("", "/login", { method: "POST", body: new URLSearchParams({ nome, tenant, ...(approvatore ? { approvatore: "on" } : {}) }) });
    return r.headers.getSetCookie()[0].split(";")[0];
  }
  const decidi = async (cookie: string, versione: number, esito: string, commento = "", headers = {}) =>
    (await chiama(cookie, "/pratiche/1/decisione", { method: "POST", headers, body: new URLSearchParams({ versione: String(versione), esito, commento }) })).status;
  const pdf = (contenuto: string, campi: Record<string, string> = {}) => {
    const f = new FormData();
    for (const [k, v] of Object.entries(campi)) f.set(k, v);
    f.set("file", new Blob([contenuto]), "analisi.pdf");
    return { method: "POST", body: f };
  };
  const statoInLista = async (cookie: string) => /class="s ([A-Z ]+)"/.exec(await (await chiama(cookie, "/")).text())?.[1];

  const adm = await login("Anna", "adm-dev");
  const sogei = await login("Sara", "sogei-dev");
  const lettore = await login("Vito", "adm-dev", false);

  assert.equal((await chiama("", "/")).status, 302); // senza login
  const estraneo = "dev_principal=" + enc([{ typ: "tid", val: "altro" }, { typ: "oid", val: "x" }, { typ: "name", val: "x" }]);
  assert.equal((await chiama(estraneo, "/")).status, 403); // tenant fuori allowlist

  const [v1, v2] = ["%PDF-1.4 v1", "%PDF-1.4 v2"];
  assert.equal((await chiama(sogei, "/pratiche", pdf(v1, { codice: "ADM196", titolo: "Analisi <b>VE</b>" }))).status, 303);
  const dettaglio = await (await chiama(adm, "/pratiche/1")).text();
  assert.ok(dettaglio.includes("Analisi &#60;b&#62;VE") && !dettaglio.includes("<b>VE"), "escape HTML");

  assert.equal(await decidi(lettore, 1, "APPROVATA"), 403); // senza ruolo
  assert.equal(await decidi(adm, 1, "RIFIUTATA"), 400); // rifiuto senza commento
  assert.equal(await decidi(adm, 1, "APPROVATA"), 303);
  assert.equal(await decidi(adm, 1, "APPROVATA"), 409); // un voto per tenant per versione
  assert.equal(await statoInLista(adm), "IN APPROVAZIONE"); // manca Sogei

  assert.equal((await chiama(sogei, "/pratiche/1/versioni", pdf(v2))).status, 303);
  assert.equal(await decidi(sogei, 1, "APPROVATA"), 409); // versione superata
  assert.equal(await decidi(sogei, 2, "APPROVATA"), 303);
  assert.equal(await statoInLista(adm), "IN APPROVAZIONE"); // l'ok ADM sulla v1 è decaduto
  assert.equal(await decidi(adm, 2, "APPROVATA", "", { "Sec-Fetch-Site": "cross-site" }), 403); // CSRF
  assert.equal(await decidi(adm, 2, "APPROVATA"), 303);
  assert.equal(await statoInLista(adm), "APPROVATA");

  const sha = createHash("sha256").update(v2).digest("hex");
  assert.ok((await (await chiama(adm, "/pratiche/1")).text()).includes(sha)); // hash in pagina e nello storico
  assert.equal(await (await chiama(adm, "/file/2")).text(), v2);
  assert.equal((await chiama(adm, "/pratiche/999")).status, 404);

  server.close();
  console.log("ok");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
