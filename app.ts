/**
 * PoC approvazione documenti ADM <-> Sogei.
 *
 * Autenticazione: NON implementata qui di proposito.
 * - Azure App Service: l'autenticazione integrata (Easy Auth) fa il login Entra multi-tenant e
 *   inietta l'header X-MS-CLIENT-PRINCIPAL. L'header è attendibile SOLO dietro Easy Auth.
 * - Locale: DEV_LOGIN=1 abilita /login, che scrive un cookie nello stesso formato.
 * Autorizzazione: tenant in allowlist (tid) + app role Entra "Approvatore" (claim roles),
 * assegnato da ciascun tenant ai propri utenti: nessun censimento in ADM.
 */
import Database from "better-sqlite3";
import express, { type NextFunction, type Request, type Response } from "express";
import multer from "multer";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const RUOLO = "Approvatore";
const DEV = process.env.DEV_LOGIN === "1";
const DATA = process.env.DATA_DIR ?? "data"; // su App Service: /home/data (persistente)

function tenant(variabile: string, devDefault: string): string {
  const tid = process.env[variabile] || (DEV ? devDefault : "");
  if (!tid) throw new Error(`${variabile} non impostata`);
  return tid;
}
const TENANTS = new Map([
  [tenant("TENANT_ADM", "adm-dev"), "ADM"],
  [tenant("TENANT_SOGEI", "sogei-dev"), "Sogei"],
]);

mkdirSync(join(DATA, "files"), { recursive: true });
// ponytail: SQLite + file su disco; Azure SQL/Postgres + Blob Storage quando serve più di un'istanza.
const db = new Database(join(DATA, "app.db"));
db.exec(`
CREATE TABLE IF NOT EXISTS pratiche(
  id INTEGER PRIMARY KEY, codice TEXT NOT NULL, titolo TEXT NOT NULL, descrizione TEXT NOT NULL,
  versione INTEGER NOT NULL DEFAULT 0, creata_da TEXT NOT NULL,
  creata_il TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS documenti(
  id INTEGER PRIMARY KEY, pratica_id INTEGER NOT NULL, versione INTEGER NOT NULL,
  nome TEXT NOT NULL, sha256 TEXT NOT NULL);
-- UNIQUE: una sola decisione per tenant per versione. Nuova versione = approvazioni da rifare.
CREATE TABLE IF NOT EXISTS approvazioni(
  id INTEGER PRIMARY KEY, pratica_id INTEGER NOT NULL, versione INTEGER NOT NULL,
  tid TEXT NOT NULL, oid TEXT NOT NULL, nome TEXT NOT NULL,
  esito TEXT NOT NULL CHECK(esito IN ('APPROVATA','RIFIUTATA')), commento TEXT NOT NULL,
  il TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE(pratica_id, versione, tid));
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY, il TEXT NOT NULL DEFAULT (datetime('now')), tid TEXT NOT NULL,
  oid TEXT NOT NULL, nome TEXT NOT NULL, azione TEXT NOT NULL, pratica_id INTEGER NOT NULL,
  dettaglio TEXT NOT NULL);
`);
const ESITI = `COALESCE((SELECT group_concat(esito) FROM approvazioni a
               WHERE a.pratica_id=p.id AND a.versione=p.versione),'') AS esiti`;

type Pratica = { id: number; codice: string; titolo: string; descrizione: string; versione: number; creata_da: string; creata_il: string; esiti: string };
type Documento = { id: number; nome: string; sha256: string };
type Approvazione = { tid: string; nome: string; esito: string; commento: string; il: string };
type Audit = { il: string; tid: string; nome: string; azione: string; dettaglio: string };
type FileCaricato = { nome: string; sha: string };

class HttpError extends Error {
  constructor(readonly status: number, messaggio = "") {
    super(messaggio);
  }
}

// ---------- identità ----------

export type User = { tid: string; oid: string; nome: string; approvatore: boolean };

/** Decodifica il principal Easy Auth: base64 di {"claims":[{"typ","val"},...]}.
 *  Accetta sia i nomi brevi dei claim (tid, oid) sia gli URI lunghi. null se non valido. */
export function parsePrincipal(b64: string): User | null {
  let claims: { typ: string; val: string }[];
  try {
    claims = JSON.parse(Buffer.from(b64, "base64").toString("utf8")).claims;
    if (!Array.isArray(claims) || claims.some((c) => typeof c?.typ !== "string" || typeof c?.val !== "string")) return null;
  } catch {
    return null;
  }
  const get = (breve: string, lungo: string) => claims.find((c) => c.typ === breve || c.typ.endsWith(lungo))?.val;
  const tid = get("tid", "/claims/tenantid");
  const oid = get("oid", "/claims/objectidentifier");
  const nome = get("name", "/claims/name") ?? get("preferred_username", "/claims/upn");
  if (!tid || !oid || !nome) return null;
  const approvatore = claims.some((c) => (c.typ === "roles" || c.typ.endsWith("/claims/role")) && c.val === RUOLO);
  return { tid, oid, nome, approvatore };
}

const utente = (res: Response) => res.locals.user as User;
const etichetta = (tid: string) => TENANTS.get(tid) ?? "?";

export const app = express();
app.disable("x-powered-by");
app.use(express.urlencoded({ extended: false }));

// ponytail: anti-CSRF via Sec-Fetch-Site (inviato da tutti i browser attuali);
// token per-form se servisse supportare browser che non lo mandano.
app.use((req, _res, next) => {
  if (req.method !== "GET" && (req.get("Sec-Fetch-Site") ?? "same-origin") !== "same-origin")
    throw new HttpError(403, "Richiesta cross-site rifiutata");
  next();
});

if (DEV) {
  app.get("/login", (_req, res) => {
    res.send(pagina(null, "Login di sviluppo", html`
      <form method=post><p><b>Solo sviluppo</b>: simula il login Microsoft.</p>
      <label>Nome <input name=nome required></label>
      <label>Tenant <select name=tenant>${[...TENANTS].map(([tid, n]) => html`<option value="${tid}">${n}</option>`)}</select></label>
      <label><input type=checkbox name=approvatore> ruolo ${RUOLO}</label>
      <button>Entra</button></form>`));
  });
  app.post("/login", (req, res) => {
    const nome = String(req.body?.nome ?? "").trim();
    const tid = String(req.body?.tenant ?? "");
    if (!nome || !TENANTS.has(tid)) throw new HttpError(400);
    const claims = [{ typ: "tid", val: tid }, { typ: "oid", val: `dev-${nome}` }, { typ: "name", val: nome }];
    if (req.body.approvatore) claims.push({ typ: "roles", val: RUOLO });
    res.cookie("dev_principal", Buffer.from(JSON.stringify({ claims })).toString("base64"), { httpOnly: true, sameSite: "lax" });
    res.redirect(303, "/");
  });
}

app.use((req, res, next) => {
  const raw = DEV
    ? req.get("Cookie")?.split(";").map((c) => c.trim()).find((c) => c.startsWith("dev_principal="))?.slice("dev_principal=".length)
    : req.get("X-MS-CLIENT-PRINCIPAL");
  const u = raw ? parsePrincipal(decodeURIComponent(raw)) : null;
  if (!u) {
    if (DEV) return res.redirect("/login");
    throw new HttpError(401);
  }
  if (!TENANTS.has(u.tid)) throw new HttpError(403, "Tenant non ammesso");
  res.locals.user = u;
  next();
});

// ---------- dominio ----------

/** Stato derivato dalle decisioni (csv) sulla versione corrente.
 *  Non è salvato: non può disallinearsi dalle approvazioni. */
export function stato(esiti: string): string {
  const e = esiti.split(",").filter(Boolean);
  if (e.includes("RIFIUTATA")) return "RIFIUTATA";
  // UNIQUE(pratica, versione, tid) + allowlist di 2 tenant => entrambi hanno approvato
  return e.length >= TENANTS.size ? "APPROVATA" : "IN APPROVAZIONE";
}

function audit(u: User, azione: string, praticaId: number | bigint, dettaglio: string) {
  db.prepare("INSERT INTO audit(tid,oid,nome,azione,pratica_id,dettaglio) VALUES(?,?,?,?,?,?)")
    .run(u.tid, u.oid, u.nome, azione, praticaId, dettaglio);
}

// ponytail: file interi in memoria (max 50 MB l'uno); streaming su Blob Storage in Azure.
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 << 20, files: 20 } }).array("file");

/** Salva i file in data/files/<sha256>: indirizzati per contenuto,
 *  il nome fornito dall'utente non tocca mai il filesystem. */
function salvaUpload(req: Request): FileCaricato[] {
  const files: FileCaricato[] = [];
  for (const f of (req.files as Express.Multer.File[] | undefined) ?? []) {
    // multer decodifica i nomi come latin1: li riporto a UTF-8
    const nome = Buffer.from(f.originalname, "latin1").toString("utf8").replace(/\\/g, "/").split("/").pop() ?? "";
    if (!nome || !f.buffer.length) continue;
    const sha = createHash("sha256").update(f.buffer).digest("hex");
    writeFileSync(join(DATA, "files", sha), f.buffer);
    files.push({ nome, sha });
  }
  if (!files.length) throw new HttpError(400, "Serve almeno un file");
  return files;
}

function nuovaVersione(u: User, praticaId: number | bigint, files: FileCaricato[]) {
  const riga = db.prepare("UPDATE pratiche SET versione=versione+1 WHERE id=? RETURNING versione").get(praticaId) as { versione: number } | undefined;
  if (!riga) throw new HttpError(404, "Non trovato");
  for (const { nome, sha } of files) {
    db.prepare("INSERT INTO documenti(pratica_id,versione,nome,sha256) VALUES(?,?,?,?)").run(praticaId, riga.versione, nome, sha);
    audit(u, "CARICAMENTO", praticaId, `v${riga.versione} ${nome} sha256=${sha}`);
  }
}

function idDa(req: Request): number {
  const n = Number(req.params.id);
  if (!Number.isSafeInteger(n)) throw new HttpError(404, "Non trovato");
  return n;
}

// ---------- pagine ----------

app.get("/", (_req, res) => {
  const pratiche = db.prepare(`SELECT p.*, ${ESITI} FROM pratiche p ORDER BY p.id DESC`).all() as Pratica[];
  res.send(pagina(utente(res), "Pratiche", html`
    <table><tr><th>Codice<th>Titolo<th>Versione<th>Stato
    ${pratiche.map((p) => html`<tr><td><a href="/pratiche/${p.id}">${p.codice}</a><td>${p.titolo}<td>v${p.versione}<td class="s ${stato(p.esiti)}">${stato(p.esiti)}`)}
    </table>
    <h2>Nuova pratica</h2>
    <form method=post action="/pratiche" enctype="multipart/form-data">
    <label>Codice <input name=codice required placeholder="ADM196-04-0B"></label>
    <label>Titolo <input name=titolo required></label>
    <label>Descrizione <textarea name=descrizione rows=3></textarea></label>
    <label>Documenti <input type=file name=file multiple required></label>
    <button>Crea e invia in approvazione</button></form>`));
});

app.post("/pratiche", upload, (req, res) => {
  const u = utente(res);
  const codice = String(req.body?.codice ?? "").trim();
  const titolo = String(req.body?.titolo ?? "").trim();
  if (!codice || !titolo) throw new HttpError(400, "Codice e titolo sono obbligatori");
  const files = salvaUpload(req);
  const id = db.transaction(() => {
    const id = db.prepare("INSERT INTO pratiche(codice,titolo,descrizione,creata_da) VALUES(?,?,?,?)")
      .run(codice, titolo, String(req.body.descrizione ?? "").trim(), u.nome).lastInsertRowid;
    audit(u, "CREAZIONE", id, "");
    nuovaVersione(u, id, files);
    return id;
  })();
  res.redirect(303, `/pratiche/${id}`);
});

app.post("/pratiche/:id/versioni", upload, (req, res) => {
  const id = idDa(req);
  const files = salvaUpload(req);
  db.transaction(() => nuovaVersione(utente(res), id, files))();
  res.redirect(303, `/pratiche/${id}`);
});

app.get("/pratiche/:id", (req, res) => {
  const u = utente(res);
  const id = idDa(req);
  const p = db.prepare(`SELECT p.*, ${ESITI} FROM pratiche p WHERE p.id=?`).get(id) as Pratica | undefined;
  if (!p) throw new HttpError(404, "Non trovato");
  const documenti = db.prepare("SELECT id, nome, sha256 FROM documenti WHERE pratica_id=? AND versione=?").all(id, p.versione) as Documento[];
  const decisioni = db.prepare("SELECT tid, nome, esito, commento, il FROM approvazioni WHERE pratica_id=? AND versione=?").all(id, p.versione) as Approvazione[];
  const storico = db.prepare("SELECT il, tid, nome, azione, dettaglio FROM audit WHERE pratica_id=? ORDER BY id").all(id) as Audit[];
  const s = stato(p.esiti);
  const t = etichetta(u.tid);

  const decisione = !u.approvatore
    ? html`<p>Per decidere serve il ruolo ${RUOLO}.</p>`
    : decisioni.some((d) => d.tid === u.tid)
      ? html`<p>${t} ha già deciso su questa versione.</p>`
      : // "versione" nel form: la decisione vale solo per i file che l'utente ha visto.
        html`<form method=post action="/pratiche/${id}/decisione"><input type=hidden name=versione value="${p.versione}">
          <label>Commento (obbligatorio per il rifiuto) <textarea name=commento rows=3></textarea></label>
          <div><button name=esito value=APPROVATA>Approva per ${t}</button> <button name=esito value=RIFIUTATA>Rifiuta</button></div></form>`;

  res.send(pagina(u, `${p.codice} — ${p.titolo}`, html`
    <p>${p.descrizione}</p>
    <p>Creata da ${p.creata_da} il ${p.creata_il} UTC · versione ${p.versione} · <span class="s ${s}">${s}</span></p>
    <h2>Documenti (v${p.versione})</h2><table><tr><th>File<th>SHA-256
    ${documenti.map((d) => html`<tr><td><a href="/file/${d.id}">${d.nome}</a><td><code>${d.sha256}</code>`)}</table>
    <h2>Decisioni sulla v${p.versione}</h2><table><tr><th>Tenant<th>Chi<th>Esito<th>Commento<th>Quando (UTC)
    ${decisioni.map((d) => html`<tr><td>${etichetta(d.tid)}<td>${d.nome}<td class="s ${d.esito}">${d.esito}<td>${d.commento}<td>${d.il}`)}</table>
    ${decisione}
    <h2>Nuova versione</h2><p>Sostituisce tutti i documenti e azzera le decisioni.</p>
    <form method=post action="/pratiche/${id}/versioni" enctype="multipart/form-data">
    <input type=file name=file multiple required><button>Carica nuova versione</button></form>
    <h2>Storico</h2><table><tr><th>Quando (UTC)<th>Chi<th>Azione<th>Dettaglio
    ${storico.map((a) => html`<tr><td>${a.il}<td>${a.nome} (${etichetta(a.tid)})<td>${a.azione}<td>${a.dettaglio}`)}</table>`));
});

app.post("/pratiche/:id/decisione", (req, res) => {
  const u = utente(res);
  const id = idDa(req);
  if (!u.approvatore) throw new HttpError(403, `Ruolo ${RUOLO} richiesto`);
  const esito = String(req.body?.esito ?? "");
  const commento = String(req.body?.commento ?? "").trim();
  if (esito !== "APPROVATA" && esito !== "RIFIUTATA") throw new HttpError(400, "Esito non valido");
  if (esito === "RIFIUTATA" && !commento) throw new HttpError(400, "Il rifiuto richiede un commento");
  db.transaction(() => {
    const p = db.prepare("SELECT versione FROM pratiche WHERE id=?").get(id) as { versione: number } | undefined;
    if (!p) throw new HttpError(404, "Non trovato");
    if (String(p.versione) !== String(req.body.versione)) throw new HttpError(409, "La pratica ha una nuova versione: ricarica la pagina");
    const hash = (db.prepare("SELECT sha256 FROM documenti WHERE pratica_id=? AND versione=?").all(id, p.versione) as Documento[]).map((d) => d.sha256).join(" ");
    try {
      db.prepare("INSERT INTO approvazioni(pratica_id,versione,tid,oid,nome,esito,commento) VALUES(?,?,?,?,?,?,?)")
        .run(id, p.versione, u.tid, u.oid, u.nome, esito, commento);
    } catch (e) {
      if ((e as { code?: string }).code === "SQLITE_CONSTRAINT_UNIQUE")
        throw new HttpError(409, "Il tuo tenant ha già registrato una decisione su questa versione");
      throw e;
    }
    audit(u, esito, id, `v${p.versione} sha256=[${hash}] ${commento}`);
  })();
  res.redirect(303, `/pratiche/${id}`);
});

app.get("/file/:id", (req, res) => {
  const d = db.prepare("SELECT id, nome, sha256 FROM documenti WHERE id=?").get(idDa(req)) as Documento | undefined;
  if (!d) throw new HttpError(404, "Non trovato");
  // Solo i PDF si aprono nel browser; tutto il resto è download, mai interpretato come HTML.
  const pdf = d.nome.toLowerCase().endsWith(".pdf");
  const sicuro = d.nome.replace(/[^A-Za-z0-9 ._-]/g, "_");
  res.set({
    "Content-Type": pdf ? "application/pdf" : "application/octet-stream",
    "Content-Disposition": `${pdf ? "inline" : "attachment"}; filename="${sicuro}"`,
    "X-Content-Type-Options": "nosniff",
  });
  res.send(readFileSync(join(DATA, "files", d.sha256)));
});

app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof HttpError) return void res.status(err.status).type("text").send(err.message || String(err.status));
  if (err instanceof multer.MulterError) return void res.status(400).type("text").send(`Upload non valido: ${err.message}`);
  console.error(err);
  res.status(500).type("text").send("Errore interno");
});

// ---------- HTML ----------

/** Frammento già sicuro. Tutto ciò che entra in html`...` e non è Html viene sottoposto a escape. */
class Html {
  constructor(readonly s: string) {}
}
function esc(v: unknown): string {
  if (v instanceof Html) return v.s;
  if (Array.isArray(v)) return v.map(esc).join("");
  return String(v ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}
function html(parti: TemplateStringsArray, ...valori: unknown[]): Html {
  return new Html(parti.reduce((out, p, i) => out + p + (i < valori.length ? esc(valori[i]) : ""), ""));
}

function pagina(u: User | null, titolo: string, corpo: Html): string {
  return html`<!doctype html><html lang=it><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>${titolo}</title><style>
body{font:16px/1.5 system-ui,sans-serif;max-width:60rem;margin:0 auto;padding:1rem;color:#1b1b1b}
header{display:flex;justify-content:space-between;flex-wrap:wrap;gap:.5rem;border-bottom:1px solid #ccc;padding-bottom:.5rem}
table{border-collapse:collapse;width:100%} td,th{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #ddd;vertical-align:top}
form{display:grid;gap:.6rem;max-width:32rem;margin:1rem 0}
input:not([type=checkbox]),textarea,select{font:inherit;padding:.4rem;width:100%;box-sizing:border-box}
button{font:inherit;padding:.5rem 1rem;cursor:pointer;justify-self:start} code{font-size:.8em;word-break:break-all}
.s{font-weight:600} .APPROVATA{color:#0a6b2d} .RIFIUTATA{color:#a4161a}
</style><header><a href="/"><b>Approvazione documenti ADM · Sogei</b></a>
${u ? html`<span>${u.nome} · ${etichetta(u.tid)}${u.approvatore ? ` · ${RUOLO}` : ""}${DEV ? html` · <a href="/login">cambia utente</a>` : ""}</span>` : ""}
</header><h1>${titolo}</h1>${corpo}</html>`.s;
}

if (require.main === module) {
  // App Service imposta PORT. In sviluppo ascolta solo su localhost: il login finto non deve uscire dalla macchina.
  const porta = Number(process.env.PORT ?? 3000);
  app.listen(porta, DEV ? "127.0.0.1" : "0.0.0.0", () =>
    console.log(`http://localhost:${porta}${DEV ? "  (DEV_LOGIN attivo: NON usare in produzione)" : ""}`));
}
