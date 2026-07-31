# Auth-Caching und geteilter HTTP-Client

## Problem

Zwei Befunde im Auth-Pfad:

1. **`HttpWebIdIssuers` cacht nichts.** Jeder authentifizierte Request dereferenziert das
   WebID-Profildokument neu über HTTP. `HttpJwksResolver` hat bereits einen TTL-Cache
   (300s positiv / 30s negativ); der Profil-Fetch hat kein Gegenstück.

2. **Kein Verbindungs-Reuse, nirgends.** Beide Verifier halten ein `reqwest::Client`-Feld,
   das tot ist: `guarded_get(_client, …)` ignoriert es und baut pro Request einen frischen
   Client, weil das DNS-Pinning (`ClientBuilder::resolve`) nur zur Build-Zeit gesetzt werden
   kann. Ein Client durchzureichen bringt also nichts, solange `guarded_get` so gebaut ist.

Der zweite Punkt ist der eigentliche Knoten: er blockiert das Ziel „shared `reqwest::Client`,
damit Sessions wiederverwendet werden".

## Was das Feld macht

Die Solid-OIDC-Spec sagt zu Caching nichts. §6.1 verlangt nur, dass das Profil auf
`solid:oidcIssuer` geprüft wird — keine TTL, kein Cache-Control, kein ETag.

`@solid/access-token-verifier` (die Referenzbibliothek, die CSS nutzt):

- `WebIDIssuersCache`: LRU, max 100 Einträge, maxAge 120s, Key `webid → Array<issuer>`.
- `IssuerKeySetCache`: identisch dimensioniert.
- Kein ETag, kein Cache-Control. [Issue #12](https://github.com/CommunitySolidServer/access-token-verifier/issues/12)
  fordert Cache-Control-basiertes Caching — offen, nie umgesetzt. Begründung dort: bei fixer
  TTL wirkt ein neu ins Profil eingetragener Issuer bis zu einer TTL-Länge nicht.
- Kein Negativ-Cache; Fehlschläge werden nicht gemerkt.

`jose` (unter dem JWKS-Cache): `cacheMaxAge` 600s, `cooldownDuration` 30s, ebenfalls kein ETag.

Kurz: fixe kurze TTL plus beschränkte LRU ist der Stand der Technik. ETag macht niemand.

## Entwurf

### 1. `GuardedClient` in `auth::safe_fetch`

Die Adressvalidierung wandert **in den DNS-Resolver**, statt davor zu laufen und die Adresse
danach zu pinnen:

```rust
pub struct GuardedClient { inner: reqwest::Client }   // Clone teilt den Pool
impl GuardedClient { pub fn new(policy: &FetchPolicy) -> Self }
```

`new` baut einmalig einen Client mit `ClientBuilder::dns_resolver(PolicyResolver { policy })`,
dazu `redirect(Policy::none())` und die bisherigen Connect-/Total-Timeouts.

`PolicyResolver` implementiert `reqwest::dns::Resolve`: `lookup_host((host, 0))`, und wenn
**irgendeine** aufgelöste Adresse verboten ist, schlägt die Auflösung fehl — nicht ein Filtern
der schlechten Adressen. Die host-weite Ausnahme für vom Operator benannte Hosts läuft über ein
neues `FetchPolicy::permits_insecure_host(host)`, weil der Resolver den Port nicht kennt.

Damit ist die TOCTOU-Lücke nicht mehr gepinnt, sondern verschwunden: der Socket kann nur zu
einer Adresse verbinden, die der Resolver zurückgegeben hat, und der Resolver *ist* die
Prüfung.

**Genau ein Klassifikator.** Die Entscheidung „ist dieses Adressset für diesen Host unter dieser
Policy zulässig" lebt in einer Funktion, `screen_addresses`, die sowohl `resolve_allowed` als
auch `PolicyResolver::resolve` aufruft. Ein Prädikat, zwei Aufrufer — nicht zwei Prädikate.
Dieses Repo trennt das an mehreren Stellen ausdrücklich so (siehe die `version`-Regel in
`docs/constraints.md`: denselben Reader zweimal aufzurufen ist der eine Reader, zweimal
benutzt). Zwei getrennt gepflegte Fassungen der Policy-Komposition
`allow_private_ips || permits_insecure(…)` wären dagegen genau die stille Drift, gegen die die
„genau eine Stelle"-Regeln dort antreten: beide antworten, eine antwortet falsch.

**Kein Rückfall hinter `ce5e696`.** Jener Commit verwarf, die URL an `reqwest` zu geben und es
selbst neu auflösen zu lassen — der Fall, in dem ein Name für die Prüfung öffentlich und für
die Verbindung privat antwortet. Hier wird `reqwest`s Resolver *ersetzt*, die Auflösung, die
`reqwest` durchführt, ist also die validierte. Oberflächlich sieht das wie die verworfene
Variante aus; es ist ihr Gegenteil.

`guarded_get(&GuardedClient, url, accept, policy)` behält Scheme-Check, Pre-flight
`resolve_allowed`, Statusprüfung, Content-Type-Erfassung, Body-Cap und Dekodierung. Es entfällt
allein der `Client::builder()`-Aufbau pro Request.

Das Pre-flight bleibt, weil `permits_insecure(host, port)` port-genau ist und der Resolver das
nicht sein kann. Ein Request auf `alice.example:443`, während der Operator nur
`alice.example:8080` benannt hat, wird vom Pre-flight abgelehnt und erreicht den laxeren
Resolver nie. Der Connection-Pool schlüsselt nach `(scheme, host, port)`, also kann eine für
8080 aufgebaute Verbindung nicht für 443 recycelt werden. Die bestehenden
`AuthError::FetchBlocked`-Meldungen bleiben wörtlich erhalten.

Der Newtype ist load-bearing, nicht Kosmetik: `guarded_get` vertraut seinem Client jetzt. Ein
blanker `reqwest::Client` würde den Rebinding-Schutz stillschweigend verlieren; mit dem Wrapper
ist das ein Compile-Fehler statt einer Grep-Regel.

### 2. Cache in `auth::webid_issuer`

```rust
const CACHE_TTL: Duration = Duration::from_secs(120);
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(30);
const MAX_CACHE_ENTRIES: usize = 1024;
```

Key ist `webid → Vec<String>` (die im Profil deklarierten Issuer), nicht `(webid, issuer) → bool`.
Ein Eintrag beantwortet jede Issuer-Frage zu diesem WebID; ein WebID mit zwei Issuern kostet
keine zwei Fetches.

`authorizes` prüft positiv → negativ → Fetch, in derselben Reihenfolge wie
`HttpJwksResolver::resolve`. Ein erfolgreicher Fetch räumt den Negativ-Eintrag ab. Die heutige
Semantik bleibt: Profil geparst, Issuer nicht deklariert → `Ok(false)`; Fetch oder Parse kaputt
→ `Err`.

120s statt der 300s des JWKS-Caches: das Profil ändert der Nutzer selbst, das JWKS rotiert der
IdP. Die kürzere TTL ist die Antwort auf die Beschwerde aus Issue #12.

Der Negativ-Cache geht bewusst über das hinaus, was CSS tut. Er ist hier zugleich der
SSRF-Dämpfer: ohne ihn löst jeder Request mit erfundener `webid` einen neuen ausgehenden Fetch
auf eine angreifer-gewählte URL aus. Bei `trusted_issuers: None` ist genau das erreichbar, weil
dann jeder mit eigenem IdP beliebige `webid`-Claims signieren kann.

Beschränkung ohne neue Dependency: beim Einfügen zuerst abgelaufene Einträge purgen; ist die
Map danach immer noch voll, den Eintrag mit dem ältesten `fetched_at` verdrängen. Positiv- und
Negativ-Map werden getrennt beschränkt. 1024 statt der 100 von CSS — deren Zahl leitet sich aus
geschätzten Requests pro Sekunde ab, was für einen Pod-Cache die falsche Achse ist.

### 3. Verdrahtung

`main.rs` baut einen `GuardedClient` aus der `FetchPolicy` und übergibt ihn an
`HttpJwksResolver::new` und `HttpWebIdIssuers::new`. Beide behalten die Policy für das
port-genaue Pre-flight. Damit teilen sich OIDC-Discovery, JWKS-Fetch und Profil-Fetch Pool und
TLS-Sessions.

### 4. `docs/deployment.md`

Das Operator-Dokument verspricht heute an zwei Stellen den *Mechanismus* statt der Eigenschaft:
„the connection is pinned to the exact address that was validated" (§ SSRF-Posture) und „the
connection is still pinned to the validated IP, so DNS rebinding is still closed" (§ What it
does not relax). Beide Sätze werden auf die Eigenschaft umgestellt: die Verbindung erreicht nur
Adressen, die der Filter freigegeben hat. Im selben Commit wie der Code — zwei lebende
Beschreibungen einer Architektur ist das Versagen, gegen das `docs/constraints.md` antritt.

Was sich für den Operator **nicht** ändert: die Regel `host` gegen `host:port` bleibt
port-genau, weil das Pre-flight sie prüft. Deshalb kann das Pre-flight auch nicht entfallen,
obwohl es die zweite Auflösung kostet.

### 5. `docs/constraints.md`

Eine neue Regel: `guarded_get` vertraut seinem Client, also darf es genau einen Ort geben, an
dem ein `reqwest::Client` entsteht. Der private Feldzugriff im Newtype macht das heute
compiler-fest, aber die Mitgliedschaft — dass kein zweiter Konstruktor und kein `inner()`
dazukommt — ist es nicht; dieselbe Form wie die `DirectlyWritable`-Regel.

    check: [ "$(rg -o 'reqwest::Client::(builder|new)' src | wc -l)" = 1 ]

Die Regel muss vor der Aufnahme gegen eine echte Verletzung rot laufen.

## Tests

- Zwei `authorizes`-Aufrufe innerhalb der TTL holen das Profil nur einmal (Hit-Counter am
  lokalen Testserver, gespiegelt vom JWKS-Cache-Test).
- Ein zweiter Issuer desselben Profils wird aus demselben Eintrag beantwortet, ohne zweiten
  Fetch.
- Ein Fehlschlag wird negativ gecacht: zweiter Aufruf trifft den 500er-Server nicht erneut.
- Die Grenze hält: MAX+1 verschiedene WebIDs lassen die Map nicht über MAX wachsen.
- Session-Reuse ist belegt: der Testserver zählt akzeptierte TCP-Verbindungen; zwei Fetches
  über denselben `GuardedClient` ergeben eine Verbindung.
- Die `safe_fetch`-Tests bauen ihre Clients auf `GuardedClient::new(&policy)` um, damit sie
  nicht am geschützten Pfad vorbei testen.

## Nicht in diesem Spec

- Eine Größengrenze für den bestehenden, ebenfalls angreifer-gefütterten JWKS-Cache
  (vorbestehend, eigener Vorgang).
- Cache-Control/ETag-basiertes Caching (CSS Issue #12; niemand hat es gebaut).
- Ein Cache über das gesamte Auth-Ergebnis (token → Agent): würde Signatur-, DPoP- und
  WebID-Prüfung überspringen und die Revocation-Semantik verschieben.
