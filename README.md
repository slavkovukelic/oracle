# Oracle Linux Oracle Setup alat

## Pregled

`oracle_setup.py` je modernizovani CLI alat namenjen pripremi Oracle Linux 8 sistema za Oracle Database i Fusion Middleware radna opterećenja. Omogućava prilagođavanje kernel parametara, sistemskih korisnika i direktorijuma prema Oracle preporukama. Pored adaptivnog Python načina rada koji izračunava podešavanja na osnovu trenutnog hardvera, dostupan je i „legacy” režim koji pokreće originalni `oracle.sh` skript za 100% usklađene rezultate.

## Instalacija

1. Instalirajte Python 3.10 ili noviji (alat podržava i Python 3.11+).
2. (Opciono) Kreirajte virtuelno okruženje:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
3. Instalirajte zavisnosti iz `requirements.txt`:
   ```bash
   pip install -r requirements.txt
   ```

> Napomena: Na Python verzijama starijim od 3.11 potreban je paket `tomli` kako bi se učitavao TOML konfiguracioni fajl.

## Pokretanje

Prilikom pokretanja uvek koristite bootstrap skript koji obezbeđuje da je prisutan podržani Python interpreter:

```bash
./oracle_setup_bootstrap.sh
```

Skript najpre proverava verziju podrazumevanog `python3`. Ako je verzija 3.11 ili novija, direktno pokreće `oracle_setup.py`. U suprotnom pokušava da instalira `python3.11` pomoću `dnf`, a zatim pokreće alat sa novoinstaliranim interpreterom. Ukoliko želite da izmene budu primenjene na sistem, prosledite `--apply` i pokrenite skript kao `root`:

```bash
sudo ./oracle_setup_bootstrap.sh --apply
```

## CLI opcije

Sve dostupne CLI opcije možete kombinovati po potrebi:

- `--oracle-user <ime>` – podrazumevano `oracle`; korisnik za koga se pripremaju limiti i direktorijumi.
- `--apply` – kada je prisutno, upisuje izračunatu konfiguraciju na sistem (zahteva root).
- `--fmw-user <ime>` – podrazumevano `fmw`; dodatni Fusion Middleware korisnik.
- `--no-fmw` – onemogućava kreiranje/ažuriranje Fusion Middleware korisnika i direktorijuma.
- `--mode {adaptive,legacy}` – bira da li se koristi Python adaptivni plan ili istorijski `oracle.sh` skript.
- `--inspect` – upoređuje trenutno stanje sistema sa planiranom konfiguracijom i prikazuje neslaganja.
- `--verbose` / `-v` – povećava količinu logovanja (ponavljanjem opcije prelazi se na debug nivo).
- `--log-file <putanja>` – upisuje logove u navedeni fajl pored izlaza na konzolu.
- `--log-format {text,json}` – format logova (podrazumevano `text`).
- `--output <putanja>` – upisuje izračunati plan u JSON fajl (korisno u dry-run režimu).
- `--legacy-script <putanja>` – ručno zadaje lokaciju `oracle.sh` skripta za `legacy` režim.
- `--config <putanja>` – čita konfiguraciju iz TOML dokumenta (podrazumevano `oracle_setup.toml`).
- `--update-existing-users` – usklađuje postojeće sistemske korisnike sa postavkama iz konfiguracije.
- `--repo-mode {system,local}` – određuje da li alat koristi postojeće internet repozitorijume (`system`) ili ih privremeno zamenjuje lokalnim ISO/CD-ROM ogledalom (`local`).
- `--local-repo-root <putanja>` – putanja do montiranog Oracle Linux medija kada je aktivan `--repo-mode=local` (podrazumevano `/INSTALL`).

## Primer TOML konfiguracije

Sledeći primer pokazuje sve sekcije koje alat podržava. Svaka od njih je opciona osim `[paths]` koji mora postojati:

```toml
[packages]
install = [
  "kmod-oracle",
  "oracle-database-preinstall-19c"
]

[[groups]]
name = "oinstall"
gid = 54321

[[groups]]
name = "dba"

[[users]]
name = "oracle"
primary_group = "oinstall"
supplementary_groups = ["dba"]
home = "/u01/app/oracle"
shell = "/bin/bash"
uid = 54321
create_home = true

[[users]]
name = "fmw"
primary_group = "oinstall"
supplementary_groups = ["dba"]
home = "/u01/app/fmw"
create_home = true

[paths]
data_root = "/u01"
profile_dir = "/etc/profile.d"
ora_inventory = "/u01/app/oraInventory"
oratab = "/etc/oratab"

[database]
target_version = "19c"
```

### Objašnjenje sekcija

- `[packages]` – navodi dodatne RPM pakete koji treba da budu instalirani; polje `install` je lista naziva paketa.
- `[[groups]]` – svaki unos definiše sistemsku grupu (ime i opciono `gid`).
- `[[users]]` – opisuje korisnike (ime, primarnu grupu, dodatne grupe, kućni direktorijum, opciono `uid`, ljusku i da li se direktorijum kreira ako ne postoji).
- `[paths]` – definiše ključne putanje za Oracle softver (`data_root`, `profile_dir`, `ora_inventory`, `oratab`).
- `[database]` – omogućava navođenje ciljne verzije baze (`target_version`) radi dokumentacije i inspekcije.

## Legacy režim

Kada je `--mode legacy` postavljen, alat pokreće originalni `oracle.sh` skript. Ovo je korisno za komande koje zahtevaju potpuno iste korake kao u postojećim okruženjima. Skript se pokreće non-interaktivno i zahteva root privilegije ako se primenjuju izmene.

---

Za dodatne informacije pregledajte izvorni kod `oracle_setup.py` i podrazumevanu konfiguraciju `oracle_setup.toml`.
