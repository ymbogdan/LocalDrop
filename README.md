# LocalDrop

Trasferimento di file tra un PC Windows e un iPhone, sulla rete locale. Il telefono apre una pagina in Safari. Non serve un account e i file non passano da un cloud.

Il computer mostra un codice QR. Inquadrandolo, l’iPhone entra già nella pagina, senza scrivere l’indirizzo né il codice.

## Requisiti

* Windows 10 o 11
* Python 3.13, se avvii dal codice
* iPhone con Safari
* PC e telefono sulla stessa rete, oppure telefono collegato col cavo e **Hotspot personale** attivo

Il solo cavo USB non basta: Safari ha bisogno di un indirizzo di rete. Con Hotspot personale acceso, il cavo crea quella rete e il PC non ha bisogno di internet.

## Avvio

Dall’eseguibile:

```text
dist\LocalDrop.exe
```

Dal codice:

```text
pip install -r requirements.txt
python -m app.main
```

Per rigenerare l’eseguibile:

```text
python -m PyInstaller --noconfirm LocalDrop.spec
```

L’exe e la cartella `build` non fanno parte del repository: si ricostruiscono in locale.

## Dal telefono al computer

1. Avvia LocalDrop sul PC.
2. Inquadra il codice QR con la fotocamera dell’iPhone.
3. Scegli i file e premi **Invia al computer**.
4. Sul PC i file restano in attesa. Scegli quali tenere, la cartella, poi **Salva i selezionati**. **Scarta** li elimina.

Un file già inviato resta in **Già inviati**. **Reinvia** lo manda di nuovo senza riselezionarlo dalla galleria.

## Dal computer al telefono

1. Sul PC, in **Verso il telefono**, premi **Scegli file**.
2. Sull’iPhone apri la pagina e scarica il file.
3. Per una foto o un video, **Salva in Foto** apre l’originale. Tieni premuto e scegli **Salva immagine** o **Salva video**.

Safari non può scrivere da solo nell’app Foto: il tocco lungo è il passaggio che mette il file in galleria. I byte sono quelli originali. L’anteprima a schermo è un’immagine a parte e non sostituisce il file.

**Svuota** toglie i file dalla pagina del telefono. Restano in **Già inviati**: **Reinvia** li ripubblica senza cercarli di nuovo. Un file arrivato dal telefono ha **Manda al telefono** per rimandarlo indietro senza riaprirlo dalla cartella.

## Rete

Funziona se il PC è in Ethernet e il telefono è sul Wi-Fi dello stesso router, purché siano nella stessa sottorete.

La pagina accetta solo indirizzi della rete locale del PC. Un IP esterno riceve «Accesso consentito solo dalla rete di casa». Il codice a 6 cifre è un secondo controllo, sulla stessa rete.

Porte usate dal PC:

| Porta | Uso |
| --- | --- |
| 47823 | Pagina del telefono, HTTP |
| 47821 | Discovery UDP, percorso fra PC |
| 47822 | Canale TLS fra due PC |

In Windows Firewall serve il consenso in ingresso per LocalDrop, anche sul profilo Pubblico se la rete è quella dell’hotspot.

## Sicurezza

La pagina del telefono è HTTP, perché Safari deve aprirla senza un certificato da installare. La protezione è il codice più il controllo che il client sia sulla rete di casa. Non va esposta su internet.

Chiavi, certificato e dispositivi associati stanno in `%APPDATA%\LocalDrop`, fuori da questa cartella, e non vanno nel repository.

Il canale fra due PC, rimasto nel codice, usa TLS 1.3. La finestra attuale è pensata per il telefono.

I file in arrivo dal telefono non vengono scritti subito nella cartella scelta. Finché non premi **Salva i selezionati** restano in una cartella temporanea. Un nome che prova a uscire da quella cartella viene ridotto al solo nome del file.

## Architettura

* `app/phone` pagina Safari, codice, invii, anteprime
* `app/gui` finestra desktop
* `app/controller.py` collega la finestra alla pagina
* `app/network` discovery e canale fra PC
* `app/security` identità, trust, controlli sui nomi
* `app/transfer` invio fra due PC

## Test

```text
python -m unittest discover -s tests
```

## Limiti

Le cartelle non si inviano. La pagina non salva da sola in Foto: serve il tocco lungo sull’originale. Senza una rete fra PC e telefono, nemmeno il cavo basta finché Hotspot personale non è attivo.
