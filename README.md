# NetGuard IDS - Network IDS 🛡️

**NetGuard IDS** è un sistema di rilevamento delle intrusioni (IDS) sviluppato in Python. Il software monitora il traffico di rete in tempo reale, identifica potenziali minacce tramite analisi euristica e archivia gli eventi sospetti in un database MySQL per una successiva visualizzazione in Dashboard Java.



## 🚀 Funzionalità principali

Il sistema analizza ogni pacchetto IP e applica tre livelli di controllo per identificare attività anomale:

1.  **Analisi della Reputazione (Blacklist)**: Confronta gli indirizzi IP sorgente e destinazione con una lista di host malevoli caricati dal file `blacklist.txt`.
2.  **Rilevamento Port Scan**: Monitora i tentativi di connessione su porte diverse. Se un host ne contatta più di 15 in 10 secondi, viene generato un alert di "Port Scan".
3.  **Monitoraggio Volumetrico (Esfiltrazione/DoS)**: Calcola i dati scambiati da ogni IP. Se un host supera la soglia di 5MB in 60 secondi, il sistema segnala una possibile esfiltrazione o un attacco DoS di volume.

## 🛠️ Stack Tecnologico

* **Linguaggio**: Python 3.x
* **Libreria Core**: Scapy (Packet Sniffing & Parsing)
* **Database**: MySQL (tramite XAMPP / MariaDB)
* **Connettore**: `mysql-connector-python`

## 📂 Struttura dei File Caricati
`core-sniffer`:
* `sniffer_to_db.py`: Lo script principale che gestisce la cattura, l'analisi e il salvataggio dei log.
* `blacklist.txt`: File di configurazione contenente gli IP da bloccare (include intestazione di sicurezza).

`fuori (ponte)`:
* `intrusion_logs.sql`: Dump SQL per la creazione automatica del database `intrusion_logs` e della tabella `log`.

## 🔧 Configurazione e Utilizzo

### 1. Preparazione Database
Importa il file `intrusion_logs.sql` in phpMyAdmin per creare la struttura:
- Tabella: `log`
- Colonne principali: `source_ip`, `dest_ip`, `protocol`, `packLength`, `info`, `isPERICOLO`, `motivo`, `DNS`.

### 2. Installazione Dipendenze
Per far funzionare lo sniffer, è necessario installare Python e le librerie richieste tramite `pip`. Apri il terminale e digita:
```pip install scapy mysql-connector-python```

Per la Dashboard Java
Per permettere a Java di comunicare con MySQL, è fondamentale includere il driver `JDBC Connector/J`:

Scarica il file `.jar (MySQL Connector/J)`.

Aggiungi il file al Build Path del tuo progetto Java (in Eclipse/IntelliJ o tramite riga di comando).

`Requisito Software: XAMPP attivo con i moduli Apache e MySQL avviati.`

### 3. Esecuzione del Sistema
- Avvia `XAMPP` e attiva i moduli `Apache` e `MySQL`.

- Assicurati che il file `blacklist.txt` sia nella stessa cartella dello script.

- Esegui lo script con privilegi di amministratore (necessari per il Packet Sniffing):

- Windows: Apri il CMD come amministratore e scrivi `python sniffer_to_db.py`.

- Linux/macOS: Esegui `sudo python3 sniffer_to_db.py`.

## 📊 Gestione dei Log e Alert

Il sistema differenzia visivamente il traffico in console per facilitare il monitoraggio immediato:

* **Traffico Lecito**: Stampato in console in tempo reale in formato tabellare (Protocollo, IP Sorgente, IP Destinazione, Dimensione e Query DNS).
* **Traffico Sospetto (ALERT)**: Quando viene rilevata una minaccia, il sistema evidenzia l'evento in console e salva i dati nel database MySQL.

### Esempio di Alert nel Database
Ogni record salvato nella tabella `log` conterrà:
- `isPERICOLO = 1`
- `motivo`: Descrizione del tipo di attacco (es. "PORT SCAN" o "BLACKLIST")
- `info`: Riassunto tecnico del pacchetto catturato.


## 🖥️ Prossimi Sviluppi: Dashboard Java

Il progetto prevede l'integrazione di una Dashboard sviluppata in **Java (Swing)** che si connetterà al database MySQL per:
- Visualizzare una tabella dinamica degli alert.
- Filtrare le minacce per gravità o tipologia.
- Fornire un'interfaccia grafica intuitiva per l'amministratore di rete.

---
**Disclaimer**: Questo software è stato sviluppato a scopo puramente didattico. L'utilizzo per il monitoraggio di reti senza autorizzazione è illegale.

## 📝 Note di Sviluppo e Prossimi Passi

- [x] Sviluppo dello sniffer Python con Scapy.
- [x] Integrazione database MySQL.
- [x] Analisi euristica (Port Scan, Blacklist, Esfiltrazione).
- [x] Sviluppo Dashboard Java: Prevista l'implementazione dell'interfaccia grafica per il monitoraggio centralizzato.
FINITO!
> **Nota di trasparenza**: La documentazione (README) è stata ottimizzata con l'ausilio di strumenti IA per garantire chiarezza e rapidità di consultazione. Il codice sorgente e la logica di analisi sono stati interamente sviluppati dal sottoscritto.
