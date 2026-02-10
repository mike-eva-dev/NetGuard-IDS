import mysql.connector
from scapy.all import sniff, IP, DNS, DNSQR
from collections import defaultdict
import time
import os

#-----INIZIALIZZO IL DATABASE----- NOTA: sto usando XAMPP.
db = mysql.connector.connect (
    host = "localhost",
    user = "root",
    password = "",
    database = "intrusion_logs" #nome del tuo database.
)
cursor = db.cursor()

## salvaPacchetto (pkt)
#  rimane in ascolto e recupera tutti i dati del pacchetto e lo stampa sulla console formattato.
#  se rileva un pericolo lo salva nel database intrusion_logs nella tabella logs.
#
#  param <- pkt: il pacchetto da scansionare.
##
def salvaPacchetto (pkt):
    if pkt.haslayer('IP'):
        mittente = pkt['IP'].src
        destinatario = pkt['IP'].dst
        lunghezza = len(pkt)
        info = pkt.summary()[:255]
        protocollo = pkt['IP'].sprintf("%IP.proto%").upper()

        portaDest = 0
        if pkt.haslayer('TCP'):
            portaDest = pkt['TCP'].dport
        elif pkt.haslayer('UDP'):
            portaDest = pkt['UDP'].dport

        pericolo, motivo = rilevaPericolo(mittente, destinatario, portaDest, lunghezza)

        valorePericolo = 1 if pericolo else 0

        dns = None
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
            try:
                dns = pkt[DNSQR].qname.decode('utf-8').strip('.')
            except:
                dns = "Errore di Decodifica."

        query = "INSERT INTO log (source_ip, dest_ip, protocol, packLength, info, isPERICOLO, motivo, DNS)" \
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
        
        valori = (mittente, destinatario, protocollo, lunghezza, info, valorePericolo, motivo, dns)

        if pericolo:
            try:
                cursor.execute(query, valori)
                db.commit()
                print(f"{info}")
                print(f"ARCHIVIATO: {protocollo} | {mittente} --> {destinatario}")
            except Exception as e:
                print(f"ERRORE DURANTE L'INSERIMENTO: {e}")
        else:
            formato = "RILEVATO: %-6s | %-15s --> %-15s | %6d bytes | %-20s"
            print(formato % (protocollo, mittente, destinatario, lunghezza, dns))
    else:
        pass

## rilevaPericolo(mittente, destinatario, portaDestinatario, dimPacchetto)
#  mette insieme tutti i metodi di controllo: Blacklist, Portscan ed Esfiltrazione.
#
#  param <- mittente: l'ip che indica il mittente.
#  param <- destinatario: l'ip che indica il destinatario.
#  param <- portaDestinatario: la porta di destinazione.
#  param <- dimPacchetto: la dimensione in byte del pacchetto.
#  output -> tupla (booleano, stringa) che indica se è stato trovato un pericolo e quale.
##
def rilevaPericolo(mittente, destinatario, portaDestinatario, dimPacchetto):
    if controllaBlacklist(mittente, destinatario):
        return True, "!-----BLACKLIST: IP malevolo rilevato-----!"
    
    if portaDestinatario > 0:
        if rilevaPortScan(mittente, portaDestinatario):
            return True, f"!-----PORT SCAN: {mittente} sta scansionando le porte-----!"
    
    if rilevaEsfiltrazione(mittente, dimPacchetto):
        return True, f"!-----VOLUME DI TRAFFICO ANOMALO: possibile ESFILTRAZIONE da {mittente}-----!"
    
    return False, None

## caricaBlacklist(nomeFile) e controllaBlacklist(mittente, destinatario)
#  permette di caricare un file blacklist (estensione .txt, con intestazione) e
#  per ogni pacchetto, controlla che il mittente o il destinatario non sia stato
#  contrassegnato come malevolo in precedenza.
#
#  param <- nomeFile: il nome del file con estensione .txt.
#  output -> set di IP malevoli.
#  param <- mittente: l'ip che indica il mittente.
#  param <- destinatario: l'ip che indica il destinatario.
#  output -> booleano che indica se è stato rilevato il pericolo o meno.
##
def caricaBlacklist(nomeFile):
    with open(nomeFile, "r") as file:
        return set(line.strip() for line in file.readlines()[1:] if line.strip())

def controllaBlacklist(mittente, destinatario):
    if (mittente in BLACKLIST) or (destinatario in BLACKLIST):
        return True
    return False

## rilevaPortScan(ipSorgente, portaDestinazione)
#  rileva se lo stesso mittente controlla più di 15 porte in 10 secondi.
#  il che potrebbe configurare un port scan.
#  
#  param <- ipSorgente: l'ip che indica il mittente.
#  param <- portaDestinazione: la porta "scansionata".
#  output -> booleano che indica se è stato rilevato il pericolo o meno.
##
def rilevaPortScan(ipSorgente, portaDestinazione):
    global ULTIMORESET

    if time.time() - ULTIMORESET > 10:
        STORIAPORTSCAN.clear()
        ULTIMORESET = time.time()
    
    STORIAPORTSCAN[ipSorgente].add(portaDestinazione)

    if len(STORIAPORTSCAN[ipSorgente]) > 15:
        return True
    return False

## rilevaEsfiltrazione(ipSorgente, dimPacchetto)
#  rileva se c'è uno scambio di una mole anomala di dati con un IP.
#  può coprire anche in caso di DoS di Volume, ma non da DoS di connessione.
#  NOTA: va tarata in base al traffico medio dell'ambiente.
#
#  param <- ipSorgente: l'ip che indica il mittente.
#  param <- dimPacchetto: la dimensione in byte del pacchetto.
#  output -> booleano che indica se è stato rilevato il pericolo o meno.
##
def rilevaEsfiltrazione(ipSorgente, dimPacchetto):
    global ULTIMOCONTROLLOVOLUME

    if time.time() - ULTIMOCONTROLLOVOLUME > 60:
        VOLUMITRAFFICO.clear()
        ULTIMOCONTROLLOVOLUME = time.time()
    
    VOLUMITRAFFICO[ipSorgente] += dimPacchetto

    if VOLUMITRAFFICO[ipSorgente] > SOGLIAESFILTRAZIONE:
        return True
    return False

#-----DATI PER I CONTROLLI-----
PERCORSOBLACKLIST = os.path.join(os.path.dirname(__file__), "blacklist.txt")
BLACKLIST = caricaBlacklist(PERCORSOBLACKLIST)
STORIAPORTSCAN = defaultdict(set)
ULTIMORESET = time.time()
VOLUMITRAFFICO = defaultdict(int)
ULTIMOCONTROLLOVOLUME = time.time()
MBESFILTRAZIONE = 5 #mb
SOGLIAESFILTRAZIONE = MBESFILTRAZIONE * 1024 * 1024 #byte

#-----AVVIO DELLO SNIFFER-----
try:
    sniff(filter = "ip", prn = salvaPacchetto, store = 0)
except KeyboardInterrupt:
    print("\nArresto dello sniffer...")
finally:
    db.close()
    print("-----connessione col database chiusa-----")