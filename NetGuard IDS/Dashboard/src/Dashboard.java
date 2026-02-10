import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.sql.*;
import java.util.Vector;

public class Dashboard {
    public static void main(String[] args) {
        /** CREAZIONE FINESTRA
         *  Crea la finestra fisica sul tuo Desktop tramite JFrame, ne imposta le dimensioni
         *  e setta la modalità di chiusura (la x).
         **/
        JFrame finestra = new JFrame("NetGuard IDS - Security Dashboard");
        finestra.setSize(800, 400);
        finestra.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        /** PANNELLO DEI COMANDI
         *  Crea un pannello JPanel per raggruppare i bottoni in alto, poi
         *  crea il campo di testo e i vari pulsanti cliccabili e ne gestisce lo stile.
         *  Si aggiungono i vari bottoni e input con panelComandi.add(input).
         **/
        JPanel panelComandi = new JPanel();
        JTextField txtRicerca = new JTextField(15);
        JButton btnCerca = new JButton("Cerca");
        JButton btnElimina = new JButton("Elimina Selezionato");
        JButton btnReset = new JButton("Reset");
        JButton btnSvuota = new JButton("Svuota Log");
        btnSvuota.setBackground(java.awt.Color.RED);
        btnSvuota.setForeground(java.awt.Color.WHITE);

        panelComandi.add(new JLabel("Filtra per IP/Motivo:"));
        panelComandi.add(txtRicerca);
        panelComandi.add(btnCerca);
        panelComandi.add(btnElimina);
        panelComandi.add(btnReset);
        panelComandi.add(btnSvuota);

        /** LA TABELLA E IL MODELLO DATI
         *  DefaultTableModel è il cervello della tabella, contiene i dati puri.
         *  isCellEditable dice che ogni cella NON è modificabile.
         *  Si aggiungono le varie colonne con modello.addColumn(nomeColonna) per ogni colonna.
         *  Si aggiunge anche la possibilità di scollare tra i log, visto che ne possono apparire 1000+ log
         *  ne carica anche i dati richiamando la funzione caricaDati(modello).
         **/
        DefaultTableModel modello = new DefaultTableModel() {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        modello.addColumn("ID");
        modello.addColumn("Data/Ora");
        modello.addColumn("IP Sorgente");
        modello.addColumn("Motivo Alert");

        JTable table = new JTable(modello);
        JScrollPane scrollPane = new JScrollPane(table);
        finestra.add(scrollPane);

        finestra.add(panelComandi, "North");
        finestra.add(scrollPane, "Center");
    
        caricaDati(modello);

        /** LOGICA DEI PULSANTI
         *  quando succede l'evento e:
         *  btnCerca: Prende il testo da txtRicerca e chiama la funzione di ricerca SQL.
         *  btnReset: Svuota il campo testo, pulisce la tabella e ricarica tutto dal DB.
         *  btnElimina: Guarda quale riga hai cliccato (getSelectedRow), recupera l'ID e lo cancella dal DB.
         *  btnSvuota: Apre un JOptionPane (una finestrella pop-up di conferma) e se rispondi "Sì", lancia il TRUNCATE sul database.
         **/
        btnCerca.addActionListener(e -> {
            String parolaChiave = txtRicerca.getText();
            cercaDati(modello, parolaChiave);
        });

        btnReset.addActionListener(e -> {
            txtRicerca.setText("");
            modello.setRowCount(0);
            caricaDati(modello);
        });

        btnElimina.addActionListener(e -> {
            int rigaSelezionata = table.getSelectedRow();
            if (rigaSelezionata != -1) {
                int id = (int) modello.getValueAt(rigaSelezionata, 0); 
                eliminaRecord(id); 
                modello.removeRow(rigaSelezionata);
            } else {
                JOptionPane.showMessageDialog(finestra, "Per favore, seleziona una riga da eliminare.");
            }
        });

        btnSvuota.addActionListener(e -> {
            int conferma = JOptionPane.showConfirmDialog(finestra, "Sei sicuro di voler cancellare TUTTI i log?", "Attenzione", JOptionPane.YES_NO_OPTION);
            if (conferma == JOptionPane.YES_OPTION) {
                svuotaTabella();
                modello.setRowCount(0);
            }
        });

        /** TIMER DI AGGIORNAMENTO
         *  Crea un processo in background che ogni 5000ms (5 secondi) svuota la tabella
         *  e la ricarica, difatti aggiornandola.
         **/
        Timer timer = new Timer(5000, e -> {
            int rigaSelezionata = table.getSelectedRow();
            modello.setRowCount(0);
            caricaDati(modello);

            if (rigaSelezionata != -1 && rigaSelezionata < modello.getRowCount()) {
                table.setRowSelectionInterval(rigaSelezionata, rigaSelezionata);
            }
        });
        timer.start();
        finestra.setVisible(true);
    }

    /** caricaDati(DefaultTableModel model)
     *  Permette a Java di leggere i messaggi lasciati dallo sniffer nel MySQL e li trasforma
     *  in righe fisiche nella Dashboard.
     *  Si definiscono le coordinate MySQL, USIAMO XAMPP.
     *  Si usa un try-with-resources per aprire la connessione e assicurarsi che poi
     *  venga chiusa, anche se c'è un errore, è fondamentale per non "intasare" il database 
     *  con troppe connessioni aperte.
     *  
     *  Esegue le Query, Statement: È l'oggetto che "trasporta" la tua query SQL al database.
     *  ResultSet rs: Come un foglio Excel virtuale che contiene i risultati della tua SELECT. 
     *                Inizialmente, il "cursore" è posizionato prima della prima riga.
     *  C'è il ciclo di lettura, sposta ogni volta il cursore alla riga successiva, il ciclo continua finché ci sono log nel DB.
     *  Vector<Object> row: È un contenitore (un array dinamico) che rappresenta una singola riga della tabella.
     *  rs.get: pesca il valore dalla colonna, si usa getInt per i numeri e getString per il testo.
     *  
     *  A livello grafico, si aggiunge la grafica con model.addRow(row).
     **/
    public static void caricaDati(DefaultTableModel model) {
        String url = "jdbc:mysql://localhost:3306/intrusion_logs";
        String user = "root";
        String password = "";

        try (Connection conn = DriverManager.getConnection(url, user, password)) {
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT logID, logTimeStamp, source_ip, motivo FROM log WHERE isPERICOLO = 1");

            while (rs.next()) {
                Vector<Object> row = new Vector<>();
                row.add(rs.getInt("logID"));             
                row.add(rs.getTimestamp("logTimeStamp"));
                row.add(rs.getString("source_ip"));
                row.add(rs.getString("motivo"));
                model.addRow(row);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /** cercaDati(DefaultTableModel model, String chiave)
     *  usa la stessa logica di caricaDati() applicando un filtro dinamico basato sulla barra di ricerca.
     *  il '?' è un segnaposto!
     **/
    public static void cercaDati(DefaultTableModel model, String chiave) {
        model.setRowCount(0);
        String query = "SELECT logID, logTimeStamp, source_ip, motivo FROM log WHERE motivo LIKE ? OR source_ip LIKE ?";
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/intrusion_logs", "root", "")) {
            PreparedStatement preparedStatement = conn.prepareStatement(query);
            String queryParam = "%" + chiave + "%";
            preparedStatement.setString(1, queryParam);
            preparedStatement.setString(2, queryParam);

            ResultSet resultSet = preparedStatement.executeQuery();

            while (resultSet.next()) {
                model.addRow(new Object[]{
                    resultSet.getInt("logID"), 
                    resultSet.getTimestamp("logTimeStamp"), 
                    resultSet.getString("source_ip"), 
                    resultSet.getString("motivo")
                });
            }
        } catch (Exception e) { 
            e.printStackTrace(); 
        }
    }

    /** eliminaRecord(int id)
     *  Prende come parametro l'ID del record da eliminare.
     *  Genera una query d'eliminazione, usando '?' come segnaposto di int id.
     *  Si collega col database ed esegue la Query.
     **/
    public static void eliminaRecord(int id) {
        String sql = "DELETE FROM log WHERE logID = ?";
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/intrusion_logs", "root", "")) {
            PreparedStatement pstmt = conn.prepareStatement(sql);
            pstmt.setInt(1, id);
            pstmt.executeUpdate();
        } catch (Exception e) { e.printStackTrace(); }
    }

    /** svuotaTabella()
     *  Genera una query TRUNCATE per svuotare completamente la tabella LOG.
     *  prima di eseguirla chiede conferma.
     **/
    public static void svuotaTabella() {
        String sql = "TRUNCATE TABLE log";
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/intrusion_logs", "root", "")) {
            Statement stmt = conn.createStatement();
            stmt.executeUpdate(sql);
        } catch (Exception e) { e.printStackTrace(); }
    }
}