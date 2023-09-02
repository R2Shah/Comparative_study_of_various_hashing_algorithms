import com.sun.management.OperatingSystemMXBean;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

public class Main extends JFrame {
    private JComboBox<String> algorithmComboBox;
    private JButton browseButton;
    private JTextArea resultTextArea;

    public Main() { 
        setTitle("Hash Algorithm Selector");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(400, 300);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout());

        initializeComponents();
        addComponentsToFrame();
    }

    private void initializeComponents() {
        String[] algorithms = {    
                "RIPEMD160","RIPEMD256","RIPEMD320",    
        };

        algorithmComboBox = new JComboBox<>(algorithms);

        browseButton = new JButton("Browse");
        browseButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                int result = fileChooser.showOpenDialog(Main.this);
                if (result == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = fileChooser.getSelectedFile();
                    calculateFileHash(selectedFile);
                }
            }
        });

        resultTextArea = new JTextArea();
        resultTextArea.setEditable(false);
    }

    private void addComponentsToFrame() {
        JPanel topPanel = new JPanel(new FlowLayout());
        topPanel.add(new JLabel("Select a Hash Algorithm:"));
        topPanel.add(algorithmComboBox);
        topPanel.add(browseButton);

        JScrollPane scrollPane = new JScrollPane(resultTextArea);

        add(topPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
    }

    private void calculateFileHash(File file) {
        long startTime = System.nanoTime();
        String selectedAlgorithm = (String) algorithmComboBox.getSelectedItem();

        try {
            Digest digest;

            switch (Objects.requireNonNull(selectedAlgorithm)) {
                case "MD2" -> digest = new MD2Digest();
                case "MD4" -> digest = new MD4Digest();
                case "MD5" -> digest = new MD5Digest();
                case "SHA1" -> digest = new SHA1Digest();
                case "SHA3-224" -> digest = new SHA3Digest(224);
                case "SHA3-256" -> digest = new SHA3Digest(256);
                case "SHA3-384" -> digest = new SHA3Digest(384);
                case "SHA3-512" -> digest = new SHA3Digest(512);
                case "SHA224" -> digest = new SHA224Digest();
                case "SHA256" -> digest = new SHA256Digest();
                case "SHA384" -> digest = new SHA384Digest();
                case "SHA512" -> digest = new SHA512Digest();
                case "KECCAK224" -> digest = new KeccakDigest(224);
                case "KECCAK256" -> digest = new KeccakDigest(256);
                case "KECCAK384" -> digest = new KeccakDigest(384);
                case "KECCAK512" -> digest = new KeccakDigest(512);
                case "Whirlpool" -> digest = new WhirlpoolDigest();
                case "Blake2b" -> digest = new Blake2bDigest();
                case "Blake2s" -> digest = new Blake2sDigest();
                case "Blake2xs" -> digest = new Blake2xsDigest();
                case "Blake3" -> digest = new Blake3Digest();
                case "RIPEMD128" -> digest = new RIPEMD128Digest();
                case "RIPEMD160" -> digest = new RIPEMD160Digest();
                case "RIPEMD256" -> digest = new RIPEMD256Digest();
                case "RIPEMD320" -> digest = new RIPEMD320Digest();
                case "TIGERDigest" -> digest = new TigerDigest();
                case "GOST3411" -> digest = new GOST3411Digest();
                case "ISAPDigest" -> digest = new ISAPDigest();
                case "DSTU7564Digest" -> digest = new DSTU7564Digest(512);
                case "SM3Digest" -> digest = new SM3Digest();


                default -> {
                    try {
                        digest = (Digest) MessageDigest.getInstance(selectedAlgorithm);
                    } catch (NoSuchAlgorithmException ex) {
                        showErrorDialog("Algorithm not supported");
                        return;
                    }
                }
            }

            FileInputStream fis = new FileInputStream(file);
            
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
            fis.close();

            byte[] hashBytes = new byte[digest.getDigestSize()];
            digest.doFinal(hashBytes, 0);
            String hash = bytesToHex(hashBytes);

            
            double cpuUsage = getCPUUsage();
            double ramUsage = getRAMUsage();
            long endTime = System.nanoTime();
            long timeTaken = endTime - startTime;
            SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    resultTextArea.setText("File: " + file.getAbsolutePath() + "\n"
                            + "Algorithm: " + selectedAlgorithm + "\n"
                            + "Hash: " + hash + "\n"
                            + "CPU Usage: " + cpuUsage + "%" + "\n"
                            + "RAM Usage: " + ramUsage + " MB" + "\n"
                            + "Time Taken: " + timeTaken + " ns");

                }
            });
        } catch (IOException e) {
            showErrorDialog("Error reading the file");
        }
    }

    private void showErrorDialog(String message) {
        JOptionPane.showMessageDialog(this, message, "Error", JOptionPane.ERROR_MESSAGE);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
    private double getCPUUsage() {
        OperatingSystemMXBean osBean = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
        double cpuUsage = osBean.getProcessCpuLoad() * 100;
        return cpuUsage;
    }



    private double getRAMUsage() {
        ManagementFactory.getOperatingSystemMXBean();
        long usedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        double ramUsage = usedMemory / (1024.0 * 1024.0); // Convert to MB
        return ramUsage;
    }


    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                Main algorithmSelector = new Main();
                algorithmSelector.setVisible(true);
            }
   }
);
}
}