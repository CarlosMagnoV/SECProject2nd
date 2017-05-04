package pt.ist.sec;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileInputStream;
import java.security.KeyStore;

public class ClientUI {
    //private static JFrame getFrame = null;
    private JButton retrievePasswordsButton;
    private JButton exitButton;
    private JButton sendPasswordButton;
    private JPanel panelMain;
    private static  JFrame frame = new JFrame("ClientUI");
    //private static String certFile = System.getProperty("user.dir") + "\\clientData\\KeyStore.jks";
    private static String certFile = System.getProperty("user.dir") + "\\clientData\\KeyStore.jce";


    public ClientUI(String port)throws Exception {

        final Lib lib = new Lib(Integer.parseInt(port));
        loadStore(lib);



        retrievePasswordsButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                frame.setVisible(false);
                final JFrame frame3 = new JFrame("Retrieve");
                frame3.setContentPane(new Retrieve(lib, frame3, frame).panelMain);
                frame3.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                frame3.pack();
                frame3.setVisible(true);
            }
        });
        sendPasswordButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                frame.setVisible(false);
                final JFrame frame2 = new JFrame("Send");
                frame2.setContentPane(new Send(lib, frame2, frame).panelMain);
                frame2.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                frame2.pack();
                frame2.setVisible(true);
            }
        });
        exitButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
            lib.close();
            }
        });
    }

    public static void main(String[] args)throws Exception
    {
        //getFrame = frame;
        frame.setContentPane(new ClientUI(args[0]).panelMain);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
    }

    private void loadStore(Lib lib) throws Exception {
        FileInputStream fis = new FileInputStream(certFile);
        //KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        KeyStore keystore = KeyStore.getInstance("JCEKS");
        keystore.load(fis, "changeit".toCharArray()); // esta password é a pass do keystore
        lib.init(keystore,"changeit","client-alias"); // password da chave dentro do keystore
    }
}
