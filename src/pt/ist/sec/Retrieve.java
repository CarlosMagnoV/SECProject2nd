package pt.ist.sec;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import static javax.xml.bind.DatatypeConverter.printBase64Binary;

/**
 * Created by lj0se on 09/03/2017.
 */
public class Retrieve {
    public JPanel panelMain;
    private JTextField DomainField;
    private JTextField UsernameField;
    private JButton receivePasswordButton;
    private JLabel PasswordLabel;                //Label a ser alterada para a palavra pass
    private JButton returnButton;

    private int maxSize = 28;

    public Retrieve(Lib lib, JFrame thisPanel, JFrame menu){

        DomainField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

            }
        });
        UsernameField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

            }
        });
        receivePasswordButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (DomainField.getText().length() <= 4) {
                    final JFrame frame = new JFrame("ErrorMessage");
                    frame.setContentPane(new ErrorMessage("Domain field incomplete.", frame).panel1);
                    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                    frame.pack();
                    frame.setVisible(true);
                } else if (DomainField.getText().length() == 0) {
                    final JFrame frame = new JFrame("ErrorMessage");
                    frame.setContentPane(new ErrorMessage("Domain field empty.", frame).panel1);
                    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                    frame.pack();
                    frame.setVisible(true);
                } else if (UsernameField.getText().length() == 0) {
                    final JFrame frame = new JFrame("ErrorMessage");
                    frame.setContentPane(new ErrorMessage("Username field empty.", frame).panel1);
                    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                    frame.pack();
                    frame.setVisible(true);
                } else if (UsernameField.getText().length() < 2) {
                    final JFrame frame = new JFrame("ErrorMessage");
                    frame.setContentPane(new ErrorMessage("Username field too short.", frame).panel1);
                    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                    frame.pack();
                    frame.setVisible(true);
                } else {
                    try {

                        byte[] pass = lib.applyPaddRet(lib.ClientPublicKey,
                                DomainField.getText(),
                                UsernameField.getText(),
                                maxSize
                                );

                        //String finalPassword = lib.DecryptionSymmetric(pass);
                        String finalPassword = new String(pass, "ASCII");
                        PasswordLabel.setText(finalPassword);

                    }
                    catch(Exception a){
                        PasswordLabel.setText("Password will show here");
                        final JFrame frame = new JFrame("ErrorMessage");
                        frame.setContentPane(new ErrorMessage("Couldn't find password!", frame).panel1);
                        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                        frame.pack();
                        frame.setVisible(true);

                    }
                }
            }
        });

        returnButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                menu.setVisible(true);
                thisPanel.setVisible(false);
                thisPanel.dispose();
            }
        });
    }

    private String concatenate (char[] c){
        String str = "";
        for(char a: c){
            str += a;
        }
        return str;
    }


}
