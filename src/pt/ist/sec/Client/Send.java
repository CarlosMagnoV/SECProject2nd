package pt.ist.sec;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;


public class Send {
    private JTextField UsernameField;
    private JPasswordField PasswordField;
    private JTextField DomainField;
    private JButton storePasswordButton;
    public JPanel panelMain;
    private JButton ReturnButton;
    private int maxSize = 28; // deixamos dois espaços para colocarmos o tamanho do padding

    public Send(Lib lib2, JFrame thisPanel2, JFrame menu2) {


		final Lib lib = lib2;
		final JFrame thisPanel = thisPanel2;
		final JFrame menu = menu2;
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
        PasswordField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

            }
        });
        storePasswordButton.addActionListener(new ActionListener() {
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
                } else if (DomainField.getText().length() > maxSize) { // maxSize - 2 para termos dois espaços livres para mostar numero de padding padding
                    final JFrame frame = new JFrame("ErrorMessage");
                    frame.setContentPane(new ErrorMessage("Domain field is too big).", frame).panel1);
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
                } else if (UsernameField.getText().length() > maxSize) {
                    final JFrame frame = new JFrame("ErrorMessage");
                    frame.setContentPane(new ErrorMessage("Username field too big.", frame).panel1);
                    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                    frame.pack();
                    frame.setVisible(true);
                } else if (PasswordField.getText().length() == 0) {
                    final JFrame frame = new JFrame("ErrorMessage");
                    frame.setContentPane(new ErrorMessage("Password field empty.", frame).panel1);
                    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                    frame.pack();
                    frame.setVisible(true);
                } else if (PasswordField.getText().length() < 4) {
                    final JFrame frame = new JFrame("ErrorMessage");
                    frame.setContentPane(new ErrorMessage("Password field must contain 5 characters or more.", frame).panel1);
                    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                    frame.pack();
                    frame.setVisible(true);
                } else if (PasswordField.getText().length() > maxSize) {
                    final JFrame frame = new JFrame("ErrorMessage");
                    frame.setContentPane(new ErrorMessage("Password field is too big.", frame).panel1);
                    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                    frame.pack();
                    frame.setVisible(true);
                } else {
                    try {
                        lib.applyPaddSend(lib.ClientPublicKey,
                                DomainField.getText(),
                                UsernameField.getText(),
                                PasswordField.getText(),
                                maxSize
                        );

                        final JFrame frame = new JFrame("ErrorMessage");
                        frame.setContentPane(new ErrorMessage(0, "Sucess: Information saved!", frame).panel1);
                        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                        frame.pack();
                        frame.setVisible(true);


                    }
                    catch(Exception a){
                        System.out.println("Exception in Send: " + a);
                        final JFrame frame = new JFrame("ErrorMessage");
                        frame.setContentPane(new ErrorMessage("Couldn't save information!", frame).panel1);
                        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                        frame.pack();
                        frame.setVisible(true);
                    }


                }
            }

        });

        ReturnButton.addActionListener(new ActionListener() {
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

    /*public static void main(String[] args)throws Exception
    {
        JFrame frame = new JFrame("Send");
        frame.setContentPane(new Send().panelMain);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
    }*/
}
