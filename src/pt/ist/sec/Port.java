package pt.ist.sec;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * Created by Asus on 05/05/2017.
 */
public class Port {
    private JButton okButton;
    private JTextField portField;
    public JPanel mainPanel;

    public Port(JFrame thisFrame, ClientUI c) {
        okButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                    try {
                        c.loadStore(Integer.parseInt(portField.getText()));
                        c.frame.setVisible(true);
                        thisFrame.setVisible(false);
                        thisFrame.dispose();

                    }catch (Exception j){
                        thisFrame.setVisible(false);
                        final JFrame frame0 = new JFrame("ErrorMessage");
                        frame0.setContentPane(new ErrorMessage("Could not connect to server!", frame0).panel1
                        );
                        frame0.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                        frame0.pack();
                        frame0.setVisible(true);
                    }

            }
        });
    }

    private void createUIComponents() {
    }
}
