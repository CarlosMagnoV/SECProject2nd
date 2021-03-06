package pt.ist.sec;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class ErrorMessage {
    public JPanel panel1;
    private JButton ErrorButton;
    private JLabel ErrorLabel;

    public ErrorMessage(String str, JFrame frame){
        ErrorMessage em = this;
        ErrorLabel.setText("Error: " + str);
        ErrorButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                frame.setVisible(false);
                frame.dispose();
            }
        });
    }

    public ErrorMessage(String str, JFrame frame, boolean end){
        ErrorMessage em = this;
        ErrorLabel.setText("Error: " + str);
        ErrorButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                frame.setVisible(false);
                frame.dispose();
                System.exit(0);
            }
        });
    }

    public ErrorMessage(int x, String str, JFrame frame){
        ErrorMessage em = this;
        ErrorLabel.setText(str);
        ErrorButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                frame.setVisible(false);
                frame.dispose();
            }
        });
    }

}
