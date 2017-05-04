package pt.ist.sec;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * Created by Romeu Viana on 10/03/2017.
 */
public class ErrorMessage {
    public JPanel panel1;
    private JButton ErrorButton;
    private JLabel ErrorLabel;

    public ErrorMessage(String str, JFrame frame2){
        ErrorMessage em = this;
		final JFrame frame = frame2;
        ErrorLabel.setText("Error: " + str);
        ErrorButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                frame.setVisible(false);
                frame.dispose();
            }
        });
    }

    public ErrorMessage(int x, String str, JFrame frame2){
        ErrorMessage em = this;
		final JFrame frame = frame2;
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
