package com.example.demo1;

import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import java.net.URL;
import java.util.ResourceBundle;

public class EncryptionController implements Initializable {

    @FXML
    private TextField txt_data;
    @FXML
    private TextField txt_key;
    @FXML
    private TextField txt_key2;
    @FXML
    private TextField txt_key3;
    @FXML
    private TextField key_3des;
    @FXML
    private TextArea txtArea_result;
    @FXML
    private TextArea txtArea_result_decrypt;
    @FXML
    private RadioButton radio_des;
    @FXML
    private RadioButton radio_3des;
    @FXML
    private Label text_time;

    Des des;
    @Override
    public void initialize(URL url, ResourceBundle rb) {
        des = new Des();
        this.buttonGenKey();
    }

    public void encryptDES() {
        long start = System.currentTimeMillis();
        String message = txt_data.getText().toUpperCase();
        String key = txt_key.getText().toUpperCase();
        String encryptedMessage = des.encrypt(message,key);

        txtArea_result.setText(encryptedMessage);
        float sec = (System.currentTimeMillis() - start) / 1000F;
        showTime(sec);
    }

    public void decryptDES() {
        try {
            long start = System.currentTimeMillis();
            String message = txt_data.getText().toUpperCase();
            String encryptedMessage = txtArea_result.getText().toUpperCase();
            String key = txt_key.getText().toUpperCase();
            String decryptedMessage = des.decrypt(encryptedMessage,key);
            txtArea_result_decrypt.setText(decryptedMessage);
            float sec = (System.currentTimeMillis() - start) / 1000F;
            showTime(sec);
        } catch (Exception ex) {
            showAlert(ex.getMessage());
        }
    }

    public void encrypt3DES() {
        try {
            long start = System.currentTimeMillis();
            String message = txt_data.getText().toUpperCase();
            String key = txt_key.getText().toUpperCase();
            String key2 = txt_key2.getText().toUpperCase();
            String key3 = txt_key3.getText().toUpperCase();
            String encryptedMessage = des.encrypt(message,key);
            String desMessage = des.decrypt(encryptedMessage, key2);
            String result = des.encrypt(desMessage, key3);
            txtArea_result.setText(result);
            float sec = (System.currentTimeMillis() - start) / 1000F;
            showTime(sec);
        } catch (Exception ex) {
            showAlert(ex.getMessage());
        }
    }

    public void decrypt3DES() {
        try {
            long start = System.currentTimeMillis();
            String encMessage = txtArea_result.getText().toUpperCase();
            String key = txt_key.getText().toUpperCase();
            String key2 = txt_key2.getText().toUpperCase();
            String key3 = txt_key3.getText().toUpperCase();
            String decrypt3des = des.decrypt(encMessage, key3);
            String encrypt3des = des.encrypt(decrypt3des, key2);
            String result = des.decrypt(encrypt3des, key);
            txtArea_result_decrypt.setText(result);
            float sec = (System.currentTimeMillis() - start) / 1000F;
            showTime(sec);
        } catch (Exception ex) {
            showAlert(ex.getMessage());

        }
    }

    private boolean validateKey3Des() {
        String key1 = txt_key.getText().trim();
        String key2 = txt_key2.getText().trim();
        String key3 = txt_key3.getText().trim();
        if(key1.isEmpty() || key2.isEmpty() || key3.isEmpty()){
            showAlert("Please fill in all the keys");
            return false;
        }
        if (key1.length() != 8 || key2.length() != 8 || key3.length() != 8) {
            showAlert("Key must contain 8 characters");
            return false;
        }
        return true;
    }

    private boolean validateKeyDes() {
        String key = txt_key.getText().trim();
        if(key.isEmpty()){
            showAlert("Key cannot be empty");
            return false;
        }
        if (key.length() != 8) {
            showAlert("Key must contain 8 characters");
            return false;
        }
        return true;
    }

    private boolean validateTextData() {
        String txt = txt_data.getText().trim();
        if (txt.isEmpty()) {
            showAlert("Data cannot be empty");
            return false;
        }
        if (txt.length() > 8) {
            showAlert("Data cannot exceed 8 characters");
            return false;
        }
        return true;
    }

    @FXML
    private void buttonEncrypt() {
        if (!validateTextData()) {
            return;
        }
        if (radio_des.isSelected() && validateKeyDes()) {
            encryptDES();
            return;
        }
        if (radio_3des.isSelected() && validateKey3Des()) {
            encrypt3DES();
        }
    }

    @FXML
    private void buttonDecrypt() {
        if (!validateTextData()) {
            return;
        }
        if (radio_des.isSelected() && validateKeyDes()) {
            decryptDES();
            return;
        }
        if (radio_3des.isSelected() && validateKey3Des()) {
            decrypt3DES();
        }
    }

    @FXML
    private void buttonGenKey(){
        String key1 = des.generateKey(8);
        String key2 = des.generateKey(8);
        String key3 = des.generateKey(8);

        txt_key.setText(key1);
        txt_key2.setText(key2);
        txt_key3.setText(key3);
    }

    @FXML
    private void radio_des() {
        radio_3des.setSelected(false);
        txt_key2.setVisible(false);
        txt_key3.setVisible(false);
    }

    @FXML
    private void radio_3des() {
        radio_des.setSelected(false);
        txt_key2.setVisible(true);
        txt_key3.setVisible(true);
    }

    private void showAlert(String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setContentText(message);
        alert.setHeaderText(null);
        alert.setTitle("Decrypt");
        alert.showAndWait();
    }

    private void showTime(Float time) {
        text_time.setText("Time: " + time + " seconds");
    }

}