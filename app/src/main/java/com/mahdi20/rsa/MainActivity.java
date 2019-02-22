package com.mahdi20.rsa;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import com.mahdi20.rsa.security.Base64Utils;
import com.mahdi20.rsa.security.FileEncryptionManager;

public class MainActivity extends AppCompatActivity {


    private Button btn_gk, btn_enc, btn_dec;
    private EditText edt_text, edt_enc;


    FileEncryptionManager mFileEncryptionManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        btn_gk = (Button) findViewById(R.id.btn_gk);
        btn_enc = (Button) findViewById(R.id.btn_enc);
        btn_dec = (Button) findViewById(R.id.btn_dec);
        edt_text = (EditText) findViewById(R.id.edt_text);
        edt_enc = (EditText) findViewById(R.id.edt_enc);
        mFileEncryptionManager = FileEncryptionManager.getInstance();


        btn_gk.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                try {

                    mFileEncryptionManager.generateKey();

                    Log.i("KKKKKKKKK: ", "pub: " + mFileEncryptionManager.getPublicKey());
                    Log.i("KKKKKKKKK: ", "pri: " + mFileEncryptionManager.getPrivateKey());

                    Toast.makeText(MainActivity.this, "The key was generated", Toast.LENGTH_SHORT).show();

                } catch (Exception e) {
                    e.printStackTrace();
                }


            }
        });


        btn_enc.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {


                String source = edt_text.getText().toString().trim();
                try {
                    byte[] encryptByte = mFileEncryptionManager.encryptByPublicKey(source.getBytes());
                    String afterencrypt = Base64Utils.encode(encryptByte);
                    edt_enc.setText(afterencrypt);
                    edt_text.setText("");

                } catch (Exception e) {
                    e.printStackTrace();
                }


            }
        });


        btn_dec.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {


                String encryptContent = edt_enc.getText().toString().trim();
                try {
                    byte[] decryptByte = mFileEncryptionManager.decryptByPrivateKey(Base64Utils.decode(encryptContent));
                    edt_text.setText(new String(decryptByte));
                } catch (Exception e) {
                    e.printStackTrace();
                }


            }
        });


    }


}

