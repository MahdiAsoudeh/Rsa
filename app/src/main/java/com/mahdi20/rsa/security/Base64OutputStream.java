
package com.mahdi20.rsa.security;

import java.io.IOException;
import java.io.OutputStream;


public class Base64OutputStream extends OutputStream {

    private OutputStream outputStream = null;

    private int buffer = 0;

    private int bytecounter = 0;

    private int linecounter = 0;

    private int linelength = 0;

    public Base64OutputStream(OutputStream outputStream) {
        this(outputStream, 76);
    }

    public Base64OutputStream(OutputStream outputStream, int wrapAt) {
        this.outputStream = outputStream;
        this.linelength = wrapAt;
    }

    public void write(int b) throws IOException {
        int value = (b & 0xFF) << (16 - (bytecounter * 8));
        buffer = buffer | value;
        bytecounter++;
        if (bytecounter == 3) {
            commit();
        }
    }

    public void close() throws IOException {
        commit();
        outputStream.close();
    }

    protected void commit() throws IOException {
        if (bytecounter > 0) {
            if (linelength > 0 && linecounter == linelength) {
                outputStream.write("\r\n".getBytes());
                linecounter = 0;
            }
            char b1 = Shared.chars.charAt((buffer << 8) >>> 26);
            char b2 = Shared.chars.charAt((buffer << 14) >>> 26);
            char b3 = (bytecounter < 2) ? Shared.pad : Shared.chars.charAt((buffer << 20) >>> 26);
            char b4 = (bytecounter < 3) ? Shared.pad : Shared.chars.charAt((buffer << 26) >>> 26);
            outputStream.write(b1);
            outputStream.write(b2);
            outputStream.write(b3);
            outputStream.write(b4);
            linecounter += 4;
            bytecounter = 0;
            buffer = 0;
        }
    }

}