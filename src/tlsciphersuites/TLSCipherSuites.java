/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tlsciphersuites;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.TimeoutException;
import jpcap.JpcapCaptor;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;

/**
 *
 * @author Muhammad Bilal <mubil@kth.se>
 */
public class TLSCipherSuites {

    // TODO: Shift from sys.out to Logger
    private int MPTCP_KIND = 30;
    private int MP_CAPABLE = 0;
    private int MP_JOIN = 1;
    private int DSS = 2;
    private int ADD_ADDR = 3;
    private int REMOVE_ADDR = 4;
    private int MP_PRIO = 5;
    private int MP_FAIL = 6;
    private int MP_FASTCLOSE = 7;
    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static HashMap<String,String> cipherSuitesSet = new HashMap<>();
    public static void main(String[] args) throws TimeoutException, IOException {
        File parentDirectory = new File("/home/mb/Aggregate_data/AllLogs/");
        File[] LogDir = parentDirectory.listFiles();
        for (int i = 0; i < LogDir.length; i++) {
            File f = LogDir[i];
            if (f.isDirectory()) {
                String dirPath = f.getAbsolutePath() + "/traces00/";
                extractHello(dirPath);
                findCipherSuites(dirPath);
                System.out.println(cipherSuitesSet.size());
            }
        }
        System.out.println(cipherSuitesSet.size());
        for(String i: cipherSuitesSet.keySet()){
            System.out.println("Ip: "+i+" cipher suites: "+cipherSuitesSet.get(i));
        }
    }

    private static void extractHello(String path) throws IOException {
        String[] cmd = {
            "/bin/sh",
            "-c",
            "tshark -r '"+path+"'/ip_complete.pcap -2R \"ssl.handshake.ciphersuites\" -w '"+path+"'/clienthello.pcap"
        };
        System.out.println(cmd[2]);
        Runtime.getRuntime().exec(cmd);
    }

    public static void findCipherSuites(String args) throws EOFException, TimeoutException, IOException {
        //open a file to read saved packets
        /*if (args.length <= 0) {
            System.out.println("Arguments missing. USAGE: java -jar MptcpStat.jar <pcap_filename>");
            return;
        }*/
         JpcapCaptor captor = null;
        try{
            captor = JpcapCaptor.openFile(args+"clienthello.pcap");
        }
        catch(IOException ex){
            return;
        }
        while (true) {
            Packet p = captor.getPacket();
            String hexdata = "";
            
            try {
                TCPPacket packet = (TCPPacket) p;
                 hexdata = bytesToHex(packet.data);
                int idLength = 0;
                String idLenString = hexdata.substring(86, 88);
                String cipherLenString = hexdata.substring(88, 92);
                idLength = Integer.parseInt(idLenString, 16);
                String cipherSuites = "";
                int cipherLen = 0;
                if (idLength == 0) {
                    cipherLen = Integer.parseInt(cipherLenString, 16);
                    cipherSuites = hexdata.substring(92, 92 + cipherLen);
                    if(!cipherSuitesSet.containsValue(cipherSuites)){
                        cipherSuitesSet.put(packet.dst_ip.toString(),cipherSuites);
                    }
                } else {
                    cipherLenString = hexdata.substring(88 + 64, 92 + 64);
                    cipherLen = Integer.parseInt(cipherLenString, 16);
                    cipherSuites = hexdata.substring(92 + 64, 92 + 64 + cipherLen);
                    if(!cipherSuitesSet.containsValue(cipherSuites)){
                        cipherSuitesSet.put(packet.dst_ip.toString(),cipherSuites);
                    }
                }
                //System.out.println(hexdata);
                //System.out.println(hexdata.substring(86,88));
                //System.out.println(hexdata.substring(88, 92));
                //System.out.println(cipherSuites);

            } catch (ClassCastException | NullPointerException e) {
                //if some error occurred or EOF has reached, break the loop
                if (p == null || p == Packet.EOF) {
                    break;
                }
                continue;
            } catch(StringIndexOutOfBoundsException ex){
                TCPPacket packet = (TCPPacket) p;
                System.out.println(packet.src_ip +" "+ packet.dst_ip);
                System.out.println(hexdata);
                continue;
            }
        }

        captor.close();
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

}
