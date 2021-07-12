package ca.ubc.cs317.dnslookup;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.Random;
import java.util.Set;
import java.util.ArrayList;
import java.util.*;

public class DNSQueryHandler {

    private static final int DEFAULT_DNS_PORT = 53;
    private static DatagramSocket socket;
    private static boolean verboseTracing = false;
    private static int curLocation = 0;

    private static final Random random = new Random();

    /**
     * Sets up the socket and set the timeout to 5 seconds
     *
     * @throws SocketException if the socket could not be opened, or if there was an
     *                         error with the underlying protocol
     */
    public static void openSocket() throws SocketException {
        socket = new DatagramSocket();
        socket.setSoTimeout(5000);
    }

    /**
     * Closes the socket
     */
    public static void closeSocket() {
        socket.close();
    }

    /**
     * Set verboseTracing to tracing
     */
    public static void setVerboseTracing(boolean tracing) {
        verboseTracing = tracing;
    }

    /**
     * Builds the query, sends it to the server, and returns the response.
     *
     * @param message Byte array used to store the query to DNS servers.
     * @param server  The IP address of the server to which the query is being sent.
     * @param node    Host and record type to be used for search.
     * @return A DNSServerResponse Object containing the response buffer and the transaction ID.
     * @throws IOException if an IO Exception occurs
     */
    public static DNSServerResponse buildAndSendQuery(byte[] message, InetAddress server,
                                                      DNSNode node) throws IOException {
        // generate query ID
        int ran = random.nextInt(65535);
        byte ranID1 = (byte) ((ran >> 8) & 0xff);
        byte ranID2 = (byte) (ran & 0xff);
        message[0] = ranID1;
        message[1] = ranID2;

        message[2] = (byte) (0x00);

        //fourth byte
        message[3] = (byte) (0x00);

        //qdcount
        message[4] = (byte) (0x00);
        message[5] = (byte) (0x01);

        //ancount
        message[6] = (byte) (0x00);
        message[7] = (byte) (0x00);

        //nscount
        message[8] = (byte) (0x00);
        message[9] = (byte) (0x00);

        //arcount
        message[10] = (byte) (0x00);
        message[11] = (byte) (0x00);

        //qname
        int position = 12;
        String[] subNames = node.getHostName().split("\\.");
        for(int i=0; i< subNames.length; i++){
          byte[] nameToHex = subNames[i].getBytes("UTF-8");
          message[position] = (byte) nameToHex.length;
          position++;
          for(int j=0; j< nameToHex.length; j++){
            message[position] = nameToHex[j];
            position++;
          }
        }

        message[position] = (byte) 0x00;
        position++;

        //qtype
        message[position] = (byte) ((node.getType().getCode() >> 8) & 0xff);
        position++;
        message[position] = (byte) (node.getType().getCode() & 0xff);
        position++;

        //qclass
        message[position] = (byte) 0x00;
        position++;
        message[position] = (byte) 0x01;

        //send packet
        try {
            socket.connect(server, DEFAULT_DNS_PORT);
            socket.setSoTimeout(5000);
        } catch (IOException ignored) {
        }
        byte transIDfirst;
        byte transIDsecond;
        ByteBuffer buffer;
        DatagramPacket sendPacket = new DatagramPacket(message, position + 1);
        DatagramPacket receivePacket = new DatagramPacket(new byte[1024], 1024);
        try {
            // prints query header
            if (verboseTracing) {
                System.out.println("\n");
                System.out.println("Query ID     " + ran + " " + node.getHostName() + "  " + node.getType() + " --> " + server.getHostAddress());
            }
            socket.send(sendPacket);
            socket.receive(receivePacket);
            byte[] response = receivePacket.getData();
            transIDfirst = response[0];
            transIDsecond = response[1];
            buffer = ByteBuffer.wrap(response);
        } catch (IOException e) {
            // retry send
            try {
                if (verboseTracing) {
                    System.out.println("\n");
                    System.out.println("Query ID     " + ran + " " + node.getHostName() + "  " + node.getType() + " --> " + server.getHostAddress());
                }
                socket.send(sendPacket);
                socket.receive(receivePacket);
                byte[] response = receivePacket.getData();
                transIDfirst = response[0];
                transIDsecond = response[1];
                buffer = ByteBuffer.wrap(response);
            } catch (IOException ignored){
            }
            return null;
        }

        //check if transaction IDs match
        int transID = ((transIDfirst & 0xff) << 8) | (transIDsecond & 0xff);
        if (transID != ran) {
            return null;
        }
        return new DNSServerResponse(buffer, transID);
    }


    /**
     * Decodes the DNS server response and caches it.
     *
     * @param transactionID  Transaction ID of the current communication with the DNS server
     * @param responseBuffer DNS server's response
     * @param cache          To store the decoded server's response
     * @return A set of resource records corresponding to the name servers of the response.
     */
    public static Set<ResourceRecord> decodeAndCacheResponse(int transactionID, ByteBuffer responseBuffer,
                                                             DNSCache cache) {
        Set<ResourceRecord> nsRR = new HashSet<>();
        byte[] response = new byte[responseBuffer.remaining()];
        responseBuffer.get(response,0,response.length);
        int queryId = (((response[curLocation++] & 0xff) <<8) | (response[curLocation++] & 0xff)) & 0xFFFF;
        if (transactionID != queryId) {
            return null;
        }
        if (verboseTracing) {
            System.out.println("Response ID: " + transactionID + " Authoritative = " + (((response[2] >> 2) & 0x01) == 1));
        }
        //flag
        short flag = (short) ((response[curLocation++] <<8) | (response[curLocation++] & 0xFF));

        //number of queries and each type of RRs
        int qcount = ((response[curLocation++] << 8) | (response[curLocation++] & 0xFF)) & 0x0000FFFF;
        int aCount = (((response[curLocation++] & 0xff) << 8) | (response[curLocation++] & 0xFF)) & 0x0000FFFF;
        int nsCount= (((response[curLocation++] & 0xff) << 8) | (response[curLocation++] & 0xFF)) & 0x0000FFFF;
        int additionalCount = (((response[curLocation++] & 0xff) << 8) | (response[curLocation++] & 0xFF)) & 0x0000FFFF;

        //qname
        String qname = "";
        int length;
        while((length = response[curLocation++])!= 0){
          for(int i=0; i< length; i++){
            qname = qname + (char)response[curLocation++];
          }
          qname = qname+ ".";
        }
//        qname = qname.substring(0,qname.length()-1);

        //qtype
        short qType = (short)(((response[curLocation++] & 0xff) << 8) | (response[curLocation++] & 0xFF));

        //qclass
        short qClass = (short)(((response[curLocation++] & 0xff) << 8) | (response[curLocation++] & 0xFF));

        if (verboseTracing) {
            System.out.println("Answers (" + aCount + ")");
        }
        // decode answer section
        for(int i=0; i< (aCount); i++){
            cacheRR(cache, nsRR, response);
        }
        if (verboseTracing) {
            System.out.println("Nameservers (" + nsCount + ")");
        }

        //decode nameservers
        for(int i=0; i< (nsCount); i++){
            cacheRR(cache, nsRR, response);
        }

        if (verboseTracing) {
            System.out.println("Additional Information (" + additionalCount + ")");
        }

        //decode additional
        for(int i=0; i< (additionalCount); i++){
            cacheRR(cache, nsRR, response);
        }
        curLocation = 0;
        return nsRR;
    }

    //decode a resource record and cache it, also add it to the set of nameservers if it is one
    private static void cacheRR(DNSCache cache, Set<ResourceRecord> nsRR, byte[] response) {
        try{
            ResourceRecord rr = decodeRR(response);
            if(rr.getType() == RecordType.getByCode(2)){
            cache.addResult(rr);
            nsRR.add(rr);
            verbosePrintResourceRecord(rr,2);
            }else{
            cache.addResult(rr);
            verbosePrintResourceRecord(rr,rr.getType().getCode());
            }
        } catch (UnknownHostException ignore) {
        }
    }

    private static ResourceRecord decodeRR(byte[] response) throws UnknownHostException {
        // decode hostName
        String hostName;
        hostName = decodeName(response, curLocation);
        curLocation+= 2;
        while (response[curLocation] != 0x00 && ((response[curLocation] & 0xff) < 0xc0)) {
            curLocation++;
        }
        if ((response[curLocation] & 0xff) >= 0xc0) {
            curLocation += 2;
        }
        // decode type
        int code = (((response[curLocation] & 0xff) << 8) | (response[curLocation + 1] & 0xff)) & 0xff;
        curLocation += 4;

        // decode ttl
        long ttl = (((response[curLocation] & 0xff) << 24) | ((response[curLocation + 1] & 0xff) << 16) | ((response[curLocation + 2] & 0xff) << 8) | (response[curLocation + 3] & 0xff)) & 0xffff;
        curLocation += 4;

        int rlength = (((response[curLocation] & 0xff) << 8) | (response[curLocation + 1] & 0xff)) & 0xff;
        curLocation +=2;
        // if RR is A or AAAA, decode the InetAddress
        InetAddress result;
        byte[] defaultAddress = new byte[]{0,0,0,0};
        result =InetAddress.getByAddress(defaultAddress);
        if (code == 1){
            byte[] address = new byte[4];
            for (int i = 0; i < 4; i++) {
                address[i] = response[curLocation + i];
            }
            try {
                result = InetAddress.getByAddress(address);
                curLocation = curLocation + rlength;
                return new ResourceRecord(hostName, RecordType.getByCode(code), ttl, result);
            } catch (UnknownHostException e) {
                System.out.println("unknown host");
            }
        } else if (code == 28) {
            byte[] address = new byte[16];
            for (int i = 0; i < 16; i++) {
                address[i] = response[curLocation + i];
            }
            try {
                result = InetAddress.getByAddress(address);
                curLocation = curLocation + rlength;
                return new ResourceRecord(hostName, RecordType.getByCode(code), ttl, result);
            } catch (UnknownHostException e) {
                System.out.println("unknown host");
            }
        } else {
        }

        //if RR is NS or CNAME, decode string, for SOA or MX or OTHER, print "----"
        String r = "";
        if (code == 2) {
            r = decodeName(response, curLocation);
        } else if (code == 5) {
            r = decodeName(response, curLocation);
        } else if (code == 6 || code == 15 || code == 0) {
            r = "----";
        }
        curLocation = curLocation + rlength;
        return new ResourceRecord(hostName, RecordType.getByCode(code), ttl, r);
    }

    // decode bytes into string name
    private static String decodeName(byte[] response, int position) {
        //recursion if first byte is pointer
        if (((response[position] & 0xff) >> 6) == 3) {
            int offset = (((response[position] & 0x3f) << 8) | (response[position + 1] & 0xff)) & 0x3fff;
            return decodeName(response, offset);
        } else {
            //store bytes in hostNameBytes to parse
            byte[] hostNameBytes = new byte[300];
            int size = 0;
            while (((response[position] & 0xff) != 0x00) && ((response[position] & 0xff) < 0xc0)) {
                hostNameBytes[size] = response[position];
                position++;
                size++;
            }
            if ((response[position] & 0xff) >= 0xc0) {
                hostNameBytes[size++] = response[position++];
                hostNameBytes[size++] = response[position++];
            }
            if(response[position] == 0) {
                hostNameBytes[size++] = response[position++];
            }
            //walk through each byte in hostNameBytes and convert to chars then add them to string
            int counter = 0;
            String hostName = "";
            for (int j = 0; j < size; j++) {
                if (j == 0) {
                    counter = hostNameBytes[j] + 1;
                } else if (((hostNameBytes[j] & 0xff) >> 6) == 3){
                    hostName += ".";
                    hostName += decodeName(response,((hostNameBytes[j++] & 0x3f) << 8) | (hostNameBytes[j] & 0xff));
                    hostName += ".";
                    j++;
                }  else if (hostNameBytes[j] == 0) {
                    hostName += ".";
                } else if (j == counter) {
                    hostName += ".";
                    counter += hostNameBytes[j] + 1;
                }else if (j == (size - 1)){
                    hostName += (char) hostNameBytes[j];
                    hostName += ".";
                } else {
                    hostName += (char) hostNameBytes[j];
                }
            }
            if (hostName.length() > 0) {
                return hostName.substring(0, hostName.length() - 1);
            } else {
                return "";
            }
        }

    }


    /**
     * Formats and prints record details (for when trace is on)
     *
     * @param record The record to be printed
     * @param rtype  The type of the record to be printed
     */
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }
}
