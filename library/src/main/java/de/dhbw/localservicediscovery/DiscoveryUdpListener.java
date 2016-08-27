package de.dhbw.localservicediscovery;

import android.os.AsyncTask;
import android.util.Log;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class DiscoveryUdpListener extends AsyncTask<Void, Void, String> {

    public static final String LOG_TAG = "DHBW UdpListener";
    public static final int SOCKET_TIMEOUT_MILLIS = 2000;

    public AtomicBoolean gotOwnDatagram;

    private static final String HMAC_SECRET = "eFqqDnFNeLLJ";
    private ArrayList<DiscoveryListener> discoveryListener = new ArrayList<>();
    private DatagramSocket socket;

    public DiscoveryUdpListener(){
        this.gotOwnDatagram = new AtomicBoolean(false);
    }

    public void subscribe(DiscoveryListener listener){
        discoveryListener.add(listener);
    }

    public void unsubscribe(DiscoveryListener listener){
        discoveryListener.remove(listener);
    }

    @Override
    protected String doInBackground(Void... params){
        return listen();
    }

    @Override
    protected void onPostExecute(String localIpAddr) {
        for(DiscoveryListener listener : discoveryListener){
            listener.onServiceDiscoveryStatusUpdate(localIpAddr);
        }
    }

    public String listen(){
        try {
            //Keep a socket open to listen to all UDP traffic that is destined for this port
            InetAddress wildCard = new InetSocketAddress(0).getAddress(); // 0.0.0.0, i.e. all interfaces
            socket = new DatagramSocket(DiscoveryUdpBroadcaster.UDP_PORT, wildCard);
            socket.setBroadcast(true);
            socket.setSoTimeout(SOCKET_TIMEOUT_MILLIS);

            //Receive a packet
            byte[] recvBuf = new byte[32];
            DatagramPacket packet = new DatagramPacket(recvBuf, recvBuf.length);
            Log.i(LOG_TAG, "Ready to receive packet");

            boolean fromThisHost;
            do{
                socket.receive(packet);
                // ignore our own packets and wait for a next one.
                // make it possible for other threads to check if
                // we got a datagram from ourselves so they know the socket is open.
                fromThisHost = isOwnIpAddress(packet.getAddress());
                if(fromThisHost){
                    this.gotOwnDatagram.compareAndSet(false, true);
                }
            } while(fromThisHost);

            //Packet received
            if(BuildConfig.DEBUG){
                Log.i(LOG_TAG, "Packet with " + packet.getData().length + " bytes data received from: " + packet.getAddress().getHostAddress());
            }

            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret = new SecretKeySpec(HMAC_SECRET.getBytes(StandardCharsets.UTF_8),"HmacSHA256");
            mac.init(secret);
            byte[] digest = mac.doFinal(DiscoveryUdpBroadcaster.getLastRandomBytes());
            if(!Arrays.equals(packet.getData(), digest)){
                Log.i(LOG_TAG, "Got invalid identifier");
                return null;
            }
            if(!packet.getAddress().isSiteLocalAddress()) {
                Log.i(LOG_TAG, "Packet did not come from local address!");
                return null;
            }
            return packet.getAddress().getHostAddress();

        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException e) {
            if(BuildConfig.DEBUG && e.getMessage() != null) {
                Log.e(LOG_TAG, e.getMessage());
            }
        } finally {
            socket.close();
        }
        return null;
    }

    public static boolean isOwnIpAddress(InetAddress addr) {
        if (addr.isAnyLocalAddress() || addr.isLoopbackAddress()) {
            return true;
        }

        try {
            return NetworkInterface.getByInetAddress(addr) != null;
        } catch (SocketException e) {
            return false;
        }
    }

}

