package de.dhbw.localservicediscovery;

public interface DiscoveryListener {
    void onServiceDiscoveryStatusUpdate(String localIpAddr);
}
