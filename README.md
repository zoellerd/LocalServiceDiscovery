# Local service discovery via UDP

### Usage

1. Implement `DiscoveryListener`
2. Override `void onServiceDiscoveryStatusUpdate(String localIpAddr)`.
3. Call:
   ```
   DiscoveryUdpListener listener = new DiscoveryUdpListener();
   listener.subscribe(this);
   listener.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
   new DiscoveryUdpBroadcaster(context, listener.gotOwnDatagram).executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
   ```

Possible return values are:

1. A local IP address as a string (success)
2. null (failure)

### Possible future improvements

Eventually the library may provide a simplification of step 3 so the user has to do just one function call.

Another nice addition would be to pass instances of a helper class as the return value that 1) makes the distinction of success/failure more clear (boolean success, String ipAddr) and 2) could optionally hold more information about the discovery result.

### Operation of the discovery mechanism

1. The server listens on a UDP socket with a predefined port (always)
2. When the discovery starts, the client listens on that port as well
3. The client broadcasts a UDP packet with 32 pseudorandom bytes as the data payload to that port
4. When the server gets that packet, it calculates `HMACSHA256(data, HMAC_SECRET)` and sends the result as a unicast packet back to the client
5. The client performs the same calculation and checks if the result is equal to the data of the packet it just received
6. If that is the case, discovery was successful
7. If not, or if the client runs into at timeout, discovery failed

The hashing allows clients to associate server responses with their own requests, which gets important in scenarios where multiple clients/servers are performing discovery at the same time. If, for example, in a scenario with multiple clients/servers, you want to make only certain clients/servers "compatible" with each other (introduce a partitioning), you have the option of changing the `HMAC_SECRET` on the client- and server side.

The `HMAC_SECRET` merely serves as a way to tie discovery responses to discovery requests more tightly and to accomplish the aforementioned option of partitioning. It is not intended as a means for providing authentication and should be considered public.
