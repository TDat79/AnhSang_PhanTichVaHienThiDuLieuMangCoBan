package com.example.LTM2;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.TcpPort;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public class NetworkDataServer {

    private static final int PORT = 5000;

    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Server started on port " + PORT);

        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("Client connected: " + clientSocket.getInetAddress());

            // Thread xử lý client
            new Thread(() -> {
                try (ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
                     ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
                     Socket autoCloseClientSocket = clientSocket) { // Đóng clientSocket tự động

                    // Nhận đường dẫn file pcapng từ client

                    String pcapFilePath = (String) in.readObject();

                    // Gửi thông báo đang phân tích file
                    System.out.println("Đã nhận được đường dẫn file pcapng: " + pcapFilePath);
                    out.writeObject("Đang phân tích file...");
                    out.flush();

                    long analysisStartTime = System.currentTimeMillis(); // ghi lại thời gian bắt đầu phân tích

                    // Phân tích file pcapng
                    List<String> analysisResult = analyzePcapFile(pcapFilePath);

                    long analysisEndTime = System.currentTimeMillis(); // ghi lại thời gian kết thúc phân tích
                    System.out.printf("Phân tích file %s hoàn thành trong %.2f giây.%n", pcapFilePath, (analysisEndTime - analysisStartTime) / 1000.0);

                    // Gửi thông báo đã phân tích xong
                    out.writeObject("Đã phân tích xong. Đang gửi kết quả...");
                    out.flush();

                    // Gửi kết quả phân tích cho client
                    out.writeObject(analysisResult);
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    try {
                        clientSocket.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }).start();
        }
    }

    // Hàm phân tích file pcapng
    private static List<String> analyzePcapFile(String pcapFilePath) throws PcapNativeException, NotOpenException {
        List<String> analysisResult = new ArrayList<>();
        int packetCount = 0;

        // Mở file pcapng
        PcapHandle handle = Pcaps.openOffline(pcapFilePath);
// Duyệt qua các gói tin
        Packet packet;
        while ((packet = handle.getNextPacket()) != null) {
            packetCount++;
            // Thu thập thông tin chi tiết về packet
            StringBuilder packetInfo = new StringBuilder();
            packetInfo.append("Packet Number: ").append(packetCount).append("\n");

            // Lấy dấu thời gian của gói tin
            packetInfo.append("Time: ").append(handle.getTimestamp()).append("\n");

            if (packet.contains(EthernetPacket.class)) {
                EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
                packetInfo.append("Source MAC: ").append(ethernetPacket.getHeader().getSrcAddr().toString()).append("\n");
                packetInfo.append("Destination MAC: ").append(ethernetPacket.getHeader().getDstAddr().toString()).append("\n");
            }

            if (packet.contains(IpV4Packet.class)) {
                IpV4Packet ipv4Packet = packet.get(IpV4Packet.class);
                packetInfo.append("Source IP: ").append(ipv4Packet.getHeader().getSrcAddr().getHostAddress()).append("\n");
                packetInfo.append("Destination IP: ").append(ipv4Packet.getHeader().getDstAddr().getHostAddress()).append("\n");
                packetInfo.append("Protocol: IPv4").append("\n");
                packetInfo.append("TTL: ").append(ipv4Packet.getHeader().getTtl()).append("\n");
                packetInfo.append("Length: ").append(ipv4Packet.getHeader().getTotalLength()).append("\n");
            } else if (packet.contains(IpV6Packet.class)) {
                IpV6Packet ipv6Packet = packet.get(IpV6Packet.class);
                packetInfo.append("Source IP: ").append(ipv6Packet.getHeader().getSrcAddr().getHostAddress()).append("\n");
                packetInfo.append("Destination IP: ").append(ipv6Packet.getHeader().getDstAddr().getHostAddress()).append("\n");
                packetInfo.append("Protocol: IPv6").append("\n");
                packetInfo.append("Length: ").append(ipv6Packet.getHeader().getPayloadLength()).append("\n");
            }

            if (packet.contains(TcpPacket.class)) {
                TcpPacket tcpPacket = packet.get(TcpPacket.class);
                packetInfo.append("Source Port: ").append(tcpPacket.getHeader().getSrcPort().valueAsInt()).append("\n");
                packetInfo.append("Destination Port: ").append(tcpPacket.getHeader().getDstPort().valueAsInt()).append("\n");
                packetInfo.append("Sequence Number: ").append(tcpPacket.getHeader().getSequenceNumber()).append("\n");
                packetInfo.append("Acknowledgment Number: ").append(tcpPacket.getHeader().getAcknowledgmentNumber()).append("\n");

                // Kiểm tra xem có phải là gói tin HTTP không
                if (tcpPacket.getHeader().getSrcPort().equals(TcpPort.HTTP) || tcpPacket.getHeader().getDstPort().equals(TcpPort.HTTP)) {
                    String payload = new String(tcpPacket.getPayload().getRawData());
                    packetInfo.append("HTTP Payload: ").append(payload).append("\n");
                }
            } else if (packet.contains(UdpPacket.class)) {
                UdpPacket udpPacket = packet.get(UdpPacket.class);
                packetInfo.append("Source Port: ").append(udpPacket.getHeader().getSrcPort().valueAsInt()).append("\n");
                packetInfo.append("Destination Port: ").append(udpPacket.getHeader().getDstPort().valueAsInt()).append("\n");
                packetInfo.append("Length: ").append(udpPacket.getHeader().getLength()).append("\n");
            }

            // Thêm thông tin packet vào kết quả phân tích
            analysisResult.add(packetInfo.toString());
        }

        // Đóng file pcapng
        handle.close();
        System.out.println("Total packets read: " + packetCount);
        return analysisResult;
    }
}
