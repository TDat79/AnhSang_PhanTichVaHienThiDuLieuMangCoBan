package com.example.LTM2;


import javax.swing.*;
import java.io.*;
import java.net.ConnectException;
import java.net.Socket;
import java.util.List;

public class NetworkDataClient {

    private static final String SERVER_IP = "localhost";
    private static final int PORT = 5000;

    public static void main(String[] args) {
        // Sử dụng JFileChooser để chọn file pcapng
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            String pcapFilePath = selectedFile.getAbsolutePath();

            try (Socket socket = new Socket(SERVER_IP, PORT);
                 ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                 ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

                System.out.println("Connected to server");

                // Gửi đường dẫn file pcapng cho server
                System.out.println("Gửi đường dẫn file pcapng cho server:" + pcapFilePath);
                out.writeObject(pcapFilePath);
                out.flush();  // Đảm bảo rằng tất cả dữ liệu đã được gửi đi

                // Nhận thông báo đang phân tích file
                String status = (String) in.readObject();
                System.out.println(status); // "Đang phân tích file..."

                // Nhận thông báo đã phân tích xong
                status = (String) in.readObject();
                System.out.println(status); // "Đã phân tích xong. Đang gửi kết quả..."

                // Nhận kết quả phân tích từ server
                List<String> analysisResult = (List<String>) in.readObject();

                // **Thêm thông báo đã nhận được kết quả phân tích**
                System.out.println("Đã nhận được kết quả phân tích.");

                // Hiển thị kết quả
                System.out.println("\nKết quả phân tích:");
                for (String result : analysisResult) {
                    System.out.println(result);
                }
            } catch (ConnectException e) {
                System.err.println("Không thể kết nối đến server. Vui lòng kiểm tra lại địa chỉ và cổng.");
            } catch (IOException | ClassNotFoundException e) {
                System.err.println("Lỗi khi giao tiếp với server: " + e.getMessage());
            }
        } else {
            System.out.println("No file selected.");
        }
    }
}
