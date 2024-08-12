package com.example.LTM2;

public class MainRunner {

    public static void main(String[] args) {
        // Chạy server trong một thread riêng
        new Thread(() -> {
            System.out.println("Starting server...");
            try {
                NetworkDataServer.main(new String[0]);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).start();

        // Đợi một chút để server có thể bắt đầu
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // Chạy client trong thread chính
        System.out.println("Starting client...");
        NetworkDataClient.main(new String[0]);
    }

}
