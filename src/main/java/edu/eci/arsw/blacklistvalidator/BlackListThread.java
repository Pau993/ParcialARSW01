package edu.eci.arsw.blacklistvalidator;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class BlackListThread extends Thread {

    private static final int BLACK_LIST_ALARM_COUNT = 5;
    private int start;
    private int end;
    private String ip;
    private AtomicInteger total;
    private List<Integer> blackListIndexes;

    /**
     * 
     * @param startIdx
     * @param endIdx
     * @param ip
     * @param totalFound
     * @param blackListIndexes
     */
    public BlackListThread(int start, int end, String ip, AtomicInteger total,List<Integer> blackListIndexes) {
        this.start = start;
        this.end = end;
        this.ip = ip;
        this.total = total;
        this.blackListIndexes = blackListIndexes;
    }

    public void run() {
        for (int i = start; i < end; i++) {
            if (isInBlacklistServer(ip, i)) {
                total.incrementAndGet();
                synchronized (blackListIndexes) {
                    blackListIndexes.add(i);
                }
            }

            if (total.get() >= BLACK_LIST_ALARM_COUNT) {
                break;
            }
        }
    }

    private boolean isInBlacklistServer(String ip, int listIndex) {
        return Math.random() > 0.999;
    }

}
