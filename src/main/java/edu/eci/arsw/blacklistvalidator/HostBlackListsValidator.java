/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author hcadavid
 */
public class HostBlackListsValidator {

    private static final int BLACK_LIST_ALARM_COUNT=5;
    private static final int TOTAL_BLACK_LISTS = 80000; 
     
    /**
     * Check the given host's IP address in all the available black lists,
     * and report it as NOT Trustworthy when such IP was reported in at least
     * BLACK_LIST_ALARM_COUNT lists, or as Trustworthy in any other case.
     * The search is not exhaustive: When the number of occurrences is equal to
     * BLACK_LIST_ALARM_COUNT, the search is finished, the host reported as
     * NOT Trustworthy, and the list of the five blacklists returned.
     * @param ipaddress suspicious host's IP address.
     * @return  Blacklists numbers where the given host's IP address was found.
     */
    public List<Integer> checkHost(String ipaddress, int numberOfThreads){
        int size = TOTAL_BLACK_LISTS / numberOfThreads;
        AtomicInteger total = new AtomicInteger(0);
        List<Thread> threads = new ArrayList<>();
        List<Integer> indices = new ArrayList<>();

        for (int i = 0; i < numberOfThreads; i++) {
            final int start = i * size;
            final int end = (i == numberOfThreads - 1) ? TOTAL_BLACK_LISTS : (i + 1) * size;

            Thread thread = new BlackListThread(start, end, ipaddress, total, indices);
            threads.add(thread);
            thread.start();
        }

        for(Thread thread: threads){
            try {
                thread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        System.out.println("Total black lists checked: " + indices.size() + " / " + TOTAL_BLACK_LISTS);
   

        LinkedList<Integer> blackListOcurrences=new LinkedList<>();

        int ocurrencesCount=0;
        
        HostBlacklistsDataSourceFacade skds=HostBlacklistsDataSourceFacade.getInstance();
        
        int checkedListsCount=0;
        
        for (int i=0;i<skds.getRegisteredServersCount() && ocurrencesCount<BLACK_LIST_ALARM_COUNT;i++){
            checkedListsCount++;
            
            if (skds.isInBlackListServer(i, ipaddress)){
                
                blackListOcurrences.add(i);
                
                ocurrencesCount++;
            }
        }

        if (ocurrencesCount>=BLACK_LIST_ALARM_COUNT){
            skds.reportAsNotTrustworthy(ipaddress);
            
            System.out.println("INFO: HOST " + ipaddress + " Reported AS NOT trustworthy");

        }
        else{
            skds.reportAsTrustworthy(ipaddress);

            System.out.println("INFO: HOST " + ipaddress + " Reported AS trustworthy");
        }

        
        LOG.log(Level.INFO, "Checked Black Lists:{0} of {1}", new Object[]{checkedListsCount, skds.getRegisteredServersCount()});
        
        return blackListOcurrences;
    }
    
    
    private static final Logger LOG = Logger.getLogger(HostBlackListsValidator.class.getName());
    
}
