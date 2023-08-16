/*
 * Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package addToTLSPassThrough.contextmenu;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class MyContextMenuItemsProvider implements ContextMenuItemsProvider
{

    private final MontoyaApi api;

    public MyContextMenuItemsProvider(MontoyaApi api)
    {

        this.api = api;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event)
    {
        if (event.isFromTool(ToolType.PROXY, ToolType.TARGET, ToolType.LOGGER))
        {
            List<Component> menuItemList = new ArrayList<>();
            List<String> regexList = new ArrayList<String>();

            List<HttpRequestResponse> requestResponses = new ArrayList<>();
            //List<HttpRequestResponse> requestResponses = event.messageEditorRequestResponse().isPresent() ? requestResponses.add(event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses();
            if(event.messageEditorRequestResponse().isPresent()){
                requestResponses.add(event.messageEditorRequestResponse().get().requestResponse());
            } else {
                requestResponses = event.selectedRequestResponses();
            }
            
            //getting Index 0 will only ever retrieve the first one.
            //If we have more than one item selected, we want to build them all.
            for(HttpRequestResponse requestResponse : requestResponses) {
            //Extract host
                String host = requestResponse.url();

                int firstSlash = host.indexOf("/");
                host = host.substring(firstSlash + 2);

                if(host.contains("/")){
                    host = host.substring(0,host.indexOf("/"));
                }

                //find number of subdomains
                long domainCount = host.chars().filter(ch -> ch == '.').count();



                //s.update.adsrvr.org

                for(int i=(int) domainCount; i >= 1 ; i--) {

                    if(i == 1){
                        regexList.add(".*" + host);

                    } else {
                        String regex = ".*" + host.substring(host.indexOf(".")).replace(".", "\\\\.");
                        regexList.add(regex);
                    }

                    host = host.substring(1).substring(host.indexOf("."));  
                }

                


                


                //api.logging().logToOutput("URLs are"+ regexList.toString());

            }
            //create JMenuItems
                JMenuItem all = new JMenuItem("ALL");
                all.addActionListener(new ActionListener(){
                    public void actionPerformed(ActionEvent e){
                        addToTlsPassthrough(regexList);
                    }
                });

                menuItemList.add(all);


                for(int i=0;i< regexList.size();i++){
                    final String currentItem = regexList.get(i);
                    JMenuItem newItem = new JMenuItem(currentItem.replace("\\\\","\\"));
                    newItem.addActionListener(new ActionListener(){
                        public void actionPerformed(ActionEvent e){

                            addSingleToTlsPassthrough(currentItem);
                        }
                    });

                    menuItemList.add(newItem);

                }
            
            return menuItemList;
        }

        return null;
    }
    
    public void addToTlsPassthrough(List<String> regexList){
        //get current TLS passthrough settings
        String fullPrefix = "{\"proxy\":{\"ssl_pass_through\":{\"rules\":[";
        String rulePrefix = "{\"enabled\":true,\"host\":\"";
        String ruleSuffix = "\",\"protocol\":\"any\"}";
        String fullSuffix = "]}}}";
        
        //Build JSON of new rules
        for(int i=0; i < regexList.size(); i++) {
            //newRules = newRules + rulePrefix + regexList + ruleSuffix + ",";
            regexList.set(i, rulePrefix + regexList.get(i) + ruleSuffix);
        }
        
        String newRules = regexList.stream().collect(Collectors.joining(","));
        
        //Get Current Rules
        String currentRules = api.burpSuite().exportProjectOptionsAsJson("proxy.ssl_pass_through.rules");
        //get rid of newlines/tabs
        currentRules = currentRules.replaceAll("[\\s\\n\\r]+","");
        api.logging().logToOutput("Current Rules: "+ currentRules);
        
        //strip off fullSuffix
        currentRules = currentRules.substring(0,currentRules.length()-4);
        
        //Combine old and new
        String combinedRules = currentRules + "," + newRules + fullSuffix;
        api.logging().logToOutput("Current Rules: "+ currentRules);
        api.logging().logToOutput("New Rules: "+ newRules);
        api.logging().logToOutput("Combined Rules: " + combinedRules);
        
        //Set new rules
        api.burpSuite().importProjectOptionsFromJson(combinedRules);
    }
    
        public void addSingleToTlsPassthrough(String singleRegex){
        //get current TLS passthrough settings
        String fullPrefix = "{\"proxy\":{\"ssl_pass_through\":{\"rules\":[";
        String rulePrefix = "{\"enabled\":true,\"host\":\"";
        String ruleSuffix = "\",\"protocol\":\"any\"}";
        String fullSuffix = "]}}}";
        
        //Build JSON of new rules
        String newRules = rulePrefix + singleRegex + ruleSuffix;
        
        //Get Current Rules
        String currentRules = api.burpSuite().exportProjectOptionsAsJson("proxy.ssl_pass_through.rules");
        //get rid of newlines/tabs
        currentRules = currentRules.replaceAll("[\\s\\n\\r]+","");
        //strip off fullSuffix
        currentRules = currentRules.substring(0,currentRules.length()-4);
        
        //Combine old and new
        String combinedRules = currentRules + "," + newRules + fullSuffix;
        
        api.logging().logToOutput("Current Rules: "+ currentRules);
        api.logging().logToOutput("New Rules: "+ newRules);
        api.logging().logToOutput("Combined Rules: " + combinedRules);
        
        api.burpSuite().importProjectOptionsFromJson(combinedRules);
    }
}
