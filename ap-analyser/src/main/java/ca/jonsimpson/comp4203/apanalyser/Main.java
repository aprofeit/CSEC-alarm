package ca.jonsimpson.comp4203.apanalyser;

import java.io.IOException;

import org.apache.log4j.Logger;

public class Main {
	private final Logger log = Logger.getLogger(Main.class);
	
	private static final String PACKET_MONITOR_BINARY = "../script/run";
	
	public static void main(String[] args) {
		new Main();
	}
	
	public Main() {
		
		log.error("testing");
		
		// run the packet-monitor binary
		try {
			Runtime.getRuntime().exec(PACKET_MONITOR_BINARY);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
}
