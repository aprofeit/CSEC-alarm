package ca.jonsimpson.comp4203.apanalyser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import org.apache.log4j.Logger;

public class Main {
	private final Logger log = Logger.getLogger(Main.class);
	
	private static final String PACKET_MONITOR_BINARY = "script/run-monitor";
	
	public static void main(String[] args) {
		new Main();
	}
	
	public Main() {
		
		log.error("testing");
		
		// run the packet-monitor binary
		try {
			Process exec = Runtime.getRuntime().exec(PACKET_MONITOR_BINARY);
			InputStream inputStream = exec.getInputStream();
			
			InputStreamReader reader = new InputStreamReader(inputStream);
			BufferedReader bufferedReader = new BufferedReader(reader);
			
			while (true) {
				String readLine = bufferedReader.readLine();
				System.out.println(readLine);
				if (readLine == null) {
					break;
				}
			}
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
}
