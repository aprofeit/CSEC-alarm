package ca.jonsimpson.comp4203.apanalyser;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import org.apache.log4j.Logger;

public class Main {

	private static final int STATISTICS_PRINT_INTERVAL = 10 * 1000;
	
	private static final String WHITELIST_CONFIG_FILE = "apanalyser.properties";
	private static final String PACKET_MONITOR_BINARY = "script/run-monitor";

	private static final String NO_CONFIG_MESSAGE = "Running with no configuration. No alerts will occur.";
	
	private final Logger log = Logger.getLogger(Main.class);
	private final Logger alertLog = Logger.getLogger("alert");
	
	
	// the map of allowed access points
	private Map<String, Set<Entry>> whitelist;
	private Process process;
	
	private Map<Integer, Integer> statistics = new HashMap<>();
	
	public static void main(String[] args) {
		new Main();
	}
	
	public Main() {
		
		loadWhitelist();
		registerExitHandler();
		startStatisticsPrinter();
		
		// run the packet-monitor binary
		try {
			process = Runtime.getRuntime().exec(PACKET_MONITOR_BINARY);
			InputStream inputStream = process.getInputStream();
			
			InputStreamReader reader = new InputStreamReader(inputStream);
			BufferedReader bufferedReader = new BufferedReader(reader);
			
			while (true) {
				String readLine = bufferedReader.readLine();
				
				if (readLine == null) {
					break;
				}
				processLine(readLine);
			}
			
		} catch (IOException e) {
			log.error(e);
		}
		
	}
	
	private void startStatisticsPrinter() {
		Timer timer = new Timer("statistics printer");
		timer.scheduleAtFixedRate(printStats, STATISTICS_PRINT_INTERVAL, STATISTICS_PRINT_INTERVAL);
		
	}

	/**
	 * Kill the process subprocess when the program is about to shut down
	 */
	private void registerExitHandler() {
		
		Runtime.getRuntime().addShutdownHook(new Thread() {
			@Override
			public void run() {
				if (process != null) {
					try {
						killUnixProcess(process);
						
					} catch (Exception e) {
						log.error("tried to kill the monitor process, but failed", e);
					}
				}
				
			}
		});

	}

	/**
	 * Load the whitelist from the configuration file
	 */
	private void loadWhitelist() {
		Path path = Paths.get(WHITELIST_CONFIG_FILE);
		File file = path.toFile();
		log.info("reading config file from: " + file.getAbsolutePath());
		
		whitelist = new HashMap<String, Set<Entry>>();
		
		if (!file.exists()) {
			log.warn(NO_CONFIG_MESSAGE);
			return;
		}
		
		// get a reader of the configuration file
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(
				file)))) {
			
			// iterate over each line, reading the configuration
			while (true) {
				String line = reader.readLine();
				if (line == null) {
					break;
				}
				
				Entry entry = getEntryFromLine(line);
				if (entry != null) {
					Set<Entry> set = whitelist.get(entry.ssid);
					// check if ssid has a set already, create on otherwise
					if (set == null) {
						set = new HashSet<Entry>();
						whitelist.put(entry.ssid, set);
					}
					
					// add the Entry to the whitelist
					set.add(entry);
					
				}
				
			}
			
		} catch (FileNotFoundException e) {
			log.warn(NO_CONFIG_MESSAGE);
		} catch (IOException e) {
			log.error(e);
		}
		
	}
	
	/**
	 * Process the access point information line by line. Determine whether the
	 * line is a channel update or access point information, then perform
	 * actions based upon that.
	 * 
	 * @param line
	 */
	private void processLine(String line) {
		
		if (line == null || line.length() == 0) {
			return;
		}
		
		// check if this is a changing channel message
		if (line.charAt(0) == '#') {
			// ignore these messages
			
		} else {
			// it's a message from the monitor
			Entry entry = getEntryFromLine(line);
			
			logEntry(entry);
			validateEntry(entry);
		}
		
	}
	
	/**
	 * Log the channel by incrementing the statistic map.
	 * @param entry
	 */
	private void logEntry(Entry entry) {
		
		// get the channel and it's value from the statistics map
		Integer channel = entry.channel;
		if (channel == null) {
			return;
		}
		Integer counter = statistics.get(channel);
		
		// set counter to 0 if null
		if (counter == null) {
			counter = 0;
		}
		
		// increment counter and put back into the map
		counter++;
		statistics.put(channel, counter);
	}

	/**
	 * Take a String and return a representation of it as an Entry.
	 * 
	 * @param line
	 * @return an Entry representing the line, null otherwise
	 */
	private Entry getEntryFromLine(String line) {
		String[] strings = line.split(",");
		
		String channel = strings[0];
		String mac = strings[1];
		String ssid = "";
		if (strings.length > 2) {
			ssid = strings[2];
		}
		
		Entry entry = new Entry(channel, mac, ssid);
		return entry;
	}
	
	/**
	 * The program only alerts when the same ssid is used and the channel or the
	 * mac address are not in the whitelist.
	 * 
	 * @param entry
	 */
	private void validateEntry(Entry entry) {
		
		Set<Entry> set = whitelist.get(entry.ssid);
		
		// if we don't have anything for this ssid, its not worth looking at
		if (set != null) {
			
			boolean contains = set.contains(entry);
			if (!contains) {
				// oh no, we don't recognize this Entry. Sound the alarm!
				alert(entry);
			}
		}
	}
	
	private void alert(Entry entry) {
		alertLog.info("Rouge AP detected! " + entry);
	}
	
	private static int getUnixPID(Process process) throws Exception {
		if (process.getClass().getName().equals("java.lang.UNIXProcess")) {
			Class cl = process.getClass();
			Field field = cl.getDeclaredField("pid");
			field.setAccessible(true);
			Object pidObject = field.get(process);
			return (Integer) pidObject;
		} else {
			throw new IllegalArgumentException("Needs to be a UNIXProcess");
		}
	}
	
	public static int killUnixProcess(Process process) throws Exception {
		int pid = getUnixPID(process);
		return Runtime.getRuntime().exec("kill " + pid).waitFor();
	}
	
	private TimerTask printStats = new TimerTask() {
		
		@Override
		public void run() {
			
			StringBuilder sb = new StringBuilder();
			sb.append("Beacons received: \n");
			
			// iterate over each channel from the statistics map, outputting the beacon count
			Set<Integer> keys = statistics.keySet();
			ArrayList<Integer> list = new ArrayList<>(keys);
			Collections.sort(list);
			
			for (Integer key : list) {
				Integer integer = statistics.get(key);
				sb.append("Channel: ").append(key).append(" count: ").append(integer).append('\n');

			}
			
			log.info(sb);
			
			// clear the statistics
			statistics.clear();
		}
	};
	
	/**
	 * Used to represent a channel-mac-ssid tuple.
	 */
	public static class Entry {
		
		private Integer channel;
		private String mac;
		private String ssid;
		
		public Entry(String channel, String mac, String ssid) {
			this.channel = Integer.parseInt(channel);
			this.mac = mac;
			this.ssid = ssid;
		}
		
		@Override
		public String toString() {
			return "Entry [channel=" + channel + ", mac=" + mac + ", ssid=" + ssid + "]";
		}
		
		@Override
		public boolean equals(Object obj) {
			if (obj instanceof Entry) {
				Entry other = (Entry) obj;
				return Objects.equals(channel, other.channel) && Objects.equals(mac, other.mac)
						&& Objects.equals(ssid, other.ssid);
			}
			
			return false;
		}
		
		@Override
		public int hashCode() {
			return Objects.hash(channel, mac, ssid);
		}
	}
}
