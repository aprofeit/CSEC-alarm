package ca.jonsimpson.comp4203.apanalyser;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.io.IOUtils;

public class AnalysisParser {
	
	public static void main(String[] args) throws IOException {
		new AnalysisParser(args);
	}
	
	int usr = 4, sys = 5, tot = 7, vsz = 11, rss = 12, mem = 13, read = 14, write = 15;
	int usrms = 4, sysms = 5;
	
	public AnalysisParser(String[] args) throws IOException {
		
		List<Integer> longLine = Arrays.asList(usr, sys, tot, vsz, rss, mem, read, write);
		List<Integer> shortLine = Arrays.asList(usrms, sysms);
		
		String input = IOUtils.toString(new File(args[0]).toURI());
		
		String[] lines = input.split("\n");
		
		for (String line : lines) {
			if (line.startsWith("#") || line.isEmpty() || line.startsWith("Linux")) {
				continue;
			}
			
			String[] lineParts = line.split(" ");
			
			List<Integer> chosenOne;
			if (lineParts.length > 60) {
				// it's the longer one
				chosenOne = longLine;
			} else {
				// it's the shorter one
				chosenOne = shortLine;
			}
			
			int i = 0;
			for (String part : lineParts) {
				if (part.isEmpty()) {
					continue;
				}
				i++;
				if (chosenOne.contains(i)) {
					System.out.print(part + "\t");
				}
				
//					System.out.print(part + " ");
				
			}
			
			if (chosenOne == shortLine) {
				System.out.println();
			}
		}
		
		
	}
	
}
