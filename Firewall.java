import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;

public class Firewall {

	private HashSet<String> rules;
	private HashMap<String, HashSet<String>> recentlyGeneratedIps;

	public Firewall(String path) {
		recentlyGeneratedIps = new HashMap<>();
		rules = getRulesFromFile(path);
	}

	public boolean accept_packet(String direction, String protocol, int port, String ipaddress) {
		String s = direction + "," + protocol + "," + port + "," + ipaddress;
		if (rules.contains(s)) {
			return true;
		}

		return false;
	}

	public HashSet<String> getRulesFromFile(String path) {
		File file = new File(path);
		BufferedReader br = null;
		HashSet<String> rules = new HashSet<String>();
		try {
			br = new BufferedReader(new FileReader(file));
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		String st;
		try {
			while ((st = br.readLine()) != null) {
				if (st.indexOf('-') != -1) {
					HashSet<String> rangeRules = getRangeOfRules(st);
					rules.addAll(rangeRules);
				} else {
					rules.add(st);
				}
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return rules;
	}

	public HashSet<String> getRangeOfRules(String rule) {
		HashSet<String> rangeRules = new HashSet<String>();
		String[] splits = rule.split(",");
		int indexOfPortDash = splits[2].indexOf('-');
		int indexOfIpDash = splits[3].indexOf('-');
		if (indexOfPortDash != -1) {
			int lowerPort = Integer.parseInt(splits[2].substring(0, indexOfPortDash));
			int upperPort = Integer.parseInt(splits[2].substring(indexOfPortDash + 1, splits[2].length()));

			for (int i = lowerPort; i <= upperPort; i++) {
				if (indexOfIpDash != -1) {
					HashSet<String> rulesWithDiffIp = new HashSet<String>();
					String lowerIp = splits[3].substring(0, indexOfIpDash);
					String upperIp = splits[3].substring(indexOfIpDash + 1, splits[3].length());
					rulesWithDiffIp = getRangeOfIps(lowerIp, upperIp, splits[0], splits[1], "" + i);
					rangeRules.addAll(rulesWithDiffIp);
				} else {
					String s = splits[0] + "," + splits[1] + "," + i + "," + splits[3];
					rangeRules.add(s);
				}
			}
		} else {
			String lowerIp = splits[3].substring(0, indexOfIpDash);
			String upperIp = splits[3].substring(indexOfIpDash + 1, splits[3].length());
			HashSet<String> ips = getRangeOfIps(lowerIp, upperIp, splits[0], splits[1], splits[2]);
			rangeRules.addAll(ips);
		}

		return rangeRules;
	}

	public HashSet<String> getRangeOfIps(String lowerIp, String upperIp, String direction, String protocol,
			String port) {
		HashSet<String> rulesWithIp = new HashSet<String>();
		HashSet<String> ips = new HashSet<String>(); 
		if (!recentlyGeneratedIps.containsKey(lowerIp + "-" + upperIp)) {
			long lower = ipToLong(lowerIp);
			long upper = ipToLong(upperIp);
			for (long i = lower; i <= upper; i++) {
				String ip = longToIp(i);
				ips.add(ip); 
				String s = direction + "," + protocol + "," + port + "," + ip;
				rulesWithIp.add(s);
			}
			recentlyGeneratedIps.put(lowerIp+"-"+upperIp, ips); 
		} else { 
			ips = recentlyGeneratedIps.get(lowerIp+"-"+upperIp); 
			for(String ip : ips) { 
				rulesWithIp.add(direction +","+protocol+","+port+","+ip); 
			}
		}
		return rulesWithIp; 
		
	}

	public long ipToLong(String ipAddress) {

		String[] ipAddressInArray = ipAddress.split("\\.");

		long result = 0;
		for (int i = 0; i < ipAddressInArray.length; i++) {

			int power = 3 - i;
			int ip = Integer.parseInt(ipAddressInArray[i]);
			result += ip * Math.pow(256, power);

		}

		return result;
	}

	public String longToIp(long ip) {
		StringBuilder result = new StringBuilder(15);

		for (int i = 0; i < 4; i++) {

			result.insert(0, Long.toString(ip & 0xff));

			if (i < 3) {
				result.insert(0, '.');
			}

			ip = ip >> 8;
		}
		return result.toString();
	}

	public static void main(String args[]) {
		Firewall fw = new Firewall("test.csv");
		System.out.println(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"));
		System.out.println(fw.accept_packet("outbound", "tcp", 15000, "192.168.10.11"));
		System.out.println(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"));
		System.out.println(fw.accept_packet("inbound", "udp", 15000, "192.168.2.1"));
		System.out.println(fw.accept_packet("inbound", "udp", 40, "192.168.2.1"));
	}

}
