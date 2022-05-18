package uef;

public class BBCLabel {
	// Yes this is lazy; but it's the quickest route because JSON for some weird reason doesn't like hex
	private String address;
	private String name;
	private String type;
	
	public BBCLabel(String address, String name, String type) {
		this.address=address;
		this.name=name;
		this.type=type;
	}
	public long getAddress() { return Integer.parseInt(address, 16); }
	public void setAddress(String address) { this.address = address; }
	public String getName() { return name; }
	public void setName(String name) { this.name = name; }
	public String getType() { return type; }
	public void setType(String type) { this.type = type; }
}
