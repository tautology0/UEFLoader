// UEF class - handles a UEF files

package uef;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class UEF {
	public UEFHeader header;
	public ArrayList<UEFChunk> chunks;
	public UEFCPUStateChunk cpustate;
	public byte[] ram;
	public byte[] rom;

	public UEF(BinaryReader reader) throws IOException {
		header = new UEFHeader(reader);
		
		readAllChunks(reader);
		
		// Look for state chunks
		for (UEFChunk chunk : chunks) {
			if (chunk.chunk_id == 0x460) {
				// This is a BeebEm CPU State chunk, we only care about PC as an entry point
				cpustate = new UEFCPUStateChunk(chunk.data);
			}
			if (chunk.chunk_id == 0x462) {
				// This is a BeebEm Memory chunk, we'll use this to make the RAM memory area
				ram = Arrays.copyOf(chunk.data, chunk.data.length);
			}
			if (chunk.chunk_id == 0x464) {
				// This is a BeebEm privileged memory chunk, we'll use this for ROM
				rom = Arrays.copyOf(chunk.data, chunk.data.length);
			}
		}
	}
	
	public ArrayList<UEFChunk> readAllChunks(BinaryReader reader) throws IOException {
		chunks = new ArrayList<UEFChunk>();
		
		while (reader.getPointerIndex() < reader.length()) {
			UEFChunk chunk = new UEFChunk(reader);
			chunks.add(chunk);
		}
		
		return chunks;
	}
}
