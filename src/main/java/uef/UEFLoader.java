/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package uef;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class UEFLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {
		return "UEF";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);
		
		// read header
		String magic = reader.readAsciiString(0, 10);
		if (magic.equals("UEF File!"))
		{
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("6502:LE:16:default", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		// Read the file
		BinaryReader reader = new BinaryReader(provider, true);
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		
		UEF UEFFile = new UEF(reader);
		
		// Now we have it loaded - it's time to create some objects
		try {
			if (UEFFile.ram != null) api.createMemoryBlock("RAM", api.toAddr(0), UEFFile.ram, false);
			if (UEFFile.rom != null) {
				api.createMemoryBlock("ROM", api.toAddr(0), UEFFile.rom, true);
			}
			else {
				MemoryBlock block = program.getMemory().createInitializedBlock("ROM", api.toAddr(0xC000), 0x4000, (byte) 0x00, null, false);
				block.setRead(true);
				block.setExecute(true);
			}
			
			if ((UEFFile.cpustate.PC & 0xffff) < 0x8000) {
				// PC is in RAM so add it as an Entrypoint
				api.addEntryPoint(api.toAddr(UEFFile.cpustate.PC & 0xffff));
			}
			
			// Create some standard functions
			api.createFunction(api.toAddr(0xfff4),"OSBYTE");
			api.createFunction(api.toAddr(0xfff1),"OSBYTE");
			
		} catch (Exception e) {
			Msg.error(this, e.getMessage());
		}
		
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
