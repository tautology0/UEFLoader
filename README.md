# UEFLoader
UEF Loader for Ghidra. Can be used to aid reverse engineering BBC Micro/Electron program from UEF state images.

# Installer
Build using Eclipse after jumping through the many hoops to set Eclipse up for Ghidra. Then you should be able to use GhidraDev->export->Ghidra Module Extension...

Put the built .zip file (which Eclipse will write in dist) in $GHIDRAPATH/Extensions/Ghidra, spawn ghidra and load extensions.

# Altering labels
By default it will put a copy of the OS 1.2 ROM in &C000 to &ffff. It will add the labels defined in data/labels.json to Ghidra. This should include the OS calls and common vectors.
