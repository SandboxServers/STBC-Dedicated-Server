def Go(sFile = "Multiplayer/Episode/Mission1/Mission1Menus.py"):
	pFile = open(sFile, "r")
	lsLines = pFile.readlines()
	pFile.close()

	# Fixup the lines..
	lsLines = FixupFile(lsLines)

	pFile = open(sFile, "w")
	pFile.writelines(lsLines)
	pFile.close()

g_lsImportedModules = []

def FixupFile(lsLines):
	import re

	pModuleSearch = re.compile(r"import\s+([\w.]+).*")
	pFunctionSearch = re.compile(r"def\s+(\w+)\s*\([^)]*\):.*")

	lImportedModuleSearches = []

	lsFixedLines = []

	iLatestFunctionLine = None
	iLatestFunctionLineFixed = None
	lLocalModules = []
	for iLine in range(len(lsLines)):
		sLine = lsLines[iLine]

		# Look for module imports..
		pModuleMatch = pModuleSearch.match(sLine)
		if pModuleMatch:
			# Found a module import.
			sModule = pModuleMatch.group(1)

			# Some modules are ok:
			if sModule not in ( "App", "MissionLib", "UIHelpers", "loadspacehelper" ):
				g_lsImportedModules.append( sModule )
				lImportedModuleSearches.append(
					re.compile("(" + sModule + r")\.\w+"))
				continue

		# Look for a function definition..
		pFunctionMatch = pFunctionSearch.match(sLine)
		if pFunctionMatch:
			sFunction = pFunctionMatch.group(1)
			iLatestFunctionLine = iLine
			iLatestFunctionLineFixed = len(lsFixedLines) + 1
			lLocalModules = []

		# Look for references to modules we imported globally.
		for pModuleCheck in lImportedModuleSearches:
			pMatch = pModuleCheck.search(sLine)
			if pMatch:
				# Found a reference to this module.  Make sure it's
				# imported locally within this function.
				if iLatestFunctionLine is not None:
					sModule = pMatch.group(1)
					if sModule not in lLocalModules:
						lsFixedLines = lsFixedLines[:iLatestFunctionLineFixed] + ["\timport " + sModule + "\n"] + lsFixedLines[iLatestFunctionLineFixed:]
						lLocalModules.append(sModule)

		# Add this line to the list of fixed lines.
		lsFixedLines.append(sLine)

	return lsFixedLines

if __name__ == "__main__":
	Go()

