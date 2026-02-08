import App

def Go():
	file = open("EventTypes.txt", "wt")
	for sKey in App.__dict__.keys():
		if sKey[:3] == "ET_":
			file.write("%s = %d\n" % (sKey, App.__dict__[sKey]))

