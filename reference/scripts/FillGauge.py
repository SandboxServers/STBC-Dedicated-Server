import App

def CurrentMainPower(pSystem):
	if (pSystem != None):
		return(pSystem.GetMainBatteryPower())
	return(0.0)

def MaxMainPower(pSystem):
	if (pSystem != None):
		return(pSystem.GetMainBatteryLimit())
	return(1.0)

def CurrentBackupPower(pSystem):
	if (pSystem != None):
		return(pSystem.GetBackupBatteryPower())
	return(0.33)

def MaxBackupPower(pSystem):
	if (pSystem != None):
		return(pSystem.GetBackupBatteryLimit())
	return(1.0)
